import { open, lstat } from "node:fs/promises";
import path from "node:path";
import { isImportError, reject, unsupported } from "./import-errors.mjs";
import { resolveImportLimits } from "./import-limits.mjs";
import { parseJsonLinesBytes, parseJsonObjectBytes } from "./import-json.mjs";
import { parseAuditZip } from "./import-zip.mjs";
import { assertNoExternalReferences, identityForContract, subjectFromRecord, verifyContractIntegrity } from "./import-normalization.mjs";
import { finalizeAuditPackage, prepareAuditPackage } from "./import-manifest.mjs";
import { runReferenceValidation } from "./reference-validation.mjs";
import { acceptedResult, rejectedResult, sha256 } from "./import-result.mjs";
import { assertLocalSourcePath } from "./import-path-policy.mjs";

const EXTENSION_KIND = Object.freeze({
  ".json": "JsonObject",
  ".jsonl": "JsonLines",
  ".zip": "AuditPackageZip"
});

const PACKAGE_KINDS = new Set(["Auto", "JsonObject", "JsonLines", "AuditPackageZip"]);
const PRIVACY_MODES = new Set(["SummaryOnly", "Private"]);

function sameFile(left, right) {
  return left.size === right.size && left.mtimeNs === right.mtimeNs
    && (left.ino === 0n || right.ino === 0n || left.ino === right.ino)
    && (left.dev === 0n || right.dev === 0n || left.dev === right.dev);
}

async function readBoundedSource(sourcePath, maximumBytes) {
  let handle;
  try {
    const pathState = await lstat(sourcePath, { bigint: true });
    if (pathState.isSymbolicLink()) reject("IMPORT_SOURCE_SYMLINK_FORBIDDEN", "Read", "Symbolic-link sources are forbidden.");
    if (!pathState.isFile()) reject("IMPORT_SOURCE_NOT_FILE", "Read", "Selected source is not a regular file.");
    if (pathState.size > BigInt(maximumBytes)) reject("IMPORT_SOURCE_BYTES_EXCEEDED", "Read", "Input exceeds the source byte limit.");
    handle = await open(sourcePath, "r");
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || !sameFile(pathState, before)) reject("IMPORT_SOURCE_CHANGED", "Read", "Selected source identity changed before reading.");
    const chunks = [];
    let total = 0;
    while (true) {
      const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes - total + 1));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maximumBytes) reject("IMPORT_SOURCE_BYTES_EXCEEDED", "Read", "Input exceeds the source byte limit.");
      chunks.push(buffer.subarray(0, bytesRead));
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(sourcePath, { bigint: true });
    if (pathAfter.isSymbolicLink() || !sameFile(before, after) || !sameFile(after, pathAfter)) {
      reject("IMPORT_SOURCE_CHANGED", "Read", "Selected source changed while it was read.");
    }
    return Buffer.concat(chunks, total);
  } catch (error) {
    if (isImportError(error)) throw error;
    reject("IMPORT_SOURCE_READ_FAILED", "Read", "Selected source could not be read safely.");
  } finally {
    await handle?.close().catch(() => {});
  }
}

function determinePackageKind(sourcePath, expectedPackageKind, bytes) {
  const detected = EXTENSION_KIND[path.extname(sourcePath).toLowerCase()];
  if (!detected) unsupported("IMPORT_FORMAT_UNSUPPORTED", "Selected file format is unsupported.");
  if (expectedPackageKind !== "Auto" && expectedPackageKind !== detected) {
    reject("IMPORT_PACKAGE_KIND_MISMATCH", "Detect", "Selected file kind does not match the expected package kind.");
  }
  const zipMagic = bytes.length >= 4 && bytes.readUInt32LE(0) === 0x04034b50;
  if (detected === "AuditPackageZip" && !zipMagic
    && (bytes.subarray(0, 2).toString("ascii") === "MZ" || bytes.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04])) > 0)) {
    unsupported("IMPORT_ZIP_SELF_EXTRACTING_UNSUPPORTED", "Self-extracting or prefixed ZIP input is unsupported.");
  }
  if ((detected === "AuditPackageZip") !== zipMagic) {
    reject("IMPORT_FORMAT_SIGNATURE_MISMATCH", "Detect", "File extension and content signature do not match.");
  }
  return detected;
}

function validateOptions(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) reject("IMPORT_OPTIONS_INVALID", "Prepare", "Import options must be an object.");
  assertLocalSourcePath(options.sourcePath);
  const expectedPackageKind = options.expectedPackageKind ?? "Auto";
  const privacyMode = options.privacyMode ?? "SummaryOnly";
  if (!PACKAGE_KINDS.has(expectedPackageKind)) reject("IMPORT_OPTIONS_INVALID", "Prepare", "expectedPackageKind is invalid.");
  if (!PRIVACY_MODES.has(privacyMode)) reject("IMPORT_OPTIONS_INVALID", "Prepare", "privacyMode is invalid.");
  return { expectedPackageKind, privacyMode, limits: resolveImportLimits(options.limits), referenceValidator: options.referenceValidator };
}

export async function importAuditPackage(options) {
  let packageKind = null;
  try {
    const normalizedOptions = validateOptions(options);
    const bytes = await readBoundedSource(options.sourcePath, normalizedOptions.limits.maxSourceBytes);
    packageKind = determinePackageKind(options.sourcePath, normalizedOptions.expectedPackageKind, bytes);
    if (packageKind === "AuditPackageZip") {
      const zip = parseAuditZip(bytes, normalizedOptions.limits);
      const prepared = prepareAuditPackage(zip, normalizedOptions.limits);
      await runReferenceValidation(prepared.subjects, normalizedOptions.referenceValidator);
      finalizeAuditPackage(prepared);
      return acceptedResult({
        packageKind,
        privacyMode: normalizedOptions.privacyMode,
        subjects: prepared.subjects,
        sourceBytes: bytes.length,
        sourceDigest: zip.archiveDigest,
        zip,
        opaqueMemberCount: prepared.opaqueMemberCount
      });
    }
    const parsed = packageKind === "JsonObject"
      ? parseJsonObjectBytes(bytes, normalizedOptions.limits)
      : parseJsonLinesBytes(bytes, normalizedOptions.limits);
    const subjects = parsed.records.map((record) => subjectFromRecord(record));
    const identities = new Set();
    for (const subject of subjects) {
      const key = `${subject.contractKind}\u0000${identityForContract(subject.contractKind, subject.value)}`;
      if (identities.has(key)) reject("IMPORT_REFERENCE_DUPLICATE_ID", "Normalize", "Duplicate imported contract identity was rejected.");
      identities.add(key);
    }
    for (const subject of subjects) assertNoExternalReferences(subject.value);
    await runReferenceValidation(subjects, normalizedOptions.referenceValidator);
    for (const subject of subjects) verifyContractIntegrity(subject.contractKind, subject.value);
    return acceptedResult({
      packageKind,
      privacyMode: normalizedOptions.privacyMode,
      subjects,
      sourceBytes: bytes.length,
      sourceDigest: sha256(bytes),
      finalLineTerminated: parsed.finalLineTerminated
    });
  } catch (error) {
    if (isImportError(error)) return rejectedResult(error, packageKind);
    return rejectedResult({
      status: "Rejected",
      code: "IMPORT_INTERNAL_ERROR",
      stage: "Finalize",
      message: "Import failed without exposing source details."
    }, packageKind);
  }
}

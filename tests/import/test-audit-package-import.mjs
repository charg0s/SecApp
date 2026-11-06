import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importAuditPackage } from "../../src/import/audit-package-importer.mjs";
import { digestWithExclusion, normalizeAuditManifest } from "../../tools/lib/jcs.mjs";
import { parseStrictJson } from "../../tools/lib/strict-json.mjs";
import { referenceValidate } from "./reference-validator.mjs";
import { assertLocalSourcePath } from "../../src/import/import-path-policy.mjs";
import { parseJsonObjectBytes, parseJsonLinesBytes } from "../../src/import/import-json.mjs";
import { resolveImportLimits } from "../../src/import/import-limits.mjs";

const directory = path.dirname(fileURLToPath(import.meta.url));
const temporaryRoot = await mkdtemp(path.join(tmpdir(), "secapp-import-test-"));
const fixturePath = (name) => path.join(directory, "fixtures", name);
let temporaryIndex = 0;

after(async () => {
  await rm(temporaryRoot, { recursive: true, force: true });
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function temporaryFile(extension, bytes) {
  temporaryIndex += 1;
  const target = path.join(temporaryRoot, `case-${String(temporaryIndex).padStart(3, "0")}${extension}`);
  await writeFile(target, bytes);
  return target;
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ byte) & 0xff];
  return (crc ^ 0xffffffff) >>> 0;
}

function buildZip(specifications) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const specification of specifications) {
    const name = Buffer.from(specification.name, "utf8");
    const payload = Buffer.from(specification.bytes);
    const method = specification.method ?? 0;
    const compressed = Buffer.concat([
      method === 8 ? deflateRawSync(payload) : payload,
      specification.compressedTail ?? Buffer.alloc(0)
    ]);
    const flags = specification.flags ?? 0x0800;
    const crc = crc32(payload);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(payload.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(((specification.platform ?? 3) << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(payload.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(specification.externalAttributes ?? ((0o100644 << 16) >>> 0), 38);
    central.writeUInt32LE(localOffset, 42);
    localParts.push(local, name, compressed);
    centralParts.push(central, name);
    localOffset += local.length + name.length + compressed.length;
  }
  const centralBytes = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(specifications.length, 8);
  eocd.writeUInt16LE(specifications.length, 10);
  eocd.writeUInt32LE(centralBytes.length, 12);
  eocd.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localParts, centralBytes, eocd]);
}

const ROLE_COLLECTION = Object.freeze({
  AuditRun: "audit_runs",
  AuditPass: "audit_passes",
  CollectorDefinition: "collector_definitions",
  RuleDefinition: "rule_definitions",
  CollectorExecution: "collector_executions",
  Observation: "observations",
  Evidence: "evidence_references",
  Finding: "findings",
  ConsentReceipt: "consent_receipts",
  ActionLog: "action_logs",
  RedactionProfile: "redaction_profiles",
  RebootContinuationState: "reboot_continuation_states"
});

async function validAuditEntries() {
  const document = parseStrictJson(await readFile(path.join(directory, "..", "contracts", "xobj", "materialized-graphs.json"), "utf8"), "synthetic graph fixture");
  const graph = structuredClone(document.base_graph);
  const manifest = graph.collections.audit_manifests[0];
  const entries = [];
  for (const member of manifest.entries) {
    const value = graph.collections[ROLE_COLLECTION[member.role]][0];
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
    member.size_bytes = bytes.length;
    member.file_digest.digest = sha256(bytes);
    entries.push({ name: member.logical_path, bytes });
  }
  manifest.manifest_digest.digest = digestWithExclusion(manifest, "manifest_digest.digest", normalizeAuditManifest);
  entries.unshift({ name: "manifest.json", bytes: Buffer.from(`${JSON.stringify(manifest)}\n`, "utf8") });
  return entries;
}

async function run(sourcePath, additions = {}) {
  return importAuditPackage({
    sourcePath,
    expectedPackageKind: "Auto",
    privacyMode: "SummaryOnly",
    referenceValidator: referenceValidate,
    ...additions
  });
}

test("imports one strict JSON contract with a privacy-safe summary", async () => {
  const result = await run(fixturePath("error-object.json"));
  const expected = JSON.parse(await readFile(path.join(directory, "expected", "error-object-summary.json"), "utf8"));
  assert.equal(result.status, expected.status);
  assert.equal(result.package_kind, expected.package_kind);
  assert.equal(result.summary.imported_object_count, expected.imported_object_count);
  assert.deepEqual(result.summary.contract_counts, expected.contract_counts);
  assert.equal(result.summary.integrity_claim, expected.integrity_claim);
  assert.equal(result.summary.provenance_claim, expected.provenance_claim);
  assert.equal(JSON.stringify(result).includes(fixturePath("error-object.json")), false);
  assert.equal(Object.hasOwn(result, "objects"), false);
});

test("private mode materializes a validated object", async () => {
  const result = await run(fixturePath("error-object.json"), { privacyMode: "Private" });
  assert.equal(result.status, "Accepted");
  assert.equal(result.objects[0].contract_kind, "ErrorObject");
  assert.equal(result.objects[0].value.details_redacted, true);
});

test("imports standalone AuditRun, AuditManifest, and ExportManifest contracts", async () => {
  const document = parseStrictJson(await readFile(path.join(directory, "..", "contracts", "xobj", "materialized-graphs.json"), "utf8"), "synthetic graph fixture");
  const values = [
    document.base_graph.collections.audit_runs[0],
    document.base_graph.collections.audit_manifests[0],
    document.base_graph.collections.export_manifests[0]
  ];
  for (const value of values) {
    const sourcePath = await temporaryFile(".json", Buffer.from(JSON.stringify(value)));
    assert.equal((await run(sourcePath)).status, "Accepted");
  }
});

test("imports JSONL with an optional final LF", async () => {
  const bytes = await readFile(fixturePath("error-objects.jsonl"));
  const sourcePath = await temporaryFile(".jsonl", bytes.subarray(0, -1));
  const result = await run(sourcePath);
  assert.equal(result.status, "Accepted");
  assert.equal(result.summary.imported_object_count, 2);
  assert.equal(result.summary.jsonl_final_lf_policy, "AbsentAllowed");
});

test("requires final LF when the explicit JSONL policy requires it", async () => {
  const bytes = await readFile(fixturePath("error-objects.jsonl"));
  const sourcePath = await temporaryFile(".jsonl", bytes.subarray(0, -1));
  const result = await run(sourcePath, { limits: { jsonlFinalLf: "Required" } });
  assert.equal(result.error.code, "IMPORT_JSONL_FINAL_LF_REQUIRED");
});

test("rejects duplicate JSON keys", async () => {
  const sourcePath = await temporaryFile(".json", Buffer.from('{"schema_version":"1.0.0","error_id":"90000000-0000-4000-8000-000000000001","code":"ImportError","stage":"Import","message":"one","message":"two","retryable":false,"details_redacted":true}'));
  assert.equal((await run(sourcePath)).error.code, "IMPORT_JSON_INVALID");
});

test("rejects primitive JSON roots and JSONL rows", async () => {
  const jsonPath = await temporaryFile(".json", Buffer.from("true"));
  const jsonlPath = await temporaryFile(".jsonl", Buffer.from("{}\n7\n"));
  assert.equal((await run(jsonPath)).error.code, "IMPORT_JSON_ROOT_NOT_OBJECT");
  assert.equal((await run(jsonlPath)).error.code, "IMPORT_JSON_ROOT_NOT_OBJECT");
});

test("rejects blank JSONL lines", async () => {
  const sourcePath = await temporaryFile(".jsonl", Buffer.from('{"schema_version":"1.0.0"}\n\n'));
  assert.equal((await run(sourcePath)).error.code, "IMPORT_JSONL_BLANK_LINE");
});

test("enforces JSONL line and record bounds", async () => {
  const lineResult = await run(fixturePath("error-objects.jsonl"), { limits: { maxJsonlLineBytes: 16 } });
  const countResult = await run(fixturePath("error-objects.jsonl"), { limits: { maxRecords: 1 } });
  assert.equal(lineResult.error.code, "IMPORT_JSONL_LINE_BYTES_EXCEEDED");
  assert.equal(countResult.error.code, "IMPORT_RECORD_COUNT_EXCEEDED");
});

test("rejects duplicate contract identities in JSONL", async () => {
  const record = JSON.stringify(JSON.parse(await readFile(fixturePath("error-object.json"), "utf8")));
  const sourcePath = await temporaryFile(".jsonl", Buffer.from(`${record}\n${record}\n`));
  assert.equal((await run(sourcePath)).error.code, "IMPORT_REFERENCE_DUPLICATE_ID");
});

test("rejects invalid UTF-8 and excessive JSON nesting", async () => {
  const utf8Path = await temporaryFile(".json", Buffer.from([0xc3, 0x28]));
  let nested = "0";
  for (let index = 0; index < 70; index += 1) nested = `[${nested}]`;
  const depthPath = await temporaryFile(".jsonl", Buffer.from(`{"schema_version":"1.0.0","error_id":"90000000-0000-4000-8000-000000000001","code":"ImportError","stage":"Import","message":"synthetic","retryable":false,"details_redacted":true,"detail_codes":${nested}}\n`));
  assert.equal((await run(utf8Path)).error.code, "IMPORT_UTF8_INVALID");
  assert.equal((await run(depthPath)).error.code, "IMPORT_JSON_DEPTH_EXCEEDED");
});

test("fails closed without the explicit reference-validation boundary", async () => {
  const result = await importAuditPackage({ sourcePath: fixturePath("error-object.json") });
  assert.equal(result.error.code, "IMPORT_REFERENCE_VALIDATION_REQUIRED");
});

test("returns controlled schema validation and external-reference failures", async () => {
  const invalid = JSON.parse(await readFile(fixturePath("error-object.json"), "utf8"));
  invalid.stage = "Unknown";
  const invalidPath = await temporaryFile(".json", Buffer.from(JSON.stringify(invalid)));
  const external = JSON.parse(await readFile(fixturePath("error-object.json"), "utf8"));
  external.$ref = "https://outside.invalid/schema.json";
  const externalPath = await temporaryFile(".json", Buffer.from(JSON.stringify(external)));
  assert.equal((await run(invalidPath)).error.code, "IMPORT_SCHEMA_VALIDATION_FAILED");
  assert.equal((await run(externalPath)).error.code, "IMPORT_EXTERNAL_REFERENCE_FORBIDDEN");
});

test("returns controlled unsupported and expected-kind statuses", async () => {
  const unsupportedPath = await temporaryFile(".tar", Buffer.from("synthetic"));
  assert.equal((await run(unsupportedPath)).status, "Unsupported");
  const mismatch = await run(fixturePath("error-object.json"), { expectedPackageKind: "JsonLines" });
  assert.equal(mismatch.error.code, "IMPORT_PACKAGE_KIND_MISMATCH");
});

test("rejects limit weakening and non-local device paths before reading", async () => {
  const weakened = await run(fixturePath("error-object.json"), { limits: { maxSourceBytes: 64 * 1024 * 1024 + 1 } });
  const device = await importAuditPackage({ sourcePath: "\\\\.\\synthetic.json", referenceValidator: referenceValidate });
  assert.equal(weakened.error.code, "IMPORT_LIMITS_INVALID");
  assert.equal(device.error.code, "IMPORT_SOURCE_PATH_INVALID");
});

test("rejects a schema-valid standalone contract with a stale ObjectDigest", async () => {
  const document = parseStrictJson(await readFile(path.join(directory, "..", "contracts", "xobj", "materialized-graphs.json"), "utf8"), "synthetic graph fixture");
  const runObject = structuredClone(document.base_graph.collections.audit_runs[0]);
  runObject.state = "Partial";
  const sourcePath = await temporaryFile(".json", Buffer.from(JSON.stringify(runObject)));
  assert.equal((await run(sourcePath)).error.code, "IMPORT_DIGEST_MISMATCH");
});

test("imports a complete synthetic manifest package without extraction", async () => {
  const sourcePath = await temporaryFile(".zip", buildZip(await validAuditEntries()));
  const result = await run(sourcePath, { expectedPackageKind: "AuditPackageZip" });
  assert.equal(result.status, "Accepted");
  assert.equal(result.validation.references, "Passed");
  assert.equal(result.summary.contract_counts.AuditManifest, 1);
  assert.equal(result.summary.contract_counts.AuditRun, 1);
  assert.equal(result.summary.provenance_claim, "NotEstablished");
});

test("rejects package member and manifest digest tampering", async () => {
  const memberTamper = await validAuditEntries();
  const runEntry = memberTamper.find((entry) => entry.name === "run.json");
  runEntry.bytes = Buffer.concat([runEntry.bytes, Buffer.from(" ")]);
  const memberPath = await temporaryFile(".zip", buildZip(memberTamper));
  assert.equal((await run(memberPath)).error.code, "IMPORT_FILE_DIGEST_MISMATCH");

  const manifestTamper = await validAuditEntries();
  const manifest = JSON.parse(manifestTamper[0].bytes.toString("utf8"));
  manifest.manifest_digest.digest = "0".repeat(64);
  manifestTamper[0].bytes = Buffer.from(JSON.stringify(manifest));
  const manifestPath = await temporaryFile(".zip", buildZip(manifestTamper));
  assert.equal((await run(manifestPath)).error.code, "IMPORT_DIGEST_MISMATCH");
});

test("rejects undeclared archive membership", async () => {
  const entries = await validAuditEntries();
  entries.push({ name: "reports/undeclared.txt", bytes: Buffer.from("synthetic") });
  const sourcePath = await temporaryFile(".zip", buildZip(entries));
  assert.equal((await run(sourcePath)).error.code, "IMPORT_MANIFEST_MEMBERSHIP_MISMATCH");
});

test("rejects a manifest role moved to a non-canonical package path", async () => {
  const entries = await validAuditEntries();
  const manifest = JSON.parse(entries[0].bytes.toString("utf8"));
  const runMember = manifest.entries.find((entry) => entry.role === "AuditRun");
  const runEntry = entries.find((entry) => entry.name === runMember.logical_path);
  runMember.logical_path = "objects/run.json";
  runEntry.name = runMember.logical_path;
  manifest.manifest_digest.digest = digestWithExclusion(manifest, "manifest_digest.digest", normalizeAuditManifest);
  entries[0].bytes = Buffer.from(JSON.stringify(manifest));
  const sourcePath = await temporaryFile(".zip", buildZip(entries));
  assert.equal((await run(sourcePath)).error.code, "IMPORT_MANIFEST_ROLE_PATH_MISMATCH");
});

test("rejects traversal, duplicate, and case-colliding ZIP paths", async () => {
  const traversal = await temporaryFile(".zip", buildZip([{ name: "../escape.json", bytes: Buffer.from("{}") }]));
  const duplicate = await temporaryFile(".zip", buildZip([{ name: "manifest.json", bytes: Buffer.from("{}") }, { name: "manifest.json", bytes: Buffer.from("{}") }]));
  const collision = await temporaryFile(".zip", buildZip([{ name: "manifest.json", bytes: Buffer.from("{}") }, { name: "MANIFEST.JSON", bytes: Buffer.from("{}") }]));
  assert.equal((await run(traversal)).error.code, "IMPORT_PATH_INVALID");
  assert.equal((await run(duplicate)).error.code, "IMPORT_ZIP_DUPLICATE_PATH");
  assert.equal((await run(collision)).error.code, "IMPORT_ZIP_PATH_COLLISION");
});

test("rejects encrypted, symlink, executable, and nested-archive entries", async () => {
  const encrypted = await temporaryFile(".zip", buildZip([{ name: "manifest.json", bytes: Buffer.from("{}"), flags: 0x0801 }]));
  const symlink = await temporaryFile(".zip", buildZip([{ name: "manifest.json", bytes: Buffer.from("target"), externalAttributes: (0xa1ff << 16) >>> 0 }]));
  const executable = await temporaryFile(".zip", buildZip([{ name: "payload.exe", bytes: Buffer.from("synthetic") }]));
  const nested = await temporaryFile(".zip", buildZip([{ name: "manifest.json", bytes: Buffer.from([0x50, 0x4b, 0x03, 0x04]) }]));
  assert.equal((await run(encrypted)).error.code, "IMPORT_ZIP_ENCRYPTED_UNSUPPORTED");
  assert.equal((await run(symlink)).error.code, "IMPORT_ZIP_SYMLINK_FORBIDDEN");
  assert.equal((await run(executable)).error.code, "IMPORT_EXECUTABLE_CONTENT_FORBIDDEN");
  assert.equal((await run(nested)).error.code, "IMPORT_ZIP_NESTED_ARCHIVE");
});

test("returns controlled statuses for self-extracting and non-regular ZIP members", async () => {
  const prefixedBytes = Buffer.concat([Buffer.from("MZsynthetic"), buildZip([{ name: "manifest.json", bytes: Buffer.from("{}") }])]);
  const prefixed = await temporaryFile(".zip", prefixedBytes);
  const directoryEntry = await temporaryFile(".zip", buildZip([{
    name: "manifest.json",
    bytes: Buffer.from("{}"),
    externalAttributes: (((0x4000 | 0o755) << 16) | 0x10) >>> 0
  }]));
  assert.equal((await run(prefixed)).status, "Unsupported");
  assert.equal((await run(prefixed)).error.code, "IMPORT_ZIP_SELF_EXTRACTING_UNSUPPORTED");
  assert.equal((await run(directoryEntry)).error.code, "IMPORT_ZIP_NON_REGULAR_FILE_FORBIDDEN");
});

test("rejects unsupported compression, high ratio, and CRC corruption", async () => {
  const unsupportedMethod = await temporaryFile(".zip", buildZip([{ name: "manifest.json", bytes: Buffer.from("{}"), method: 99 }]));
  const highRatio = await temporaryFile(".zip", buildZip([{ name: "manifest.json", bytes: Buffer.alloc(4096, 0x41), method: 8 }]));
  const crcBytes = buildZip([{ name: "manifest.json", bytes: Buffer.from("synthetic") }]);
  crcBytes[30 + Buffer.byteLength("manifest.json")] ^= 0x01;
  const crcPath = await temporaryFile(".zip", crcBytes);
  assert.equal((await run(unsupportedMethod)).error.code, "IMPORT_ZIP_METHOD_UNSUPPORTED");
  assert.equal((await run(highRatio, { limits: { maxCompressionRatio: 2 } })).error.code, "IMPORT_ZIP_COMPRESSION_RATIO_EXCEEDED");
  assert.equal((await run(crcPath)).error.code, "IMPORT_ZIP_CRC_MISMATCH");
});

test("rejects very deep JSON before the recursive parser exhausts its stack", async () => {
  const sourcePath = await temporaryFile(".json", Buffer.from('{"value":' + '['.repeat(20_000) + '0' + ']'.repeat(20_000) + '}'));
  assert.equal((await run(sourcePath)).error.code, "IMPORT_JSON_DEPTH_EXCEEDED");
});

test("depth checks ignore escaped quotes and brackets inside JSON strings", async () => {
  const value = JSON.parse(await readFile(fixturePath("error-object.json"), "utf8"));
  value.message = 'Synthetic brackets { [ and escaped quote " and slash \\';
  const sourcePath = await temporaryFile(".json", Buffer.from(JSON.stringify(value)));
  assert.equal((await run(sourcePath)).status, "Accepted");
});

test("rejects lone Unicode surrogates even in contracts without object digests", async () => {
  const value = JSON.parse(await readFile(fixturePath("error-object.json"), "utf8"));
  value.message = "synthetic\ud800";
  const sourcePath = await temporaryFile(".json", Buffer.from(JSON.stringify(value)));
  assert.equal((await run(sourcePath)).error?.code, "IMPORT_JSON_VALUE_INVALID");
  value.message = "synthetic \ud83d\udd12";
  assert.equal((await run(await temporaryFile(".json", Buffer.from(JSON.stringify(value))))).status, "Accepted");
});

test("accepts a complete deflated package", async () => {
  const entries = (await validAuditEntries()).map((entry) => ({ ...entry, method: 8 }));
  const sourcePath = await temporaryFile(".zip", buildZip(entries));
  assert.equal((await run(sourcePath)).status, "Accepted");
});

test("rejects hidden trailing bytes inside a declared DEFLATE payload", async () => {
  const entries = await validAuditEntries();
  entries[0].method = 8;
  entries[0].compressedTail = Buffer.from("synthetic-hidden-tail");
  const sourcePath = await temporaryFile(".zip", buildZip(entries));
  assert.equal((await run(sourcePath)).error?.code, "IMPORT_ZIP_HIDDEN_DATA_FORBIDDEN");
});

test("rejects UTF-8 BOM normalization in ZIP member names", async () => {
  const entries = await validAuditEntries();
  entries[0].name = "\ufeffmanifest.json";
  const sourcePath = await temporaryFile(".zip", buildZip(entries));
  assert.equal((await run(sourcePath)).error?.code, "IMPORT_PATH_INVALID");
});

test("rejects remote path spellings and Windows stream/device aliases without IO", () => {
  const unsafe = [
    "//synthetic.invalid/share/input.json", "\\\\synthetic.invalid\\share\\input.json",
    "/\\synthetic.invalid/share/input.json", "\\/synthetic.invalid/share/input.json",
    "\\\\?\\C:\\synthetic\\input.json", "C:input.json", "C:/synthetic/input.json:stream",
    "C:/synthetic/NUL.json", "C:/synthetic/input.json.", "C:/synthetic/input.json ",
    "C:/synthetic/input\u0000.json", "/synthetic/input.json", undefined
  ];
  for (const value of unsafe) {
    assert.throws(() => assertLocalSourcePath(value, "win32"), { code: "IMPORT_SOURCE_PATH_INVALID" });
  }
  assert.equal(assertLocalSourcePath("C:/synthetic/input.json", "win32"), "C:/synthetic/input.json");
  assert.equal(assertLocalSourcePath("/synthetic/input.json", "linux"), "/synthetic/input.json");
  assert.throws(() => assertLocalSourcePath("//synthetic.invalid/share/input.json", "linux"), { code: "IMPORT_SOURCE_PATH_INVALID" });
});

test("enforces JSONL bounds before parsing an over-limit record", () => {
  const limits = resolveImportLimits({ maxRecords: 1, maxJsonlLineBytes: 8 });
  const valid = parseJsonLinesBytes(Buffer.from("{}\r\n"), limits);
  assert.equal(valid.records.length, 1);
  assert.throws(() => parseJsonLinesBytes(Buffer.from("{}\ninvalid"), limits), { code: "IMPORT_RECORD_COUNT_EXCEEDED" });
  assert.throws(() => parseJsonLinesBytes(Buffer.from("x".repeat(9)), limits), { code: "IMPORT_JSONL_LINE_BYTES_EXCEEDED" });
});

test("rejects non-finite JSON numbers and malformed Unicode keys", () => {
  const limits = resolveImportLimits();
  for (const text of ['{"value":1e400}', '{"value":-1e400}', '{"\\ud800":1}']) {
    assert.throws(() => parseJsonObjectBytes(Buffer.from(text), limits), { code: "IMPORT_JSON_VALUE_INVALID" });
  }
  assert.equal(parseJsonObjectBytes(Buffer.from('{"value":1e300}'), limits).records[0].value.value, 1e300);
});

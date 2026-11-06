import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { checkedAdd } from "./import-limits.mjs";
import { reject } from "./import-errors.mjs";
import { assertNonExecutableContent, assertUniqueArchivePath } from "./import-path-policy.mjs";

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
const UTF8_FLAG = 0x0800;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
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

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function need(bytes, offset, size, code = "IMPORT_ZIP_STRUCTURE_INVALID") {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 || offset + size > bytes.length) {
    reject(code, "Container", "ZIP structure exceeds archive bounds.");
  }
}

function findEocd(bytes) {
  const minimum = Math.max(0, bytes.length - (0xffff + 22));
  for (let offset = bytes.length - 22; offset >= minimum; offset -= 1) {
    if (bytes.readUInt32LE(offset) !== EOCD) continue;
    need(bytes, offset, 22);
    const commentLength = bytes.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength === bytes.length) return { offset, commentLength };
  }
  reject("IMPORT_ZIP_EOCD_INVALID", "Container", "ZIP end-of-central-directory is missing or truncated.");
}

function decodeName(bytes, flags) {
  if ((flags & UTF8_FLAG) === 0) {
    if (bytes.some((byte) => byte > 0x7f)) reject("IMPORT_ZIP_NAME_ENCODING_INVALID", "Container", "Non-ASCII ZIP names require UTF-8.");
    return bytes.toString("ascii");
  }
  try {
    // Preserve a BOM so the canonical ASCII path policy rejects it.
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    reject("IMPORT_ZIP_NAME_ENCODING_INVALID", "Container", "A ZIP name is not valid UTF-8.");
  }
}

function inflateEntry(compressed, method, expectedSize) {
  if (method === 0) {
    if (compressed.length !== expectedSize) reject("IMPORT_ZIP_SIZE_MISMATCH", "Container", "Stored ZIP size does not match metadata.");
    return Buffer.from(compressed);
  }
  let inflated;
  try {
    inflated = inflateRawSync(compressed, { maxOutputLength: Math.max(1, expectedSize), info: true });
  } catch {
    reject("IMPORT_ZIP_DECOMPRESSION_FAILED", "Container", "ZIP entry decompression failed.");
  }
  if (inflated.engine.bytesWritten !== compressed.length) {
    reject("IMPORT_ZIP_HIDDEN_DATA_FORBIDDEN", "Container", "Unused bytes follow a ZIP compression stream.");
  }
  return inflated.buffer;
}

export function parseAuditZip(bytes, limits) {
  if (bytes.length < 22 || bytes.readUInt32LE(0) !== LOCAL) {
    reject("IMPORT_ZIP_SELF_EXTRACTING_UNSUPPORTED", "Container", "Self-extracting, prefixed, or truncated ZIP input is unsupported.", "Unsupported");
  }
  const { offset: eocdOffset, commentLength } = findEocd(bytes);
  if (commentLength !== 0) reject("IMPORT_ZIP_PROFILE_UNSUPPORTED", "Container", "ZIP archive comments are unsupported.", "Unsupported");
  const diskNumber = bytes.readUInt16LE(eocdOffset + 4);
  const centralDisk = bytes.readUInt16LE(eocdOffset + 6);
  const entriesOnDisk = bytes.readUInt16LE(eocdOffset + 8);
  const entryCount = bytes.readUInt16LE(eocdOffset + 10);
  const centralSize = bytes.readUInt32LE(eocdOffset + 12);
  const centralOffset = bytes.readUInt32LE(eocdOffset + 16);
  if (diskNumber !== 0 || centralDisk !== 0 || entriesOnDisk !== entryCount) {
    reject("IMPORT_ZIP_MULTIPART_UNSUPPORTED", "Container", "Multipart ZIP input is unsupported.", "Unsupported");
  }
  if (entryCount === 0xffff || [centralSize, centralOffset].includes(0xffffffff)) {
    reject("IMPORT_ZIP64_UNSUPPORTED", "Container", "ZIP64 is unsupported by this bounded profile.", "Unsupported");
  }
  if (entryCount > limits.maxZipEntries) reject("IMPORT_ZIP_ENTRY_COUNT_EXCEEDED", "Container", "ZIP entry count exceeds the limit.");
  if (centralOffset + centralSize !== eocdOffset) reject("IMPORT_ZIP_STRUCTURE_INVALID", "Container", "ZIP central-directory bounds are invalid.");

  const entries = [];
  const ranges = [];
  const exactNames = new Set();
  const foldedNames = new Set();
  let expandedBytes = 0;
  let position = centralOffset;
  for (let index = 0; index < entryCount; index += 1) {
    need(bytes, position, 46);
    if (bytes.readUInt32LE(position) !== CENTRAL) reject("IMPORT_ZIP_STRUCTURE_INVALID", "Container", "ZIP central-directory entry is invalid.");
    const versionMadeBy = bytes.readUInt16LE(position + 4);
    const versionNeeded = bytes.readUInt16LE(position + 6);
    const flags = bytes.readUInt16LE(position + 8);
    const method = bytes.readUInt16LE(position + 10);
    const expectedCrc = bytes.readUInt32LE(position + 16);
    const compressedSize = bytes.readUInt32LE(position + 20);
    const expandedSize = bytes.readUInt32LE(position + 24);
    const nameLength = bytes.readUInt16LE(position + 28);
    const extraLength = bytes.readUInt16LE(position + 30);
    const entryCommentLength = bytes.readUInt16LE(position + 32);
    const diskStart = bytes.readUInt16LE(position + 34);
    const externalAttributes = bytes.readUInt32LE(position + 38);
    const localOffset = bytes.readUInt32LE(position + 42);
    const centralEnd = position + 46 + nameLength + extraLength + entryCommentLength;
    need(bytes, position, centralEnd - position);
    if (centralEnd > eocdOffset || nameLength === 0) reject("IMPORT_ZIP_STRUCTURE_INVALID", "Container", "ZIP central-directory fields are invalid.");
    if (versionNeeded > 20 || extraLength !== 0 || entryCommentLength !== 0) {
      reject("IMPORT_ZIP_PROFILE_UNSUPPORTED", "Container", "ZIP extra fields, comments, or newer features are unsupported.", "Unsupported");
    }
    if (diskStart !== 0) reject("IMPORT_ZIP_MULTIPART_UNSUPPORTED", "Container", "Multipart ZIP entries are unsupported.", "Unsupported");
    if ((flags & 0x0001) !== 0) reject("IMPORT_ZIP_ENCRYPTED_UNSUPPORTED", "Container", "Encrypted ZIP entries are unsupported.", "Unsupported");
    if ((flags & ~UTF8_FLAG) !== 0) reject("IMPORT_ZIP_PROFILE_UNSUPPORTED", "Container", "Unsupported ZIP general-purpose flags were rejected.", "Unsupported");
    if (![0, 8].includes(method)) reject("IMPORT_ZIP_METHOD_UNSUPPORTED", "Container", "ZIP compression method is unsupported.", "Unsupported");
    if (compressedSize === 0xffffffff || expandedSize === 0xffffffff || localOffset === 0xffffffff) {
      reject("IMPORT_ZIP64_UNSUPPORTED", "Container", "ZIP64 entries are unsupported.", "Unsupported");
    }
    const platform = versionMadeBy >>> 8;
    const unixMode = externalAttributes >>> 16;
    if (platform === 3 && (unixMode & 0xf000) === 0xa000) reject("IMPORT_ZIP_SYMLINK_FORBIDDEN", "Container", "ZIP symlink entries are forbidden.");
    if ((platform === 3 && (unixMode & 0xf000) !== 0 && (unixMode & 0xf000) !== 0x8000)
      || (externalAttributes & 0x10) !== 0) {
      reject("IMPORT_ZIP_NON_REGULAR_FILE_FORBIDDEN", "Container", "Only regular-file ZIP members are supported.", "Unsupported");
    }
    const nameBytes = bytes.subarray(position + 46, position + 46 + nameLength);
    const name = decodeName(nameBytes, flags);
    assertUniqueArchivePath(name, exactNames, foldedNames);
    if (expandedSize > limits.maxZipEntryExpandedBytes) reject("IMPORT_ZIP_ENTRY_SIZE_EXCEEDED", "Container", "A ZIP entry exceeds the expanded-size limit.");
    expandedBytes = checkedAdd(expandedBytes, expandedSize);
    if (expandedBytes > limits.maxZipExpandedBytes) reject("IMPORT_ZIP_EXPANDED_BYTES_EXCEEDED", "Container", "ZIP expanded bytes exceed the limit.");
    if (expandedSize > Math.max(1, compressedSize) * limits.maxCompressionRatio) {
      reject("IMPORT_ZIP_COMPRESSION_RATIO_EXCEEDED", "Container", "ZIP compression ratio exceeds the limit.");
    }

    need(bytes, localOffset, 30);
    if (localOffset >= centralOffset || bytes.readUInt32LE(localOffset) !== LOCAL) reject("IMPORT_ZIP_STRUCTURE_INVALID", "Container", "ZIP local header is invalid.");
    const localFlags = bytes.readUInt16LE(localOffset + 6);
    const localMethod = bytes.readUInt16LE(localOffset + 8);
    const localCrc = bytes.readUInt32LE(localOffset + 14);
    const localCompressedSize = bytes.readUInt32LE(localOffset + 18);
    const localExpandedSize = bytes.readUInt32LE(localOffset + 22);
    const localNameLength = bytes.readUInt16LE(localOffset + 26);
    const localExtraLength = bytes.readUInt16LE(localOffset + 28);
    if (localFlags !== flags || localMethod !== method || localCrc !== expectedCrc
      || localCompressedSize !== compressedSize || localExpandedSize !== expandedSize || localExtraLength !== 0) {
      reject("IMPORT_ZIP_HEADER_MISMATCH", "Container", "ZIP local and central metadata do not match.");
    }
    const localNameStart = localOffset + 30;
    const dataStart = localNameStart + localNameLength;
    const dataEnd = dataStart + compressedSize;
    need(bytes, localNameStart, localNameLength + compressedSize);
    if (dataEnd > centralOffset || decodeName(bytes.subarray(localNameStart, localNameStart + localNameLength), flags) !== name) {
      reject("IMPORT_ZIP_HEADER_MISMATCH", "Container", "ZIP local and central names or bounds do not match.");
    }
    const expanded = inflateEntry(bytes.subarray(dataStart, dataEnd), method, expandedSize);
    if (expanded.length !== expandedSize) reject("IMPORT_ZIP_SIZE_MISMATCH", "Container", "ZIP expanded size does not match metadata.");
    if (crc32(expanded) !== expectedCrc) reject("IMPORT_ZIP_CRC_MISMATCH", "Container", "ZIP entry CRC verification failed.");
    assertNonExecutableContent(name, expanded);
    ranges.push({ start: localOffset, end: dataEnd });
    entries.push(Object.freeze({
      name,
      bytes: expanded,
      compressedSize,
      expandedSize,
      compressionMethod: method === 0 ? "Stored" : "Deflate",
      contentDigest: sha256(expanded)
    }));
    position = centralEnd;
  }
  if (position !== eocdOffset) reject("IMPORT_ZIP_STRUCTURE_INVALID", "Container", "ZIP central-directory size does not match entries.");
  ranges.sort((left, right) => left.start - right.start);
  if (ranges.length === 0 || ranges[0].start !== 0 || ranges.at(-1).end !== centralOffset
    || ranges.some((range, index) => index > 0 && ranges[index - 1].end !== range.start)) {
    reject("IMPORT_ZIP_HIDDEN_DATA_FORBIDDEN", "Container", "ZIP hidden, overlapping, or prefixed data was rejected.");
  }
  return Object.freeze({
    entries: Object.freeze(entries),
    entryCount,
    expandedBytes,
    archiveDigest: sha256(bytes)
  });
}

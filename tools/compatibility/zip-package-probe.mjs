import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";
import { inflateRawSync } from "node:zlib";
import { parseStrictJson } from "../lib/strict-json.mjs";

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
const DEFAULT_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES = 512;
const DEFAULT_MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_EXPANDED_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_RATIO = 100;

function fail(message) {
  throw new Error(message);
}

function parseUnsigned(value, name, maximum) {
  if (!/^[1-9][0-9]*$/u.test(value ?? "")) fail(`${name} must be a positive decimal integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) fail(`${name} is out of range`);
  return parsed;
}

function parseArguments(argv) {
  if (argv.length % 2 !== 0) fail("Every option requires one value");
  const options = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    if (!name.startsWith("--") || options.has(name)) fail(`Invalid or duplicate option: ${name}`);
    options.set(name, argv[index + 1]);
  }
  if (!options.has("--input")) fail("Missing --input");
  return {
    input: options.get("--input"),
    expectedSyntheticEcho: options.get("--expected-synthetic-echo") ?? null,
    maxArchiveBytes: parseUnsigned(options.get("--max-archive-bytes") ?? String(DEFAULT_MAX_ARCHIVE_BYTES), "max-archive-bytes", 1024 * 1024 * 1024),
    maxEntries: parseUnsigned(options.get("--max-entries") ?? String(DEFAULT_MAX_ENTRIES), "max-entries", 100_000),
    maxEntryBytes: parseUnsigned(options.get("--max-entry-bytes") ?? String(DEFAULT_MAX_ENTRY_BYTES), "max-entry-bytes", 1024 * 1024 * 1024),
    maxExpandedBytes: parseUnsigned(options.get("--max-expanded-bytes") ?? String(DEFAULT_MAX_EXPANDED_BYTES), "max-expanded-bytes", 1024 * 1024 * 1024),
    maxRatio: parseUnsigned(options.get("--max-ratio") ?? String(DEFAULT_MAX_RATIO), "max-ratio", 1_000_000),
  };
}

function normalizeSyntheticPackageRows(bytes, expectedEcho) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("Synthetic package result is not valid UTF-8");
  }
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const rawRows = lines.map((line, index) => parseStrictJson(line.replace(/\r$/u, ""), `synthetic package row ${index + 1}`));
  if (rawRows.length !== 2) fail("Synthetic package result must contain exactly two rows");
  const expectedKeys = [
    "EchoValue", "RowOrder", "SchemaVersion", "SyntheticBoolean",
    "SyntheticInteger", "SyntheticString",
  ];
  const expectations = [
    { string: "alpha", integer: 7, boolean: true, order: 1 },
    { string: "beta", integer: 11, boolean: false, order: 2 },
  ];
  const rows = rawRows.map((row, index) => {
    if (row === null || Array.isArray(row) || typeof row !== "object") fail("Synthetic package row is not an object");
    if (JSON.stringify(Object.keys(row).sort()) !== JSON.stringify(expectedKeys)) fail("Synthetic package row field set mismatch");
    const expected = expectations[index];
    if (row.SchemaVersion !== "1.0.0"
      || row.SyntheticString !== expected.string
      || row.SyntheticInteger !== expected.integer
      || row.SyntheticBoolean !== expected.boolean
      || row.RowOrder !== expected.order
      || row.EchoValue !== expectedEcho) {
      fail("Synthetic package row value or type mismatch");
    }
    return {
      schema_version: row.SchemaVersion,
      synthetic_string: row.SyntheticString,
      synthetic_integer: row.SyntheticInteger,
      synthetic_boolean: row.SyntheticBoolean,
      row_order: row.RowOrder,
      echo_value: row.EchoValue,
    };
  });
  const normalized = {
    compatibility_contract_version: 1,
    artifact: "SecApp.Compatibility.Synthetic",
    source: "Rows",
    rows,
  };
  const serialized = `${JSON.stringify(normalized, null, 2)}\n`;
  return {
    status: "VALID",
    source_entry: "results/SecApp.Compatibility.Synthetic%2FRows.json",
    source_framing: "JSONLines",
    row_count: rows.length,
    normalized_bytes: Buffer.byteLength(serialized, "utf8"),
    normalized_sha256: sha256(Buffer.from(serialized, "utf8")),
  };
}

const crcTable = (() => {
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
  for (const byte of bytes) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff];
  return (crc ^ 0xffffffff) >>> 0;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function decodeEntryName(bytes, flags) {
  if ((flags & 0x0800) !== 0) {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      fail("ZIP entry name is not valid UTF-8");
    }
  }
  if (bytes.some((byte) => byte > 0x7f)) fail("Non-ASCII ZIP entry name without UTF-8 flag is rejected");
  return bytes.toString("ascii");
}

function validateEntryName(name, seenNames) {
  if (name.length === 0 || name.includes("\u0000")) fail("Empty or NUL-containing ZIP entry name is rejected");
  if (name.includes("\\")) fail("Backslash in ZIP entry name is rejected");
  if (name.startsWith("/") || /^[A-Za-z]:/u.test(name) || name.startsWith("//")) {
    fail("Absolute ZIP entry path is rejected");
  }
  const directory = name.endsWith("/");
  const pathWithoutTrailingSlash = directory ? name.slice(0, -1) : name;
  const segments = pathWithoutTrailingSlash.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    fail("ZIP traversal or ambiguous path segment is rejected");
  }
  const collisionKey = pathWithoutTrailingSlash.normalize("NFC").toLocaleLowerCase("en-US");
  if (seenNames.has(collisionKey)) fail("Duplicate or case-colliding ZIP entry path is rejected");
  seenNames.add(collisionKey);
  return { directory };
}

function findEndOfCentralDirectory(bytes) {
  const minimum = Math.max(0, bytes.length - (0xffff + 22));
  for (let offset = bytes.length - 22; offset >= minimum; offset -= 1) {
    if (bytes.readUInt32LE(offset) !== EOCD_SIGNATURE) continue;
    const commentLength = bytes.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength === bytes.length) return offset;
  }
  fail("ZIP end-of-central-directory record is missing or truncated");
}

function structuralShape(records) {
  const fields = new Map();
  for (const record of records) {
    if (record === null || Array.isArray(record) || typeof record !== "object") continue;
    for (const [name, value] of Object.entries(record)) {
      if (!fields.has(name)) fields.set(name, new Set());
      fields.get(name).add(value === null ? "null" : Array.isArray(value) ? "array" : typeof value);
    }
  }
  return [...fields.entries()]
    .sort(([left], [right]) => left.localeCompare(right, "en"))
    .map(([name, types]) => ({ name, raw_types: [...types].sort() }));
}

function describeJson(bytes, name) {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { candidate: true, valid_utf8_no_bom: false, strict_json: false, error_class: "Utf8Bom" };
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { candidate: true, valid_utf8_no_bom: false, strict_json: false, error_class: "InvalidUtf8" };
  }
  try {
    const value = parseStrictJson(text, name);
    const records = Array.isArray(value) ? value : [value];
    return {
      candidate: true,
      valid_utf8_no_bom: true,
      strict_json: true,
      framing: "JSONDocument",
      root_type: Array.isArray(value) ? "array" : value === null ? "null" : typeof value,
      record_count: records.length,
      fields: structuralShape(records),
    };
  } catch {
    const terminated = text.endsWith("\n");
    const lines = text.split("\n");
    if (terminated) lines.pop();
    try {
      const values = lines.map((line, index) => {
        if (line.endsWith("\r")) line = line.slice(0, -1);
        if (line.length === 0) fail("Empty JSONL line");
        return parseStrictJson(line, `${name} line ${index + 1}`);
      });
      return {
        candidate: true,
        valid_utf8_no_bom: true,
        strict_json: true,
        framing: "JSONLines",
        root_type: "records",
        record_count: values.length,
        final_line_terminated: terminated,
        fields: structuralShape(values),
      };
    } catch {
      return { candidate: true, valid_utf8_no_bom: true, strict_json: false, error_class: "MalformedStructuredJson" };
    }
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const fileStat = await stat(options.input);
  if (!fileStat.isFile() || fileStat.size > options.maxArchiveBytes) fail("ZIP input is absent or exceeds archive byte limit");
  const bytes = await readFile(options.input);
  if (bytes.length < 22) fail("ZIP input is truncated");
  const eocdOffset = findEndOfCentralDirectory(bytes);
  const diskNumber = bytes.readUInt16LE(eocdOffset + 4);
  const centralDisk = bytes.readUInt16LE(eocdOffset + 6);
  const entriesOnDisk = bytes.readUInt16LE(eocdOffset + 8);
  const entryCount = bytes.readUInt16LE(eocdOffset + 10);
  const centralSize = bytes.readUInt32LE(eocdOffset + 12);
  const centralOffset = bytes.readUInt32LE(eocdOffset + 16);
  if (diskNumber !== 0 || centralDisk !== 0 || entriesOnDisk !== entryCount) fail("Multi-disk ZIP is rejected");
  if (entryCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) fail("ZIP64 is not supported by this bounded probe");
  if (entryCount > options.maxEntries) fail("ZIP entry count exceeds limit");
  if (centralOffset + centralSize !== eocdOffset || centralOffset > bytes.length) fail("ZIP central directory bounds are invalid");

  const entries = [];
  let syntheticImport = null;
  const seenNames = new Set();
  let expandedBytes = 0;
  let position = centralOffset;
  for (let index = 0; index < entryCount; index += 1) {
    if (position + 46 > eocdOffset || bytes.readUInt32LE(position) !== CENTRAL_SIGNATURE) fail("ZIP central directory entry is corrupt");
    const versionMadeBy = bytes.readUInt16LE(position + 4);
    const flags = bytes.readUInt16LE(position + 8);
    const method = bytes.readUInt16LE(position + 10);
    const expectedCrc = bytes.readUInt32LE(position + 16);
    const compressedSize = bytes.readUInt32LE(position + 20);
    const uncompressedSize = bytes.readUInt32LE(position + 24);
    const nameLength = bytes.readUInt16LE(position + 28);
    const extraLength = bytes.readUInt16LE(position + 30);
    const commentLength = bytes.readUInt16LE(position + 32);
    const diskStart = bytes.readUInt16LE(position + 34);
    const externalAttributes = bytes.readUInt32LE(position + 38);
    const localOffset = bytes.readUInt32LE(position + 42);
    const centralEnd = position + 46 + nameLength + extraLength + commentLength;
    if (centralEnd > eocdOffset) fail("ZIP central directory variable fields exceed bounds");
    if (diskStart !== 0) fail("Multi-disk ZIP entry is rejected");
    if ((flags & 0x0001) !== 0) fail("Encrypted ZIP entry is rejected");
    if (![0, 8].includes(method)) fail("Unsupported ZIP compression method");
    const nameBytes = bytes.subarray(position + 46, position + 46 + nameLength);
    const name = decodeEntryName(nameBytes, flags);
    const { directory } = validateEntryName(name, seenNames);
    const platform = versionMadeBy >>> 8;
    const unixMode = externalAttributes >>> 16;
    if (platform === 3 && (unixMode & 0xf000) === 0xa000) fail("ZIP symlink entry is rejected");
    if (uncompressedSize > options.maxEntryBytes) fail("ZIP individual expanded size exceeds limit");
    expandedBytes += uncompressedSize;
    if (expandedBytes > options.maxExpandedBytes) fail("ZIP total expanded size exceeds limit");
    const ratio = uncompressedSize === 0 ? 0 : uncompressedSize / Math.max(1, compressedSize);
    if (ratio > options.maxRatio) fail("ZIP compression ratio exceeds limit");

    if (localOffset + 30 > centralOffset || bytes.readUInt32LE(localOffset) !== LOCAL_SIGNATURE) fail("ZIP local header is missing or out of bounds");
    const localFlags = bytes.readUInt16LE(localOffset + 6);
    const localMethod = bytes.readUInt16LE(localOffset + 8);
    const localNameLength = bytes.readUInt16LE(localOffset + 26);
    const localExtraLength = bytes.readUInt16LE(localOffset + 28);
    const localNameStart = localOffset + 30;
    const dataStart = localNameStart + localNameLength + localExtraLength;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > centralOffset) fail("ZIP compressed data exceeds local-data bounds");
    if (localFlags !== flags || localMethod !== method) fail("ZIP local and central header metadata mismatch");
    const localName = decodeEntryName(bytes.subarray(localNameStart, localNameStart + localNameLength), flags);
    if (localName !== name) fail("ZIP local and central entry names mismatch");
    const compressed = bytes.subarray(dataStart, dataEnd);
    let expanded;
    try {
      expanded = method === 0
        ? Buffer.from(compressed)
        : inflateRawSync(compressed, { maxOutputLength: options.maxEntryBytes });
    } catch {
      fail("ZIP entry decompression failed");
    }
    if (expanded.length !== uncompressedSize) fail("ZIP expanded size mismatch");
    if (crc32(expanded) !== expectedCrc) fail("ZIP entry CRC mismatch");
    const jsonDescription = /(?:^|\/)[^/]+\.(?:json|jsonl)$/iu.test(name)
      ? describeJson(expanded, name)
      : { candidate: false };
    if (options.expectedSyntheticEcho !== null
      && name === "results/SecApp.Compatibility.Synthetic%2FRows.json") {
      syntheticImport = normalizeSyntheticPackageRows(expanded, options.expectedSyntheticEcho);
    }
    entries.push({
      name,
      directory,
      compression_method: method === 0 ? "Stored" : "Deflate",
      compressed_size: compressedSize,
      expanded_size: uncompressedSize,
      compression_ratio: Number(ratio.toFixed(3)),
      content_sha256: sha256(expanded),
      json: jsonDescription,
    });
    position = centralEnd;
  }
  if (position !== eocdOffset) fail("ZIP central directory size does not match entries");

  process.stdout.write(`${JSON.stringify({
    status: "VALID",
    input_file: basename(options.input),
    archive_format: "ZIP",
    archive_bytes: bytes.length,
    archive_sha256: sha256(bytes),
    central_directory: { offset: centralOffset, size: centralSize, entry_count: entryCount },
    expanded_bytes: expandedBytes,
    synthetic_import: syntheticImport,
    limits: {
      maximum_archive_bytes: options.maxArchiveBytes,
      maximum_entries: options.maxEntries,
      maximum_individual_expanded_bytes: options.maxEntryBytes,
      maximum_total_expanded_bytes: options.maxExpandedBytes,
      maximum_compression_ratio: options.maxRatio,
    },
    entries,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`zip-package-probe: ${error.message}\n`);
  process.exitCode = 1;
});

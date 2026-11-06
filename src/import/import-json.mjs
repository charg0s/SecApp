import { createHash } from "node:crypto";
import { parseStrictJson } from "../../tools/lib/strict-json.mjs";
import { reject } from "./import-errors.mjs";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function decodeUtf8(bytes, source) {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    reject("IMPORT_UTF8_BOM_FORBIDDEN", "Parse", "UTF-8 BOM is forbidden.");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    reject("IMPORT_UTF8_INVALID", "Parse", "Input is not valid UTF-8.");
  }
}

function assertTextDepth(text, maximum) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (const character of text) {
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
    } else if (character === '"') inString = true;
    else if (character === "{" || character === "[") {
      depth += 1;
      if (depth > maximum) reject("IMPORT_JSON_DEPTH_EXCEEDED", "Parse", "JSON nesting depth exceeds the import limit.");
    } else if (character === "}" || character === "]") depth -= 1;
  }
}

function parseObject(text, source, maximumDepth) {
  // Bound recursion before invoking the strict parser or allocating the object tree.
  assertTextDepth(text, maximumDepth);
  let value;
  try {
    value = parseStrictJson(text, source);
  } catch {
    reject("IMPORT_JSON_INVALID", "Parse", "Strict JSON parsing failed.");
  }
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    reject("IMPORT_JSON_ROOT_NOT_OBJECT", "Parse", "Every imported JSON record must be an object.");
  }
  assertValues(value, maximumDepth);
  return value;
}

function assertValues(value, maximum) {
  function visit(current, depth) {
    if (depth > maximum) reject("IMPORT_JSON_DEPTH_EXCEEDED", "Parse", "JSON nesting depth exceeds the import limit.");
    if ((typeof current === "number" && !Number.isFinite(current))
      || (typeof current === "string" && /[\uD800-\uDFFF]/u.test(current))) {
      reject("IMPORT_JSON_VALUE_INVALID", "Parse", "Input contains a non-I-JSON value.");
    }
    if (Array.isArray(current)) {
      for (const child of current) visit(child, depth + 1);
    } else if (current !== null && typeof current === "object") {
      for (const key of Object.keys(current)) {
        if (/[\uD800-\uDFFF]/u.test(key)) reject("IMPORT_JSON_VALUE_INVALID", "Parse", "Input contains an invalid Unicode key.");
        visit(current[key], depth + 1);
      }
    }
  }
  visit(value, 1);
}

export function parseJsonObjectBytes(bytes, limits, source = "JSON object") {
  if (bytes.length > limits.maxJsonBytes) reject("IMPORT_JSON_BYTES_EXCEEDED", "Read", "JSON input exceeds the byte limit.");
  const value = parseObject(decodeUtf8(bytes, source), source, limits.maxJsonDepth);
  return {
    records: [{ value, byteSize: bytes.length, fileDigest: sha256(bytes), recordIndex: 0 }],
    finalLineTerminated: bytes.at(-1) === 0x0a
  };
}

export function parseJsonLinesBytes(bytes, limits, source = "JSONL") {
  if (bytes.length === 0) reject("IMPORT_JSONL_EMPTY", "Parse", "JSONL input must contain at least one record.");
  if (bytes.length > limits.maxSourceBytes) reject("IMPORT_SOURCE_BYTES_EXCEEDED", "Read", "Input exceeds the source byte limit.");
  const finalLineTerminated = bytes.at(-1) === 0x0a;
  if (!finalLineTerminated && limits.jsonlFinalLf === "Required") {
    reject("IMPORT_JSONL_FINAL_LF_REQUIRED", "Parse", "JSONL final LF is required by policy.");
  }
  const records = [];
  let start = 0;
  for (let index = 0; index <= bytes.length; index += 1) {
    if (index - start > limits.maxJsonlLineBytes) reject("IMPORT_JSONL_LINE_BYTES_EXCEEDED", "Parse", "A JSONL line exceeds the byte limit.");
    if (index !== bytes.length && bytes[index] !== 0x0a) continue;
    if (index === bytes.length && finalLineTerminated) break;
    if (records.length >= limits.maxRecords) reject("IMPORT_RECORD_COUNT_EXCEEDED", "Parse", "JSONL record count exceeds the limit.");
    const rawLine = bytes.subarray(start, index);
    start = index + 1;
    const line = rawLine.at(-1) === 0x0d ? rawLine.subarray(0, -1) : rawLine;
    if (line.length === 0) reject("IMPORT_JSONL_BLANK_LINE", "Parse", "Blank JSONL lines are forbidden.");
    const value = parseObject(decodeUtf8(line, `${source} record`), `${source} record`, limits.maxJsonDepth);
    records.push({ value, byteSize: rawLine.length, fileDigest: sha256(rawLine), recordIndex: records.length });
  }
  return { records, finalLineTerminated };
}

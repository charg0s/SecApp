import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";
import { parseStrictJson } from "../lib/strict-json.mjs";

const DEFAULT_MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_LINE_BYTES = 1024 * 1024;
const DEFAULT_MAX_RECORDS = 1024;
const DEFAULT_MAX_DEPTH = 64;

function fail(message) {
  throw new Error(message);
}

function parseUnsigned(value, name, maximum) {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value ?? "")) fail(`${name} must be an unsigned decimal integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) fail(`${name} is out of range`);
  return parsed;
}

function parseArguments(argv) {
  if (argv.length % 2 !== 0) fail("Every option requires one value");
  const options = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index].startsWith("--") || options.has(argv[index])) fail(`Invalid or duplicate option: ${argv[index]}`);
    options.set(argv[index], argv[index + 1]);
  }
  if (!options.has("--input")) fail("Missing --input");
  const mode = options.get("--mode") ?? "auto";
  if (!["auto", "json", "jsonl"].includes(mode)) fail("Invalid mode");
  return {
    input: options.get("--input"),
    mode,
    maxTotalBytes: parseUnsigned(options.get("--max-total-bytes") ?? String(DEFAULT_MAX_TOTAL_BYTES), "max-total-bytes", 1024 * 1024 * 1024),
    maxLineBytes: parseUnsigned(options.get("--max-line-bytes") ?? String(DEFAULT_MAX_LINE_BYTES), "max-line-bytes", 64 * 1024 * 1024),
    maxRecords: parseUnsigned(options.get("--max-records") ?? String(DEFAULT_MAX_RECORDS), "max-records", 1_000_000),
    maxDepth: parseUnsigned(options.get("--max-depth") ?? String(DEFAULT_MAX_DEPTH), "max-depth", 256),
  };
}

function rawType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function validateDepth(value, maximumDepth, depth = 1) {
  if (depth > maximumDepth) fail("JSON nesting depth exceeds limit");
  if (Array.isArray(value)) {
    for (const item of value) validateDepth(item, maximumDepth, depth + 1);
  } else if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) validateDepth(item, maximumDepth, depth + 1);
  }
}

function structuralShape(records) {
  const keys = new Map();
  let objectRecords = 0;
  for (const record of records) {
    if (record === null || Array.isArray(record) || typeof record !== "object") continue;
    objectRecords += 1;
    for (const [key, value] of Object.entries(record)) {
      if (!keys.has(key)) keys.set(key, { presence: 0, types: new Set() });
      const entry = keys.get(key);
      entry.presence += 1;
      entry.types.add(rawType(value));
    }
  }
  return {
    object_record_count: objectRecords,
    fields: [...keys.entries()]
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([name, entry]) => ({
        name,
        raw_types: [...entry.types].sort(),
        required_in_observed_rows: entry.presence === records.length,
        nullable_in_observed_rows: entry.types.has("null"),
      })),
  };
}

function parseJsonDocument(text, source, limits) {
  const value = parseStrictJson(text, source);
  validateDepth(value, limits.maxDepth);
  const records = Array.isArray(value) ? value : [value];
  if (records.length > limits.maxRecords) fail("JSON record count exceeds limit");
  return { framing: "JSONDocument", rootType: rawType(value), records, value };
}

function parseJsonLines(text, source, limits) {
  if (text.length === 0) return { framing: "JSONLines", rootType: "empty", records: [], finalLineTerminated: true };
  const finalLineTerminated = text.endsWith("\n");
  const lines = text.split("\n");
  if (finalLineTerminated) lines.pop();
  if (lines.length > limits.maxRecords) fail("JSONL record count exceeds limit");
  const records = lines.map((line, index) => {
    if (line.endsWith("\r")) line = line.slice(0, -1);
    if (Buffer.byteLength(line, "utf8") > limits.maxLineBytes) fail(`JSONL line ${index + 1} exceeds byte limit`);
    if (line.trim() === "") fail(`JSONL line ${index + 1} is empty`);
    const value = parseStrictJson(line, `${source} line ${index + 1}`);
    validateDepth(value, limits.maxDepth);
    return value;
  });
  return { framing: "JSONLines", rootType: "records", records, finalLineTerminated };
}

function splitConcatenatedDocuments(text, maximumDocumentBytes, maximumDocuments) {
  const documents = [];
  let position = 0;
  while (position < text.length) {
    while (/\s/u.test(text[position] ?? "")) position += 1;
    if (position >= text.length) break;
    if (text[position] !== "{" && text[position] !== "[") {
      fail(`Concatenated JSON document must start with object or array at character ${position}`);
    }
    const start = position;
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (; position < text.length; position += 1) {
      const character = text[position];
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
        continue;
      }
      if (character === '"') {
        inString = true;
      } else if (character === "{" || character === "[") {
        depth += 1;
      } else if (character === "}" || character === "]") {
        depth -= 1;
        if (depth < 0) fail(`Unbalanced concatenated JSON at character ${position}`);
        if (depth === 0) {
          position += 1;
          break;
        }
      }
    }
    if (inString || depth !== 0) fail("Partial final concatenated JSON document is rejected");
    const document = text.slice(start, position);
    if (Buffer.byteLength(document, "utf8") > maximumDocumentBytes) fail("Concatenated JSON document exceeds byte limit");
    documents.push(document);
    if (documents.length > maximumDocuments) fail("Concatenated JSON document count exceeds limit");
  }
  return documents;
}

function parseConcatenatedJson(text, source, limits) {
  const documents = splitConcatenatedDocuments(text, limits.maxLineBytes, limits.maxRecords);
  if (documents.length < 2) fail("Input is not a multi-document concatenated JSON stream");
  const values = documents.map((document, index) => {
    const value = parseStrictJson(document, `${source} document ${index + 1}`);
    validateDepth(value, limits.maxDepth);
    return value;
  });
  const records = values.flatMap((value) => Array.isArray(value) ? value : [value]);
  if (records.length > limits.maxRecords) fail("Concatenated JSON record count exceeds limit");
  return {
    framing: "ConcatenatedJSONDocuments",
    rootType: "sequence",
    records,
    documentCount: documents.length,
    documentRootTypes: [...new Set(values.map(rawType))].sort(),
    finalLineTerminated: text.endsWith("\n"),
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const fileStat = await stat(options.input);
  if (!fileStat.isFile() || fileStat.size > options.maxTotalBytes) fail("Input is absent or exceeds total byte limit");
  const bytes = await readFile(options.input);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail("UTF-8 BOM is rejected");
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("Input is not valid UTF-8");
  }
  if (text.charCodeAt(0) === 0xfeff) fail("UTF-8 BOM is rejected");

  const limits = options;
  let parsed;
  if (options.mode === "json") {
    parsed = parseJsonDocument(text, basename(options.input), limits);
  } else if (options.mode === "jsonl") {
    parsed = parseJsonLines(text, basename(options.input), limits);
  } else {
    try {
      parsed = parseJsonDocument(text, basename(options.input), limits);
    } catch (jsonError) {
      try {
        parsed = parseConcatenatedJson(text, basename(options.input), limits);
      } catch (sequenceError) {
        try {
          parsed = parseJsonLines(text, basename(options.input), limits);
        } catch (jsonlError) {
          fail(`No accepted structured framing: JSON=${jsonError.message}; sequence=${sequenceError.message}; JSONL=${jsonlError.message}`);
        }
      }
    }
  }

  const result = {
    status: "VALID",
    input_file: basename(options.input),
    input_bytes: bytes.length,
    input_sha256: createHash("sha256").update(bytes).digest("hex"),
    utf8: "ValidNoBom",
    framing: parsed.framing,
    root_type: parsed.rootType,
    document_count: parsed.documentCount ?? 1,
    document_root_types: parsed.documentRootTypes ?? [parsed.rootType],
    final_line_terminated: parsed.finalLineTerminated ?? text.endsWith("\n"),
    record_count: parsed.records.length,
    empty_semantics: parsed.records.length === 0 ? "ExplicitEmpty" : "NonEmpty",
    shape: structuralShape(parsed.records),
    limits: {
      maximum_total_bytes: options.maxTotalBytes,
      maximum_line_bytes: options.maxLineBytes,
      maximum_records: options.maxRecords,
      maximum_depth: options.maxDepth,
    },
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`structured-output-probe: ${error.message}\n`);
  process.exitCode = 1;
});

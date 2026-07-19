import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { basename, isAbsolute } from "node:path";
import { parseStrictJson } from "../lib/strict-json.mjs";

const MAX_INPUT_BYTES = 1024 * 1024;
const EXPECTED_KEYS = [
  "EchoValue",
  "RowOrder",
  "SchemaVersion",
  "SyntheticBoolean",
  "SyntheticInteger",
  "SyntheticString",
  "_Source",
];

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  if (argv.length % 2 !== 0) fail("Every option requires one value");
  const options = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index].startsWith("--") || options.has(argv[index])) fail(`Invalid or duplicate option: ${argv[index]}`);
    options.set(argv[index], argv[index + 1]);
  }
  if (!options.has("--input") || !options.has("--output") || !options.has("--expected-echo")) {
    fail("Required: --input FILE --output FILE --expected-echo VALUE");
  }
  if (!isAbsolute(options.get("--output"))) fail("Output path must be absolute");
  return options;
}

function compareKeys(record, rowIndex) {
  if (record === null || Array.isArray(record) || typeof record !== "object") fail(`Row ${rowIndex} is not an object`);
  const keys = Object.keys(record).sort();
  if (JSON.stringify(keys) !== JSON.stringify(EXPECTED_KEYS)) fail(`Row ${rowIndex} field set mismatch`);
}

function validateRow(record, expected, expectedEcho, rowIndex) {
  compareKeys(record, rowIndex);
  if (record.SchemaVersion !== "1.0.0") fail(`Row ${rowIndex} schema version mismatch`);
  if (record.SyntheticString !== expected.string) fail(`Row ${rowIndex} synthetic string mismatch`);
  if (!Number.isSafeInteger(record.SyntheticInteger) || record.SyntheticInteger !== expected.integer) {
    fail(`Row ${rowIndex} synthetic integer mismatch`);
  }
  if (typeof record.SyntheticBoolean !== "boolean" || record.SyntheticBoolean !== expected.boolean) {
    fail(`Row ${rowIndex} synthetic boolean mismatch`);
  }
  if (!Number.isSafeInteger(record.RowOrder) || record.RowOrder !== expected.order) fail(`Row ${rowIndex} order mismatch`);
  if (record.EchoValue !== expectedEcho) fail(`Row ${rowIndex} echo mismatch`);
  if (record._Source !== "SecApp.Compatibility.Synthetic/Rows") fail(`Row ${rowIndex} source mismatch`);

  return {
    schema_version: record.SchemaVersion,
    synthetic_string: record.SyntheticString,
    synthetic_integer: record.SyntheticInteger,
    synthetic_boolean: record.SyntheticBoolean,
    row_order: record.RowOrder,
    echo_value: record.EchoValue,
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const inputPath = options.get("--input");
  const outputPath = options.get("--output");
  const expectedEcho = options.get("--expected-echo");
  const fileStat = await stat(inputPath);
  if (!fileStat.isFile() || fileStat.size > MAX_INPUT_BYTES) fail("Input is absent or over limit");
  const bytes = await readFile(inputPath);
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
  const value = parseStrictJson(text, basename(inputPath));
  if (!Array.isArray(value) || value.length !== 2) fail("Expected exactly two synthetic rows");

  const rows = [
    validateRow(value[0], { string: "alpha", integer: 7, boolean: true, order: 1 }, expectedEcho, 1),
    validateRow(value[1], { string: "beta", integer: 11, boolean: false, order: 2 }, expectedEcho, 2),
  ];
  const normalized = {
    compatibility_contract_version: 1,
    artifact: "SecApp.Compatibility.Synthetic",
    source: "Rows",
    rows,
  };
  const serialized = `${JSON.stringify(normalized, null, 2)}\n`;
  await writeFile(outputPath, serialized, { encoding: "utf8", flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    status: "VALID",
    input_file: basename(inputPath),
    input_sha256: createHash("sha256").update(bytes).digest("hex"),
    normalized_file: basename(outputPath),
    normalized_bytes: Buffer.byteLength(serialized, "utf8"),
    normalized_sha256: createHash("sha256").update(serialized, "utf8").digest("hex"),
    row_count: rows.length,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`normalize-synthetic-output: ${error.message}\n`);
  process.exitCode = 1;
});

import { reject } from "./import-errors.mjs";

const MiB = 1024 * 1024;

export const IMPORT_LIMIT_CEILINGS = Object.freeze({
  maxSourceBytes: 64 * MiB,
  maxJsonBytes: 16 * MiB,
  maxJsonlLineBytes: MiB,
  maxRecords: 100_000,
  maxJsonDepth: 64,
  maxZipEntries: 10_000,
  maxZipEntryExpandedBytes: 16 * MiB,
  maxZipExpandedBytes: 64 * MiB,
  maxCompressionRatio: 100,
  maxManifestEntries: 100_000
});

export const DEFAULT_IMPORT_LIMITS = Object.freeze({
  ...IMPORT_LIMIT_CEILINGS,
  jsonlFinalLf: "Optional"
});

const INTEGER_LIMITS = Object.freeze(Object.keys(IMPORT_LIMIT_CEILINGS));

export function resolveImportLimits(overrides = {}) {
  if (overrides === null || typeof overrides !== "object" || Array.isArray(overrides)) {
    reject("IMPORT_LIMITS_INVALID", "Prepare", "Import limits must be an object.");
  }
  const unknown = Object.keys(overrides).filter((key) => !INTEGER_LIMITS.includes(key) && key !== "jsonlFinalLf");
  if (unknown.length !== 0) reject("IMPORT_LIMITS_INVALID", "Prepare", "Unknown import limit.");
  const result = { ...DEFAULT_IMPORT_LIMITS, ...overrides };
  for (const name of INTEGER_LIMITS) {
    const value = result[name];
    if (!Number.isSafeInteger(value) || value < 1 || value > IMPORT_LIMIT_CEILINGS[name]) {
      reject("IMPORT_LIMITS_INVALID", "Prepare", `Invalid or weakened import limit: ${name}.`);
    }
  }
  if (!["Optional", "Required"].includes(result.jsonlFinalLf)) {
    reject("IMPORT_LIMITS_INVALID", "Prepare", "jsonlFinalLf must be Optional or Required.");
  }
  return Object.freeze(result);
}

export function checkedAdd(left, right) {
  if (!Number.isSafeInteger(left) || left < 0 || !Number.isSafeInteger(right) || right < 0) {
    reject("IMPORT_INTEGER_OVERFLOW", "Parse", "Unsafe size arithmetic was rejected.");
  }
  const result = left + right;
  if (!Number.isSafeInteger(result)) reject("IMPORT_INTEGER_OVERFLOW", "Parse", "Unsafe size arithmetic was rejected.");
  return result;
}

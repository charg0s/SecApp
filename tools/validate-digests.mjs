import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkedAdd,
  checkedMultiply,
  evaluateApplicationRecord,
  validateActionLog,
  verifyAuditManifestDigest
} from "./lib/application-rules.mjs";
import {
  canonicalizeContentBytes,
  digestWithExclusion,
  JcsInputError,
  jcs,
  jcsSha256,
  materializeByteSource,
  normalizeAuditManifest,
  normalizeExportManifest,
  normalizeRedactionProfile,
  profileDigest,
  sha256LowerHex
} from "./lib/jcs.mjs";
import { compareUnicodeCodeUnits } from "./lib/order.mjs";
import { createResult, emit, finish } from "./lib/report.mjs";
import { createSchemaRegistry, validateSchemaIdentity } from "./lib/schema-registry.mjs";
import { loadVectorCatalog, schemaSubjects } from "./lib/vectors.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = createResult("validate-digests");

export const REQUIRED_CASE_IDS_BY_CATEGORY = Object.freeze({
  catalog_digest: Object.freeze([
    "DIGEST_ACTION_FULL_OBJECT_VALID",
    "DIGEST_MANIFEST_FULL_OBJECT_VALID",
    "DIGEST_ACTION_CHAIN_VALID",
    "DIGEST_ACTION_GAP_INVALID",
    "DIGEST_ACTION_DUP_SEQUENCE_INVALID",
    "DIGEST_ACTION_PREVIOUS_MISMATCH_INVALID",
    "DIGEST_ACTION_CROSS_RUN_INVALID",
    "DIGEST_MANIFEST_PERMUTATION_VALID",
    "DIGEST_EXPORT_PERMUTATION_VALID"
  ]),
  jcs_conformance: Object.freeze([
    "JCS_RFC8785_SERIALIZATION_SAMPLE",
    "JCS_RFC8785_PROPERTY_ORDER_SAMPLE",
    "JCS_NUMBER_POSITIVE_ZERO",
    "JCS_NUMBER_NEGATIVE_ZERO",
    "JCS_NUMBER_MAX_SAFE_INTEGER",
    "JCS_NUMBER_FRACTION",
    "JCS_NUMBER_EXPONENT",
    "JCS_NUMBER_FIXED_THRESHOLD",
    "JCS_NUMBER_EXPONENT_THRESHOLD",
    "JCS_NUMBER_LARGE_THRESHOLD",
    "JCS_NUMBER_MAX_FINITE",
    "JCS_NUMBER_ROUNDING",
    "JCS_STRING_EMPTY",
    "JCS_STRING_BMP",
    "JCS_STRING_SUPPLEMENTARY",
    "JCS_STRING_COMPOSED",
    "JCS_STRING_DECOMPOSED",
    "JCS_STRING_ESCAPES_CONTROLS",
    "JCS_PROPERTY_ORDER_ADVERSARIAL"
  ]),
  jcs_direct_api_positive: Object.freeze([
    "JCS_DIRECT_POSITIVE_null",
    "JCS_DIRECT_POSITIVE_boolean",
    "JCS_DIRECT_POSITIVE_finite-number",
    "JCS_DIRECT_POSITIVE_valid-unicode",
    "JCS_DIRECT_POSITIVE_dense-array",
    "JCS_DIRECT_POSITIVE_plain-object",
    "JCS_DIRECT_POSITIVE_null-prototype-object",
    "JCS_DIRECT_POSITIVE_shared-noncyclic-object"
  ]),
  jcs_direct_api_negative: Object.freeze([
    "JCS_DIRECT_NEGATIVE_high-lone-surrogate-value",
    "JCS_DIRECT_NEGATIVE_low-lone-surrogate-value",
    "JCS_DIRECT_NEGATIVE_surrogate-property-name",
    "JCS_DIRECT_NEGATIVE_undefined-value",
    "JCS_DIRECT_NEGATIVE_function-value",
    "JCS_DIRECT_NEGATIVE_symbol-value",
    "JCS_DIRECT_NEGATIVE_bigint",
    "JCS_DIRECT_NEGATIVE_nan",
    "JCS_DIRECT_NEGATIVE_positive-infinity",
    "JCS_DIRECT_NEGATIVE_negative-infinity",
    "JCS_DIRECT_NEGATIVE_sparse-array",
    "JCS_DIRECT_NEGATIVE_cyclic-object",
    "JCS_DIRECT_NEGATIVE_date",
    "JCS_DIRECT_NEGATIVE_map",
    "JCS_DIRECT_NEGATIVE_set",
    "JCS_DIRECT_NEGATIVE_typed-array",
    "JCS_DIRECT_NEGATIVE_getter",
    "JCS_DIRECT_NEGATIVE_non-enumerable-property",
    "JCS_DIRECT_NEGATIVE_symbol-key",
    "JCS_DIRECT_NEGATIVE_array-extra-property",
    "JCS_DIRECT_NEGATIVE_proxy"
  ]),
  profile_digest: Object.freeze([
    "PROFILE_PUBLIC_NONEMPTY_A_DOT_A_A_UNDERSCORE_A",
    "PROFILE_PUBLIC_NONEMPTY_A_DOT_A_A_UNDERSCORE_A_PERMUTATION",
    "PROFILE_PUBLIC_NONEMPTY_A_DOT_A_A_UNDERSCORE_A_MUTATION_action",
    "PROFILE_PUBLIC_NONEMPTY_A_DOT_A_A_UNDERSCORE_A_MUTATION_path",
    "PROFILE_PUBLIC_NONEMPTY_A_DOT_A_A_UNDERSCORE_A_MUTATION_class",
    "PROFILE_PUBLIC_NONEMPTY_A_DOT_A_A_UNDERSCORE_A_MUTATION_key",
    "PROFILE_PUBLIC_NONEMPTY_A_DOT_A_A_UNDERSCORE_A_MUTATION_public-private",
    "PROFILE_PRIVATE_NONEMPTY",
    "PROFILE_PRIVATE_NONEMPTY_PERMUTATION",
    "PROFILE_DUPLICATE_FIELD_REJECTED",
    "PROFILE_FIELD_FALLBACK_REJECTED"
  ]),
  file_digest: Object.freeze([
    "FILE_EMPTY",
    "FILE_ASCII",
    "FILE_UTF8",
    "FILE_UTF8_BOM",
    "FILE_LF",
    "FILE_CRLF",
    "FILE_FINAL_LF",
    "FILE_NO_FINAL_LF",
    "FILE_NUL",
    "FILE_BYTE_BOUNDARIES",
    "FILE_ARBITRARY_BINARY",
    "FILE_INVALID_HEX",
    "FILE_ODD_HEX",
    "FILE_INVALID_BASE64",
    "FILE_UNSUPPORTED_ENCODING"
  ]),
  content_digest: Object.freeze([
    "CONTENT_EMPTY",
    "CONTENT_ASCII_NO_FINAL_LF",
    "CONTENT_CRLF",
    "CONTENT_CR",
    "CONTENT_BOM",
    "CONTENT_BOM_ONLY",
    "CONTENT_LF_ONLY",
    "CONTENT_MIXED_LINE_ENDINGS",
    "CONTENT_FINAL_LF",
    "CONTENT_UTF8",
    "CONTENT_COMPOSED",
    "CONTENT_DECOMPOSED",
    "CONTENT_SUPPLEMENTARY",
    "CONTENT_NUL",
    "CONTENT_INVALID_UTF8",
    "CONTENT_INVALID_UTF8_BINARY"
  ]),
  schema_guard_negative: Object.freeze([
    "SCHEMA_FORMAT_UUID_INVALID",
    "SCHEMA_FORMAT_DATE_TIME_INVALID",
    "SCHEMA_FORMAT_URI_INVALID",
    "SCHEMA_KEYWORD_UNKNOWN_ORDINARY_INVALID",
    "SCHEMA_KEYWORD_UNKNOWN_X_INVALID",
    "SCHEMA_NAMESPACE_UNKNOWN_MAJOR_INVALID"
  ]),
  checked_arithmetic: Object.freeze([
    "CHECKED_ADD_MAX_SAFE_BOUNDARY",
    "CHECKED_ADD_OVERFLOW",
    "CHECKED_MULTIPLY_MAX_SAFE_BOUNDARY",
    "CHECKED_MULTIPLY_OVERFLOW",
    "CHECKED_MULTIPLY_ORDINARY"
  ])
});

const OFFICIAL_JCS_CASE_IDS = Object.freeze([
  "JCS_RFC8785_SERIALIZATION_SAMPLE",
  "JCS_RFC8785_PROPERTY_ORDER_SAMPLE"
]);
const caseDefinitions = [];
const executedCaseRecords = [];
let caseControlById = new Map();

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function runCase(caseId, category, action, { additional = false } = {}) {
  const control = caseControlById.get(caseId) ?? {};
  const definition = {
    case_id: caseId,
    category,
    additional,
    skipped: control.skipped === true,
    execute: control.execute !== false
  };
  caseDefinitions.push(definition);
  if (definition.skipped || !definition.execute) return;
  result.vector_count += 1;
  const execution = { case_id: caseId, category, passed: false };
  executedCaseRecords.push(execution);
  try {
    action();
    execution.passed = true;
    result.passed += 1;
  } catch (error) {
    result.failed += 1;
    result.errors.push({ error_code: "DIGEST_CASE_FAILED", vector_id: caseId, message: error.message });
  }
}

function categoryIds(definitions, additional) {
  const result = Object.fromEntries(Object.keys(REQUIRED_CASE_IDS_BY_CATEGORY).map((category) => [category, []]));
  for (const definition of definitions) {
    if (definition.additional !== additional) continue;
    if (!result[definition.category]) result[definition.category] = [];
    result[definition.category].push(definition.case_id);
  }
  for (const ids of Object.values(result)) ids.sort(compareUnicodeCodeUnits);
  return result;
}

export function analyzeRequiredCases(definitions, executions) {
  const requiredCategoryById = new Map();
  for (const [category, ids] of Object.entries(REQUIRED_CASE_IDS_BY_CATEGORY)) {
    for (const id of ids) requiredCategoryById.set(id, category);
  }
  const requiredDefinitions = definitions.filter((item) => !item.additional);
  const definitionIds = requiredDefinitions.map((item) => item.case_id);
  const duplicateCaseIds = [...new Set(definitionIds.filter((id, index) => definitionIds.indexOf(id) !== index))]
    .filter((id) => requiredCategoryById.has(id))
    .sort(compareUnicodeCodeUnits);
  const missingRequiredCaseIds = [];
  const categoryMismatchCaseIds = [];
  const skippedRequiredCaseIds = [];
  const notExecutedRequiredCaseIds = [];
  const failedRequiredCaseIds = [];
  for (const [id, expectedCategory] of requiredCategoryById) {
    const matchingId = requiredDefinitions.filter((item) => item.case_id === id);
    const matchingCategory = matchingId.filter((item) => item.category === expectedCategory);
    if (matchingCategory.length === 0) missingRequiredCaseIds.push(id);
    if (matchingId.some((item) => item.category !== expectedCategory)) categoryMismatchCaseIds.push(id);
    if (matchingCategory.some((item) => item.skipped)) skippedRequiredCaseIds.push(id);
    if (matchingCategory.length > 0 && !executions.some((item) => item.case_id === id && item.category === expectedCategory)) {
      notExecutedRequiredCaseIds.push(id);
    }
    if (executions.some((item) => item.case_id === id && item.category === expectedCategory && item.passed === false)) {
      failedRequiredCaseIds.push(id);
    }
  }
  const actualByCategory = categoryIds(requiredDefinitions, false);
  const exactSet = Object.entries(REQUIRED_CASE_IDS_BY_CATEGORY).every(([category, requiredIds]) => {
    const actualIds = actualByCategory[category] ?? [];
    const expectedIds = [...requiredIds].sort(compareUnicodeCodeUnits);
    return actualIds.length === expectedIds.length && actualIds.every((id, index) => id === expectedIds[index]);
  }) && Object.keys(actualByCategory).every((category) => Object.hasOwn(REQUIRED_CASE_IDS_BY_CATEGORY, category));
  const requiredSetComplete = exactSet
    && duplicateCaseIds.length === 0
    && categoryMismatchCaseIds.length === 0
    && skippedRequiredCaseIds.length === 0
    && notExecutedRequiredCaseIds.length === 0
    && failedRequiredCaseIds.length === 0;
  const failures = [
    ...missingRequiredCaseIds.map((case_id) => ({ error_code: "DIGEST_REQUIRED_CASE_MISSING", case_id })),
    ...duplicateCaseIds.map((case_id) => ({ error_code: "DIGEST_REQUIRED_CASE_DUPLICATE", case_id })),
    ...categoryMismatchCaseIds.map((case_id) => ({ error_code: "DIGEST_CASE_CATEGORY_MISMATCH", case_id })),
    ...skippedRequiredCaseIds.map((case_id) => ({ error_code: "DIGEST_REQUIRED_CASE_SKIPPED", case_id })),
    ...notExecutedRequiredCaseIds.map((case_id) => ({ error_code: "DIGEST_REQUIRED_CASE_NOT_EXECUTED", case_id }))
  ];
  if (!requiredSetComplete) failures.push({ error_code: "DIGEST_REQUIRED_SET_MISMATCH" });
  return {
    failures,
    required_case_ids_by_category: Object.fromEntries(Object.entries(REQUIRED_CASE_IDS_BY_CATEGORY)
      .map(([category, ids]) => [category, [...ids]])),
    actual_case_ids_by_category: actualByCategory,
    missing_required_case_ids: missingRequiredCaseIds.sort(compareUnicodeCodeUnits),
    duplicate_case_ids: duplicateCaseIds,
    category_mismatch_case_ids: categoryMismatchCaseIds.sort(compareUnicodeCodeUnits),
    skipped_required_case_ids: skippedRequiredCaseIds.sort(compareUnicodeCodeUnits),
    not_executed_required_case_ids: notExecutedRequiredCaseIds.sort(compareUnicodeCodeUnits),
    failed_required_case_ids: failedRequiredCaseIds.sort(compareUnicodeCodeUnits),
    required_set_complete: requiredSetComplete
  };
}

function runDigestCompletenessSelfTests(definitions, executions) {
  const required = Object.entries(REQUIRED_CASE_IDS_BY_CATEGORY)
    .flatMap(([category, ids]) => ids.map((case_id) => ({ case_id, category })));
  let count = 0;
  for (const target of required) {
    const peers = REQUIRED_CASE_IDS_BY_CATEGORY[target.category].filter((id) => id !== target.case_id);
    const replacementId = peers[0];
    const removedDefinitions = definitions.filter((item) => item.additional || item.case_id !== target.case_id);
    const removedExecutions = executions.filter((item) => item.case_id !== target.case_id);
    assert(analyzeRequiredCases(removedDefinitions, removedExecutions).failures.some((item) =>
      item.error_code === "DIGEST_REQUIRED_CASE_MISSING" && item.case_id === target.case_id), `${target.case_id}: removal self-test failed`);
    count += 1;

    const replacedDefinitions = structuredClone(definitions);
    const replaced = replacedDefinitions.find((item) => !item.additional && item.case_id === target.case_id);
    replaced.case_id = replacementId;
    const replacedAnalysis = analyzeRequiredCases(replacedDefinitions, executions);
    assert(replacedAnalysis.failures.some((item) => item.error_code === "DIGEST_REQUIRED_CASE_MISSING" && item.case_id === target.case_id)
      && replacedAnalysis.failures.some((item) => item.error_code === "DIGEST_REQUIRED_CASE_DUPLICATE" && item.case_id === replacementId),
    `${target.case_id}: replacement-by-duplicate self-test failed`);
    count += 1;

    const duplicateDefinitions = structuredClone(definitions);
    duplicateDefinitions.push(structuredClone(duplicateDefinitions.find((item) => !item.additional && item.case_id === target.case_id)));
    assert(analyzeRequiredCases(duplicateDefinitions, executions).failures.some((item) =>
      item.error_code === "DIGEST_REQUIRED_CASE_DUPLICATE" && item.case_id === target.case_id), `${target.case_id}: duplicate self-test failed`);
    count += 1;

    const categoryDefinitions = structuredClone(definitions);
    categoryDefinitions.find((item) => !item.additional && item.case_id === target.case_id).category = "category-mismatch";
    assert(analyzeRequiredCases(categoryDefinitions, executions).failures.some((item) =>
      item.error_code === "DIGEST_CASE_CATEGORY_MISMATCH" && item.case_id === target.case_id), `${target.case_id}: category self-test failed`);
    count += 1;

    const skippedDefinitions = structuredClone(definitions);
    skippedDefinitions.find((item) => !item.additional && item.case_id === target.case_id).skipped = true;
    assert(analyzeRequiredCases(skippedDefinitions, executions).failures.some((item) =>
      item.error_code === "DIGEST_REQUIRED_CASE_SKIPPED" && item.case_id === target.case_id), `${target.case_id}: skipped self-test failed`);
    count += 1;

    const notExecuted = executions.filter((item) => item.case_id !== target.case_id);
    assert(analyzeRequiredCases(definitions, notExecuted).failures.some((item) =>
      item.error_code === "DIGEST_REQUIRED_CASE_NOT_EXECUTED" && item.case_id === target.case_id), `${target.case_id}: not-executed self-test failed`);
    count += 1;
  }
  return { case_ids: required.map((item) => item.case_id), mutation_count: count };
}

function normalizeExample(schemaId, example) {
  if (schemaId.endsWith("/audit-manifest.schema.json")) return normalizeAuditManifest(example);
  if (schemaId.endsWith("/export-manifest.schema.json")) return normalizeExportManifest(example);
  if (schemaId.endsWith("/action-log.schema.json")) {
    const copy = structuredClone(example);
    copy.entries.sort((left, right) => left.sequence_number - right.sequence_number);
    return copy;
  }
  if (schemaId.endsWith("/redaction-profile.schema.json")) return normalizeRedactionProfile(example);
  return example;
}

function verifyExample(schemaId, example) {
  if (schemaId.endsWith("/action-log.schema.json")) {
    const errors = validateActionLog(example);
    if (errors.length) return { checked: 1, errors };
  }
  let checked = 0;
  const errors = [];
  for (const metadata of Object.values(example)) {
    if (!metadata || typeof metadata !== "object" || metadata.canonicalization !== "JCS-RFC8785" || !Array.isArray(metadata.excluded_fields)) continue;
    const expected = metadata.digest ?? metadata.object_digest;
    if (typeof expected !== "string" || metadata.excluded_fields.length !== 1) continue;
    checked += 1;
    try {
      const actual = digestWithExclusion(example, metadata.excluded_fields[0], (value) => normalizeExample(schemaId, value));
      if (actual !== expected) errors.push("DIGEST_CONTRACT_MISMATCH");
    } catch {
      errors.push("DIGEST_CONTRACT_MISMATCH");
    }
  }
  return { checked, errors };
}

function evaluateCatalogDigest(record) {
  const vector = record.fixture;
  if (vector.source) {
    const instance = schemaSubjects(root, record)[0].instance;
    if (vector.schema_id.endsWith("/action-log.schema.json")) {
      const errors = validateActionLog(instance);
      if (errors.length) return errors;
      if (instance.entries[0].entry_digest.digest !== vector.expected_entry_digest || instance.log_digest.digest !== vector.expected_log_digest) return ["DIGEST_CONTRACT_MISMATCH"];
      return [];
    }
    const digest = verifyAuditManifestDigest(instance);
    return digest === vector.expected_manifest_digest && digest === instance.manifest_digest.digest ? [] : ["DIGEST_CONTRACT_MISMATCH"];
  }
  if (vector.entries || vector.sequence_numbers || vector.previous_entry_digest || vector.log_run_id) return evaluateApplicationRecord(record);
  if (vector.input_arrays) {
    const digests = vector.input_arrays.map((entries) => jcsSha256(normalizeAuditManifest({ entries, manifest_digest: { algorithm: "SHA-256" } })));
    return digests.every((digest) => digest === vector.expected_digest) ? [] : ["DIGEST_CONTRACT_MISMATCH"];
  }
  if (vector.input_orders) {
    const digest = jcsSha256(normalizeExportManifest(vector.canonical_object_after_exclusion_and_sort));
    return digest === vector.expected_digest ? [] : ["DIGEST_CONTRACT_MISMATCH"];
  }
  return ["DIGEST_CONTRACT_MISMATCH"];
}

function directPositiveFactories() {
  const shared = { value: "shared" };
  return new Map([
    ["null", () => null],
    ["boolean", () => true],
    ["finite-number", () => -123.5],
    ["valid-unicode", () => "BMP € and supplementary 😀"],
    ["dense-array", () => [null, false, 0, ""]],
    ["plain-object", () => ({ b: 2, a: 1 })],
    ["null-prototype-object", () => Object.assign(Object.create(null), { a: 1 })],
    ["shared-noncyclic-object", () => ({ left: shared, right: shared })]
  ]);
}

function directNegativeFactories() {
  const high = String.fromCharCode(0xd800);
  const low = String.fromCharCode(0xdc00);
  return new Map([
    ["high-lone-surrogate-value", () => ({ value: high })],
    ["low-lone-surrogate-value", () => ({ value: low })],
    ["surrogate-property-name", () => ({ [high]: 1 })],
    ["undefined-value", () => ({ value: undefined })],
    ["function-value", () => ({ value() {} })],
    ["symbol-value", () => ({ value: Symbol("x") })],
    ["bigint", () => 1n],
    ["nan", () => Number.NaN],
    ["positive-infinity", () => Number.POSITIVE_INFINITY],
    ["negative-infinity", () => Number.NEGATIVE_INFINITY],
    ["sparse-array", () => { const value = []; value.length = 1; return value; }],
    ["cyclic-object", () => { const value = {}; value.self = value; return value; }],
    ["date", () => new Date("2026-01-01T00:00:00Z")],
    ["map", () => new Map([["a", 1]])],
    ["set", () => new Set([1])],
    ["typed-array", () => new Uint8Array([1])],
    ["getter", () => Object.defineProperty({}, "value", { enumerable: true, get: () => 1 })],
    ["non-enumerable-property", () => Object.defineProperty({}, "value", { enumerable: false, value: 1 })],
    ["symbol-key", () => ({ [Symbol("key")]: 1 })],
    ["array-extra-property", () => { const value = [1]; value.extra = 2; return value; }],
    ["proxy", () => new Proxy({ value: 1 }, {})]
  ]);
}

function applyFixtureMutation(value, mutation) {
  const copy = structuredClone(value);
  const tokens = mutation.path.slice(1).split("/").map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"));
  const leaf = tokens.pop();
  let current = copy;
  for (const token of tokens) current = current[token];
  if (mutation.op !== "add" && mutation.op !== "replace") throw new Error(`unsupported mutation ${mutation.op}`);
  current[leaf] = mutation.value;
  return copy;
}

function mutatedBytes(bytes) {
  if (bytes.length === 0) return Buffer.from([0]);
  const result = Buffer.from(bytes);
  result[0] ^= 0xff;
  return result;
}

function collectDigestKinds(value, counts = new Map()) {
  if (Array.isArray(value)) {
    for (const item of value) collectDigestKinds(item, counts);
  } else if (value && typeof value === "object") {
    if (typeof value.digest_kind === "string") counts.set(value.digest_kind, (counts.get(value.digest_kind) ?? 0) + 1);
    for (const item of Object.values(value)) collectDigestKinds(item, counts);
  }
  return counts;
}

try {
  const registry = createSchemaRegistry(root);
  const catalog = loadVectorCatalog(root);
  const records = catalog.records.filter((record) => record.source === "tests/contracts/digests/digests.json");
  const fixtureDocument = records[0]?.document;
  if (!fixtureDocument) throw new Error("digest fixture document is missing");
  if (!Array.isArray(fixtureDocument.case_controls ?? [])) throw new Error("digest case_controls must be an array");
  caseControlById = new Map();
  for (const control of fixtureDocument.case_controls ?? []) {
    if (!control || typeof control.case_id !== "string" || caseControlById.has(control.case_id)) {
      throw new Error("digest case_controls contains a duplicate or invalid case_id");
    }
    caseControlById.set(control.case_id, control);
  }
  result.schema_count = registry.schemas.length;

  for (const record of records) {
    runCase(record.descriptor.vector_id, "catalog_digest", () => {
      const expected = record.descriptor.expected_application_valid;
      const errors = evaluateCatalogDigest(record);
      if (expected) assert(errors.length === 0, `expected valid digest; got ${errors.join(",")}`);
      else assert(errors[0] === record.fixture.expected_error_code, `expected ${record.fixture.expected_error_code}; got ${errors.join(",") || "valid"}`);
    });
  }

  for (const vector of fixtureDocument.jcs_conformance_vectors) {
    runCase(vector.case_id, "jcs_conformance", () => {
      const before = JSON.stringify(vector.input);
      const actual = jcs(vector.input);
      assert(actual === vector.expected_canonical, `canonical mismatch: ${JSON.stringify(actual)}`);
      assert(sha256LowerHex(Buffer.from(actual, "utf8")) === vector.expected_digest, "canonical SHA-256 mismatch");
      assert(JSON.stringify(vector.input) === before, "JCS mutated its input");
    });
  }

  const positives = directPositiveFactories();
  for (const caseId of fixtureDocument.jcs_direct_api_positive_cases) {
    runCase(`JCS_DIRECT_POSITIVE_${caseId}`, "jcs_direct_api_positive", () => {
      const factory = positives.get(caseId);
      assert(factory, "unknown direct positive case");
      const value = factory();
      const first = jcs(value);
      assert(typeof first === "string" && first === jcs(value), "direct positive case is not deterministic");
    });
  }

  const negatives = directNegativeFactories();
  for (const caseId of fixtureDocument.jcs_direct_api_negative_cases) {
    runCase(`JCS_DIRECT_NEGATIVE_${caseId}`, "jcs_direct_api_negative", () => {
      const factory = negatives.get(caseId);
      assert(factory, "unknown direct negative case");
      try {
        jcs(factory());
        throw new Error("invalid direct API value was accepted");
      } catch (error) {
        if (!(error instanceof JcsInputError) || error.code !== "JCS_INPUT_INVALID") throw error;
      }
    });
  }

  const validateProfile = registry.ajv.getSchema("https://schemas.secapp.dev/v1/redaction-profile.schema.json");
  let profileDigestCases = 0;
  for (const vector of fixtureDocument.profile_digest_cases) {
    runCase(vector.case_id, "profile_digest", () => {
      profileDigestCases += 1;
      assert(validateProfile(vector.profile), `profile fixture is schema-invalid: ${JSON.stringify(validateProfile.errors)}`);
      const before = JSON.stringify(vector.profile);
      assert(profileDigest(vector.profile) === vector.expected_digest, "ProfileDigest mismatch");
      assert(vector.profile.profile_digest.digest === vector.expected_digest, "embedded ProfileDigest mismatch");
      assert(JSON.stringify(vector.profile) === before, "ProfileDigest mutated its input");
    });
    if (vector.permutation_invariant) {
      runCase(`${vector.case_id}_PERMUTATION`, "profile_digest", () => {
        profileDigestCases += 1;
        const permutation = structuredClone(vector.profile);
        permutation.field_rules.reverse();
        permutation.class_actions = Object.fromEntries(Object.entries(permutation.class_actions).reverse());
        assert(profileDigest(permutation) === vector.expected_digest, "profile rule permutation changed digest");
      });
    }
    for (const mutation of vector.mutations) {
      runCase(`${vector.case_id}_MUTATION_${mutation.name}`, "profile_digest", () => {
        profileDigestCases += 1;
        const mutated = applyFixtureMutation(vector.profile, mutation);
        assert(validateProfile(mutated), `${mutation.name} mutation is schema-invalid: ${JSON.stringify(validateProfile.errors)}`);
        const actual = profileDigest(mutated);
        assert(actual === mutation.expected_digest && actual !== vector.expected_digest, `${mutation.name} mutation digest mismatch`);
      });
    }
  }
  runCase("PROFILE_DUPLICATE_FIELD_REJECTED", "profile_digest", () => {
    profileDigestCases += 1;
    const duplicate = structuredClone(fixtureDocument.profile_digest_cases[0].profile);
    duplicate.field_rules.push(structuredClone(duplicate.field_rules[0]));
    try {
      profileDigest(duplicate);
      throw new Error("duplicate profile field was accepted");
    } catch (error) {
      assert(error.message === "DIGEST_PROFILE_DUPLICATE_FIELD", `unexpected duplicate error: ${error.message}`);
    }
  });
  runCase("PROFILE_FIELD_FALLBACK_REJECTED", "profile_digest", () => {
    profileDigestCases += 1;
    const wrongName = structuredClone(fixtureDocument.profile_digest_cases[0].profile);
    wrongName.field_rules = [{ field_id: "a.a", privacy_class: "Public", action: "Include" }];
    try {
      profileDigest(wrongName);
      throw new Error("legacy profile field fallback was accepted");
    } catch (error) {
      assert(error.message === "DIGEST_PROFILE_FIELD_INVALID", `unexpected field error: ${error.message}`);
    }
  });

  for (const vector of fixtureDocument.file_digest_cases) {
    runCase(vector.case_id, "file_digest", () => {
      try {
        const bytes = materializeByteSource(vector.source_bytes);
        assert(!vector.expected_error, `expected ${vector.expected_error}; bytes were accepted`);
        assert(sha256LowerHex(bytes) === vector.expected_digest, "raw-byte SHA-256 mismatch");
        assert(sha256LowerHex(mutatedBytes(bytes)) === vector.expected_mutation_digest, "raw-byte mutation SHA-256 mismatch");
        assert(vector.expected_mutation_digest !== vector.expected_digest, "byte mutation did not change digest");
      } catch (error) {
        if (!vector.expected_error || error.message !== vector.expected_error) throw error;
      }
    });
  }

  for (const vector of fixtureDocument.content_digest_cases) {
    runCase(vector.case_id, "content_digest", () => {
      try {
        const canonical = canonicalizeContentBytes(materializeByteSource(vector.source_bytes));
        assert(!vector.expected_error, `expected ${vector.expected_error}; content was accepted`);
        assert(canonical.toString("hex") === vector.canonical_hex, "ContentDigest canonical bytes mismatch");
        assert(sha256LowerHex(canonical) === vector.expected_digest, "ContentDigest SHA-256 mismatch");
      } catch (error) {
        if (!vector.expected_error || error.message !== vector.expected_error) throw error;
      }
    });
  }

  for (const vector of fixtureDocument.schema_guard_negative_cases) {
    runCase(vector.case_id, "schema_guard_negative", () => {
      if (vector.kind === "Format") {
        const validate = registry.ajv.compile({ type: "string", format: vector.format });
        assert(!validate(vector.invalid_value), `${vector.case_id}: invalid format value was accepted`);
        return;
      }
      if (vector.kind === "UnknownKeyword") {
        try {
          registry.ajv.compile({ type: "object", [vector.keyword]: true });
          throw new Error(`${vector.case_id}: unknown keyword was accepted`);
        } catch (error) {
          assert(String(error.message).includes(`unknown keyword: "${vector.keyword}"`), `${vector.case_id}: unexpected keyword error`);
        }
        return;
      }
      if (vector.kind === "Namespace") {
        try {
          validateSchemaIdentity("synthetic.schema.json", vector.schema);
          throw new Error(`${vector.case_id}: unknown namespace was accepted`);
        } catch (error) {
          assert(String(error.message).includes("invalid immutable $id"), `${vector.case_id}: unexpected namespace error`);
        }
        return;
      }
      throw new Error(`${vector.case_id}: unknown schema guard kind`);
    });
  }

  for (const vector of fixtureDocument.checked_arithmetic_cases) {
    runCase(vector.case_id, "checked_arithmetic", () => {
      const operation = vector.operator === "checkedAdd" ? checkedAdd : vector.operator === "checkedMultiply" ? checkedMultiply : undefined;
      assert(operation, `${vector.case_id}: unknown arithmetic operator`);
      try {
        const actual = operation(...vector.operands);
        assert(vector.expected_error === undefined, `${vector.case_id}: expected ${vector.expected_error}; operation was accepted`);
        assert(actual === vector.expected, `${vector.case_id}: checked arithmetic result mismatch`);
      } catch (error) {
        if (vector.expected_error === undefined || error.message !== vector.expected_error) throw error;
      }
    });
  }

  let embeddedExampleChecks = 0;
  const digestKindCounts = new Map();
  for (const item of registry.schemas) {
    for (const [exampleIndex, example] of (item.schema.examples ?? []).entries()) {
      collectDigestKinds(example, digestKindCounts);
      const check = verifyExample(item.schema.$id, example);
      embeddedExampleChecks += check.checked;
      for (let checkIndex = 0; checkIndex < check.checked; checkIndex += 1) {
        runCase(`EMBEDDED_DIGEST_${path.basename(item.file)}_${exampleIndex}_${checkIndex}`, "embedded_digest", () => {
          assert(check.errors.length === 0, check.errors.join(",") || "embedded digest check failed");
        }, { additional: true });
      }
    }
  }

  const supportedSchemaDigestKinds = new Set(["EntryDigest", "FileDigest", "ManifestDigest", "ObjectDigest", "ProfileDigest"]);
  const structurallyOnlyDigestCases = digestKindCounts.get("FileDigest") ?? 0;
  const unsupportedDigestCases = [...digestKindCounts.entries()]
    .filter(([kind]) => !supportedSchemaDigestKinds.has(kind))
    .reduce((total, [, count]) => total + count, 0);
  const completeness = {
    catalog_digest_vectors: records.length,
    jcs_conformance_cases: fixtureDocument.jcs_conformance_vectors.length,
    jcs_direct_api_negative_cases: fixtureDocument.jcs_direct_api_negative_cases.length,
    jcs_direct_api_positive_cases: fixtureDocument.jcs_direct_api_positive_cases.length,
    profile_digest_cases: profileDigestCases,
    byte_backed_file_digest_cases: fixtureDocument.file_digest_cases.length,
    byte_backed_content_digest_cases: fixtureDocument.content_digest_cases.length,
    schema_guard_negative_cases: fixtureDocument.schema_guard_negative_cases.length,
    checked_arithmetic_cases: fixtureDocument.checked_arithmetic_cases.length,
    structurally_only_digest_cases: structurallyOnlyDigestCases,
    unsupported_digest_cases: unsupportedDigestCases,
    skipped_digest_cases: 0
  };
  const canonicalDefinitions = Object.entries(REQUIRED_CASE_IDS_BY_CATEGORY)
    .flatMap(([category, ids]) => ids.map((case_id) => ({
      case_id,
      category,
      additional: false,
      skipped: false,
      execute: true
    })));
  const canonicalExecutions = canonicalDefinitions.map((item) => ({
    case_id: item.case_id,
    category: item.category,
    passed: true
  }));
  const completenessSelfTests = runDigestCompletenessSelfTests(canonicalDefinitions, canonicalExecutions);
  const requiredAnalysis = analyzeRequiredCases(caseDefinitions, executedCaseRecords);
  const { failures: requiredFailures, ...requiredSummary } = requiredAnalysis;
  completeness.skipped_digest_cases = requiredSummary.skipped_required_case_ids.length;
  const declared = catalog.index.digest_gate_coverage;
  const declaredCountsMatch = Object.entries(completeness).every(([field, value]) => declared?.[field] === value);
  const declaredRequiredIdsMatch = JSON.stringify(declared?.required_case_ids_by_category)
    === JSON.stringify(requiredSummary.required_case_ids_by_category);
  const metadataComplete = unsupportedDigestCases === 0 && declaredCountsMatch && declaredRequiredIdsMatch;
  for (const failure of requiredFailures) {
    result.failed += 1;
    result.errors.push({ ...failure, message: failure.case_id ?? "digest required set mismatch" });
  }
  if (!metadataComplete) {
    result.failed += 1;
    result.errors.push({
      error_code: "DIGEST_REQUIRED_SET_MISMATCH",
      message: "digest index/count/metadata declaration mismatch"
    });
  }
  const requiredSetComplete = requiredSummary.required_set_complete && metadataComplete;
  finish(result, {
    algorithm: "SHA-256",
    encoding: "LowerHex",
    canonicalization: "JCS-RFC8785",
    digest_types: ["AuditManifest ManifestDigest", "ContentDigest", "EntryDigest/ObjectDigest", "ExportManifest ManifestDigest", "FileDigest", "ObjectDigest", "ProfileDigest"].sort(compareUnicodeCodeUnits),
    embedded_example_digest_checks: embeddedExampleChecks,
    ...completeness,
    ...requiredSummary,
    required_set_complete: requiredSetComplete,
    additional_case_ids_by_category: categoryIds(caseDefinitions, true),
    digest_completeness_self_tested_case_ids: completenessSelfTests.case_ids,
    digest_completeness_self_test_mutation_count: completenessSelfTests.mutation_count,
    digest_completeness_self_test_operations: [
      "remove-required-id",
      "replace-required-id-with-duplicate",
      "duplicate-vector-id",
      "change-category",
      "mark-skipped",
      "mark-not-executed"
    ],
    canonical_sort_implementation: "RFC 8785 raw UTF-16 code-unit property ordering; contract arrays use shared bytewise UTF-8 comparators from tools/lib/order.mjs",
    rfc8785_conformance_status: result.failed === 0 ? "covered_conformance_set_passed" : "covered_conformance_set_failed",
    conformance_claim: "CoveredSet",
    covered_case_count: REQUIRED_CASE_IDS_BY_CATEGORY.jcs_conformance.length,
    full_corpus_claimed: false,
    official_or_derived_vectors: {
      official: [...OFFICIAL_JCS_CASE_IDS],
      derived: REQUIRED_CASE_IDS_BY_CATEGORY.jcs_conformance.filter((id) => !OFFICIAL_JCS_CASE_IDS.includes(id))
    },
    content_digest_contract: "UTF-8 without BOM; CRLF/CR normalized to LF; required final LF; no Unicode normalization",
    file_digest_contract: "exact materialized bytes; no decoding or normalization",
    file_digest_mutation: "flip first byte, or append 00 for empty input",
    arch_review4_direct_api_status: "all invalid counterexamples rejected with JCS_INPUT_INVALID"
  });
} catch (error) {
  result.failed += 1;
  result.errors.push({ error_code: "DIGEST_GATE_INITIALIZATION_FAILED", message: error.message });
  finish(result, {
    jcs_conformance_cases: 0,
    jcs_direct_api_negative_cases: 0,
    jcs_direct_api_positive_cases: 0,
    profile_digest_cases: 0,
    byte_backed_file_digest_cases: 0,
    byte_backed_content_digest_cases: 0,
    structurally_only_digest_cases: 0,
    unsupported_digest_cases: 0,
    skipped_digest_cases: 0,
    required_case_ids_by_category: Object.fromEntries(Object.entries(REQUIRED_CASE_IDS_BY_CATEGORY)
      .map(([category, ids]) => [category, [...ids]])),
    actual_case_ids_by_category: {},
    missing_required_case_ids: Object.values(REQUIRED_CASE_IDS_BY_CATEGORY).flat(),
    duplicate_case_ids: [],
    category_mismatch_case_ids: [],
    skipped_required_case_ids: [],
    not_executed_required_case_ids: Object.values(REQUIRED_CASE_IDS_BY_CATEGORY).flat(),
    required_set_complete: false,
    canonical_sort_implementation: "initialization failed",
    rfc8785_conformance_status: "covered_conformance_set_failed",
    conformance_claim: "CoveredSet",
    covered_case_count: 0,
    full_corpus_claimed: false,
    official_or_derived_vectors: { official: [...OFFICIAL_JCS_CASE_IDS], derived: [] }
  });
}

emit(result);

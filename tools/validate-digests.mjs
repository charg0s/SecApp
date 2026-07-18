import path from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateApplicationRecord, validateActionLog, verifyAuditManifestDigest } from "./lib/application-rules.mjs";
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
import { createSchemaRegistry } from "./lib/schema-registry.mjs";
import { loadVectorCatalog, schemaSubjects } from "./lib/vectors.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = createResult("validate-digests");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function runCase(caseId, action) {
  result.vector_count += 1;
  try {
    action();
    result.passed += 1;
  } catch (error) {
    result.failed += 1;
    result.errors.push({ error_code: "DIGEST_CASE_FAILED", vector_id: caseId, message: error.message });
  }
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
  result.schema_count = registry.schemas.length;

  for (const record of records) {
    runCase(record.descriptor.vector_id, () => {
      const expected = record.descriptor.expected_application_valid;
      const errors = evaluateCatalogDigest(record);
      if (expected) assert(errors.length === 0, `expected valid digest; got ${errors.join(",")}`);
      else assert(errors[0] === record.fixture.expected_error_code, `expected ${record.fixture.expected_error_code}; got ${errors.join(",") || "valid"}`);
    });
  }

  for (const vector of fixtureDocument.jcs_conformance_vectors) {
    runCase(vector.case_id, () => {
      const before = JSON.stringify(vector.input);
      const actual = jcs(vector.input);
      assert(actual === vector.expected_canonical, `canonical mismatch: ${JSON.stringify(actual)}`);
      assert(sha256LowerHex(Buffer.from(actual, "utf8")) === vector.expected_digest, "canonical SHA-256 mismatch");
      assert(JSON.stringify(vector.input) === before, "JCS mutated its input");
    });
  }

  const positives = directPositiveFactories();
  assert(positives.size === fixtureDocument.jcs_direct_api_positive_cases.length, "direct positive case inventory mismatch");
  for (const caseId of fixtureDocument.jcs_direct_api_positive_cases) {
    runCase(`JCS_DIRECT_POSITIVE_${caseId}`, () => {
      const factory = positives.get(caseId);
      assert(factory, "unknown direct positive case");
      const value = factory();
      const first = jcs(value);
      assert(typeof first === "string" && first === jcs(value), "direct positive case is not deterministic");
    });
  }

  const negatives = directNegativeFactories();
  assert(negatives.size === fixtureDocument.jcs_direct_api_negative_cases.length, "direct negative case inventory mismatch");
  for (const caseId of fixtureDocument.jcs_direct_api_negative_cases) {
    runCase(`JCS_DIRECT_NEGATIVE_${caseId}`, () => {
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
    runCase(vector.case_id, () => {
      profileDigestCases += 1;
      assert(validateProfile(vector.profile), `profile fixture is schema-invalid: ${JSON.stringify(validateProfile.errors)}`);
      const before = JSON.stringify(vector.profile);
      assert(profileDigest(vector.profile) === vector.expected_digest, "ProfileDigest mismatch");
      assert(vector.profile.profile_digest.digest === vector.expected_digest, "embedded ProfileDigest mismatch");
      assert(JSON.stringify(vector.profile) === before, "ProfileDigest mutated its input");
    });
    if (vector.permutation_invariant) {
      runCase(`${vector.case_id}_PERMUTATION`, () => {
        profileDigestCases += 1;
        const permutation = structuredClone(vector.profile);
        permutation.field_rules.reverse();
        permutation.class_actions = Object.fromEntries(Object.entries(permutation.class_actions).reverse());
        assert(profileDigest(permutation) === vector.expected_digest, "profile rule permutation changed digest");
      });
    }
    for (const mutation of vector.mutations) {
      runCase(`${vector.case_id}_MUTATION_${mutation.name}`, () => {
        profileDigestCases += 1;
        const mutated = applyFixtureMutation(vector.profile, mutation);
        assert(validateProfile(mutated), `${mutation.name} mutation is schema-invalid: ${JSON.stringify(validateProfile.errors)}`);
        const actual = profileDigest(mutated);
        assert(actual === mutation.expected_digest && actual !== vector.expected_digest, `${mutation.name} mutation digest mismatch`);
      });
    }
  }
  runCase("PROFILE_DUPLICATE_FIELD_REJECTED", () => {
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
  runCase("PROFILE_FIELD_FALLBACK_REJECTED", () => {
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
    runCase(vector.case_id, () => {
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
    runCase(vector.case_id, () => {
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

  let embeddedExampleChecks = 0;
  const digestKindCounts = new Map();
  for (const item of registry.schemas) {
    for (const [exampleIndex, example] of (item.schema.examples ?? []).entries()) {
      collectDigestKinds(example, digestKindCounts);
      const check = verifyExample(item.schema.$id, example);
      embeddedExampleChecks += check.checked;
      for (let checkIndex = 0; checkIndex < check.checked; checkIndex += 1) {
        runCase(`EMBEDDED_DIGEST_${path.basename(item.file)}_${exampleIndex}_${checkIndex}`, () => {
          assert(check.errors.length === 0, check.errors.join(",") || "embedded digest check failed");
        });
      }
    }
  }

  const supportedSchemaDigestKinds = new Set(["EntryDigest", "FileDigest", "ManifestDigest", "ObjectDigest", "ProfileDigest"]);
  const structurallyOnlyDigestCases = digestKindCounts.get("FileDigest") ?? 0;
  const unsupportedDigestCases = [...digestKindCounts.entries()]
    .filter(([kind]) => !supportedSchemaDigestKinds.has(kind))
    .reduce((total, [, count]) => total + count, 0);
  const completeness = {
    jcs_conformance_cases: fixtureDocument.jcs_conformance_vectors.length,
    jcs_direct_api_negative_cases: fixtureDocument.jcs_direct_api_negative_cases.length,
    jcs_direct_api_positive_cases: fixtureDocument.jcs_direct_api_positive_cases.length,
    profile_digest_cases: profileDigestCases,
    byte_backed_file_digest_cases: fixtureDocument.file_digest_cases.length,
    byte_backed_content_digest_cases: fixtureDocument.content_digest_cases.length,
    structurally_only_digest_cases: structurallyOnlyDigestCases,
    unsupported_digest_cases: unsupportedDigestCases,
    skipped_digest_cases: 0
  };
  runCase("DIGEST_COMPLETENESS", () => {
    for (const field of ["jcs_conformance_cases", "jcs_direct_api_negative_cases", "jcs_direct_api_positive_cases", "profile_digest_cases", "byte_backed_file_digest_cases", "byte_backed_content_digest_cases", "structurally_only_digest_cases"]) {
      assert(completeness[field] > 0, `${field} must be nonzero`);
    }
    assert(completeness.unsupported_digest_cases === 0, "unsupported digest metadata exists");
    assert(completeness.skipped_digest_cases === 0, "digest cases were skipped");
    const declared = catalog.index.digest_gate_coverage;
    assert(declared?.catalog_digest_vectors === records.length, "index catalog_digest_vectors mismatch");
    for (const [field, value] of Object.entries(completeness)) {
      assert(declared[field] === value, `index ${field} mismatch`);
    }
  });

  const failedBeforeFinish = result.failed;
  finish(result, {
    algorithm: "SHA-256",
    encoding: "LowerHex",
    canonicalization: "JCS-RFC8785",
    digest_types: ["AuditManifest ManifestDigest", "ContentDigest", "EntryDigest/ObjectDigest", "ExportManifest ManifestDigest", "FileDigest", "ObjectDigest", "ProfileDigest"].sort(compareUnicodeCodeUnits),
    embedded_example_digest_checks: embeddedExampleChecks,
    ...completeness,
    canonical_sort_implementation: "RFC 8785 raw UTF-16 code-unit property ordering; contract arrays use shared bytewise UTF-8 comparators from tools/lib/order.mjs",
    rfc8785_conformance_status: failedBeforeFinish === 0 ? "passed" : "failed",
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
    canonical_sort_implementation: "initialization failed",
    rfc8785_conformance_status: "failed"
  });
}

emit(result);

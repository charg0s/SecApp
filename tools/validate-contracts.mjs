import path from "node:path";
import { fileURLToPath } from "node:url";
import { PATH_PATTERN } from "./lib/constants.mjs";
import { createResult, emit, finish } from "./lib/report.mjs";
import { createSchemaRegistry, formatAjvErrors } from "./lib/schema-registry.mjs";
import { loadVectorCatalog, schemaSubjects } from "./lib/vectors.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = createResult("validate-contracts");

try {
  const registry = createSchemaRegistry(root);
  const catalog = loadVectorCatalog(root);
  result.schema_count = registry.schemas.length;
  result.vector_count = catalog.records.length;
  const counts = { full_contract_instances: 0, schema_positive: 0, schema_negative: 0, application_negative_schema_preconditions: 0 };

  for (const record of catalog.records) {
    const { descriptor, fixture } = record;
    const expected = descriptor.expected_schema_valid;
    if (descriptor.fixture_kind === "FullContractInstance") counts.full_contract_instances += 1;
    if (expected === null) {
      result.skipped_by_fixture_kind[descriptor.fixture_kind] += 1;
      continue;
    }
    let actual;
    let validationErrors = [];
    if (Object.hasOwn(fixture, "path")) {
      actual = fixture.path.length <= 1024 && PATH_PATTERN.test(fixture.path);
      if (!actual) validationErrors = [{ instance_path: "/path", keyword: "pattern", message: "must be a canonical logical path" }];
    } else {
      const subjects = schemaSubjects(root, record);
      if (subjects.length === 0) throw new Error(`${descriptor.vector_id}: no schema instance was materialized`);
      actual = true;
      for (const subject of subjects) {
        const validate = registry.ajv.getSchema(subject.schemaId);
        if (!validate) throw new Error(`${descriptor.vector_id}: unknown schema_id ${subject.schemaId}`);
        if (!validate(subject.instance)) {
          actual = false;
          validationErrors.push(...formatAjvErrors(validate.errors).map((error) => ({ ...error, schema_id: subject.schemaId })));
        }
      }
    }
    if (actual === expected) {
      result.passed += 1;
      if (expected) counts.schema_positive += 1;
      else counts.schema_negative += 1;
      if (expected && descriptor.expected_application_valid === false) counts.application_negative_schema_preconditions += 1;
    } else {
      result.failed += 1;
      result.errors.push({
        error_code: actual ? "UNEXPECTED_SCHEMA_ACCEPTANCE" : "UNEXPECTED_SCHEMA_REJECTION",
        vector_id: descriptor.vector_id,
        schema_id: descriptor.schema_id ?? descriptor.schema_ids?.join(","),
        message: validationErrors.length ? JSON.stringify(validationErrors) : `expected schema_valid=${expected}, got ${actual}`
      });
    }
  }
  if (registry.warnings.length) {
    result.failed += registry.warnings.length;
    for (const warning of registry.warnings) result.errors.push({ error_code: "AJV_STRICT_WARNING", message: warning });
  }
  finish(result, { counts, index_declared_counts: catalog.index.counts });
} catch (error) {
  result.failed += 1;
  result.errors.push({ error_code: "CONTRACT_GATE_INITIALIZATION_FAILED", message: error.message });
  finish(result);
}

emit(result);

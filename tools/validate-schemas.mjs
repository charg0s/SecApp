import path from "node:path";
import { fileURLToPath } from "node:url";
import { AJV_OPTIONS } from "./lib/constants.mjs";
import { createResult, emit, finish } from "./lib/report.mjs";
import { createSchemaRegistry, formatAjvErrors, validateSchemaIdentity } from "./lib/schema-registry.mjs";
import { validateSupplyChain } from "./lib/supply-chain.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = createResult("validate-schemas");

function runSchemaGateSelfTests(registry) {
  const cases = [];
  for (const [name, format, invalid] of [
    ["invalid-uuid", "uuid", "not-a-uuid"],
    ["invalid-date-time", "date-time", "2026-13-99T25:61:61Z"],
    ["invalid-uri", "uri", "http://["]
  ]) {
    const validate = registry.ajv.compile({ type: "string", format });
    if (validate(invalid)) throw new Error(`${name} schema-gate self-test was accepted`);
    cases.push(name);
  }
  for (const [name, keyword] of [["unknown-ordinary-keyword", "ordinaryUnknownKeyword"], ["unknown-x-keyword", "x-unknown-jcs-test"]]) {
    try {
      registry.ajv.compile({ type: "object", [keyword]: true });
      throw new Error(`${name} schema-gate self-test was accepted`);
    } catch (error) {
      if (!String(error.message).includes(`unknown keyword: \"${keyword}\"`)) throw error;
    }
    cases.push(name);
  }
  try {
    validateSchemaIdentity("synthetic.schema.json", {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      $id: "https://schemas.secapp.dev/v2/synthetic.schema.json",
      properties: { schema_version: { const: "1.0.0" } }
    });
    throw new Error("unknown-major-namespace schema-gate self-test was accepted");
  } catch (error) {
    if (!String(error.message).includes("invalid immutable $id")) throw error;
  }
  cases.push("unknown-major-namespace");
  return cases;
}

try {
  const registry = createSchemaRegistry(root);
  const supplyChain = validateSupplyChain(root);
  const gateSelfTests = runSchemaGateSelfTests(registry);
  result.schema_count = registry.schemas.length;
  result.vector_count = gateSelfTests.length;
  const schemaResults = [];
  for (const item of registry.schemas) {
    const entry = {
      schema_id: item.schema.$id,
      meta_validation: "passed",
      compile: "passed",
      example_count: Array.isArray(item.schema.examples) ? item.schema.examples.length : 0,
      examples: "passed"
    };
    let failed = false;
    if (!registry.ajv.validateSchema(item.schema)) {
      failed = true;
      entry.meta_validation = "failed";
      result.errors.push({
        error_code: "SCHEMA_META_VALIDATION_FAILED",
        schema_id: item.schema.$id,
        message: JSON.stringify(formatAjvErrors(registry.ajv.errors))
      });
    }
    let validate;
    try {
      validate = registry.ajv.getSchema(item.schema.$id);
      if (typeof validate !== "function") throw new Error("compiled validator was not registered");
    } catch (error) {
      failed = true;
      entry.compile = "failed";
      result.errors.push({ error_code: "SCHEMA_COMPILE_FAILED", schema_id: item.schema.$id, message: error.message });
    }
    if (validate) {
      for (const [index, example] of (item.schema.examples ?? []).entries()) {
        if (!validate(example)) {
          failed = true;
          entry.examples = "failed";
          result.errors.push({
            error_code: "SCHEMA_EXAMPLE_REJECTED",
            schema_id: item.schema.$id,
            example_index: index,
            message: JSON.stringify(formatAjvErrors(validate.errors))
          });
        }
      }
    }
    if (failed) result.failed += 1;
    else result.passed += 1;
    schemaResults.push(entry);
  }
  if (registry.warnings.length) {
    result.failed += registry.warnings.length;
    for (const warning of registry.warnings) result.errors.push({ error_code: "AJV_STRICT_WARNING", message: warning });
  }
  result.passed += gateSelfTests.length;
  finish(result, {
    ajv_options: AJV_OPTIONS,
    remote_schema_loading: "disabled",
    formats: ["date-time", "uri", "uuid"],
    custom_annotation_keywords: registry.annotations,
    schema_reference_count: registry.referenceCount,
    schema_gate_negative_cases: gateSelfTests,
    supply_chain: supplyChain,
    schema_results: schemaResults
  });
} catch (error) {
  result.failed += 1;
  result.errors.push({ error_code: "SCHEMA_GATE_INITIALIZATION_FAILED", message: error.message });
  finish(result);
}

emit(result);

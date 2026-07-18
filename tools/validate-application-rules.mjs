import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkedMultiply, evaluateApplicationRecord, REGISTERED_RULES } from "./lib/application-rules.mjs";
import { createResult, emit, finish } from "./lib/report.mjs";
import { createSchemaRegistry, formatAjvErrors } from "./lib/schema-registry.mjs";
import { isXobjRecord, materializeGraph, materializeXobjRecord } from "./lib/xobj-graph.mjs";
import { evaluateXobjRule, evaluateXobjThrough, XOBJ_RULE_IDS, XOBJ_RULE_IMPLEMENTATIONS, XOBJ_RULE_SPECS } from "./lib/xobj-rules.mjs";
import { loadVectorCatalog, schemaSubjects } from "./lib/vectors.mjs";
import { compareUnicodeCodeUnits } from "./lib/order.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = createResult("validate-application-rules");

function sameArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function completenessFailures({ registered, executable, covered, positiveByRule, negativeByRule, executedVectorIds, vectorIds, skipped }) {
  const failures = [];
  for (const rule of registered) {
    if (!executable.includes(rule)) failures.push({ error_code: "XOBJ_RULE_IMPLEMENTATION_MISSING", rule_id: rule });
    if ((positiveByRule.get(rule) ?? 0) === 0) failures.push({ error_code: "XOBJ_POSITIVE_VECTOR_MISSING", rule_id: rule });
    if ((negativeByRule.get(rule) ?? 0) === 0) failures.push({ error_code: "XOBJ_NEGATIVE_VECTOR_MISSING", rule_id: rule });
    if (!covered.includes(rule)) failures.push({ error_code: "XOBJ_RULE_UNCOVERED", rule_id: rule });
  }
  for (const rule of executable) if (!registered.includes(rule)) failures.push({ error_code: "UNKNOWN_APPLICATION_RULE", rule_id: rule });
  for (const vectorId of vectorIds) if (!executedVectorIds.has(vectorId)) failures.push({ error_code: "XOBJ_VECTOR_NOT_EXECUTED", vector_id: vectorId });
  if (skipped !== 0) failures.push({ error_code: "XOBJ_VECTOR_SKIPPED", message: String(skipped) });
  if (!sameArray(registered, executable) || !sameArray(registered, covered)) failures.push({ error_code: "XOBJ_RULE_COUNT_MISMATCH" });
  return failures;
}

function expectError(name, actual, expected) {
  if (actual.length !== 1 || actual[0] !== expected) throw new Error(`${name}: expected ${expected}; got ${actual.join(",") || "no error"}`);
}

function runXobjSelfTests(baseGraph) {
  const alternateRun = "00000000-0000-4000-8000-000000000002";
  const alternateDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const cases = [
    { name: "valid-complete-graph", rule: "XOBJ-018", mutations: [], expected: undefined },
    { name: "missing-execution", rule: "XOBJ-003", mutations: [{ op: "remove", path: "/collections/collector_executions/0" }], expected: "OBSERVATION_EXECUTION_MISMATCH" },
    { name: "duplicate-observation-id", rule: "XOBJ-002", mutations: [{ op: "copy", from: "/collections/observations/0", path: "/collections/observations/-" }], expected: "EXECUTION_PASS_MISMATCH" },
    { name: "cross-run-finding", rule: "XOBJ-001", mutations: [{ op: "replace", path: "/collections/findings/0/run_id", value: alternateRun }], expected: "RUN_ID_MISMATCH" },
    { name: "missing-manifest-member", rule: "XOBJ-008", mutations: [{ op: "remove", path: "/collections/audit_manifests/0/entries/7" }], expected: "MANIFEST_MEMBERSHIP_MISMATCH" },
    { name: "action-log-broken-chain", rule: "XOBJ-012", mutations: [
      { op: "replace", path: "/collections/action_logs/0/entries/0/sequence_number", value: 1 },
      { op: "replace", path: "/collections/action_logs/0/entries/0/previous_entry_digest", value: alternateDigest }
    ], expected: "ACTION_LOG_CHAIN_INVALID" },
    { name: "replayed-reboot-nonce", rule: "XOBJ-013", mutations: [{ op: "copy", from: "/collections/reboot_continuation_states/0/nonce", path: "/replay_history/reboot_nonces/-" }], expected: "REBOOT_STATE_INVALID" },
    { name: "cyclic-rule-definition", rule: "XOBJ-014", mutations: [
      { op: "replace", path: "/collections/rule_definitions/0/expression/predicates", value: [
        { predicate_id: "p:a", kind: "All", child_ids: ["p:b"] }, { predicate_id: "p:b", kind: "All", child_ids: ["p:a"] }
      ] },
      { op: "replace", path: "/collections/rule_definitions/0/expression/root_predicate_id", value: "p:a" }
    ], expected: "RULE_GRAPH_INVALID" },
    { name: "invalid-consent-binding", rule: "XOBJ-011", mutations: [{ op: "replace", path: "/collections/consent_receipts/0/collector_binding/collector_id", value: "collector:secapp:other-network" }], expected: "CONSENT_SCOPE_INVALID" }
  ];
  for (const item of cases) {
    const graph = materializeGraph(baseGraph, item.mutations);
    const actual = evaluateXobjThrough(item.rule, graph);
    if (item.expected === undefined) {
      if (actual.length) throw new Error(`${item.name}: expected no error; got ${actual.join(",")}`);
    } else expectError(item.name, actual, item.expected);
  }

  const frozen = materializeGraph(baseGraph);
  if (!Object.isFrozen(frozen) || !Object.isFrozen(frozen.collections) || !Object.isFrozen(frozen.collections.audit_runs[0])) {
    throw new Error("materialized graph is not deeply immutable");
  }
  expectError("unknown-rule-self-test", evaluateXobjRule("XOBJ-999", frozen), "UNKNOWN_APPLICATION_RULE");
  const missingImplementation = { ...XOBJ_RULE_IMPLEMENTATIONS };
  delete missingImplementation["XOBJ-018"];
  expectError("missing-implementation-self-test", evaluateXobjRule("XOBJ-018", frozen, missingImplementation), "XOBJ_RULE_IMPLEMENTATION_MISSING");
  const missingInput = materializeGraph(baseGraph, [{ op: "remove", path: "/loaded_digests/collector_definitions" }]);
  expectError("missing-input-self-test", evaluateXobjRule("XOBJ-006", missingInput), "XOBJ_GRAPH_INPUT_MISSING");
  try {
    materializeGraph(baseGraph, [{ op: "add", path: "/collections/unknown_kind", value: [] }]);
    throw new Error("unknown object kind was accepted");
  } catch (error) {
    if (error.message !== "XOBJ_GRAPH_UNKNOWN_OBJECT_KIND") throw error;
  }

  const all = [...XOBJ_RULE_IDS];
  const coverage = new Map(all.map((rule) => [rule, 1]));
  const vectorIds = ["self-test-vector"];
  const common = { registered: all, covered: all, positiveByRule: coverage, negativeByRule: coverage, executedVectorIds: new Set(vectorIds), vectorIds, skipped: 0 };
  if (!completenessFailures({ ...common, executable: all.slice(1) }).some((item) => item.error_code === "XOBJ_RULE_IMPLEMENTATION_MISSING")) throw new Error("missing implementation completeness self-test failed");
  if (!completenessFailures({ ...common, executable: [...all, "XOBJ-999"] }).some((item) => item.error_code === "UNKNOWN_APPLICATION_RULE")) throw new Error("unknown rule completeness self-test failed");
  if (!completenessFailures({ ...common, executable: all, skipped: 1 }).some((item) => item.error_code === "XOBJ_VECTOR_SKIPPED")) throw new Error("skipped vector completeness self-test failed");
  return cases.map((item) => item.name);
}

try {
  const registry = createSchemaRegistry(root);
  const catalog = loadVectorCatalog(root);
  result.schema_count = registry.schemas.length;
  result.vector_count = catalog.records.length;
  const counts = { application_positive: 0, application_negative: 0, schema_invalid_stopped: 0 };
  const registeredXobj = REGISTERED_RULES.filter((rule) => rule.startsWith("XOBJ-")).sort(compareUnicodeCodeUnits);
  const executableXobj = Object.keys(XOBJ_RULE_IMPLEMENTATIONS).sort(compareUnicodeCodeUnits);
  const xobjRecords = catalog.records.filter(isXobjRecord);
  const executedXobjVectorIds = new Set();
  const successfulXobjVectorIds = new Set();
  const positiveByRule = new Map();
  const negativeByRule = new Map();
  let skippedXobjVectors = 0;

  for (const record of catalog.records) {
    const { descriptor, fixture } = record;
    const expected = descriptor.expected_application_valid;
    const xobj = isXobjRecord(record);
    if (expected === null) {
      if (xobj) skippedXobjVectors += 1;
      result.skipped_by_fixture_kind[descriptor.fixture_kind] += 1;
      continue;
    }
    if (descriptor.expected_schema_valid === false) {
      if (xobj) skippedXobjVectors += 1;
      counts.schema_invalid_stopped += 1;
      result.skipped_by_fixture_kind[descriptor.fixture_kind] += 1;
      continue;
    }
    if (descriptor.expected_schema_valid === true) {
      const schemaFailures = [];
      for (const subject of schemaSubjects(root, record)) {
        const validate = registry.ajv.getSchema(subject.schemaId);
        if (!validate || !validate(subject.instance)) schemaFailures.push(...formatAjvErrors(validate?.errors));
      }
      if (schemaFailures.length) {
        if (xobj) skippedXobjVectors += 1;
        result.failed += 1;
        result.errors.push({ error_code: "APPLICATION_PRECONDITION_SCHEMA_INVALID", vector_id: descriptor.vector_id, message: JSON.stringify(schemaFailures) });
        continue;
      }
    }
    if (xobj) executedXobjVectorIds.add(descriptor.vector_id);
    const actualErrors = evaluateApplicationRecord(record);
    const additional = new Set(fixture.expected_additional_error_codes ?? []);
    const matches = expected
      ? actualErrors.length === 0
      : actualErrors.length >= 1 && actualErrors[0] === fixture.expected_error_code && actualErrors.slice(1).every((code) => additional.has(code));
    if (matches) {
      result.passed += 1;
      if (expected) counts.application_positive += 1;
      else counts.application_negative += 1;
      if (xobj) successfulXobjVectorIds.add(descriptor.vector_id);
    } else {
      result.failed += 1;
      result.errors.push({
        error_code: "APPLICATION_RESULT_MISMATCH",
        vector_id: descriptor.vector_id,
        message: `expected ${expected ? "no error" : fixture.expected_error_code}; got ${actualErrors.join(",") || "no error"}`
      });
    }
  }

  for (const record of xobjRecords) {
    const rule = record.fixture.rule_id;
    const target = record.descriptor.expected_application_valid ? positiveByRule : negativeByRule;
    target.set(rule, (target.get(rule) ?? 0) + 1);
  }
  const coveredXobj = registeredXobj.filter((rule) => (positiveByRule.get(rule) ?? 0) > 0 && (negativeByRule.get(rule) ?? 0) > 0
    && xobjRecords.filter((record) => record.fixture.rule_id === rule).every((record) => successfulXobjVectorIds.has(record.descriptor.vector_id)));
  const uncoveredXobj = registeredXobj.filter((rule) => !coveredXobj.includes(rule));
  const coverageProblems = completenessFailures({
    registered: registeredXobj,
    executable: executableXobj,
    covered: coveredXobj,
    positiveByRule,
    negativeByRule,
    executedVectorIds: executedXobjVectorIds,
    vectorIds: xobjRecords.map((record) => record.descriptor.vector_id),
    skipped: skippedXobjVectors
  });
  for (const failure of coverageProblems) {
    result.failed += 1;
    result.errors.push({ ...failure, message: failure.message ?? failure.rule_id ?? "XOBJ completeness failure" });
  }

  try {
    checkedMultiply(Number.MAX_SAFE_INTEGER, 2);
    throw new Error("checked multiplication accepted overflow");
  } catch (error) {
    if (error.message !== "LIMIT_INTEGER_OVERFLOW") throw error;
  }
  if (checkedMultiply(Number.MAX_SAFE_INTEGER, 1) !== Number.MAX_SAFE_INTEGER) throw new Error("checked multiplication safe-integer boundary self-test failed");
  if (checkedMultiply(1024, 1024) !== 1048576) throw new Error("checked multiplication ordinary-value self-test failed");
  const baseGraph = xobjRecords[0]?.document.base_graph;
  if (!baseGraph) throw new Error("XOBJ_GRAPH_INPUT_MISSING");
  const counterexamples = runXobjSelfTests(baseGraph);
  const xobjFailures = result.errors.filter((error) => error.vector_id?.startsWith("XOBJ_") || error.rule_id?.startsWith("XOBJ-") || error.error_code.startsWith("XOBJ_"));
  finish(result, {
    counts,
    rule_evaluation_order: ["Parse", "Schema", "ObjectLocalApplication", "GraphMaterialization", "XOBJCrossObject", "DigestIntegrity"],
    registered_rules: REGISTERED_RULES,
    executable_vector_rule_families: ["XOBJ", "PASS", "CONSENT", "ACTION", "MANIFEST", "LIMIT", "PATH"],
    registered_xobj_rules: registeredXobj,
    executable_xobj_rules: executableXobj,
    covered_xobj_rules: coveredXobj,
    uncovered_xobj_rules: uncoveredXobj,
    positive_xobj_vectors: xobjRecords.filter((record) => record.descriptor.expected_application_valid === true).length,
    negative_xobj_vectors: xobjRecords.filter((record) => record.descriptor.expected_application_valid === false).length,
    skipped_xobj_vectors: skippedXobjVectors,
    xobj_failures: xobjFailures,
    xobj_primary_error_codes: Object.fromEntries(XOBJ_RULE_SPECS.map((spec) => [spec.rule_id, spec.error_code])),
    xobj_missing_input_error_code: "XOBJ_GRAPH_INPUT_MISSING",
    auditor_counterexamples: counterexamples,
    checked_multiply_self_tests: ["MAX_SAFE_INTEGER * 1 accepted exactly", "MAX_SAFE_INTEGER * 2 rejected with LIMIT_INTEGER_OVERFLOW", "1024 * 1024 accepted exactly"]
  });
} catch (error) {
  result.failed += 1;
  result.errors.push({ error_code: "APPLICATION_GATE_INITIALIZATION_FAILED", message: error.message });
  finish(result);
}

emit(result);

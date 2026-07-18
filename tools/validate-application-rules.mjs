import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkedMultiply, evaluateApplicationRecord, REGISTERED_RULES } from "./lib/application-rules.mjs";
import { createResult, emit, finish } from "./lib/report.mjs";
import { createSchemaRegistry, formatAjvErrors } from "./lib/schema-registry.mjs";
import { isXobjRecord, materializeGraph, materializeXobjRecord } from "./lib/xobj-graph.mjs";
import {
  evaluateXobjRule,
  evaluateXobjThrough,
  validateXobj011,
  XOBJ011_CONSENT_TYPE_MODELS,
  XOBJ011_CONSENT_TYPES,
  XOBJ011_CONSENT_VARIANTS,
  XOBJ_RULE_IDS,
  XOBJ_RULE_IMPLEMENTATIONS,
  XOBJ_RULE_SPECS
} from "./lib/xobj-rules.mjs";
import { loadVectorCatalog, schemaSubjects } from "./lib/vectors.mjs";
import { compareUnicodeCodeUnits } from "./lib/order.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = createResult("validate-application-rules");

const REQUIRED_CONSENT_POSITIVE_VECTOR_IDS = Object.freeze({
  CollectorExecution: Object.freeze([
    "XOBJ_011_GRAPH_VALID",
    "XOBJ_011_DEFENDER_OFFLINE_COLLECTOR_VARIANT_VALID"
  ]),
  Export: Object.freeze(["XOBJ_011_EXPORT_VARIANT_VALID"]),
  Remediation: Object.freeze(["XOBJ_011_REMEDIATION_VARIANT_VALID"]),
  Reboot: Object.freeze(["XOBJ_011_REBOOT_VARIANT_VALID"])
});

const REQUIRED_CONSENT_NEGATIVE_VECTOR_IDS = Object.freeze({
  CollectorExecution: Object.freeze([
    "XOBJ_011_CONSENT_BINDING_INVALID",
    "XOBJ_011_CONSENT_EXPIRED_INVALID",
    "XOBJ_011_CONSENT_REVOKED_INVALID",
    "XOBJ_011_CONSENT_REPLAY_INVALID",
    "XOBJ_011_COLLECTOR_EXECUTION_MISSING_INVALID",
    "XOBJ_011_COLLECTOR_OTHER_PASS_INVALID",
    "XOBJ_011_APPROVED_CAPABILITIES_ESCALATION_INVALID",
    "XOBJ_011_APPROVED_PRIVACY_ESCALATION_INVALID"
  ]),
  Export: Object.freeze([
    "XOBJ_011_EXPORT_COLLECTOR_EXECUTION_BINDING_INVALID",
    "XOBJ_011_EXPORT_BINDING_TARGET_MISSING_INVALID",
    "XOBJ_011_EXPORT_REDACTION_PROFILE_DIGEST_MISMATCH_INVALID",
    "XOBJ_011_EXPORT_OTHER_ACTION_INVALID",
    "XOBJ_011_EXPORT_RECEIPT_FOR_REMEDIATION_INVALID",
    "XOBJ_011_REBOOT_RECEIPT_FOR_EXPORT_INVALID",
    "XOBJ_011_RECEIPT_REUSED_BY_SECOND_ACTION_INVALID"
  ]),
  Remediation: Object.freeze([
    "XOBJ_011_REMEDIATION_ACTION_BINDING_MISSING_INVALID",
    "XOBJ_011_REMEDIATION_OTHER_ACTION_INVALID",
    "XOBJ_011_REMEDIATION_TARGET_INVALID",
    "XOBJ_011_EXPORT_RECEIPT_FOR_REMEDIATION_INVALID"
  ]),
  Reboot: Object.freeze([
    "XOBJ_011_REBOOT_STAGE_BINDING_MISSING_INVALID",
    "XOBJ_011_REBOOT_FOREIGN_WORKFLOW_INVALID",
    "XOBJ_011_REBOOT_RECEIPT_FOR_EXPORT_INVALID"
  ])
});

function sameArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function orderedCoverage(required, values) {
  const covered = new Set(values);
  return required.filter((value) => covered.has(value));
}

function copyVectorMap(value) {
  return Object.fromEntries(Object.entries(value).map(([key, ids]) => [key, [...ids]]));
}

function consentVariantCompletenessFailures(state) {
  const failures = [];
  const positiveCoverage = orderedCoverage(state.required, state.required.filter((variant) =>
    (state.positiveVectorIdsByVariant[variant] ?? []).some((id) =>
      state.executedVectorIds.has(id) && state.successfulVectorIds.has(id) && !state.skippedVectorIds.has(id))));
  const negativeCoverage = orderedCoverage(state.required, state.required.filter((variant) =>
    (state.negativeVectorIdsByVariant[variant] ?? []).some((id) =>
      state.executedVectorIds.has(id) && state.successfulVectorIds.has(id) && !state.skippedVectorIds.has(id))));
  const executedCoverage = orderedCoverage(state.required, state.required.filter((variant) =>
    [...(state.positiveVectorIdsByVariant[variant] ?? []), ...(state.negativeVectorIdsByVariant[variant] ?? [])]
      .some((id) => state.executedVectorIds.has(id))));
  for (const variant of state.required) {
    if (!state.executable.includes(variant)) failures.push({ error_code: "CONSENT_VARIANT_IMPLEMENTATION_MISSING", consent_variant: variant });
    if (!positiveCoverage.includes(variant)) failures.push({ error_code: "CONSENT_VARIANT_POSITIVE_VECTOR_MISSING", consent_variant: variant });
    if (!negativeCoverage.includes(variant)) failures.push({ error_code: "CONSENT_VARIANT_NEGATIVE_VECTOR_MISSING", consent_variant: variant });
    if (!executedCoverage.includes(variant)) failures.push({ error_code: "CONSENT_VARIANT_NOT_EXECUTED", consent_variant: variant });
    for (const id of REQUIRED_CONSENT_POSITIVE_VECTOR_IDS[variant]) {
      if (!state.vectorIds.has(id)
        || !(state.positiveVectorIdsByVariant[variant] ?? []).includes(id)
        || !state.executedVectorIds.has(id)
        || !state.successfulVectorIds.has(id)) {
        failures.push({ error_code: "CONSENT_VARIANT_REQUIRED_POSITIVE_MISSING", consent_variant: variant, vector_id: id });
      }
    }
    for (const id of REQUIRED_CONSENT_NEGATIVE_VECTOR_IDS[variant]) {
      if (!state.vectorIds.has(id)
        || !(state.negativeVectorIdsByVariant[variant] ?? []).includes(id)
        || !state.executedVectorIds.has(id)
        || !state.successfulVectorIds.has(id)) {
        failures.push({ error_code: "CONSENT_VARIANT_REQUIRED_NEGATIVE_MISSING", consent_variant: variant, vector_id: id });
      }
    }
  }
  if (!sameArray(state.required, state.executable)
    || !sameArray(state.required, positiveCoverage)
    || !sameArray(state.required, negativeCoverage)) {
    failures.push({ error_code: "CONSENT_VARIANT_SET_MISMATCH" });
  }
  if (!sameArray(XOBJ011_CONSENT_TYPES, state.dispatchedTypes)) failures.push({ error_code: "CONSENT_TYPE_DISPATCH_MISMATCH" });
  for (const vectorId of state.skippedVectorIds) {
    failures.push({ error_code: "CONSENT_VARIANT_VECTOR_SKIPPED", vector_id: vectorId });
  }
  return { failures, positiveCoverage, negativeCoverage, executedCoverage };
}

function runConsentVariantCompletenessSelfTests(state) {
  const names = [];
  for (const variant of ["Export", "Remediation", "Reboot"]) {
    const mutated = {
      ...state,
      positiveVectorIdsByVariant: copyVectorMap(state.positiveVectorIdsByVariant),
      vectorIds: new Set(state.vectorIds),
      executedVectorIds: new Set(state.executedVectorIds),
      successfulVectorIds: new Set(state.successfulVectorIds),
      skippedVectorIds: new Set(state.skippedVectorIds)
    };
    for (const id of REQUIRED_CONSENT_POSITIVE_VECTOR_IDS[variant]) {
      mutated.vectorIds.delete(id);
      mutated.executedVectorIds.delete(id);
      mutated.successfulVectorIds.delete(id);
    }
    mutated.positiveVectorIdsByVariant[variant] = [];
    if (!consentVariantCompletenessFailures(mutated).failures.some((item) => item.error_code === "CONSENT_VARIANT_POSITIVE_VECTOR_MISSING")) {
      throw new Error(`missing ${variant} positive completeness self-test failed`);
    }
    names.push(`missing-${variant.toLowerCase()}-positive`);
  }
  const missingDispatch = { ...state, executable: state.executable.filter((item) => item !== "Export") };
  if (!consentVariantCompletenessFailures(missingDispatch).failures.some((item) => item.error_code === "CONSENT_VARIANT_IMPLEMENTATION_MISSING")) {
    throw new Error("missing consent dispatch completeness self-test failed");
  }
  names.push("missing-export-dispatch");
  const skippedId = REQUIRED_CONSENT_POSITIVE_VECTOR_IDS.Export[0];
  const skipped = { ...state, skippedVectorIds: new Set([...state.skippedVectorIds, skippedId]) };
  if (!consentVariantCompletenessFailures(skipped).failures.some((item) => item.error_code === "CONSENT_VARIANT_VECTOR_SKIPPED")) {
    throw new Error("skipped consent variant completeness self-test failed");
  }
  names.push("skipped-consent-variant");
  const substitutionId = "XOBJ_011_EXPORT_RECEIPT_FOR_REMEDIATION_INVALID";
  const substitutionAccepted = { ...state, successfulVectorIds: new Set(state.successfulVectorIds) };
  substitutionAccepted.successfulVectorIds.delete(substitutionId);
  if (!consentVariantCompletenessFailures(substitutionAccepted).failures.some((item) =>
    item.error_code === "CONSENT_VARIANT_REQUIRED_NEGATIVE_MISSING" && item.vector_id === substitutionId)) {
    throw new Error("accepted consent substitution completeness self-test failed");
  }
  names.push("accepted-substitution");
  return names;
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

function runXobjSelfTests(baseGraph, xobjRecords) {
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

  const recordById = new Map(xobjRecords.map((record) => [record.descriptor.vector_id, record]));
  for (const vectorId of [
    "XOBJ_011_GRAPH_VALID",
    "XOBJ_011_EXPORT_VARIANT_VALID",
    "XOBJ_011_REMEDIATION_VARIANT_VALID",
    "XOBJ_011_REBOOT_VARIANT_VALID",
    "XOBJ_011_DEFENDER_OFFLINE_COLLECTOR_VARIANT_VALID"
  ]) {
    const record = recordById.get(vectorId);
    if (!record) throw new Error(`${vectorId}: consent positive self-test input is missing`);
    const actual = evaluateXobjThrough("XOBJ-011", materializeXobjRecord(record));
    if (actual.length) throw new Error(`${vectorId}: discriminator positive returned ${actual.join(",")}`);
    cases.push({ name: `consent-positive-${vectorId.toLowerCase()}` });
  }
  for (const vectorId of [
    "XOBJ_011_EXPORT_RECEIPT_FOR_REMEDIATION_INVALID",
    "XOBJ_011_REBOOT_RECEIPT_FOR_EXPORT_INVALID"
  ]) {
    const record = recordById.get(vectorId);
    if (!record) throw new Error(`${vectorId}: consent substitution self-test input is missing`);
    expectError(vectorId, evaluateXobjThrough("XOBJ-011", materializeXobjRecord(record)), "CONSENT_SCOPE_INVALID");
    cases.push({ name: `consent-substitution-${vectorId.toLowerCase()}` });
  }
  const exportGraph = materializeXobjRecord(recordById.get("XOBJ_011_EXPORT_VARIANT_VALID"));
  const exportReceipt = exportGraph.collections.consent_receipts.find((item) => item.consent_type === "Export");
  if (!exportReceipt || exportReceipt.collector_binding !== undefined || exportReceipt.exact_scope.pass_id !== undefined) {
    throw new Error("universal collector-binding regression fixture is not isolated");
  }
  cases.push({ name: "universal-collector-binding-regression" });
  const missingExportDispatch = { ...XOBJ011_CONSENT_TYPE_MODELS };
  delete missingExportDispatch.Export;
  expectError("missing-export-dispatch", validateXobj011(exportGraph, missingExportDispatch), "CONSENT_SCOPE_INVALID");
  cases.push({ name: "missing-export-dispatch" });
  const exportIndex = exportGraph.collections.consent_receipts.findIndex((item) => item.consent_type === "Export");
  const unknownVariant = materializeGraph(exportGraph, [{
    op: "replace",
    path: `/collections/consent_receipts/${exportIndex}/consent_type`,
    value: "UnknownConsentVariant"
  }]);
  expectError("unknown-consent-variant", validateXobj011(unknownVariant), "CONSENT_SCOPE_INVALID");
  cases.push({ name: "unknown-consent-variant" });

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
  const consentSchemaTypes = [...(registry.ajv.getSchema("https://schemas.secapp.dev/v1/consent-receipt.schema.json")
    ?.schema?.properties?.consent_type?.enum ?? [])].sort(compareUnicodeCodeUnits);
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
  const skippedConsentVariantVectorIds = new Set();

  for (const record of catalog.records) {
    const { descriptor, fixture } = record;
    const expected = descriptor.expected_application_valid;
    const xobj = isXobjRecord(record);
    if (expected === null) {
      if (xobj) {
        skippedXobjVectors += 1;
        if (fixture.rule_id === "XOBJ-011") skippedConsentVariantVectorIds.add(descriptor.vector_id);
      }
      result.skipped_by_fixture_kind[descriptor.fixture_kind] += 1;
      continue;
    }
    if (descriptor.expected_schema_valid === false) {
      if (xobj) {
        skippedXobjVectors += 1;
        if (fixture.rule_id === "XOBJ-011") skippedConsentVariantVectorIds.add(descriptor.vector_id);
      }
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
        if (xobj) {
          skippedXobjVectors += 1;
          if (fixture.rule_id === "XOBJ-011") skippedConsentVariantVectorIds.add(descriptor.vector_id);
        }
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

  const consentRecords = xobjRecords.filter((record) => record.fixture.rule_id === "XOBJ-011");
  const positiveVectorIdsByVariant = Object.fromEntries(XOBJ011_CONSENT_VARIANTS.map((variant) => [variant, []]));
  const negativeVectorIdsByVariant = Object.fromEntries(XOBJ011_CONSENT_VARIANTS.map((variant) => [variant, []]));
  const consentMetadataFailures = [];
  for (const record of consentRecords) {
    const variants = record.fixture.consent_variants;
    if (!Array.isArray(variants) || variants.length === 0 || variants.some((variant) => !XOBJ011_CONSENT_VARIANTS.includes(variant))) {
      consentMetadataFailures.push({
        error_code: "CONSENT_VARIANT_VECTOR_METADATA_INVALID",
        vector_id: record.descriptor.vector_id
      });
      continue;
    }
    const target = record.descriptor.expected_application_valid ? positiveVectorIdsByVariant : negativeVectorIdsByVariant;
    for (const variant of variants) target[variant].push(record.descriptor.vector_id);
  }
  for (const ids of [...Object.values(positiveVectorIdsByVariant), ...Object.values(negativeVectorIdsByVariant)]) {
    ids.sort(compareUnicodeCodeUnits);
  }
  const executableConsentVariants = XOBJ011_CONSENT_VARIANTS.filter((variant) =>
    Object.values(XOBJ011_CONSENT_TYPE_MODELS).includes(variant));
  const consentState = {
    required: [...XOBJ011_CONSENT_VARIANTS],
    executable: executableConsentVariants,
    dispatchedTypes: Object.keys(XOBJ011_CONSENT_TYPE_MODELS).sort(compareUnicodeCodeUnits),
    positiveVectorIdsByVariant,
    negativeVectorIdsByVariant,
    vectorIds: new Set(consentRecords.map((record) => record.descriptor.vector_id)),
    executedVectorIds: executedXobjVectorIds,
    successfulVectorIds: successfulXobjVectorIds,
    skippedVectorIds: skippedConsentVariantVectorIds
  };
  const consentCompleteness = consentVariantCompletenessFailures(consentState);
  const declaredConsentCoverage = catalog.index.consent_variant_coverage;
  const expectedDeclaration = {
    required_consent_variants: [...XOBJ011_CONSENT_VARIANTS],
    required_consent_types: [...XOBJ011_CONSENT_TYPES],
    required_positive_vector_ids_by_variant: REQUIRED_CONSENT_POSITIVE_VECTOR_IDS,
    required_negative_vector_ids_by_variant: REQUIRED_CONSENT_NEGATIVE_VECTOR_IDS
  };
  if (JSON.stringify(declaredConsentCoverage) !== JSON.stringify(expectedDeclaration)) {
    consentMetadataFailures.push({ error_code: "CONSENT_VARIANT_INDEX_MISMATCH" });
  }
  if (!sameArray(consentSchemaTypes, XOBJ011_CONSENT_TYPES)) {
    consentMetadataFailures.push({ error_code: "CONSENT_TYPE_SCHEMA_DISPATCH_MISMATCH" });
  }
  for (const failure of [...consentMetadataFailures, ...consentCompleteness.failures]) {
    result.failed += 1;
    result.errors.push({ ...failure, message: failure.consent_variant ?? failure.vector_id ?? "consent variant completeness failure" });
  }
  const consentCompletenessSelfTests = runConsentVariantCompletenessSelfTests(consentState);

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
  const counterexamples = runXobjSelfTests(baseGraph, xobjRecords);
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
    required_consent_variants: [...XOBJ011_CONSENT_VARIANTS],
    executable_consent_variants: executableConsentVariants,
    executed_consent_variants: consentCompleteness.executedCoverage,
    positively_covered_consent_variants: consentCompleteness.positiveCoverage,
    negatively_covered_consent_variants: consentCompleteness.negativeCoverage,
    uncovered_consent_variants: XOBJ011_CONSENT_VARIANTS.filter((variant) =>
      !consentCompleteness.positiveCoverage.includes(variant)
        || !consentCompleteness.negativeCoverage.includes(variant)
        || !executableConsentVariants.includes(variant)),
    skipped_consent_variant_vectors: [...skippedConsentVariantVectorIds].sort(compareUnicodeCodeUnits),
    required_consent_types: [...XOBJ011_CONSENT_TYPES],
    schema_consent_types: consentSchemaTypes,
    dispatched_consent_types: Object.keys(XOBJ011_CONSENT_TYPE_MODELS).sort(compareUnicodeCodeUnits),
    consent_type_binding_models: XOBJ011_CONSENT_TYPE_MODELS,
    required_positive_consent_vector_ids_by_variant: REQUIRED_CONSENT_POSITIVE_VECTOR_IDS,
    required_negative_consent_vector_ids_by_variant: REQUIRED_CONSENT_NEGATIVE_VECTOR_IDS,
    consent_variant_completeness_self_tests: consentCompletenessSelfTests,
    checked_multiply_self_tests: ["MAX_SAFE_INTEGER * 1 accepted exactly", "MAX_SAFE_INTEGER * 2 rejected with LIMIT_INTEGER_OVERFLOW", "1024 * 1024 accepted exactly"]
  });
} catch (error) {
  result.failed += 1;
  result.errors.push({ error_code: "APPLICATION_GATE_INITIALIZATION_FAILED", message: error.message });
  finish(result);
}

emit(result);

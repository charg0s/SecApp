import { digestWithExclusion, jcs } from "./jcs.mjs";
import { compareUnicodeCodeUnits } from "./order.mjs";

export const XOBJ_RULE_SPECS = Object.freeze([
  ["XOBJ-001", "RUN_ID_MISMATCH", ["collections.audit_runs"]],
  ["XOBJ-002", "EXECUTION_PASS_MISMATCH", ["collections.audit_passes", "collections.collector_executions"]],
  ["XOBJ-003", "OBSERVATION_EXECUTION_MISMATCH", ["collections.collector_executions", "collections.observations"]],
  ["XOBJ-004", "EVIDENCE_OBSERVATION_MISMATCH", ["collections.observations", "collections.evidence_references"]],
  ["XOBJ-005", "FINDING_REFERENCE_MISMATCH", ["collections.findings", "collections.observations", "collections.evidence_references", "collections.collector_executions"]],
  ["XOBJ-006", "COLLECTOR_DEFINITION_MISMATCH", ["collections.collector_definitions", "collections.collector_executions", "loaded_digests.collector_definitions"]],
  ["XOBJ-007", "RULE_DEFINITION_MISMATCH", ["collections.rule_definitions", "collections.findings", "loaded_digests.rule_definitions"]],
  ["XOBJ-008", "MANIFEST_MEMBERSHIP_MISMATCH", ["collections.audit_manifests", "collections.audit_runs", "collections.action_logs", "manifest_membership_index"]],
  ["XOBJ-009", "EXPORT_SOURCE_MISMATCH", ["collections.export_manifests", "collections.audit_manifests", "collections.redaction_profiles", "loaded_digests.redaction_profiles", "loaded_digests.composition_policies", "loaded_digests.audit_manifests"]],
  ["XOBJ-010", "TIMESTAMP_ORDER_INVALID", ["validation_context.validation_time", "collections.audit_runs"]],
  ["XOBJ-011", "CONSENT_SCOPE_INVALID", [
    "validation_context.validation_time", "collections.audit_runs", "collections.audit_passes",
    "collections.collector_definitions", "collections.collector_executions", "collections.observations",
    "collections.findings", "collections.consent_receipts", "collections.action_logs",
    "collections.export_manifests", "collections.redaction_profiles",
    "loaded_digests.collector_definitions", "loaded_digests.redaction_profiles",
    "replay_history.consent_nonces"
  ]],
  ["XOBJ-012", "ACTION_LOG_CHAIN_INVALID", ["collections.action_logs"]],
  ["XOBJ-013", "REBOOT_STATE_INVALID", ["collections.reboot_continuation_states", "validation_context.verified_reboot_state_ids", "replay_history.reboot_nonces", "replay_history.minimum_reboot_sequence"]],
  ["XOBJ-014", "RULE_GRAPH_INVALID", ["collections.rule_definitions"]],
  ["XOBJ-015", "REDACTION_POLICY_INVALID", ["collections.redaction_profiles", "redaction_field_registry"]],
  ["XOBJ-016", "PATH_SET_INVALID", ["collections.audit_manifests", "collections.export_manifests", "manifest_membership_index"]],
  ["XOBJ-017", "SIZE_LIMIT_EXCEEDED", ["collections", "size_measurements"]],
  ["XOBJ-018", "TRANSITIVE_CAPABILITY_MISMATCH", ["collections.collector_definitions", "capability_graph"]]
].map(([rule_id, error_code, required_graph_input]) => Object.freeze({ rule_id, error_code, required_graph_input })));

export const XOBJ_RULE_IDS = Object.freeze(XOBJ_RULE_SPECS.map((spec) => spec.rule_id));
const SPEC_BY_ID = new Map(XOBJ_RULE_SPECS.map((spec) => [spec.rule_id, spec]));

function hasPath(value, dottedPath) {
  let current = value;
  for (const token of dottedPath.split(".")) {
    if (current === null || typeof current !== "object" || !Object.hasOwn(current, token)) return false;
    current = current[token];
  }
  return true;
}

function sorted(items, field) {
  return [...items].sort((left, right) => compareUnicodeCodeUnits(String(left?.[field] ?? ""), String(right?.[field] ?? "")));
}

function duplicates(values) {
  const seen = new Set();
  for (const value of values) {
    if (seen.has(value)) return true;
    seen.add(value);
  }
  return false;
}

function exactlyOnce(values, expected) {
  return values.filter((value) => value === expected).length === 1;
}

function oneBy(items, field, value) {
  const matches = items.filter((item) => item[field] === value);
  return matches.length === 1 ? matches[0] : undefined;
}

function sameSet(left, right) {
  const sortedLeft = [...left].sort(compareUnicodeCodeUnits);
  const sortedRight = [...right].sort(compareUnicodeCodeUnits);
  return sortedLeft.length === sortedRight.length && sortedLeft.every((value, index) => value === sortedRight[index]);
}

function isSubset(subset, superset) {
  const values = new Set(superset);
  return subset.every((value) => values.has(value));
}

function asTime(value) {
  const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) ? parsed : undefined;
}

function validInterval(start, end) {
  const left = asTime(start);
  const right = asTime(end);
  return left !== undefined && right !== undefined && left <= right;
}

export function validateXobj001(graph) {
  const run = graph.collections.audit_runs.length === 1 ? graph.collections.audit_runs[0] : undefined;
  if (!run || run.run_id !== graph.run_id) return ["RUN_ID_MISMATCH"];
  const bindings = [
    ["audit_passes", "run_id"], ["collector_executions", "run_id"], ["observations", "run_id"],
    ["evidence_references", "run_id"], ["findings", "run_id"], ["consent_receipts", "audit_run_id"],
    ["action_logs", "run_id"], ["audit_manifests", "run_id"], ["export_manifests", "run_id"],
    ["reboot_continuation_states", "expected_run_id"]
  ];
  for (const [collection, field] of bindings) {
    if (graph.collections[collection].some((item) => item[field] !== graph.run_id)) return ["RUN_ID_MISMATCH"];
  }
  return [];
}

export function validateXobj002(graph) {
  const identityFields = {
    audit_runs: "run_id", audit_passes: "pass_id", collector_definitions: "collector_id", collector_executions: "execution_id",
    observations: "observation_id", evidence_references: "evidence_id", findings: "finding_id", consent_receipts: "receipt_id",
    action_logs: "action_log_id", audit_manifests: "manifest_id", export_manifests: "export_id", redaction_profiles: "profile_id",
    reboot_continuation_states: "state_id", rule_definitions: "rule_id"
  };
  for (const [collection, field] of Object.entries(identityFields)) {
    if (duplicates(graph.collections[collection].map((item) => item[field]))) return ["EXECUTION_PASS_MISMATCH"];
  }
  const passes = graph.collections.audit_passes;
  for (const execution of sorted(graph.collections.collector_executions, "execution_id")) {
    const owners = passes.filter((pass) => pass.collector_execution_ids.includes(execution.execution_id));
    if (owners.length !== 1 || owners[0].pass_id !== execution.pass_id || owners[0].privilege_class !== execution.privilege) {
      return ["EXECUTION_PASS_MISMATCH"];
    }
  }
  return [];
}

export function validateXobj003(graph) {
  const observations = graph.collections.observations;
  const executions = graph.collections.collector_executions;
  for (const observation of sorted(observations, "observation_id")) {
    const execution = oneBy(executions, "execution_id", observation.execution_id);
    if (!execution || !["Succeeded", "Partial"].includes(execution.state)
      || !exactlyOnce(execution.observation_ids, observation.observation_id)) return ["OBSERVATION_EXECUTION_MISMATCH"];
  }
  for (const execution of sorted(executions, "execution_id")) {
    for (const observationId of execution.observation_ids) {
      const observation = oneBy(observations, "observation_id", observationId);
      if (!observation || observation.execution_id !== execution.execution_id) return ["OBSERVATION_EXECUTION_MISMATCH"];
    }
  }
  return [];
}

export function validateXobj004(graph) {
  const observations = graph.collections.observations;
  const evidence = graph.collections.evidence_references;
  for (const item of sorted(evidence, "evidence_id")) {
    const observation = oneBy(observations, "observation_id", item.observation_id);
    if (!observation || !exactlyOnce(observation.evidence_ids, item.evidence_id)) return ["EVIDENCE_OBSERVATION_MISMATCH"];
  }
  for (const observation of sorted(observations, "observation_id")) {
    for (const evidenceId of observation.evidence_ids) {
      const item = oneBy(evidence, "evidence_id", evidenceId);
      if (!item || item.observation_id !== observation.observation_id) return ["EVIDENCE_OBSERVATION_MISMATCH"];
    }
  }
  return [];
}

export function validateXobj005(graph) {
  const observations = graph.collections.observations;
  const evidence = graph.collections.evidence_references;
  const executions = graph.collections.collector_executions;
  for (const finding of sorted(graph.collections.findings, "finding_id")) {
    if (finding.finding_kind === "Security") {
      if (finding.observation_ids.length === 0 || finding.coverage !== undefined) return ["FINDING_REFERENCE_MISMATCH"];
      if (finding.observation_ids.some((id) => !oneBy(observations, "observation_id", id))) return ["FINDING_REFERENCE_MISMATCH"];
      if (finding.evidence_ids.some((id) => {
        const item = oneBy(evidence, "evidence_id", id);
        return !item || !finding.observation_ids.includes(item.observation_id);
      })) return ["FINDING_REFERENCE_MISMATCH"];
    } else if (finding.finding_kind === "Coverage") {
      const execution = finding.coverage && oneBy(executions, "execution_id", finding.coverage.execution_id);
      if (finding.observation_ids.length !== 0 || finding.evidence_ids.length !== 0 || !execution
        || execution.state !== finding.coverage.execution_state
        || !["NotTested", "BackendNotFound", "ConsentDenied", "PolicyRejected"].includes(execution.state)) return ["FINDING_REFERENCE_MISMATCH"];
    } else return ["FINDING_REFERENCE_MISMATCH"];
  }
  return [];
}

export function validateXobj006(graph) {
  const definitions = graph.collections.collector_definitions;
  const loaded = graph.loaded_digests.collector_definitions;
  for (const execution of sorted(graph.collections.collector_executions, "execution_id")) {
    const definition = definitions.find((item) => item.collector_id === execution.collector_id && item.version === execution.collector_version);
    const pin = loaded.find((item) => item.collector_id === execution.collector_id && item.version === execution.collector_version);
    if (!definition || !pin || execution.collector_definition_digest !== definition.integrity.object_digest
      || pin.object_digest !== definition.integrity.object_digest) return ["COLLECTOR_DEFINITION_MISMATCH"];
  }
  return [];
}

export function validateXobj007(graph) {
  const definitions = graph.collections.rule_definitions;
  const loaded = graph.loaded_digests.rule_definitions;
  for (const finding of sorted(graph.collections.findings, "finding_id")) {
    const definition = definitions.find((item) => item.rule_id === finding.rule_id && item.version === finding.rule_version);
    const pin = loaded.find((item) => item.rule_id === finding.rule_id && item.version === finding.rule_version);
    if (!definition || !pin || finding.rule_definition_digest !== definition.integrity.object_digest
      || pin.object_digest !== definition.integrity.object_digest) return ["RULE_DEFINITION_MISMATCH"];
  }
  return [];
}

const KIND_COLLECTION = Object.freeze({
  AuditRun: ["audit_runs", "run_id"], AuditPass: ["audit_passes", "pass_id"], CollectorDefinition: ["collector_definitions", "collector_id"],
  CollectorExecution: ["collector_executions", "execution_id"], Observation: ["observations", "observation_id"], Evidence: ["evidence_references", "evidence_id"],
  Finding: ["findings", "finding_id"], ConsentReceipt: ["consent_receipts", "receipt_id"], ActionLog: ["action_logs", "action_log_id"],
  RedactionProfile: ["redaction_profiles", "profile_id"], RebootContinuationState: ["reboot_continuation_states", "state_id"], RuleDefinition: ["rule_definitions", "rule_id"]
});

function membershipKey(item) {
  return `${item.role}\u0000${item.member_id}\u0000${item.logical_path}`;
}

export function validateXobj008(graph) {
  if (graph.collections.audit_manifests.length !== 1 || graph.collections.action_logs.length !== 1) return ["MANIFEST_MEMBERSHIP_MISMATCH"];
  const manifest = graph.collections.audit_manifests[0];
  const actual = manifest.entries.map(membershipKey).sort(compareUnicodeCodeUnits);
  const expected = graph.manifest_membership_index.map(membershipKey).sort(compareUnicodeCodeUnits);
  if (!sameSet(actual, expected) || duplicates(manifest.entries.map((item) => item.member_id))) return ["MANIFEST_MEMBERSHIP_MISMATCH"];
  for (const member of graph.manifest_membership_index) {
    const mapping = KIND_COLLECTION[member.object_kind];
    if (!mapping || member.role !== member.object_kind) return ["MANIFEST_MEMBERSHIP_MISMATCH"];
    if (!oneBy(graph.collections[mapping[0]], mapping[1], member.object_id)) return ["MANIFEST_MEMBERSHIP_MISMATCH"];
  }
  const run = graph.collections.audit_runs[0];
  const required = [
    ["AuditRun", run.run_id], ...run.pass_references.map((item) => ["AuditPass", item.pass_id]),
    ...run.execution_references.map((item) => ["CollectorExecution", item.object_id]),
    ...run.observation_references.map((item) => ["Observation", item.object_id]),
    ...run.evidence_references.map((item) => ["Evidence", item.object_id]),
    ...run.finding_references.map((item) => ["Finding", item.object_id]),
    ...run.consent_receipt_ids.map((id) => ["ConsentReceipt", id]), ["ActionLog", run.action_log_reference.action_log_id]
  ];
  if (required.some(([kind, id]) => !graph.manifest_membership_index.some((item) => item.object_kind === kind && item.object_id === id))) {
    return ["MANIFEST_MEMBERSHIP_MISMATCH"];
  }
  const log = graph.collections.action_logs[0];
  if (manifest.action_log_reference.action_log_id !== log.action_log_id
    || manifest.action_log_reference.logical_path !== run.action_log_reference.logical_path
    || manifest.action_log_reference.log_digest !== log.log_digest.digest) return ["MANIFEST_MEMBERSHIP_MISMATCH"];
  return [];
}

export function validateXobj009(graph) {
  if (graph.collections.export_manifests.length !== 1 || graph.collections.audit_manifests.length !== 1 || graph.collections.redaction_profiles.length !== 1) {
    return ["EXPORT_SOURCE_MISMATCH"];
  }
  const exported = graph.collections.export_manifests[0];
  const source = graph.collections.audit_manifests[0];
  const profile = graph.collections.redaction_profiles[0];
  const sourcePin = graph.loaded_digests.audit_manifests.find((item) => item.manifest_id === source.manifest_id);
  const profilePin = graph.loaded_digests.redaction_profiles.find((item) => item.profile_id === profile.profile_id && item.version === profile.version);
  const compositionPin = graph.loaded_digests.composition_policies.find((item) => item.policy_id === profile.composition_policy.policy_id);
  if (!sourcePin || !profilePin || !compositionPin
    || exported.source_manifest_digest !== source.manifest_digest.digest || sourcePin.manifest_digest !== source.manifest_digest.digest
    || exported.redaction_profile_id !== profile.profile_id || exported.redaction_profile_version !== profile.version
    || exported.redaction_profile_digest !== profile.profile_digest.digest || profilePin.profile_digest !== profile.profile_digest.digest
    || exported.composition_policy_digest !== profile.composition_policy.policy_digest
    || compositionPin.policy_digest !== profile.composition_policy.policy_digest) return ["EXPORT_SOURCE_MISMATCH"];
  const sourceById = new Map(source.entries.map((item) => [item.member_id, item]));
  for (const entry of exported.entries) {
    const member = sourceById.get(entry.source_member_id);
    if (!member || member.logical_path !== entry.source_logical_path) return ["EXPORT_SOURCE_MISMATCH"];
  }
  for (const omission of exported.omissions) {
    const member = sourceById.get(omission.source_member_id);
    if (!member || member.logical_path !== omission.source_logical_path) return ["EXPORT_SOURCE_MISMATCH"];
  }
  if (exported.entries.some((entry) => exported.omissions.some((item) => item.source_member_id === entry.source_member_id))) return ["EXPORT_SOURCE_MISMATCH"];
  return [];
}

export function validateXobj010(graph) {
  const run = graph.collections.audit_runs[0];
  if (!validInterval(run.started_at, run.ended_at)) return ["TIMESTAMP_ORDER_INVALID"];
  const runStart = asTime(run.started_at);
  const runEnd = asTime(run.ended_at);
  const passes = graph.collections.audit_passes;
  for (const pass of passes) {
    if (pass.started_at !== undefined && (!validInterval(pass.started_at, pass.ended_at) || asTime(pass.started_at) < runStart || asTime(pass.ended_at) > runEnd)) return ["TIMESTAMP_ORDER_INVALID"];
  }
  for (const execution of graph.collections.collector_executions) {
    const pass = oneBy(passes, "pass_id", execution.pass_id);
    if (execution.started_at !== undefined && (!validInterval(execution.started_at, execution.ended_at) || asTime(execution.started_at) < runStart || asTime(execution.ended_at) > runEnd
      || (pass?.started_at && (asTime(execution.started_at) < asTime(pass.started_at) || asTime(execution.ended_at) > asTime(pass.ended_at))))) return ["TIMESTAMP_ORDER_INVALID"];
  }
  for (const observation of graph.collections.observations) {
    const execution = oneBy(graph.collections.collector_executions, "execution_id", observation.execution_id);
    const observed = asTime(observation.observed_at);
    if (observed === undefined || observed < runStart || observed > runEnd || !execution?.started_at || observed < asTime(execution.started_at)
      || (execution.ended_at && observed > asTime(execution.ended_at))) return ["TIMESTAMP_ORDER_INVALID"];
  }
  for (const evidence of graph.collections.evidence_references) {
    const observation = oneBy(graph.collections.observations, "observation_id", evidence.observation_id);
    const captured = asTime(evidence.captured_at);
    if (!observation || captured === undefined || captured < asTime(observation.observed_at) || captured > runEnd) return ["TIMESTAMP_ORDER_INVALID"];
  }
  if (graph.collections.findings.some((item) => asTime(item.detected_at) < runStart || asTime(item.detected_at) > runEnd)) return ["TIMESTAMP_ORDER_INVALID"];
  for (const receipt of graph.collections.consent_receipts) {
    if (!validInterval(receipt.presented_at, receipt.accepted_at) || !validInterval(receipt.accepted_at, receipt.expires_at)) return ["TIMESTAMP_ORDER_INVALID"];
  }
  for (const log of graph.collections.action_logs) {
    let prior = asTime(log.created_at);
    for (const entry of [...log.entries].sort((a, b) => a.sequence_number - b.sequence_number)) {
      const current = asTime(entry.timestamp);
      if (current === undefined || current < prior || current < runStart || current > runEnd) return ["TIMESTAMP_ORDER_INVALID"];
      prior = current;
    }
  }
  const manifestTime = asTime(graph.collections.audit_manifests[0]?.generated_at);
  if (manifestTime === undefined || manifestTime < runEnd) return ["TIMESTAMP_ORDER_INVALID"];
  if (graph.collections.export_manifests.some((item) => asTime(item.generated_at) < manifestTime)) return ["TIMESTAMP_ORDER_INVALID"];
  if (graph.collections.reboot_continuation_states.some((item) => !validInterval(item.issued_at, item.expires_at))) return ["TIMESTAMP_ORDER_INVALID"];
  return [];
}

export const XOBJ011_CONSENT_VARIANTS = Object.freeze(["CollectorExecution", "Export", "Remediation", "Reboot"]);

export const XOBJ011_CONSENT_TYPE_MODELS = Object.freeze({
  Administrative: "CollectorExecution",
  NetworkAccess: "CollectorExecution",
  DefenderScan: "CollectorExecution",
  DefenderOffline: "CollectorExecution",
  MemoryAcquisition: "CollectorExecution",
  SensitiveDataCollection: "CollectorExecution",
  Export: "Export",
  Remediation: "Remediation",
  Reboot: "Reboot"
});

export const XOBJ011_CONSENT_TYPES = Object.freeze(Object.keys(XOBJ011_CONSENT_TYPE_MODELS).sort(compareUnicodeCodeUnits));

const XOBJ011_OPERATIONS_BY_TYPE = Object.freeze({
  Administrative: new Set(["CollectPrivilegedReadOnly"]),
  NetworkAccess: new Set(["UseNetwork", "OnlineLookup"]),
  DefenderScan: new Set(["RunDefenderScan"]),
  DefenderOffline: new Set(["ScheduleDefenderOffline", "PerformDefenderOffline"]),
  MemoryAcquisition: new Set(["AcquireMemory"]),
  SensitiveDataCollection: new Set(["CollectSensitiveData"]),
  Export: new Set(["Export"]),
  Remediation: new Set(["Remediate"]),
  Reboot: new Set(["ScheduleRebootContinuation", "PerformRebootContinuation"])
});

const XOBJ011_AUTHORIZATION_FIELD_BY_TYPE = Object.freeze({
  Administrative: "elevation_authorization",
  NetworkAccess: "network_authorization",
  DefenderScan: "defender_scan_authorization",
  DefenderOffline: "reboot_authorization",
  MemoryAcquisition: "memory_authorization",
  Export: "export_authorization",
  Remediation: "remediation_authorization",
  Reboot: "reboot_authorization"
});

function loadedCollectorBinding(graph, binding) {
  if (!binding) return undefined;
  const definition = graph.collections.collector_definitions.find((item) =>
    item.collector_id === binding.collector_id && item.integrity.object_digest === binding.collector_definition_digest);
  const loaded = graph.loaded_digests.collector_definitions.find((item) =>
    item.collector_id === binding.collector_id && item.object_digest === binding.collector_definition_digest);
  return definition && loaded ? definition : undefined;
}

function receiptPassBinding(graph, receipt, action) {
  const scopePassId = receipt.exact_scope.pass_id;
  if ((scopePassId === undefined) !== (action.pass_id === undefined)) return undefined;
  const referencingPasses = graph.collections.audit_passes.filter((item) => item.consent_receipt_ids.includes(receipt.receipt_id));
  if (scopePassId === undefined) return referencingPasses.length === 0 ? null : undefined;
  const pass = oneBy(graph.collections.audit_passes, "pass_id", scopePassId);
  return pass && action.pass_id === scopePassId && referencingPasses.length === 1 && referencingPasses[0] === pass ? pass : undefined;
}

function findingUsesCollector(graph, finding, definition) {
  const executionIds = new Set();
  if (finding.finding_kind === "Coverage" && finding.coverage?.execution_id) executionIds.add(finding.coverage.execution_id);
  for (const observationId of finding.observation_ids ?? []) {
    const observation = oneBy(graph.collections.observations, "observation_id", observationId);
    if (observation) executionIds.add(observation.execution_id);
  }
  return graph.collections.collector_executions.some((execution) =>
    executionIds.has(execution.execution_id)
      && execution.collector_id === definition.collector_id
      && execution.collector_definition_digest === definition.integrity.object_digest);
}

function validateCollectorConsent(graph, receipt, action, definitions) {
  const definition = loadedCollectorBinding(graph, receipt.collector_binding);
  const pass = receiptPassBinding(graph, receipt, action);
  const executions = graph.collections.collector_executions.filter((item) => item.consent_receipt_ids.includes(receipt.receipt_id));
  if (!definition || !pass || receipt.export_binding || receipt.action_binding || receipt.reboot_binding
    || executions.length !== 1 || executions[0].collector_id !== definition.collector_id
    || executions[0].collector_definition_digest !== definition.integrity.object_digest
    || executions[0].pass_id !== pass.pass_id
    || (action.execution_id !== undefined && action.execution_id !== executions[0].execution_id)
    || !definition.execution_context.consent_requirements.includes(receipt.consent_type)
    || !definition.backend.capabilities.every((item) => receipt.approved_capabilities.includes(item))
    || !definition.privacy_classes.every((item) => receipt.approved_privacy_classes.includes(item))) return false;
  return definitions.includes(definition);
}

function validateExportConsent(graph, receipt, action) {
  if (!receipt.export_binding || receipt.collector_binding || receipt.action_binding || receipt.reboot_binding
    || receipt.exact_scope.pass_id !== undefined
    || graph.collections.audit_passes.some((item) => item.consent_receipt_ids.includes(receipt.receipt_id))
    || graph.collections.collector_executions.some((item) => item.consent_receipt_ids.includes(receipt.receipt_id))
    || action.action_type !== "Export") return false;
  const exported = oneBy(graph.collections.export_manifests, "export_id", receipt.export_binding.export_id);
  if (!exported || exported.run_id !== graph.run_id) return false;
  const profile = graph.collections.redaction_profiles.find((item) =>
    item.profile_id === exported.redaction_profile_id && item.version === exported.redaction_profile_version);
  const loadedProfile = profile && graph.loaded_digests.redaction_profiles.find((item) =>
    item.profile_id === profile.profile_id && item.version === profile.version);
  return Boolean(profile && loadedProfile
    && receipt.export_binding.redaction_profile_digest === exported.redaction_profile_digest
    && receipt.export_binding.redaction_profile_digest === profile.profile_digest.digest
    && loadedProfile.profile_digest === profile.profile_digest.digest
    && action.export_authorization?.redaction_profile_digest === profile.profile_digest.digest
    && action.export_authorization?.export_manifest_reference === receipt.exact_scope.target_reference);
}

function validateRemediationConsent(graph, receipt, action) {
  if (!receipt.action_binding || receipt.collector_binding || receipt.export_binding || receipt.reboot_binding
    || action.action_type !== "Remediation"
    || receipt.action_binding.action_id !== receipt.exact_scope.authorized_action_id
    || receipt.action_binding.action_id !== action.action_id
    || receipt.action_binding.exact_target_reference !== receipt.exact_scope.target_reference
    || action.remediation_authorization?.exact_target_reference !== receipt.exact_scope.target_reference
    || receiptPassBinding(graph, receipt, action) === undefined
    || graph.collections.collector_executions.some((item) => item.consent_receipt_ids.includes(receipt.receipt_id))) return false;
  if (receipt.action_binding.finding_id !== undefined) {
    const finding = oneBy(graph.collections.findings, "finding_id", receipt.action_binding.finding_id);
    if (!finding) return false;
    if (receipt.action_binding.related_collector_binding !== undefined) {
      const definition = loadedCollectorBinding(graph, receipt.action_binding.related_collector_binding);
      if (!definition || !findingUsesCollector(graph, finding, definition)) return false;
    }
  }
  return true;
}

function validateRebootConsent(graph, receipt, action) {
  if (!receipt.reboot_binding || receipt.collector_binding || receipt.export_binding || receipt.action_binding
    || action.action_type !== "Reboot"
    || receipt.reboot_binding.workflow_id !== receipt.exact_scope.target_reference
    || action.reboot_authorization?.continuation_state_reference !== receipt.exact_scope.target_reference
    || receiptPassBinding(graph, receipt, action) === undefined
    || graph.collections.collector_executions.some((item) => item.consent_receipt_ids.includes(receipt.receipt_id))) return false;
  const expectedStages = receipt.exact_scope.operation_code === "ScheduleRebootContinuation"
    ? new Set(["Schedule"])
    : new Set(["Perform", "Continue"]);
  if (!expectedStages.has(receipt.reboot_binding.stage)) return false;
  if (receipt.reboot_binding.stage === "Schedule" && action.reboot_authorization?.next_stage !== "RebootContinuation") return false;
  if (receipt.reboot_binding.planned_by_collector !== undefined) {
    const definition = loadedCollectorBinding(graph, receipt.reboot_binding.planned_by_collector);
    if (!definition || !graph.collections.collector_executions.some((execution) =>
      execution.collector_id === definition.collector_id
        && execution.collector_definition_digest === definition.integrity.object_digest
        && execution.pass_id === receipt.exact_scope.pass_id)) return false;
  }
  return true;
}

export function validateXobj011(graph, typeModels = XOBJ011_CONSENT_TYPE_MODELS) {
  const now = asTime(graph.validation_context.validation_time);
  if (now === undefined || !Array.isArray(graph.replay_history.consent_nonces)) return ["XOBJ_GRAPH_INPUT_MISSING"];
  const receipts = graph.collections.consent_receipts;
  const actions = graph.collections.action_logs.flatMap((log) => log.entries);
  const definitions = graph.collections.collector_definitions;
  const run = graph.collections.audit_runs[0];
  if (!run || duplicates(receipts.map((item) => item.receipt_id)) || duplicates(receipts.map((item) => item.nonce))) {
    return ["CONSENT_SCOPE_INVALID"];
  }
  for (const receipt of sorted(receipts, "receipt_id")) {
    const model = typeModels[receipt.consent_type];
    const operations = XOBJ011_OPERATIONS_BY_TYPE[receipt.consent_type];
    const action = oneBy(actions, "action_id", receipt.exact_scope.authorized_action_id);
    const authorizationField = XOBJ011_AUTHORIZATION_FIELD_BY_TYPE[receipt.consent_type];
    if (!model || !XOBJ011_CONSENT_VARIANTS.includes(model) || !operations?.has(receipt.exact_scope.operation_code)
      || receipt.audit_run_id !== graph.run_id || receipt.revocation.state !== "Active" || asTime(receipt.expires_at) <= now
      || graph.replay_history.consent_nonces.includes(receipt.nonce) || receipt.exact_scope.single_use !== true
      || !isSubset(receipt.approved_capabilities, receipt.requested_capabilities)
      || !isSubset(receipt.approved_privacy_classes, receipt.requested_privacy_classes)
      || !exactlyOnce(run.consent_receipt_ids, receipt.receipt_id)
      || !action || !exactlyOnce(action.consent_receipt_ids, receipt.receipt_id)
      || action.audit_run_id !== graph.run_id || action.operation.purpose_code !== receipt.purpose_code
      || action.operation.operation_code !== receipt.exact_scope.operation_code || action.operation.target_reference !== receipt.exact_scope.target_reference
      || actions.filter((item) => item.consent_receipt_ids.includes(receipt.receipt_id)).length !== 1
      || (authorizationField !== undefined && action[authorizationField]?.consent_receipt_id !== receipt.receipt_id)) {
      return ["CONSENT_SCOPE_INVALID"];
    }
    const validVariant = model === "CollectorExecution"
      ? validateCollectorConsent(graph, receipt, action, definitions)
      : model === "Export"
        ? validateExportConsent(graph, receipt, action)
        : model === "Remediation"
          ? validateRemediationConsent(graph, receipt, action)
          : model === "Reboot" && validateRebootConsent(graph, receipt, action);
    if (!validVariant) return ["CONSENT_SCOPE_INVALID"];
  }
  for (const execution of graph.collections.collector_executions) {
    const definition = definitions.find((item) => item.collector_id === execution.collector_id && item.version === execution.collector_version);
    if (!definition) return ["CONSENT_SCOPE_INVALID"];
    for (const type of definition.execution_context.consent_requirements) {
      if (typeModels[type] === "CollectorExecution"
        && !execution.consent_receipt_ids.some((id) => receipts.some((receipt) => receipt.receipt_id === id && receipt.consent_type === type))) {
        return ["CONSENT_SCOPE_INVALID"];
      }
    }
  }
  return [];
}

export function validateXobj012(graph) {
  for (const log of sorted(graph.collections.action_logs, "action_log_id")) {
    const entries = [...log.entries].sort((left, right) => left.sequence_number - right.sequence_number);
    const actionIds = new Set();
    let previous = null;
    let priorTime;
    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      const actual = digestWithExclusion(entry, "entry_digest");
      const currentTime = asTime(entry.timestamp);
      if (entry.sequence_number !== index || entry.previous_entry_digest !== previous || entry.audit_run_id !== log.run_id
        || actionIds.has(entry.action_id) || (priorTime !== undefined && currentTime < priorTime) || actual !== entry.entry_digest.digest) {
        return ["ACTION_LOG_CHAIN_INVALID"];
      }
      previous = actual;
      priorTime = currentTime;
      actionIds.add(entry.action_id);
    }
    const normalized = structuredClone(log);
    normalized.entries.sort((left, right) => left.sequence_number - right.sequence_number);
    if (digestWithExclusion(normalized, "log_digest.digest") !== log.log_digest.digest) return ["ACTION_LOG_CHAIN_INVALID"];
  }
  return [];
}

export function validateXobj013(graph) {
  const context = graph.validation_context;
  const now = asTime(context.validation_time);
  const manifest = graph.collections.audit_manifests[0];
  if (now === undefined || !Array.isArray(context.verified_reboot_state_ids)) return ["XOBJ_GRAPH_INPUT_MISSING"];
  for (const state of sorted(graph.collections.reboot_continuation_states, "state_id")) {
    if (!context.verified_reboot_state_ids.includes(state.state_id) || state.expected_run_id !== graph.run_id
      || state.consumption_state !== "Unconsumed" || now >= asTime(state.expires_at)
      || state.monotonic_sequence <= graph.replay_history.minimum_reboot_sequence
      || graph.replay_history.reboot_nonces.includes(state.nonce)
      || state.expected_executable_digest !== context.expected_executable_digest
      || state.expected_build_digest !== context.expected_build_digest
      || state.machine_binding_digest !== context.machine_binding_digest
      || !manifest || state.prior_manifest_digest !== manifest.manifest_digest.digest) return ["REBOOT_STATE_INVALID"];
  }
  return [];
}

function predicateChildren(predicate) {
  if (predicate.kind === "Not") return [predicate.child_id];
  if (["All", "Any"].includes(predicate.kind)) return predicate.child_ids;
  return [];
}

export function validateXobj014(graph) {
  for (const rule of sorted(graph.collections.rule_definitions, "rule_id")) {
    const predicates = rule.expression.predicates;
    const ids = predicates.map((item) => item.predicate_id);
    if (predicates.length < 1 || predicates.length > 64 || duplicates(ids)) return ["RULE_GRAPH_INVALID"];
    const byId = new Map(predicates.map((item) => [item.predicate_id, item]));
    if (!byId.has(rule.expression.root_predicate_id)) return ["RULE_GRAPH_INVALID"];
    for (const predicate of predicates) {
      const children = predicateChildren(predicate);
      if (children.length > 16 || children.some((id) => !byId.has(id))) return ["RULE_GRAPH_INVALID"];
    }
    const reached = new Set();
    const active = new Set();
    const memo = new Map();
    let invalid = false;
    function longestPath(id) {
      if (active.has(id)) { invalid = true; return 65; }
      if (memo.has(id)) return memo.get(id);
      active.add(id);
      reached.add(id);
      const children = predicateChildren(byId.get(id));
      const depth = 1 + (children.length ? Math.max(...children.map(longestPath)) : 0);
      active.delete(id);
      memo.set(id, depth);
      return depth;
    }
    const depth = longestPath(rule.expression.root_predicate_id);
    if (invalid || depth > Math.min(8, rule.expression.maximum_depth) || reached.size !== predicates.length || reached.size > 64) return ["RULE_GRAPH_INVALID"];
  }
  return [];
}

const ALLOWED_FIELD_ACTIONS = Object.freeze({
  Include: new Set(["Include", "Redact", "Hash", "Exclude"]),
  Redact: new Set(["Redact", "Exclude"]),
  Hash: new Set(["Hash", "Exclude"]),
  Exclude: new Set(["Exclude"])
});

export function validateXobj015(graph) {
  const registry = new Map(graph.redaction_field_registry.map((item) => [item.field, item]));
  if (registry.size !== graph.redaction_field_registry.length) return ["REDACTION_POLICY_INVALID"];
  for (const profile of sorted(graph.collections.redaction_profiles, "profile_id")) {
    if (duplicates(profile.field_rules.map((item) => item.field))) return ["REDACTION_POLICY_INVALID"];
    for (const rule of profile.field_rules) {
      const registered = registry.get(rule.field);
      const floor = profile.class_actions[rule.privacy_class];
      if (!registered || registered.privacy_class !== rule.privacy_class || !ALLOWED_FIELD_ACTIONS[floor]?.has(rule.action)) {
        return ["REDACTION_POLICY_INVALID"];
      }
    }
  }
  return [];
}

const CANONICAL_PATH = /^(?!\/)(?!.*\/\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*[\\:\u0000-\u001F\u007F])(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127})(?:\/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$/u;

function invalidPathSet(values) {
  return duplicates(values) || values.some((value) => typeof value !== "string" || value.length > 1024 || !CANONICAL_PATH.test(value));
}

export function validateXobj016(graph) {
  for (const manifest of graph.collections.audit_manifests) {
    if (invalidPathSet(manifest.entries.map((item) => item.logical_path))) return ["PATH_SET_INVALID"];
  }
  for (const manifest of graph.collections.export_manifests) {
    if (invalidPathSet(manifest.entries.map((item) => item.export_logical_path))) return ["PATH_SET_INVALID"];
  }
  if (invalidPathSet(graph.manifest_membership_index.map((item) => item.logical_path))) return ["PATH_SET_INVALID"];
  const referenced = graph.collections.audit_runs.flatMap((run) => [
    ...run.pass_references.map((item) => item.logical_path), run.action_log_reference.logical_path, run.manifest_reference.logical_path
  ]);
  const evidence = graph.collections.evidence_references.map((item) => item.logical_path);
  if ([...referenced, ...evidence].some((value) => !CANONICAL_PATH.test(value))) return ["PATH_SET_INVALID"];
  return [];
}

const SIZE_LIMITS = Object.freeze({
  ordinary_contract_bytes: 16777216,
  observation_payload_bytes: 1048576,
  raw_output_or_file_bytes: 1073741824,
  collector_records: 1000000,
  total_decompressed_run_bytes: 2147483648,
  audit_package_bytes: 4294967296,
  manifest_entries: 100000,
  action_log_entries: 100000,
  zip_entries: 10000,
  zip_total_expanded_bytes: 1073741824,
  zip_single_entry_expanded_bytes: 268435456,
  zip_compression_ratio: 100,
  archive_nesting: 0,
  json_nesting_depth: 64,
  logical_paths: 100000,
  imported_records: 1000000
});

function jsonDepth(value) {
  let maximum = 0;
  const stack = [[value, 1]];
  while (stack.length) {
    const [current, depth] = stack.pop();
    maximum = Math.max(maximum, depth);
    if (current && typeof current === "object") for (const child of Object.values(current)) stack.push([child, depth + 1]);
  }
  return maximum;
}

export function validateXobj017(graph) {
  for (const [key, limit] of Object.entries(SIZE_LIMITS)) {
    const value = graph.size_measurements[key];
    if (!Number.isSafeInteger(value) || value < 0 || value > limit) return ["SIZE_LIMIT_EXCEEDED"];
  }
  for (const collection of Object.values(graph.collections)) {
    for (const item of collection) {
      if (Buffer.byteLength(jcs(item), "utf8") > SIZE_LIMITS.ordinary_contract_bytes || jsonDepth(item) > SIZE_LIMITS.json_nesting_depth) return ["SIZE_LIMIT_EXCEEDED"];
    }
  }
  if (graph.collections.observations.some((item) => Buffer.byteLength(jcs(item.data), "utf8") > SIZE_LIMITS.observation_payload_bytes)
    || graph.collections.collector_executions.some((item) => (item.record_count ?? 0) > SIZE_LIMITS.collector_records)
    || graph.collections.audit_manifests.some((item) => item.entries.length > SIZE_LIMITS.manifest_entries)
    || graph.collections.action_logs.some((item) => item.entries.length > SIZE_LIMITS.action_log_entries)) return ["SIZE_LIMIT_EXCEEDED"];
  return [];
}

export function validateXobj018(graph) {
  for (const definition of sorted(graph.collections.collector_definitions, "collector_id")) {
    const capability = graph.capability_graph.find((item) => item.collector_id === definition.collector_id && item.collector_version === definition.version);
    if (!capability || !sameSet(capability.declared_capabilities, definition.backend.capabilities)
      || capability.nodes.length > 64 || duplicates(capability.nodes.map((item) => item.node_id))) return ["TRANSITIVE_CAPABILITY_MISMATCH"];
    const byId = new Map(capability.nodes.map((item) => [item.node_id, item]));
    if (!byId.has(capability.root_node_id)) return ["TRANSITIVE_CAPABILITY_MISMATCH"];
    const reached = new Set();
    const active = new Set();
    const memo = new Map();
    let invalid = false;
    function longestPath(id) {
      const node = byId.get(id);
      if (!node || active.has(id) || node.capabilities.some((item) => !definition.backend.capabilities.includes(item))) { invalid = true; return 65; }
      if (memo.has(id)) return memo.get(id);
      active.add(id);
      reached.add(id);
      const depth = 1 + (node.child_ids.length ? Math.max(...node.child_ids.map(longestPath)) : 0);
      active.delete(id);
      memo.set(id, depth);
      return depth;
    }
    const depth = longestPath(capability.root_node_id);
    if (invalid || depth > 8 || reached.size !== capability.nodes.length) return ["TRANSITIVE_CAPABILITY_MISMATCH"];
  }
  return [];
}

export const XOBJ_RULE_IMPLEMENTATIONS = Object.freeze({
  "XOBJ-001": validateXobj001, "XOBJ-002": validateXobj002, "XOBJ-003": validateXobj003,
  "XOBJ-004": validateXobj004, "XOBJ-005": validateXobj005, "XOBJ-006": validateXobj006,
  "XOBJ-007": validateXobj007, "XOBJ-008": validateXobj008, "XOBJ-009": validateXobj009,
  "XOBJ-010": validateXobj010, "XOBJ-011": validateXobj011, "XOBJ-012": validateXobj012,
  "XOBJ-013": validateXobj013, "XOBJ-014": validateXobj014, "XOBJ-015": validateXobj015,
  "XOBJ-016": validateXobj016, "XOBJ-017": validateXobj017, "XOBJ-018": validateXobj018
});

export function evaluateXobjRule(ruleId, graph, implementations = XOBJ_RULE_IMPLEMENTATIONS) {
  const spec = SPEC_BY_ID.get(ruleId);
  if (!spec) return ["UNKNOWN_APPLICATION_RULE"];
  const implementation = implementations[ruleId];
  if (typeof implementation !== "function") return ["XOBJ_RULE_IMPLEMENTATION_MISSING"];
  if (spec.required_graph_input.some((required) => !hasPath(graph, required))) return ["XOBJ_GRAPH_INPUT_MISSING"];
  return implementation(graph);
}

export function evaluateXobjThrough(targetRuleId, graph, implementations = XOBJ_RULE_IMPLEMENTATIONS) {
  const targetIndex = XOBJ_RULE_IDS.indexOf(targetRuleId);
  if (targetIndex < 0) return ["UNKNOWN_APPLICATION_RULE"];
  for (let index = 0; index <= targetIndex; index += 1) {
    const errors = evaluateXobjRule(XOBJ_RULE_IDS[index], graph, implementations);
    if (errors.length) return errors;
  }
  return [];
}

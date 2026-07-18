import { digestWithExclusion, jcs, jcsSha256, normalizeAuditManifest, normalizeExportManifest } from "./jcs.mjs";
import { materializeXobjRecord } from "./xobj-graph.mjs";
import { evaluateXobjThrough } from "./xobj-rules.mjs";

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const AUTHORIZATION_FIELDS = Object.freeze({
  StartCollector: "collector_authorization",
  NetworkUse: "network_authorization",
  Elevation: "elevation_authorization",
  Reboot: "reboot_authorization",
  DefenderScan: "defender_scan_authorization",
  MemoryAcquisition: "memory_authorization",
  Remediation: "remediation_authorization",
  Export: "export_authorization"
});
const ALL_AUTHORIZATION_FIELDS = Object.values(AUTHORIZATION_FIELDS);

export function checkedUnsigned(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("LIMIT_INTEGER_OVERFLOW");
  return BigInt(value);
}

export function checkedAdd(left, right) {
  const result = checkedUnsigned(left) + checkedUnsigned(right);
  if (result > MAX_SAFE) throw new Error("LIMIT_INTEGER_OVERFLOW");
  return Number(result);
}

export function checkedMultiply(left, right) {
  const result = checkedUnsigned(left) * checkedUnsigned(right);
  if (result > MAX_SAFE) throw new Error("LIMIT_INTEGER_OVERFLOW");
  return Number(result);
}

export function validateActionLog(log) {
  const errors = [];
  const entries = [...log.entries].sort((left, right) => left.sequence_number - right.sequence_number);
  const actionIds = new Set();
  let previousDigest = null;
  let previousTimestamp = null;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry.sequence_number !== index || entry.previous_entry_digest !== previousDigest || entry.audit_run_id !== log.run_id || actionIds.has(entry.action_id)) {
      errors.push("ACTION_LOG_CHAIN_INVALID");
      break;
    }
    if (previousTimestamp !== null && entry.timestamp < previousTimestamp) {
      errors.push("ACTION_LOG_CHAIN_INVALID");
      break;
    }
    const actual = digestWithExclusion(entry, "entry_digest");
    if (actual !== entry.entry_digest.digest) {
      errors.push("ACTION_LOG_CHAIN_INVALID");
      break;
    }
    actionIds.add(entry.action_id);
    previousDigest = actual;
    previousTimestamp = entry.timestamp;
  }
  if (errors.length) return errors;
  const normalized = structuredClone(log);
  normalized.entries.sort((left, right) => left.sequence_number - right.sequence_number);
  if (digestWithExclusion(normalized, "log_digest.digest") !== log.log_digest.digest) return ["ACTION_LOG_CHAIN_INVALID"];

  for (const entry of entries) {
    const expected = AUTHORIZATION_FIELDS[entry.action_type];
    const present = ALL_AUTHORIZATION_FIELDS.filter((field) => Object.hasOwn(entry, field));
    if ((expected && (present.length !== 1 || present[0] !== expected)) || (!expected && present.length !== 0)) return ["ACTION_EFFECT_CONFLICT"];
    for (const parameter of entry.redacted_parameters ?? []) {
      if (Object.hasOwn(parameter, "original_value")) return ["ACTION_REDACTION_INVALID"];
      if (["PersonalMetadata", "NetworkMetadata", "SensitiveSecurityData", "Secret", "MemoryContent"].includes(parameter.privacy_class)
        && parameter.redaction_action === "IncludeSanitized") return ["ACTION_REDACTION_INVALID"];
    }
  }
  return [];
}

function validateManifest(manifest) {
  const roles = new Set(manifest.entries.map((entry) => entry.role));
  if (!["ActionLog", "AuditPass", "AuditRun"].every((role) => roles.has(role))) return ["MANIFEST_REQUIRED_ROLE_MISSING"];
  try {
    const actual = digestWithExclusion(manifest, "manifest_digest.digest", normalizeAuditManifest);
    if (actual !== manifest.manifest_digest.digest) return ["MANIFEST_ORDER_OR_DIGEST_INVALID"];
  } catch {
    return ["MANIFEST_ORDER_OR_DIGEST_INVALID"];
  }
  const observed = Object.hasOwn(manifest.backend, "observed_identity");
  const requiresObserved = ["Found", "Started"].includes(manifest.backend.availability_state);
  if (observed !== requiresObserved) return ["BACKEND_IDENTITY_STATE_CONFLICT"];
  return [];
}

function validatePassGraph(fixture) {
  const passes = fixture.schema_instances.filter((item) => item.schema_id.endsWith("/audit-pass.schema.json")).map((item) => item.instance);
  const run = fixture.schema_instances.find((item) => item.schema_id.endsWith("/audit-run.schema.json"))?.instance;
  const graph = fixture.application_graph;
  if (passes.filter((pass) => pass.kind === "Standard").length !== 1) return ["PASS_CARDINALITY_INVALID"];
  const ids = passes.map((pass) => pass.pass_id);
  const optionalKinds = passes.filter((pass) => pass.kind !== "Standard").map((pass) => pass.kind);
  if (new Set(ids).size !== ids.length || new Set(optionalKinds).size !== optionalKinds.length) return ["PASS_KIND_DUPLICATE"];
  const byId = new Map(passes.map((pass) => [pass.pass_id, pass]));
  const ranks = { Standard: 0, Elevated: 1, RebootContinuation: 2, PostReboot: 3 };
  if (graph.pass_order.length !== passes.length || graph.pass_order.some((id, index) => id !== passes[index].pass_id)
    || passes[0].kind !== "Standard" || passes.some((pass, index) => index > 0 && ranks[pass.kind] < ranks[passes[index - 1].kind])) {
    return ["PASS_ORDER_INVALID"];
  }
  for (const binding of graph.execution_bindings) {
    const pass = byId.get(binding.pass_id);
    if (!pass || pass.privilege_class !== binding.privilege_class) return ["PASS_PRIVILEGE_MISMATCH"];
  }
  for (const pass of passes) {
    if (pass.kind === "Elevated") {
      if (!graph.consent_bindings.some((binding) => binding.consent_type === "Administrative" && binding.run_id === run.run_id && binding.pass_id === pass.pass_id)) return ["PASS_CONSENT_BINDING_INVALID"];
    }
    if (pass.kind === "RebootContinuation") {
      if (!graph.consent_bindings.some((binding) => binding.consent_type === "Reboot" && binding.run_id === run.run_id && binding.pass_id === pass.pass_id)) return ["PASS_CONSENT_BINDING_INVALID"];
    }
  }
  const order = new Map(graph.pass_order.map((id, index) => [id, index]));
  for (const pass of passes) {
    for (const prerequisite of pass.prerequisite_pass_ids) {
      if (!order.has(prerequisite) || order.get(prerequisite) >= order.get(pass.pass_id)) return ["PASS_PREREQUISITE_INVALID"];
    }
    if (pass.kind === "PostReboot" && !pass.prerequisite_pass_ids.some((id) => byId.get(id)?.kind === "RebootContinuation")) return ["PASS_PREREQUISITE_INVALID"];
  }
  return [];
}

const OPERATION_BY_CONSENT = Object.freeze({
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

function isSubset(subset, superset) {
  const values = new Set(superset);
  return subset.every((value) => values.has(value));
}

function validateConsent(fixture) {
  const receipt = fixture.instance;
  if (!OPERATION_BY_CONSENT[receipt.consent_type]?.has(receipt.exact_scope.operation_code)) return ["CONSENT_OPERATION_MISMATCH"];
  if (!isSubset(receipt.approved_capabilities, receipt.requested_capabilities)
    || !isSubset(receipt.approved_privacy_classes, receipt.requested_privacy_classes)) return ["CONSENT_SCOPE_ESCALATION"];
  const context = fixture.validation_context ?? { validation_time: "2026-01-01T00:10:00Z", consumed_nonces: [] };
  if (receipt.revocation.state !== "Active" || receipt.expires_at <= context.validation_time || context.consumed_nonces.includes(receipt.nonce)) return ["CONSENT_RECEIPT_INVALID"];
  const collectorTypes = new Set(["Administrative", "NetworkAccess", "DefenderScan", "DefenderOffline", "MemoryAcquisition", "SensitiveDataCollection"]);
  if (collectorTypes.has(receipt.consent_type) && !receipt.collector_binding) return ["CONSENT_BINDING_VARIANT_INVALID"];
  if (receipt.consent_type === "Export" && (!receipt.export_binding || receipt.exact_scope.pass_id !== undefined)) return ["CONSENT_BINDING_VARIANT_INVALID"];
  if (receipt.consent_type === "Remediation") {
    if (!receipt.action_binding || receipt.action_binding.action_id !== receipt.exact_scope.authorized_action_id
      || receipt.action_binding.exact_target_reference !== receipt.exact_scope.target_reference) return ["CONSENT_BINDING_VARIANT_INVALID"];
  }
  if (receipt.consent_type === "Reboot" && (!receipt.reboot_binding || receipt.reboot_binding.workflow_id !== receipt.exact_scope.target_reference)) return ["CONSENT_BINDING_VARIANT_INVALID"];
  return [];
}

const LIMITS = Object.freeze({
  SERIALIZED_AUDIT_RUN_BYTES: [4194304, "LIMIT_SERIALIZED_OBJECT_EXCEEDED"],
  PASS_REFERENCES: [4, "LIMIT_REFERENCE_COUNT_EXCEEDED"],
  EXECUTION_REFERENCES: [4096, "LIMIT_REFERENCE_COUNT_EXCEEDED"],
  OBSERVATION_REFERENCES: [10000, "LIMIT_REFERENCE_COUNT_EXCEEDED"],
  EVIDENCE_REFERENCES: [10000, "LIMIT_REFERENCE_COUNT_EXCEEDED"],
  FINDING_REFERENCES: [5000, "LIMIT_REFERENCE_COUNT_EXCEEDED"],
  INLINE_SUMMARY_COUNT: [256, "LIMIT_REFERENCE_COUNT_EXCEEDED"],
  INLINE_SUMMARY_BYTES: [2048, "LIMIT_SERIALIZED_OBJECT_EXCEEDED"],
  DECOMPRESSED_RUN_BYTES: [2147483648, "LIMIT_DECOMPRESSED_BUDGET_EXCEEDED"],
  AUDIT_PACKAGE_BYTES: [4294967296, "LIMIT_PACKAGE_BUDGET_EXCEEDED"],
  ZIP_ENTRY_COUNT: [10000, "LIMIT_ZIP_ENTRY_COUNT_EXCEEDED"],
  ZIP_TOTAL_EXPANDED_BYTES: [1073741824, "LIMIT_DECOMPRESSED_BUDGET_EXCEEDED"],
  ZIP_SINGLE_ENTRY_EXPANDED_BYTES: [268435456, "LIMIT_ZIP_ENTRY_SIZE_EXCEEDED"],
  ZIP_COMPRESSION_RATIO: [100, "LIMIT_COMPRESSION_RATIO_EXCEEDED"],
  LOGICAL_PATH_COUNT: [100000, "LIMIT_REFERENCE_COUNT_EXCEEDED"],
  IMPORTED_RECORD_COUNT: [1000000, "LIMIT_REFERENCE_COUNT_EXCEEDED"],
  JSON_NESTING_DEPTH: [64, "LIMIT_NESTING_DEPTH_EXCEEDED"],
  RAW_STDOUT_BYTES: [1073741824, "LIMIT_RAW_STREAM_EXCEEDED"],
  RAW_STDERR_BYTES: [1073741824, "LIMIT_RAW_STREAM_EXCEEDED"]
});

function validateLimit(fixture) {
  if (fixture.instance) {
    return Buffer.byteLength(jcs(fixture.instance), "utf8") <= LIMITS.SERIALIZED_AUDIT_RUN_BYTES[0] ? [] : [LIMITS.SERIALIZED_AUDIT_RUN_BYTES[1]];
  }
  const measurement = fixture.measurement;
  if (measurement.dimension === "CHECKED_UNSIGNED_ADDITION") {
    try {
      const actual = checkedAdd(...measurement.operands);
      return measurement.expected === undefined || actual === measurement.expected ? [] : ["LIMIT_INTEGER_OVERFLOW"];
    } catch (error) {
      return [error.message];
    }
  }
  const limit = LIMITS[measurement.dimension];
  if (!limit) return ["UNKNOWN_APPLICATION_RULE"];
  try {
    const value = checkedUnsigned(measurement.value);
    return value <= BigInt(limit[0]) ? [] : [limit[1]];
  } catch (error) {
    return [error.message];
  }
}

function validateDigestProjection(fixture) {
  if (fixture.sequence_numbers) {
    if (fixture.sequence_numbers.some((value, index) => value !== index)) return ["ACTION_LOG_CHAIN_INVALID"];
  }
  if (fixture.previous_entry_digest) return ["ACTION_LOG_CHAIN_INVALID"];
  if (fixture.log_run_id && fixture.entry_run_id && fixture.log_run_id !== fixture.entry_run_id) return ["ACTION_LOG_CHAIN_INVALID"];
  if (fixture.entries) {
    let previous = null;
    for (let index = 0; index < fixture.entries.length; index += 1) {
      const entry = fixture.entries[index];
      if (entry.logical_entry_without_entry_digest.sequence_number !== index || entry.logical_entry_without_entry_digest.previous_entry_digest !== previous) return ["ACTION_LOG_CHAIN_INVALID"];
      if (jcs(entry.logical_entry_without_entry_digest) !== entry.expected_canonical_utf8) return ["ACTION_LOG_CHAIN_INVALID"];
      const digest = jcsSha256(entry.logical_entry_without_entry_digest);
      if (digest !== entry.expected_entry_digest) return ["ACTION_LOG_CHAIN_INVALID"];
      previous = digest;
    }
  }
  return [];
}

function validateExportProjection(projection) {
  try {
    normalizeExportManifest(projection);
    return [];
  } catch {
    return ["MANIFEST_ORDER_OR_DIGEST_INVALID"];
  }
}

export const REGISTERED_RULES = Object.freeze([
  ...Array.from({ length: 18 }, (_, index) => `XOBJ-${String(index + 1).padStart(3, "0")}`),
  ...Array.from({ length: 6 }, (_, index) => `PASS-${String(index + 1).padStart(3, "0")}`),
  ...Array.from({ length: 4 }, (_, index) => `CONSENT-${String(index + 1).padStart(3, "0")}`),
  ...Array.from({ length: 4 }, (_, index) => `ACTION-${String(index + 1).padStart(3, "0")}`),
  ...Array.from({ length: 3 }, (_, index) => `MANIFEST-${String(index + 1).padStart(3, "0")}`),
  "LIMIT-001",
  "PATH-001"
]);

export function evaluateApplicationRecord(record) {
  const declared = record.fixture.rule_ids ?? (record.fixture.rule_id ? [record.fixture.rule_id] : []);
  const unknown = declared.filter((rule) => !REGISTERED_RULES.includes(rule));
  if (unknown.length) return ["UNKNOWN_APPLICATION_RULE"];
  const xobjRules = declared.filter((rule) => rule.startsWith("XOBJ-"));
  if (xobjRules.length) {
    if (xobjRules.length !== 1) return ["XOBJ_GRAPH_INPUT_MISSING"];
    try {
      return evaluateXobjThrough(xobjRules[0], materializeXobjRecord(record));
    } catch (error) {
      return [String(error.message).startsWith("XOBJ_") ? error.message : "XOBJ_GRAPH_MATERIALIZATION_FAILED"];
    }
  }
  if (record.source.includes("/action-log/")) return validateActionLog(record.fixture.instance);
  if (record.source.includes("/audit-manifest/")) return validateManifest(record.fixture.instance);
  if (record.source.includes("/audit-run/")) return validatePassGraph(record.fixture);
  if (record.source.includes("/consent-receipt/")) return validateConsent(record.fixture);
  if (record.source.includes("/limits/")) return validateLimit(record.fixture);
  if (record.source.includes("/export-manifest/")) return validateExportProjection(record.fixture.application_projection);
  if (record.source.includes("/digests/")) return validateDigestProjection(record.fixture);
  return [];
}

export function verifyAuditManifestDigest(manifest) {
  return digestWithExclusion(manifest, "manifest_digest.digest", normalizeAuditManifest);
}

export function verifyExportManifestDigest(manifest) {
  return digestWithExclusion(manifest, "manifest_digest.digest", normalizeExportManifest);
}

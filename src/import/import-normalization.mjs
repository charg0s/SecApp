import {
  digestWithExclusion,
  normalizeAuditManifest,
  normalizeExportManifest,
  profileDigest
} from "../../tools/lib/jcs.mjs";
import { reject } from "./import-errors.mjs";

const SCHEMA_ROOT = "https://schemas.secapp.dev/v1/";

export const ROLE_CONTRACT_KIND = Object.freeze({
  ActionLog: "ActionLog",
  AuditManifest: "AuditManifest",
  AuditPass: "AuditPass",
  AuditRun: "AuditRun",
  CollectorDefinition: "CollectorDefinition",
  CollectorExecution: "CollectorExecution",
  ConsentReceipt: "ConsentReceipt",
  ErrorObject: "ErrorObject",
  Evidence: "EvidenceReference",
  ExportManifest: "ExportManifest",
  Finding: "Finding",
  Observation: "Observation",
  RebootContinuationState: "RebootContinuationState",
  RedactionProfile: "RedactionProfile",
  RuleDefinition: "RuleDefinition"
});

const CONTRACT_FILE = Object.freeze({
  ActionLog: "action-log.schema.json",
  AuditManifest: "audit-manifest.schema.json",
  AuditPass: "audit-pass.schema.json",
  AuditRun: "audit-run.schema.json",
  CollectorDefinition: "collector-definition.schema.json",
  CollectorExecution: "collector-execution.schema.json",
  ConsentReceipt: "consent-receipt.schema.json",
  ErrorObject: "error-object.schema.json",
  EvidenceReference: "evidence-reference.schema.json",
  ExportManifest: "export-manifest.schema.json",
  Finding: "finding.schema.json",
  Observation: "observation.schema.json",
  RebootContinuationState: "reboot-continuation-state.schema.json",
  RedactionProfile: "redaction-profile.schema.json",
  RuleDefinition: "rule-definition.schema.json"
});

const CONTRACT_ID_FIELD = Object.freeze({
  ActionLog: "action_log_id",
  AuditManifest: "manifest_id",
  AuditPass: "pass_id",
  AuditRun: "run_id",
  CollectorDefinition: "collector_id",
  CollectorExecution: "execution_id",
  ConsentReceipt: "receipt_id",
  ErrorObject: "error_id",
  EvidenceReference: "evidence_id",
  ExportManifest: "export_id",
  Finding: "finding_id",
  Observation: "observation_id",
  RebootContinuationState: "state_id",
  RedactionProfile: "profile_id",
  RuleDefinition: "rule_id"
});

const SIGNATURES = Object.freeze([
  ["AuditRun", ["run_id", "audit_profile", "package_limits", "manifest_reference"]],
  ["AuditManifest", ["manifest_id", "run_state", "backend", "manifest_digest"]],
  ["ExportManifest", ["export_id", "source_manifest_digest", "omissions", "manifest_digest"]],
  ["ActionLog", ["action_log_id", "entries", "log_digest"]],
  ["AuditPass", ["pass_id", "kind", "collector_execution_ids", "integrity"]],
  ["CollectorDefinition", ["collector_id", "execution_context", "resource_limits", "integrity"]],
  ["CollectorExecution", ["execution_id", "collector_id", "observation_ids", "integrity"]],
  ["ConsentReceipt", ["receipt_id", "consent_type", "exact_scope", "revocation"]],
  ["ErrorObject", ["error_id", "code", "stage", "details_redacted"]],
  ["EvidenceReference", ["evidence_id", "observation_id", "logical_path", "file_digest"]],
  ["Finding", ["finding_id", "finding_kind", "rule_id", "severity"]],
  ["Observation", ["observation_id", "execution_id", "data_schema", "data"]],
  ["RebootContinuationState", ["state_id", "expected_run_id", "expected_next_stage", "authentication"]],
  ["RedactionProfile", ["profile_id", "class_actions", "field_rules", "profile_digest"]],
  ["RuleDefinition", ["rule_id", "expression", "finding_template", "integrity"]]
]);

export function schemaIdForContractKind(kind) {
  const file = CONTRACT_FILE[kind];
  if (!file) reject("IMPORT_CONTRACT_KIND_UNKNOWN", "Normalize", "Imported object kind is not recognized.");
  return `${SCHEMA_ROOT}${file}`;
}

export function identityForContract(kind, value) {
  const field = CONTRACT_ID_FIELD[kind];
  const identity = field && value?.[field];
  if (typeof identity !== "string" || identity.length === 0) {
    reject("IMPORT_CONTRACT_ID_INVALID", "Normalize", "Imported contract identity is missing or invalid.");
  }
  return identity;
}

export function detectContractKind(value) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    reject("IMPORT_JSON_ROOT_NOT_OBJECT", "Normalize", "Imported record is not an object.");
  }
  const matches = SIGNATURES.filter(([, fields]) => fields.every((field) => Object.hasOwn(value, field)));
  if (matches.length !== 1) reject("IMPORT_CONTRACT_KIND_UNKNOWN", "Normalize", "Imported object kind is unknown or ambiguous.");
  return matches[0][0];
}

export function assertRoleMatchesContract(role, kind) {
  if (ROLE_CONTRACT_KIND[role] !== kind) reject("IMPORT_MANIFEST_ROLE_MISMATCH", "Manifest", "Manifest role does not match member contract.");
}

export function assertNoExternalReferences(value) {
  const stack = [value];
  while (stack.length !== 0) {
    const current = stack.pop();
    if (Array.isArray(current)) {
      stack.push(...current);
      continue;
    }
    if (current === null || typeof current !== "object") continue;
    for (const [key, child] of Object.entries(current)) {
      if (typeof child === "string" && key === "$schema"
        && child !== "https://json-schema.org/draft/2020-12/schema") {
        reject("IMPORT_REMOTE_SCHEMA_FORBIDDEN", "Validate", "Remote or unknown schema declarations are forbidden.");
      }
      const localReference = typeof child === "string"
        && (child.startsWith(SCHEMA_ROOT) || (key === "data_schema" && child.startsWith("urn:secapp:")));
      if (typeof child === "string" && key === "$id" && !child.startsWith(SCHEMA_ROOT)) {
        reject("IMPORT_REMOTE_SCHEMA_FORBIDDEN", "Validate", "Non-local schema identifiers are forbidden.");
      }
      if (typeof child === "string" && ["$id", "$ref", "data_schema"].includes(key)
        && (/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(child) || child.startsWith("//")
          || child.startsWith("\\\\") || (key === "$ref" && child.startsWith("/")))
        && !localReference) {
        reject("IMPORT_EXTERNAL_REFERENCE_FORBIDDEN", "Validate", "External URL references are forbidden.");
      }
      stack.push(child);
    }
  }
}

function verifyActionLog(log) {
  const entries = [...log.entries].sort((left, right) => left.sequence_number - right.sequence_number);
  const actionIds = new Set();
  let previous = null;
  let priorTimestamp = null;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    let actual;
    try {
      actual = digestWithExclusion(entry, "entry_digest");
    } catch {
      reject("IMPORT_DIGEST_INVALID", "Integrity", "ActionLog entry digest could not be computed.");
    }
    if (entry.sequence_number !== index || entry.previous_entry_digest !== previous || actual !== entry.entry_digest.digest
      || entry.audit_run_id !== log.run_id || actionIds.has(entry.action_id)
      || (priorTimestamp !== null && entry.timestamp < priorTimestamp)) {
      reject("IMPORT_DIGEST_MISMATCH", "Integrity", "ActionLog entry digest or chain does not match.");
    }
    actionIds.add(entry.action_id);
    previous = actual;
    priorTimestamp = entry.timestamp;
  }
  const normalized = structuredClone(log);
  normalized.entries.sort((left, right) => left.sequence_number - right.sequence_number);
  if (digestWithExclusion(normalized, "log_digest.digest") !== log.log_digest.digest) {
    reject("IMPORT_DIGEST_MISMATCH", "Integrity", "ActionLog digest does not match.");
  }
}

export function verifyContractIntegrity(kind, value) {
  try {
    if (kind === "AuditManifest") {
      if (digestWithExclusion(value, "manifest_digest.digest", normalizeAuditManifest) !== value.manifest_digest.digest) {
        reject("IMPORT_DIGEST_MISMATCH", "Integrity", "AuditManifest digest does not match.");
      }
      const roles = new Set(value.entries.map((entry) => entry.role));
      if (!["ActionLog", "AuditPass", "AuditRun"].every((role) => roles.has(role))) {
        reject("IMPORT_MANIFEST_REQUIRED_ROLE_MISSING", "Integrity", "AuditManifest required roles are missing.");
      }
      const observed = Object.hasOwn(value.backend, "observed_identity");
      if (observed !== ["Found", "Started"].includes(value.backend.availability_state)) {
        reject("IMPORT_BACKEND_IDENTITY_STATE_CONFLICT", "Integrity", "Backend identity state is inconsistent.");
      }
      return;
    }
    if (kind === "ExportManifest") {
      if (digestWithExclusion(value, "manifest_digest.digest", normalizeExportManifest) !== value.manifest_digest.digest) {
        reject("IMPORT_DIGEST_MISMATCH", "Integrity", "ExportManifest digest does not match.");
      }
      return;
    }
    if (kind === "RedactionProfile") {
      if (profileDigest(value) !== value.profile_digest.digest) reject("IMPORT_DIGEST_MISMATCH", "Integrity", "RedactionProfile digest does not match.");
      return;
    }
    if (kind === "ActionLog") {
      verifyActionLog(value);
      return;
    }
    if (value.integrity?.object_digest !== undefined
      && digestWithExclusion(value, "integrity.object_digest") !== value.integrity.object_digest) {
      reject("IMPORT_DIGEST_MISMATCH", "Integrity", "Contract object digest does not match.");
    }
  } catch (error) {
    if (error?.code?.startsWith("IMPORT_")) throw error;
    reject("IMPORT_DIGEST_INVALID", "Integrity", "Contract digest could not be computed.");
  }
}

export function subjectFromRecord(record, additions = {}) {
  const contractKind = additions.contractKind ?? detectContractKind(record.value);
  return Object.freeze({
    contractKind,
    schemaId: schemaIdForContractKind(contractKind),
    value: record.value,
    byteSize: record.byteSize,
    fileDigest: record.fileDigest,
    recordIndex: record.recordIndex,
    ...additions
  });
}

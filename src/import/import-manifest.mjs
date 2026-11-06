import { createHash } from "node:crypto";
import { parseJsonObjectBytes } from "./import-json.mjs";
import { assertCanonicalLogicalPath } from "./import-path-policy.mjs";
import {
  ROLE_CONTRACT_KIND,
  assertNoExternalReferences,
  assertRoleMatchesContract,
  detectContractKind,
  subjectFromRecord,
  verifyContractIntegrity
} from "./import-normalization.mjs";
import { reject } from "./import-errors.mjs";

const OPAQUE_ROLES = new Set(["BackendOutput", "Report", "Schema"]);
const ID_FIELD = Object.freeze({
  ActionLog: "action_log_id",
  AuditManifest: "manifest_id",
  AuditPass: "pass_id",
  AuditRun: "run_id",
  CollectorDefinition: "collector_id",
  CollectorExecution: "execution_id",
  ConsentReceipt: "receipt_id",
  EvidenceReference: "evidence_id",
  ExportManifest: "export_id",
  Finding: "finding_id",
  Observation: "observation_id",
  RebootContinuationState: "state_id",
  RedactionProfile: "profile_id",
  RuleDefinition: "rule_id"
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireObject(value, code, message) {
  if (value === null || Array.isArray(value) || typeof value !== "object") reject(code, "Manifest", message);
  return value;
}

function indexKind(subjects, kind) {
  const field = ID_FIELD[kind];
  const result = new Map();
  for (const subject of subjects.filter((item) => item.contractKind === kind)) {
    const id = subject.value[field];
    if (typeof id !== "string" || result.has(id)) reject("IMPORT_REFERENCE_DUPLICATE_ID", "References", "Duplicate or invalid contract identity was rejected.");
    result.set(id, subject);
  }
  return result;
}

function exactIds(actual, expected) {
  return actual.size === expected.length && expected.every((id) => actual.has(id));
}

function integrityDigest(value) {
  return value?.integrity?.object_digest;
}

function validateRolePaths(subjects) {
  const expected = {
    AuditRun: (value) => "run.json",
    AuditPass: (value) => `passes/${value.pass_id}.json`,
    CollectorExecution: (value) => `executions/${value.execution_id}.json`,
    Observation: (value) => `observations/${value.observation_id}.json`,
    EvidenceReference: (value) => `evidence/${value.evidence_id}.json`,
    Finding: (value) => `findings/${value.finding_id}.json`,
    ActionLog: () => "action-log/action-log.json"
  };
  for (const subject of subjects) {
    const build = expected[subject.contractKind];
    if (build && subject.logicalPath !== build(subject.value)) {
      reject("IMPORT_MANIFEST_ROLE_PATH_MISMATCH", "References", "Manifest role path does not match the contract identity.");
    }
    if (subject.contractKind === "EvidenceReference" && subject.value.logical_path !== subject.logicalPath) {
      reject("IMPORT_MANIFEST_ROLE_PATH_MISMATCH", "References", "Evidence logical path does not match its manifest member.");
    }
  }
}

function validateObjectReferences(run, subjects) {
  const specifications = [
    ["execution_references", "CollectorExecution"],
    ["observation_references", "Observation"],
    ["evidence_references", "EvidenceReference"],
    ["finding_references", "Finding"]
  ];
  for (const [field, kind] of specifications) {
    const index = indexKind(subjects, kind);
    if (!exactIds(index, run[field].map((item) => item.object_id))) reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "AuditRun reference set does not match package members.");
    for (const reference of run[field]) {
      if (integrityDigest(index.get(reference.object_id).value) !== reference.object_digest) {
        reject("IMPORT_REFERENCE_DIGEST_MISMATCH", "References", "AuditRun reference digest does not match its member.");
      }
    }
  }
}

function validatePasses(run, subjects) {
  const passes = indexKind(subjects, "AuditPass");
  if (!exactIds(passes, run.pass_references.map((item) => item.pass_id))) reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "AuditRun pass references do not match package members.");
  const ordered = run.pass_references.map((reference) => passes.get(reference.pass_id));
  if (ordered.filter((subject) => subject.value.kind === "Standard").length !== 1 || ordered[0].value.kind !== "Standard") {
    reject("IMPORT_PASS_MODEL_INVALID", "References", "Audit package pass model is invalid.");
  }
  const optionalKinds = ordered.filter((subject) => subject.value.kind !== "Standard").map((subject) => subject.value.kind);
  if (new Set(optionalKinds).size !== optionalKinds.length) reject("IMPORT_PASS_MODEL_INVALID", "References", "Duplicate optional pass kind was rejected.");
  const ranks = { Standard: 0, Elevated: 1, RebootContinuation: 2, PostReboot: 3 };
  if (ordered.some((subject, index) => index > 0 && ranks[subject.value.kind] < ranks[ordered[index - 1].value.kind])) {
    reject("IMPORT_PASS_MODEL_INVALID", "References", "AuditPass kind order is invalid.");
  }
  const order = new Map(ordered.map((subject, index) => [subject.value.pass_id, index]));
  for (let index = 0; index < ordered.length; index += 1) {
    const pass = ordered[index].value;
    const reference = run.pass_references[index];
    if (pass.kind !== reference.kind || pass.privilege_class !== reference.privilege_class
      || ordered[index].logicalPath !== reference.logical_path || integrityDigest(pass) !== reference.object_digest) {
      reject("IMPORT_REFERENCE_DIGEST_MISMATCH", "References", "AuditPass reference does not match its member.");
    }
    if (pass.prerequisite_pass_ids.some((id) => !order.has(id) || order.get(id) >= index)) {
      reject("IMPORT_PASS_MODEL_INVALID", "References", "AuditPass prerequisite order is invalid.");
    }
  }
  return passes;
}

function validateGraphLinks(run, subjects, passes) {
  const executions = indexKind(subjects, "CollectorExecution");
  const observations = indexKind(subjects, "Observation");
  const evidence = indexKind(subjects, "EvidenceReference");
  const findings = indexKind(subjects, "Finding");
  const definitions = indexKind(subjects, "CollectorDefinition");
  const rules = indexKind(subjects, "RuleDefinition");
  const ownership = new Map();
  for (const passSubject of passes.values()) {
    const pass = passSubject.value;
    for (const id of pass.collector_execution_ids) {
      if (ownership.has(id) || !executions.has(id)) reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "CollectorExecution pass ownership is invalid.");
      ownership.set(id, pass.pass_id);
    }
  }
  for (const [id, subject] of executions) {
    const execution = subject.value;
    if (ownership.get(id) !== execution.pass_id || passes.get(execution.pass_id)?.value.privilege_class !== execution.privilege) {
      reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "CollectorExecution pass binding is invalid.");
    }
    const definition = definitions.get(execution.collector_id)?.value;
    if (!definition || definition.version !== execution.collector_version
      || definition.integrity.object_digest !== execution.collector_definition_digest) {
      reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "CollectorDefinition reference is invalid.");
    }
    for (const observationId of execution.observation_ids) {
      if (observations.get(observationId)?.value.execution_id !== id) reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "Observation execution link is invalid.");
    }
  }
  for (const [id, subject] of observations) {
    const observation = subject.value;
    const execution = executions.get(observation.execution_id)?.value;
    if (!execution || execution.observation_ids.filter((value) => value === id).length !== 1) reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "Observation execution reciprocity is invalid.");
    for (const evidenceId of observation.evidence_ids) {
      if (evidence.get(evidenceId)?.value.observation_id !== id) reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "Evidence observation link is invalid.");
    }
  }
  for (const [id, subject] of evidence) {
    const observation = observations.get(subject.value.observation_id)?.value;
    if (!observation || observation.evidence_ids.filter((value) => value === id).length !== 1) reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "Evidence observation reciprocity is invalid.");
  }
  for (const subject of findings.values()) {
    const finding = subject.value;
    const rule = rules.get(finding.rule_id)?.value;
    if (!rule || rule.version !== finding.rule_version || rule.integrity.object_digest !== finding.rule_definition_digest
      || finding.observation_ids.some((id) => !observations.has(id)) || finding.evidence_ids.some((id) => !evidence.has(id))) {
      reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "Finding references are invalid.");
    }
  }
  validateObjectReferences(run, subjects);
}

export function prepareAuditPackage(zip, limits) {
  const archiveByPath = new Map(zip.entries.map((entry) => [entry.name, entry]));
  const manifestEntry = archiveByPath.get("manifest.json");
  if (!manifestEntry) reject("IMPORT_MANIFEST_REQUIRED", "Manifest", "The restricted audit-package profile requires manifest.json.");
  const parsedManifest = parseJsonObjectBytes(manifestEntry.bytes, limits, "manifest.json").records[0];
  const manifestKind = detectContractKind(parsedManifest.value);
  if (manifestKind !== "AuditManifest") reject("IMPORT_MANIFEST_INVALID", "Manifest", "manifest.json is not an AuditManifest.");
  const manifest = requireObject(parsedManifest.value, "IMPORT_MANIFEST_INVALID", "AuditManifest is invalid.");
  if (!Array.isArray(manifest.entries) || manifest.entries.length > limits.maxManifestEntries) {
    reject("IMPORT_MANIFEST_INVALID", "Manifest", "AuditManifest entries are absent or exceed the limit.");
  }
  const subjects = [subjectFromRecord(parsedManifest, { contractKind: "AuditManifest", logicalPath: "manifest.json", role: "AuditManifest" })];
  const memberIds = new Set();
  const listedPaths = new Set();
  let opaqueMemberCount = 0;
  for (const rawMember of manifest.entries) {
    const member = requireObject(rawMember, "IMPORT_MANIFEST_INVALID", "AuditManifest member is invalid.");
    if (typeof member.member_id !== "string" || memberIds.has(member.member_id)) reject("IMPORT_MANIFEST_DUPLICATE_MEMBER", "Manifest", "Duplicate manifest member ID was rejected.");
    memberIds.add(member.member_id);
    assertCanonicalLogicalPath(member.logical_path);
    if (member.logical_path === "manifest.json" || listedPaths.has(member.logical_path)) reject("IMPORT_MANIFEST_DUPLICATE_PATH", "Manifest", "Duplicate manifest path was rejected.");
    listedPaths.add(member.logical_path);
    const archiveEntry = archiveByPath.get(member.logical_path);
    if (!archiveEntry) reject("IMPORT_MANIFEST_MEMBER_MISSING", "Manifest", "A manifest member is missing from the archive.");
    if (member.size_bytes !== archiveEntry.bytes.length || member.file_digest?.digest !== sha256(archiveEntry.bytes)) {
      reject("IMPORT_FILE_DIGEST_MISMATCH", "Integrity", "Manifest member size or FileDigest does not match stored bytes.");
    }
    const contractKind = ROLE_CONTRACT_KIND[member.role];
    if (contractKind) {
      if (member.media_type !== "application/json") reject("IMPORT_MANIFEST_MEDIA_TYPE_INVALID", "Manifest", "Contract members must use application/json.");
      const record = parseJsonObjectBytes(archiveEntry.bytes, limits, "package member").records[0];
      const detected = detectContractKind(record.value);
      assertRoleMatchesContract(member.role, detected);
      assertNoExternalReferences(record.value);
      subjects.push(subjectFromRecord(record, {
        contractKind,
        logicalPath: member.logical_path,
        memberId: member.member_id,
        role: member.role,
        privacyClass: member.privacy_class
      }));
    } else if (OPAQUE_ROLES.has(member.role)) {
      opaqueMemberCount += 1;
      if (member.role === "Schema") {
        const record = parseJsonObjectBytes(archiveEntry.bytes, limits, "schema member").records[0];
        assertNoExternalReferences(record.value);
      }
    } else {
      reject("IMPORT_MANIFEST_ROLE_UNSUPPORTED", "Manifest", "Manifest role is unsupported by this import profile.", "Unsupported");
    }
  }
  if (archiveByPath.size !== listedPaths.size + 1 || [...archiveByPath.keys()].some((name) => name !== "manifest.json" && !listedPaths.has(name))) {
    reject("IMPORT_MANIFEST_MEMBERSHIP_MISMATCH", "Manifest", "Archive membership is not exactly described by AuditManifest.");
  }
  return Object.freeze({ manifest, subjects: Object.freeze(subjects), opaqueMemberCount, zip });
}

export function finalizeAuditPackage(prepared) {
  const { manifest, subjects } = prepared;
  for (const subject of subjects) verifyContractIntegrity(subject.contractKind, subject.value);
  validateRolePaths(subjects);
  const runs = subjects.filter((item) => item.contractKind === "AuditRun");
  const logs = subjects.filter((item) => item.contractKind === "ActionLog");
  if (runs.length !== 1 || logs.length !== 1) reject("IMPORT_MANIFEST_REQUIRED_ROLE_MISSING", "References", "Audit package requires exactly one AuditRun and ActionLog.");
  const run = runs[0].value;
  const log = logs[0].value;
  if (manifest.run_id !== run.run_id || log.run_id !== run.run_id
    || subjects.some((subject) => ["AuditPass", "CollectorExecution", "Observation", "EvidenceReference", "Finding"].includes(subject.contractKind)
      && subject.value.run_id !== run.run_id)
    || subjects.some((subject) => subject.contractKind === "ConsentReceipt" && subject.value.audit_run_id !== run.run_id)
    || subjects.some((subject) => subject.contractKind === "RebootContinuationState" && subject.value.expected_run_id !== run.run_id)) {
    reject("IMPORT_RUN_ID_MISMATCH", "References", "Cross-object run identity does not match.");
  }
  if (run.manifest_reference.manifest_id !== manifest.manifest_id || run.manifest_reference.logical_path !== "manifest.json") {
    reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "AuditRun manifest reference is invalid.");
  }
  if (run.action_log_reference.action_log_id !== log.action_log_id || run.action_log_reference.logical_path !== logs[0].logicalPath
    || run.action_log_reference.log_digest !== log.log_digest.digest
    || manifest.action_log_reference.action_log_id !== log.action_log_id
    || manifest.action_log_reference.logical_path !== logs[0].logicalPath
    || manifest.action_log_reference.log_digest !== log.log_digest.digest) {
    reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "ActionLog references are invalid.");
  }
  const observed = Object.hasOwn(manifest.backend, "observed_identity");
  if (observed !== ["Found", "Started"].includes(manifest.backend.availability_state)) {
    reject("IMPORT_BACKEND_IDENTITY_STATE_CONFLICT", "References", "Backend identity state is inconsistent.");
  }
  const passes = validatePasses(run, subjects);
  validateGraphLinks(run, subjects, passes);
  const consents = indexKind(subjects, "ConsentReceipt");
  if (!exactIds(consents, run.consent_receipt_ids)) reject("IMPORT_REFERENCE_SET_MISMATCH", "References", "Consent receipt references do not match package members.");
  for (const entry of log.entries) if (entry.audit_run_id !== run.run_id) reject("IMPORT_RUN_ID_MISMATCH", "References", "ActionLog run identity does not match.");
  return prepared;
}

import { types } from "node:util";
import { digestWithExclusion, jcsSha256 } from "./jcs.mjs";

// Development-only pure model. All supplied identities, confirmation and events
// are hypotheses, never authenticated evidence or authority to modify a host.
export const MAINTENANCE_OPERATIONS = Object.freeze(["Install", "Update", "EnrollBackend", "Repair", "Uninstall"]);
export const DEPLOYMENT_EVENTS = Object.freeze([
  "Prepare", "Stage", "Verify", "BeginPublish", "Commit", "BeginCleanup", "Finish",
  "Cancel", "Fail", "Crash", "Busy", "TrustUnavailable", "RebootRequired",
  "RollbackUnavailable", "InconsistentState", "CleanupFailed"
]);
export const MODEL_LIMITS = Object.freeze({ events: 32, used_nonces: 64, confirmation_seconds: 300 });
const STATES = {
  Requested: ["Prepare", "Prepared"], Prepared: ["Stage", "Staged"],
  Staged: ["Verify", "Verified"], Verified: ["BeginPublish", "PublishPending"],
  PublishPending: ["Commit", "Committed"], Committed: ["BeginCleanup", "CleanupPending"],
  CleanupPending: ["Finish", "Completed"]
};
const TUPLE_KEYS = ["app_id", "supervisor_id", "backend_id", "policy_id", "compatibility_id", "security_epoch", "manifest_digest", "policy_digest"];
const DIGEST = /^[0-9a-f]{64}$/u;
const ID = /^synthetic-[a-z0-9][a-z0-9-]{0,53}$/u;
const MACHINES = ["synthetic-machine-a", "synthetic-machine-b"];
const EFFECTS = Object.freeze({
  installation_enabled: false, backend_execution_enabled: false, uac_enabled: false,
  network_enabled: false, reboot_enabled: false, user_data_deletion_enabled: false,
  automatic_recovery_enabled: false, filesystem_writes_enabled: false
});

export class DeploymentModelInputError extends Error {
  constructor() {
    super("Invalid deployment-model data or event sequence.");
    this.name = "DeploymentModelInputError";
    this.code = "DEPLOYMENT_MODEL_INPUT_INVALID";
  }
}
function invalid() { throw new DeploymentModelInputError(); }
function check(condition) { if (!condition) invalid(); }
function record(value, keys) {
  check(value !== null && typeof value === "object" && !types.isProxy(value) && !Array.isArray(value));
  check([Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const actual = Reflect.ownKeys(value);
  check(actual.length === keys.length);
  for (const key of actual) {
    check(typeof key === "string" && keys.includes(key));
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    check(descriptor.enumerable && Object.hasOwn(descriptor, "value"));
  }
}
function text(value, pattern) {
  check(typeof value === "string" && value.length <= 64 && !/[\r\n]/u.test(value) && pattern.test(value));
}
function integer(value) { check(Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)); }
function member(value, values) { check(typeof value === "string" && values.includes(value)); }
function array(value, limit, validate) {
  check(value !== null && typeof value === "object" && !types.isProxy(value) && Array.isArray(value));
  check(Object.getPrototypeOf(value) === Array.prototype && value.length <= limit);
  check(Reflect.ownKeys(value).length === value.length + 1);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    check(descriptor && descriptor.enumerable && Object.hasOwn(descriptor, "value"));
    validate(descriptor.value);
  }
}
function timestamp(value) {
  text(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u);
  const milliseconds = Date.parse(value);
  check(Number.isFinite(milliseconds) && new Date(milliseconds).toISOString().replace(".000Z", "Z") === value);
  return milliseconds;
}
function tuple(value) {
  if (value === null) return;
  record(value, TUPLE_KEYS);
  for (const key of ["app_id", "supervisor_id", "policy_id", "compatibility_id"]) text(value[key], ID);
  if (value.backend_id !== null) text(value.backend_id, ID);
  integer(value.security_epoch);
  text(value.manifest_digest, DIGEST);
  text(value.policy_digest, DIGEST);
}
function snapshot(value) {
  record(value, ["generation", "security_floor", "selection"]);
  integer(value.generation);
  integer(value.security_floor);
  tuple(value.selection);
}
function intent(value) {
  record(value, ["operation", "expected_generation", "next_generation", "desired"]);
  member(value.operation, MAINTENANCE_OPERATIONS);
  integer(value.expected_generation);
  integer(value.next_generation);
  tuple(value.desired);
}
function binding(value) {
  record(value, ["machine_id", "snapshot", "intent"]);
  member(value.machine_id, MACHINES);
  snapshot(value.snapshot);
  intent(value.intent);
}
export function maintenanceBindingDigest(value) {
  binding(value);
  return jcsSha256(value);
}
function scenario(value) {
  record(value, ["schema_version", "model_kind", "privacy_class", "provenance", "simulated_at", "machine_id", "snapshot", "intent", "confirmation", "used_nonces", "events"]);
  check(value.schema_version === "1.0.0" && value.model_kind === "DeploymentScenario");
  check(value.privacy_class === "PublicSynthetic" && value.provenance === "SyntheticModelOnly");
  timestamp(value.simulated_at);
  binding({ machine_id: value.machine_id, snapshot: value.snapshot, intent: value.intent });
  if (value.confirmation !== null) {
    const receipt = value.confirmation;
    record(receipt, ["kind", "decision", "operation", "machine_id", "expected_generation", "binding_digest", "nonce", "issued_at", "expires_at"]);
    check(receipt.kind === "SyntheticMaintenanceConfirmation");
    member(receipt.decision, ["Approved", "Declined"]);
    member(receipt.operation, MAINTENANCE_OPERATIONS);
    member(receipt.machine_id, MACHINES);
    integer(receipt.expected_generation);
    text(receipt.binding_digest, DIGEST);
    text(receipt.nonce, ID);
    timestamp(receipt.issued_at);
    timestamp(receipt.expires_at);
  }
  array(value.used_nonces, MODEL_LIMITS.used_nonces, (item) => text(item, ID));
  check(new Set(value.used_nonces).size === value.used_nonces.length);
  array(value.events, MODEL_LIMITS.events, (item) => member(item, DEPLOYMENT_EVENTS));
}
function same(left, right) { return jcsSha256(left) === jcsSha256(right); }
function scopeReason(current, request) {
  const desired = request.desired;
  switch (request.operation) {
    case "Install": return current === null && desired !== null && desired.backend_id === null ? null : "OperationScopeMismatch";
    case "Uninstall": return current !== null && desired === null ? null : "OperationScopeMismatch";
    case "Repair": return current !== null && same(current, desired) ? null : "OperationScopeMismatch";
    case "Update": return current !== null && desired !== null && current.backend_id === desired.backend_id
      && current.manifest_digest !== desired.manifest_digest ? null : "OperationScopeMismatch";
    case "EnrollBackend": {
      if (current === null || desired === null || current.backend_id !== null || desired.backend_id === null) return "OperationScopeMismatch";
      // The full manifest changes when the backend is added, but unrelated
      // application, supervisor, policy, compatibility and epoch may not change.
      const unchanged = TUPLE_KEYS.filter((key) => !["backend_id", "manifest_digest"].includes(key));
      return unchanged.every((key) => current[key] === desired[key])
        && current.manifest_digest !== desired.manifest_digest ? null : "OperationScopeMismatch";
    }
    default: invalid();
  }
}
function admissionReason(input) {
  const { snapshot: current, intent: request, confirmation: receipt } = input;
  if (current.generation === Number.MAX_SAFE_INTEGER || request.expected_generation !== current.generation
    || request.next_generation !== current.generation + 1) return "GenerationMismatch";
  const scope = scopeReason(current.selection, request);
  if (scope) return scope;
  if (request.desired !== null && request.desired.security_epoch < Math.max(current.security_floor, current.selection?.security_epoch ?? 0)) return "SecurityEpochRejected";
  if (receipt === null) return "ConfirmationMissing";
  if (receipt.decision !== "Approved") return "ConfirmationDeclined";
  if (receipt.operation !== request.operation || receipt.machine_id !== input.machine_id
    || receipt.expected_generation !== current.generation
    || receipt.binding_digest !== maintenanceBindingDigest({ machine_id: input.machine_id, snapshot: current, intent: request })) return "ConfirmationBindingMismatch";
  const now = timestamp(input.simulated_at);
  const issued = timestamp(receipt.issued_at);
  const expires = timestamp(receipt.expires_at);
  if (!(issued <= now && now < expires && expires > issued && expires - issued <= MODEL_LIMITS.confirmation_seconds * 1000)) return "ConfirmationTimeRejected";
  if (input.used_nonces.includes(receipt.nonce)) return "ConfirmationReplay";
  return null;
}
function freeze(value) {
  if (value !== null && typeof value === "object") {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

export function simulateDeployment(value) {
  scenario(value);
  // Copy only after bounded, accessor/proxy-free validation. Never freeze caller data.
  const input = JSON.parse(JSON.stringify(value));
  const result = {
    schema_version: "1.0.0", model_kind: "DeploymentProjection",
    privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly",
    simulated_at: input.simulated_at, scenario_digest: jcsSha256(input),
    operation: input.intent.operation, state: "Requested", reason: "None",
    states: ["Requested"], projected_snapshot: input.snapshot,
    minimum_security_floor: input.snapshot.security_floor,
    confirmation_consumed_in_model: false, outcome: "NotCommitted",
    effects: { ...EFFECTS }, installer_status: "NotImplemented", launch_status: "Blocked",
    result_digest: ""
  };
  const move = (state, reason = "None") => {
    result.state = state;
    result.reason = reason;
    result.states.push(state);
  };
  const finish = () => {
    result.result_digest = digestWithExclusion(result, "result_digest");
    return freeze(result);
  };
  if (input.snapshot.selection !== null && input.snapshot.selection.security_epoch < input.snapshot.security_floor) {
    move("RecoveryRequired", "SnapshotBelowFloor");
    result.projected_snapshot = null;
    result.outcome = "Unknown";
    return finish();
  }
  const rejected = admissionReason(input);
  if (rejected) {
    move("Rejected", rejected);
    return finish();
  }
  let terminal = false;
  for (const event of input.events) {
    if (terminal) invalid();
    const expected = STATES[result.state];
    if (event === expected?.[0]) {
      if (event === "Prepare") result.confirmation_consumed_in_model = true;
      if (event === "BeginPublish") {
        // An uncertain publish cannot safely assume that an advanced floor was
        // not persisted. Recovery must preserve at least this conservative floor.
        result.minimum_security_floor = Math.max(result.minimum_security_floor,
          input.snapshot.selection?.security_epoch ?? 0, input.intent.desired?.security_epoch ?? 0);
      }
      if (event === "Commit") {
        result.projected_snapshot = {
          generation: input.intent.next_generation,
          security_floor: result.minimum_security_floor, selection: input.intent.desired
        };
        result.outcome = input.intent.desired === null ? "Uninstalled"
          : input.intent.desired.backend_id === null ? "BackendNotEnrolled" : "InstalledLaunchBlocked";
      }
      move(expected[1]);
      terminal = result.state === "Completed";
      continue;
    }
    if (["Prepare", "Stage", "Verify", "BeginPublish", "Commit", "BeginCleanup", "Finish"].includes(event)) invalid();
    if (event === "CleanupFailed" && !["Committed", "CleanupPending"].includes(result.state)) invalid();
    terminal = true;
    if (event === "InconsistentState" || result.state === "PublishPending"
      || (event === "TrustUnavailable" && ["Committed", "CleanupPending"].includes(result.state))) {
      move("RecoveryRequired", "ExplicitRecoveryRequired");
      result.projected_snapshot = null;
      result.outcome = "Unknown";
    } else if (["Committed", "CleanupPending"].includes(result.state)) {
      move("CleanupPending", "CleanupIncomplete");
    } else if (event === "Cancel") {
      move("Cancelled", "CancelledBeforePublish");
    } else if (["Busy", "RebootRequired"].includes(event)) {
      move("Deferred", event);
    } else {
      move("Rejected", event);
    }
  }
  // PublishPending is already an ambiguous selection, even without a failure
  // event. A projection must not present the old selection as current here.
  if (result.state === "PublishPending") {
    result.projected_snapshot = null;
    result.outcome = "Unknown";
  }
  return finish();
}

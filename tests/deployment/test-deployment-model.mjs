import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createSchemaRegistry } from "../../tools/lib/schema-registry.mjs";
import { digestWithExclusion, jcsSha256 } from "../../tools/lib/jcs.mjs";
import { simulateDeployment, maintenanceBindingDigest, MAINTENANCE_OPERATIONS, DEPLOYMENT_EVENTS, MODEL_LIMITS } from "../../tools/lib/deployment-model.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const registry = createSchemaRegistry(root);
const inputSchema = JSON.parse(await readFile(path.join(root, "schemas/development/deployment-scenario.schema.json"), "utf8"));
const outputSchema = JSON.parse(await readFile(path.join(root, "schemas/development/deployment-projection.schema.json"), "utf8"));
assert.equal(registry.ajv.validateSchema(inputSchema), true);
assert.equal(registry.ajv.validateSchema(outputSchema), true);
registry.ajv.addSchema(inputSchema);
const validateInput = registry.ajv.getSchema(inputSchema.$id);
const validateOutput = registry.ajv.compile(outputSchema);
assert.deepEqual(registry.warnings, []);
const clone = (value) => structuredClone(value);
const hash = (value) => jcsSha256({ synthetic_label: value });
const progress = ["Prepare", "Stage", "Verify", "BeginPublish", "Commit", "BeginCleanup", "Finish"];
const phases = ["Requested", "Prepared", "Staged", "Verified", "PublishPending", "Committed", "CleanupPending", "Completed"];
const requiredIds = Object.freeze([
  "DP-001", "DP-002", "DP-003", "DP-004", "DP-005", "DP-006", "DP-007", "DP-008", "DP-009", "DP-010",
  "DP-011", "DP-012", "DP-013", "DP-014", "DP-015", "DP-016", "DP-017", "DP-018", "DP-019", "DP-020",
  "DP-021", "DP-022", "DP-023", "DP-024", "DP-025", "DP-026", "DP-027", "DP-028", "DP-029", "DP-030",
  "DP-031", "DP-032", "DP-033", "DP-034", "DP-035", "DP-036", "DP-037", "DP-038", "DP-039", "DP-040"
]);
const cases = [];
function vector(id, name, run) { cases.push({ id, name, run }); }
function tuple() {
  return { app_id: "synthetic-app-v1", supervisor_id: "synthetic-supervisor-v1", backend_id: null,
    policy_id: "synthetic-policy-v1", compatibility_id: "synthetic-contract-v1", security_epoch: 4,
    manifest_digest: hash("manifest-v1"), policy_digest: hash("policy-v1") };
}
function confirm(input) {
  input.confirmation = {
    kind: "SyntheticMaintenanceConfirmation", decision: "Approved", operation: input.intent.operation,
    machine_id: input.machine_id, expected_generation: input.intent.expected_generation,
    binding_digest: maintenanceBindingDigest({ machine_id: input.machine_id, snapshot: input.snapshot, intent: input.intent }),
    nonce: "synthetic-nonce-a", issued_at: "2026-09-29T12:00:00Z", expires_at: "2026-09-29T12:05:00Z"
  };
  return input;
}
function scenario(operation = "Update", events = progress) {
  const selection = operation === "Install" ? null : tuple();
  let desired = tuple();
  if (operation === "Update") desired = { ...desired, app_id: "synthetic-app-v2", security_epoch: 5, manifest_digest: hash("manifest-v2") };
  if (operation === "EnrollBackend") desired = { ...desired, backend_id: "synthetic-backend-v1", manifest_digest: hash("manifest-with-backend") };
  if (operation === "Uninstall") desired = null;
  return confirm({ schema_version: "1.0.0", model_kind: "DeploymentScenario", privacy_class: "PublicSynthetic",
    provenance: "SyntheticModelOnly", simulated_at: "2026-09-29T12:01:00Z", machine_id: "synthetic-machine-a",
    snapshot: { generation: 7, security_floor: 4, selection },
    intent: { operation, expected_generation: 7, next_generation: 8, desired },
    confirmation: null, used_nonces: [], events: [...events] });
}
function run(input) {
  assert.equal(validateInput(input), true, JSON.stringify(validateInput.errors));
  const result = simulateDeployment(input);
  assert.equal(validateOutput(result), true, JSON.stringify(validateOutput.errors));
  assert.equal(result.result_digest, digestWithExclusion(result, "result_digest"));
  assert.equal(result.scenario_digest, jcsSha256(input));
  assert.equal(result.installer_status, "NotImplemented");
  assert.equal(result.launch_status, "Blocked");
  assert.ok(Object.values(result.effects).every((value) => value === false));
  return result;
}
function reject(input, reason) {
  const result = run(input);
  assert.equal(result.state, "Rejected");
  assert.equal(result.reason, reason);
  assert.equal(result.confirmation_consumed_in_model, false);
  assert.deepEqual(result.projected_snapshot, input.snapshot);
}
function invalid(input) {
  assert.throws(() => simulateDeployment(input), { code: "DEPLOYMENT_MODEL_INPUT_INVALID" });
}

vector("DP-001", "fixed operation registry and positive completion for every operation", () => {
  assert.deepEqual(MAINTENANCE_OPERATIONS, ["Install", "Update", "EnrollBackend", "Repair", "Uninstall"]);
  const outcomes = ["BackendNotEnrolled", "BackendNotEnrolled", "InstalledLaunchBlocked", "BackendNotEnrolled", "Uninstalled"];
  MAINTENANCE_OPERATIONS.forEach((operation, index) => {
    const input = scenario(operation);
    const result = run(input);
    assert.equal(result.state, "Completed");
    assert.equal(result.outcome, outcomes[index]);
    assert.deepEqual(result.states, phases);
    assert.deepEqual(result.projected_snapshot, { generation: 8,
      security_floor: operation === "Update" ? 5 : 4, selection: input.intent.desired });
  });
});
vector("DP-002", "every normal prefix is schema-valid without execution authority", () => {
  phases.forEach((phase, index) => {
    const result = run(scenario("Update", progress.slice(0, index)));
    assert.equal(result.state, phase);
    assert.equal(result.confirmation_consumed_in_model, index > 0);
    if (phase === "PublishPending") assert.equal(result.projected_snapshot, null);
  });
});
vector("DP-003", "deterministic digests and deep immutability without freezing callers", () => {
  const input = scenario();
  const before = clone(input);
  const result = run(input);
  assert.deepEqual(result, run(clone(input)));
  assert.deepEqual(input, before);
  assert.equal(Object.isFrozen(input), false);
  function frozen(value) {
    if (value !== null && typeof value === "object") {
      assert.equal(Object.isFrozen(value), true);
      Object.values(value).forEach(frozen);
    }
  }
  frozen(result);
  input.intent.desired.app_id = "synthetic-mutated";
  assert.equal(result.projected_snapshot.selection.app_id, "synthetic-app-v2");
  assert.throws(() => { result.effects.installation_enabled = true; }, TypeError);
  assert.ok(Object.isFrozen(MAINTENANCE_OPERATIONS) && Object.isFrozen(DEPLOYMENT_EVENTS) && Object.isFrozen(MODEL_LIMITS));
});
vector("DP-004", "stale and skipped generation rejected", () => {
  for (const field of ["expected_generation", "next_generation"]) {
    const input = scenario(); input.intent[field] += 1;
    reject(confirm(input), "GenerationMismatch");
  }
});
vector("DP-005", "generation arithmetic rejects overflow, accepts last safe increment", () => {
  const input = scenario();
  input.snapshot.generation = Number.MAX_SAFE_INTEGER;
  input.intent.expected_generation = input.intent.next_generation = Number.MAX_SAFE_INTEGER;
  reject(confirm(input), "GenerationMismatch");
  input.snapshot.generation -= 1; input.intent.expected_generation -= 1;
  assert.equal(run(confirm(input)).projected_snapshot.generation, Number.MAX_SAFE_INTEGER);
});
vector("DP-006", "downgrade rejected even when signed-looking digest changes", () => {
  const input = scenario(); input.intent.desired.security_epoch = 3;
  reject(confirm(input), "SecurityEpochRejected");
  input.snapshot.security_floor = 1;
  reject(confirm(input), "SecurityEpochRejected");
});
vector("DP-007", "below-floor current selection requires recovery, never fallback", () => {
  const input = scenario(); input.snapshot.security_floor = 6;
  const result = run(confirm(input));
  assert.equal(result.state, "RecoveryRequired");
  assert.equal(result.reason, "SnapshotBelowFloor");
  assert.equal(result.projected_snapshot, null);
  assert.equal(result.minimum_security_floor, 6);
  assert.equal(result.confirmation_consumed_in_model, false);
});
vector("DP-008", "uninstall preserves floor and reinstall cannot reset it", () => {
  const uninstalled = run(scenario("Uninstall"));
  const input = scenario("Install"); input.snapshot = clone(uninstalled.projected_snapshot);
  input.intent.expected_generation = 8; input.intent.next_generation = 9;
  input.intent.desired.security_epoch = 3;
  reject(confirm(input), "SecurityEpochRejected");
  input.intent.desired.security_epoch = 4;
  assert.equal(run(confirm(input)).projected_snapshot.security_floor, 4);
});
vector("DP-009", "install cannot overwrite an installation or enroll backend", () => {
  const input = scenario("Install"); input.snapshot.selection = tuple();
  reject(confirm(input), "OperationScopeMismatch");
  input.snapshot.selection = null; input.intent.desired.backend_id = "synthetic-backend-v1";
  reject(confirm(input), "OperationScopeMismatch");
});
vector("DP-010", "update cannot add, replace or remove backend", () => {
  for (const [oldId, newId] of [[null, "synthetic-backend-v1"], ["synthetic-backend-v1", null], ["synthetic-backend-v1", "synthetic-backend-v2"]]) {
    const input = scenario(); input.snapshot.selection.backend_id = oldId; input.intent.desired.backend_id = newId;
    reject(confirm(input), "OperationScopeMismatch");
  }
  const input = scenario(); input.snapshot.selection.backend_id = input.intent.desired.backend_id = "synthetic-backend-v1";
  assert.equal(run(confirm(input)).outcome, "InstalledLaunchBlocked");
});
vector("DP-011", "repair cannot replace any identity or lower epoch", () => {
  for (const field of Object.keys(tuple())) {
    const input = scenario("Repair");
    input.intent.desired[field] = field === "security_epoch" ? 3 : field.endsWith("digest") ? hash("other") : "synthetic-other";
    reject(confirm(input), "OperationScopeMismatch");
  }
});
vector("DP-012", "backend enrollment cannot alter unrelated components", () => {
  for (const field of ["app_id", "supervisor_id", "policy_id", "policy_digest", "compatibility_id", "security_epoch"]) {
    const input = scenario("EnrollBackend");
    input.intent.desired[field] = field === "security_epoch" ? 5 : field.endsWith("digest") ? hash("other") : "synthetic-other";
    reject(confirm(input), "OperationScopeMismatch");
  }
  const input = scenario("EnrollBackend"); input.snapshot.selection.backend_id = "synthetic-backend-v0";
  reject(confirm(input), "OperationScopeMismatch");
});
vector("DP-013", "operation presence and full-manifest binding cannot be bypassed", () => {
  for (const operation of ["Update", "Repair", "EnrollBackend", "Uninstall"]) {
    const input = scenario(operation); input.snapshot.selection = null;
    reject(confirm(input), "OperationScopeMismatch");
  }
  const input = scenario("Uninstall"); input.intent.desired = tuple();
  reject(confirm(input), "OperationScopeMismatch");
  for (const operation of ["Update", "EnrollBackend"]) {
    const item = scenario(operation); item.intent.desired.manifest_digest = item.snapshot.selection.manifest_digest;
    reject(confirm(item), "OperationScopeMismatch");
  }
});
vector("DP-014", "missing or declined confirmation is not authority", () => {
  const input = scenario(); input.confirmation = null; reject(input, "ConfirmationMissing");
  confirm(input); input.confirmation.decision = "Declined"; reject(input, "ConfirmationDeclined");
});
vector("DP-015", "operation, machine, generation and digest substitutions rejected", () => {
  for (const [field, value] of [["operation", "Repair"], ["machine_id", "synthetic-machine-b"], ["expected_generation", 6], ["binding_digest", hash("other")]]) {
    const input = scenario(); input.confirmation[field] = value;
    reject(input, "ConfirmationBindingMismatch");
  }
});
vector("DP-016", "every bound identity field invalidates old confirmation", () => {
  for (const field of Object.keys(tuple())) {
    const input = scenario();
    if (field === "backend_id") {
      input.snapshot.selection.backend_id = input.intent.desired.backend_id = "synthetic-backend-v1";
    } else input.intent.desired[field] = field === "security_epoch" ? 6 : field.endsWith("digest") ? hash("other") : "synthetic-other";
    reject(input, "ConfirmationBindingMismatch");
  }
  const input = scenario(); input.snapshot.security_floor = 3;
  reject(input, "ConfirmationBindingMismatch");
});
vector("DP-017", "expired, future, inverted and overlong approval windows rejected", () => {
  for (const [issued, expires, now] of [
    ["12:00:00", "12:05:00", "12:05:00"], ["12:02:00", "12:05:00", "12:01:00"],
    ["12:00:00", "11:59:59", "12:01:00"], ["12:00:00", "12:05:01", "12:01:00"]
  ]) {
    const input = scenario(); input.confirmation.issued_at = `2026-09-29T${issued}Z`;
    input.confirmation.expires_at = `2026-09-29T${expires}Z`; input.simulated_at = `2026-09-29T${now}Z`;
    reject(input, "ConfirmationTimeRejected");
  }
  const input = scenario(); input.simulated_at = input.confirmation.issued_at;
  assert.equal(run(input).state, "Completed");
});
vector("DP-018", "modeled nonce replay rejected; no real replay-store claim", () => {
  const input = scenario(); input.used_nonces = [input.confirmation.nonce];
  reject(input, "ConfirmationReplay");
  input.used_nonces = ["synthetic-nonce-b"];
  assert.deepEqual(run(input), run(input));
});
vector("DP-019", "cancellation at each boundary preserves or blocks selection correctly", () => {
  for (let index = 0; index < progress.length; index += 1) {
    const input = scenario("Update", [...progress.slice(0, index), "Cancel"]);
    const result = run(input);
    assert.equal(result.state, index < 4 ? "Cancelled" : index === 4 ? "RecoveryRequired" : "CleanupPending");
    if (index < 4) assert.deepEqual(result.projected_snapshot, input.snapshot);
    else if (index === 4) { assert.equal(result.projected_snapshot, null); assert.equal(result.minimum_security_floor, 5); }
    else assert.equal(result.projected_snapshot.generation, 8);
  }
});
vector("DP-020", "failure and crash at every boundary never fabricate rollback", () => {
  for (const event of ["Fail", "Crash"]) for (let index = 0; index < progress.length; index += 1) {
    const input = scenario("Update", [...progress.slice(0, index), event]); const result = run(input);
    assert.equal(result.state, index < 4 ? "Rejected" : index === 4 ? "RecoveryRequired" : "CleanupPending");
    if (index < 4) assert.deepEqual(result.projected_snapshot, input.snapshot);
    else if (index === 4) assert.equal(result.projected_snapshot, null);
    else assert.equal(result.projected_snapshot.selection.security_epoch, 5);
  }
});
vector("DP-021", "Busy and reboot-required defer without termination or reboot", () => {
  for (const event of ["Busy", "RebootRequired"]) for (let index = 0; index < 4; index += 1) {
    const input = scenario("Update", [...progress.slice(0, index), event]); const result = run(input);
    assert.equal(result.state, "Deferred"); assert.equal(result.reason, event);
    assert.deepEqual(result.projected_snapshot, input.snapshot);
  }
});
vector("DP-022", "missing trust and disabled rollback reject, with no network fallback", () => {
  for (const event of ["TrustUnavailable", "RollbackUnavailable"]) for (let index = 0; index < 4; index += 1) {
    const result = run(scenario("Update", [...progress.slice(0, index), event]));
    assert.equal(result.state, "Rejected"); assert.equal(result.reason, event);
  }
});
vector("DP-023", "any uncertain event after publish requires explicit recovery", () => {
  for (const event of ["Cancel", "Fail", "Crash", "Busy", "TrustUnavailable", "RebootRequired", "RollbackUnavailable", "InconsistentState"]) {
    const result = run(scenario("Update", [...progress.slice(0, 4), event]));
    assert.equal(result.state, "RecoveryRequired"); assert.equal(result.outcome, "Unknown");
    assert.equal(result.projected_snapshot, null); assert.equal(result.minimum_security_floor, 5);
  }
});
vector("DP-024", "inconsistent state always blocks instead of trusting a committed label", () => {
  for (let index = 0; index < progress.length; index += 1) {
    const result = run(scenario("Update", [...progress.slice(0, index), "InconsistentState"]));
    assert.equal(result.state, "RecoveryRequired"); assert.equal(result.projected_snapshot, null);
    assert.equal(result.minimum_security_floor, index < 4 ? 4 : 5);
  }
  for (const index of [5, 6]) {
    const result = run(scenario("Update", [...progress.slice(0, index), "TrustUnavailable"]));
    assert.equal(result.state, "RecoveryRequired"); assert.equal(result.projected_snapshot, null);
    assert.equal(result.minimum_security_floor, 5);
  }
});
vector("DP-025", "cleanup failure retains committed tuple/floor, never claims deletion", () => {
  for (const index of [5, 6]) {
    const result = run(scenario("Update", [...progress.slice(0, index), "CleanupFailed"]));
    assert.equal(result.state, "CleanupPending"); assert.equal(result.reason, "CleanupIncomplete");
    assert.equal(result.projected_snapshot.generation, 8); assert.equal(result.projected_snapshot.security_floor, 5);
    assert.equal(result.outcome, "BackendNotEnrolled");
  }
  invalid(scenario("Update", ["CleanupFailed"]));
});
vector("DP-026", "all out-of-order normal transitions are rejected", () => {
  for (let index = 0; index < progress.length; index += 1) for (const event of progress) {
    if (event !== progress[index]) invalid(scenario("Update", [...progress.slice(0, index), event]));
  }
});
vector("DP-027", "terminal cancellation/recovery/completion cannot resume or replay", () => {
  for (const prefix of [["Cancel"], ["Busy"], ["Fail"], [...progress.slice(0, 4), "Crash"], [...progress.slice(0, 5), "CleanupFailed"], progress]) {
    for (const event of DEPLOYMENT_EVENTS) invalid(scenario("Update", [...prefix, event]));
  }
});
vector("DP-028", "no arbitrary commands, installer properties, paths or force flags", () => {
  for (const field of Object.keys(scenario())) {
    const input = scenario(); delete input[field];
    assert.equal(validateInput(input), false); invalid(input);
  }
  for (const field of ["command", "path", "destination", "argv", "environment", "msi_properties", "transform", "force", "verified", "execution_enabled", "consent_receipt"]) {
    const input = scenario(); input[field] = "synthetic-forbidden";
    assert.equal(validateInput(input), false); invalid(input);
  }
  for (const field of ["snapshot", "intent", "confirmation"]) {
    const input = scenario(); input[field].force = true;
    assert.equal(validateInput(input), false); invalid(input);
  }
});
vector("DP-029", "foreign authority, operations and enum versions rejected", () => {
  const mutations = [input => { input.schema_version = "2.0.0"; }, input => { input.provenance = "Verified"; },
    input => { input.confirmation.kind = "Administrative"; }, input => { input.intent.operation = "CollectPrivilegedReadOnly"; },
    input => { input.intent.operation = "Recover"; }, input => { input.events = ["InvokeUac"]; }];
  for (const mutate of mutations) { const input = scenario(); mutate(input); assert.equal(validateInput(input), false); invalid(input); }
});
vector("DP-030", "unsafe integers and non-JSON numeric values rejected", () => {
  for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, "7", null]) {
    const input = scenario(); input.snapshot.generation = value;
    assert.equal(validateInput(input), false); invalid(input);
  }
  const input = scenario(); input.snapshot.generation = -0; invalid(input);
});
vector("DP-031", "bounded arrays reject oversized, duplicate nonce and unknown events", () => {
  for (const mutate of [input => { input.events = Array(33).fill("Fail"); },
    input => { input.used_nonces = Array.from({ length: 65 }, (_, i) => `synthetic-nonce-${i}`); },
    input => { input.used_nonces = ["synthetic-nonce-a", "synthetic-nonce-a"]; },
    input => { input.events = ["Execute"]; }]) {
    const input = scenario(); mutate(input); assert.equal(validateInput(input), false); invalid(input);
  }
});
vector("DP-032", "accessors and proxies rejected without executing traps", () => {
  let touched = false;
  const proxy = new Proxy({}, { get() { touched = true; throw Error("trap"); }, ownKeys() { touched = true; throw Error("trap"); } });
  invalid(proxy);
  for (const field of ["snapshot", "intent", "confirmation", "events", "used_nonces"]) {
    const input = scenario(); input[field] = proxy; invalid(input);
  }
  const input = scenario();
  Object.defineProperty(input.intent, "desired", { enumerable: true, get() { touched = true; throw Error("getter"); } });
  invalid(input);
  const item = scenario();
  Object.defineProperty(item.events, "0", { enumerable: true, get() { touched = true; throw Error("array getter"); } });
  invalid(item); assert.equal(touched, false);
});
vector("DP-033", "sparse arrays, exotic prototypes, hidden/symbol keys and cycles rejected", () => {
  for (const mutate of [input => { input.events = Array(1); }, input => { input.events.extra = true; },
    input => { Object.setPrototypeOf(input.snapshot, { foreign: true }); },
    input => { Object.defineProperty(input, "hidden", { value: true }); }, input => { input[Symbol("foreign")] = true; },
    input => { input.intent.desired = input; }, input => { input.snapshot = new Date(); }]) {
    const input = scenario(); mutate(input); invalid(input);
  }
});
vector("DP-034", "identifier, digest and UTC timestamp admission stays strict", () => {
  for (const value of ["../backend", "C:\\synthetic\\file", "synthetic-a/b", "synthetic-" + "a".repeat(55), "synthetic-a\n"]) {
    const input = scenario(); input.intent.desired.app_id = value;
    assert.equal(validateInput(input), false); invalid(input);
  }
  for (const value of ["2026-09-29T12:01:00+00:00", "2026-02-30T12:01:00Z", "2026-09-29T12:01:60Z", "2026-09-29T12:01:00.000Z"]) {
    const input = scenario(); input.simulated_at = value; invalid(input);
  }
  const input = scenario(); input.intent.desired.manifest_digest = "a".repeat(63);
  assert.equal(validateInput(input), false); invalid(input);
});
vector("DP-035", "schema rejects every authority and readiness escalation in output", () => {
  const result = run(scenario());
  for (const field of Object.keys(result.effects)) {
    const mutated = clone(result); mutated.effects[field] = true;
    assert.equal(validateOutput(mutated), false, field);
  }
  for (const [field, value] of [["installer_status", "Implemented"], ["launch_status", "Ready"], ["provenance", "Authenticated"]]) {
    const mutated = clone(result); mutated[field] = value; assert.equal(validateOutput(mutated), false);
  }
});
vector("DP-036", "schema rejects selected tuple in recovery and false committed outcomes", () => {
  const recovery = clone(run(scenario("Update", [...progress.slice(0, 4), "Crash"])));
  recovery.projected_snapshot = scenario().snapshot;
  assert.equal(validateOutput(recovery), false);
  const committed = clone(run(scenario())); committed.outcome = "NotCommitted";
  assert.equal(validateOutput(committed), false);
  const cancelled = clone(run(scenario("Update", ["Cancel"]))); cancelled.outcome = "InstalledLaunchBlocked";
  assert.equal(validateOutput(cancelled), false);
});
vector("DP-037", "schema rejects missing security metadata and additional output fields", () => {
  const result = run(scenario());
  for (const field of Object.keys(result)) {
    const mutated = clone(result); delete mutated[field]; assert.equal(validateOutput(mutated), false, field);
  }
  const mutated = clone(result); mutated.command = "synthetic-forbidden"; assert.equal(validateOutput(mutated), false);
});
vector("DP-038", "hashes bind scenario and full projection but are not signatures", () => {
  const input = scenario(); const result = run(input);
  const changed = clone(result); changed.projected_snapshot.selection.app_id = "synthetic-other";
  assert.notEqual(digestWithExclusion(changed, "result_digest"), result.result_digest);
  const other = clone(input); other.simulated_at = "2026-09-29T12:02:00Z";
  assert.notEqual(run(other).scenario_digest, result.scenario_digest);
  assert.notEqual(run(other).result_digest, result.result_digest);
});
vector("DP-039", "limits apply without dependencies or host operations in the model", async () => {
  const source = await readFile(path.join(root, "tools/lib/deployment-model.mjs"), "utf8");
  const imports = [...source.matchAll(/^import .* from "([^"]+)";/gmu)].map(match => match[1]);
  assert.deepEqual(imports, ["node:util", "./jcs.mjs"]);
  assert.doesNotMatch(source, /\b(?:import\s*\(|fetch\s*\(|eval\s*\(|process\.|Date\.now\s*\()/u);
  assert.deepEqual(MODEL_LIMITS, { events: 32, used_nonces: 64, confirmation_seconds: 300 });
});
vector("DP-040", "historical nine launch gates remain open in the independent planner", async () => {
  const { planBackendLaunch } = await import("../../src/backend/launch-plan.mjs");
  run(scenario("EnrollBackend"));
  const plan = planBackendLaunch({ operation: "Version" });
  assert.equal(plan.execution_enabled, false);
  assert.deepEqual(plan.blockers.map(item => item.id), ["TL-ADJACENT-DLL", "TL-LINKED-TOKEN", "TL-NON-ELEVATED-MECHANISM", "TL-REPARSE-REPLACEMENT", "TL-INITIAL-INVENTORY", "TL-PREVENTIVE-LOAD-POLICY", "TL-UNKNOWN-MODULES", "TL-IMAGE-BYTE-BINDING", "TL-PRODUCTION-LOAD-CONTEXT"]);
  assert.ok(plan.blockers.every(item => item.status === "Open"));
});

assert.equal(new Set(cases.map(item => item.id)).size, cases.length);
assert.deepEqual(cases.map(item => item.id).sort(), [...requiredIds].sort());
const executed = new Set();
for (const item of cases) test(`${item.id}: ${item.name}`, async () => {
  await item.run();
  executed.add(item.id);
});
test("deployment gate: exact required IDs executed successfully, with zero skipped vectors", () => {
  assert.deepEqual([...executed].sort(), [...requiredIds].sort());
});

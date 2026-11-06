import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createSchemaRegistry } from "../../tools/lib/schema-registry.mjs";
import { jcsSha256, digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { simulateMaintenancePersistence, MAINTENANCE_PERSISTENCE_LIMITS } from "../../tools/lib/maintenance-persistence-model.mjs";
import { baseStorage, intentFor, recoveryIntent, sealIntent, harness, hash, copy } from "./synthetic-persistence.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const registry = createSchemaRegistry(root);
const schemas = {};
for (const name of ["scenario", "projection"]) {
  const schema = JSON.parse(await readFile(path.join(root, `schemas/development/maintenance-persistence-${name}.schema.json`), "utf8"));
  assert.equal(registry.ajv.validateSchema(schema), true); registry.ajv.addSchema(schema); schemas[name] = schema;
}
const inputGate = registry.ajv.getSchema(schemas.scenario.$id);
const outputGate = registry.ajv.getSchema(schemas.projection.$id);
assert.deepEqual(registry.warnings, []);
const required = Object.freeze([
  "MPS-001", "MPS-002", "MPS-003", "MPS-004", "MPS-005", "MPS-006", "MPS-007", "MPS-008",
  "MPS-009", "MPS-010", "MPS-011", "MPS-012", "MPS-013", "MPS-014", "MPS-015", "MPS-016",
  "MPS-017", "MPS-018", "MPS-019", "MPS-020", "MPS-021", "MPS-022", "MPS-023", "MPS-024",
  "MPS-025", "MPS-026", "MPS-027", "MPS-028", "MPS-029", "MPS-030", "MPS-031", "MPS-032",
  "MPS-033", "MPS-034", "MPS-035", "MPS-036", "MPS-037", "MPS-038", "MPS-039", "MPS-040"
]);
const cases = [];
const vector = (id, label, fn) => cases.push({ id, label, fn });
function run(input) {
  assert.equal(inputGate(input), true, JSON.stringify(inputGate.errors));
  const result = simulateMaintenancePersistence(input);
  assert.equal(outputGate(result), true, JSON.stringify(outputGate.errors));
  assert.equal(result.scenario_digest, jcsSha256(input));
  assert.equal(result.result_digest, digestWithExclusion(result, "result_digest"));
  assert.ok(Object.values(result.effects).every(value => value === false));
  assert.equal(result.launch_status, "Blocked"); assert.equal(result.launcher_status, "NotImplemented");
  return result;
}
function denied(input, reason) { const result = run(input); assert.equal(result.reason, reason); return result; }
function invalid(input) { assert.throws(() => simulateMaintenancePersistence(input), { code: "MAINTENANCE_PERSISTENCE_INPUT_INVALID" }); }
const resealHead = disk => { disk.head.head_digest = digestWithExclusion(disk.head, "head_digest"); };

vector("MPS-001", "complete transaction separates record, flush, read-back, head and replies", () => {
  const result = run(harness().full().input);
  assert.equal(result.status, "Completed"); assert.equal(result.reason, "None");
  assert.deepEqual(result.watermarks, { counter: 11, generation: 8, security_floor: 5 });
  assert.equal(result.selected_digest, hash("synthetic-v2")); assert.equal(result.selection_known, true);
  assert.equal(result.admission_ack, "Delivered"); assert.equal(result.result_ack, "Delivered");
  assert.deepEqual(result.storage.records.map(record => record.record_kind), ["Reserve", "Block", "Commit", "Complete"]);
});
vector("MPS-002", "every normal prefix is schema-valid and partial I/O cannot become known selection", () => {
  const full = harness().full().input;
  for (let i = 0; i <= full.events.length; i += 1) {
    const input = copy(full); input.events.length = i;
    const result = run(input); assert.equal(result.reason, "None");
    if (result.pending_stage !== "None" || ["InProgress", "PublicationBlocked"].includes(result.status)) assert.equal(result.selection_known, false);
  }
});
vector("MPS-003", "known unwritten reservation preserves counter and prior selected state", () => {
  const result = denied(harness().write("Reserve", "NotWritten").input, "NotWritten");
  assert.equal(result.watermarks.counter, 10); assert.equal(result.storage.records.length, 0);
  assert.equal(result.admission_ack, "NotSent"); assert.equal(result.selected_digest, hash("synthetic-v1"));
});
vector("MPS-004", "torn or unknown reservation never falls back to an unused counter", () => {
  for (const outcome of ["Torn", "Unknown"]) {
    const result = denied(harness().write("Reserve", outcome).input, "WriteUncertain");
    assert.equal(result.watermarks.counter, 11); assert.equal(result.status, "RecoveryRequired");
    assert.equal(result.storage.integrity, "Unknown"); assert.equal(result.selection_known, false);
  }
});
vector("MPS-005", "failed or unknown journal flush is not known NotWritten", () => {
  for (const outcome of ["Failed", "Unknown"]) {
    const result = denied(harness().write("Reserve").flush("Journal", outcome).input, "FlushUncertain");
    assert.equal(result.watermarks.counter, 11); assert.equal(result.admission_ack, "NotSent");
    assert.equal(result.status, "RecoveryRequired");
  }
});
vector("MPS-006", "cached read-back cannot substitute for a journal flush", () => {
  denied(harness().write("Reserve").read("Journal").input, "OrderRejected");
  denied(harness().write("Reserve").flush("Head").input, "OrderRejected");
});
vector("MPS-007", "post-flush mismatch or unavailable re-read blocks acknowledgement", () => {
  for (const outcome of ["Mismatch", "Unknown"]) {
    const result = denied(harness().write("Reserve").flush("Journal").read("Journal", outcome).input, "ReadBackMismatch");
    assert.equal(result.storage.records.length, 1); assert.equal(result.watermarks.counter, 11);
    assert.equal(result.status, "RecoveryRequired");
  }
});
vector("MPS-008", "admission reply requires the complete matching head persistence sequence", () => {
  const full = harness().reserve().input;
  for (let i = 0; i < 6; i += 1) {
    const input = copy(full); input.events = input.events.slice(0, i);
    input.events.push({ kind: "Acknowledge", phase: "Admission", delivery: "Delivered" });
    assert.equal(denied(input, "OrderRejected").admission_ack, "NotSent");
  }
});
vector("MPS-009", "failed head write, flush or re-read cannot expose stale public state", () => {
  for (const outcome of ["NotWritten", "Torn", "Unknown"]) {
    const result = denied(harness().write("Reserve").flush("Journal").read("Journal").head(outcome).input,
      outcome === "NotWritten" ? "NotWritten" : "WriteUncertain");
    assert.equal(result.watermarks.counter, 11); assert.equal(result.selection_known, false);
  }
  denied(harness().write("Reserve").flush("Journal").read("Journal").head().flush("Head", "Failed").input, "FlushUncertain");
  denied(harness().write("Reserve").flush("Journal").read("Journal").head().flush("Head").read("Head", "Mismatch").input, "ReadBackMismatch");
});
vector("MPS-010", "commit requires a durably published block and quiescence hypothesis", () => {
  denied(harness().reserve().write("Commit").input, "OrderRejected");
  denied(harness().reserve().write("Block").input, "RuntimeBusy");
  for (const result of ["Busy", "Unknown"]) denied(harness().reserve().event("ObserveQuiescence", { result }).input, "RuntimeBusy");
  const h = harness().reserve().event("ObserveQuiescence", { result: "Quiescent" }).write("Block").flush("Journal").read("Journal");
  denied(h.write("Commit").input, "OrderRejected");
});
vector("MPS-011", "publish intent raises possible generation and floor before tuple commit", () => {
  const result = run(harness().reserve().block().input);
  assert.equal(result.status, "PublicationBlocked"); assert.equal(result.storage.head.generation, 7);
  assert.deepEqual(result.watermarks, { counter: 11, generation: 8, security_floor: 5 });
  assert.equal(result.storage.head.phase, "Blocked"); assert.equal(result.selection_known, false);
  const uncertain = denied(harness().reserve().event("ObserveQuiescence", { result: "Quiescent" }).write("Block", "Unknown").input, "WriteUncertain");
  assert.deepEqual(uncertain.watermarks, result.watermarks);
});
vector("MPS-012", "crash at every normal I/O boundary stops the session without regressing watermarks", () => {
  const full = harness().full().input;
  for (let i = 0; i <= full.events.length; i += 1) {
    const prefix = copy(full); prefix.events.length = i; const before = run(prefix);
    prefix.events.push({ kind: "Crash" }, { kind: "WriteRecord", record_kind: "Reserve", result: "Complete" });
    const after = denied(prefix, "Crash"); assert.equal(after.events_processed, i + 1);
    for (const field of ["counter", "generation", "security_floor"]) assert.ok(after.watermarks[field] >= before.watermarks[field]);
    if (before.pending_stage !== "None" || before.status === "PublicationBlocked") assert.equal(after.status, "RecoveryRequired");
  }
});
vector("MPS-013", "known committed crash preserves the new tuple and requires cleanup", () => {
  const result = denied(harness().reserve().block().commit().crash().input, "Crash");
  assert.equal(result.status, "CleanupPending"); assert.equal(result.selected_digest, hash("synthetic-v2"));
  assert.equal(result.watermarks.generation, 8);
});
vector("MPS-014", "lost admission reply permits only exact status resolution before more effects", () => {
  const h = harness().reserve("Lost").query().block().commit().complete();
  const result = run(h.input); assert.equal(result.reason, "None"); assert.equal(result.watermarks.counter, 11);
  const wrong = harness().reserve("Lost").query(9).block(); denied(wrong.input, "StatusRejected");
  denied(harness().reserve("Lost").block().input, "StatusRejected");
});
vector("MPS-015", "lost result and old status never authorize a second reservation", () => {
  const h = harness().reserve().block().commit().complete("Lost").query();
  assert.equal(run(h.input).last_status, "Completed");
  assert.equal(denied(h.write("Reserve").input, "OrderRejected").watermarks.counter, 11);
});
vector("MPS-016", "candidate recovery appends fresh authority and publishes a newer generation", () => {
  const prior = run(harness().reserve().block().crash().input);
  const result = run(harness(prior.storage, recoveryIntent(prior.storage)).full().input);
  assert.equal(result.status, "Completed"); assert.deepEqual(result.watermarks, { counter: 12, generation: 9, security_floor: 5 });
  assert.deepEqual(result.storage.records.slice(0, 2), prior.storage.records);
  assert.notEqual(result.storage.records[2].intent.confirmation_digest, prior.storage.records[0].intent.confirmation_digest);
});
vector("MPS-017", "previous selection recovery cannot cross the maximum reserved floor", () => {
  let prior = run(harness().reserve().block().crash().input);
  denied(harness(prior.storage, recoveryIntent(prior.storage, "RestorePermittedPrevious")).write("Reserve").input, "EpochRejected");
  prior = run(harness(baseStorage({ security_floor: 5, selection_epoch: 5 })).reserve().block().crash().input);
  const result = run(harness(prior.storage, recoveryIntent(prior.storage, "RestorePermittedPrevious")).full().input);
  assert.equal(result.selected_digest, hash("synthetic-v1")); assert.equal(result.watermarks.generation, 9);
});
vector("MPS-018", "committed cleanup recovery consumes fresh counter without republishing", () => {
  const prior = run(harness().reserve().block().commit().crash().input);
  const result = run(harness(prior.storage, recoveryIntent(prior.storage, "FinishCommittedCleanup")).reserve().complete().input);
  assert.equal(result.watermarks.counter, 12); assert.equal(result.watermarks.generation, 8);
  assert.equal(result.selected_digest, hash("synthetic-v2")); assert.equal(result.status, "Completed");
});
vector("MPS-019", "interrupted recovery retains original lineage and cannot reveal pending selection", () => {
  const first = run(harness().reserve().block().crash().input);
  const second = run(harness(first.storage, recoveryIntent(first.storage)).reserve().crash().input);
  assert.equal(second.selection_known, false); assert.equal(second.watermarks.counter, 12);
  const third = run(harness(second.storage, recoveryIntent(second.storage)).full().input);
  assert.equal(third.watermarks.counter, 13); assert.equal(third.watermarks.generation, 9);
  assert.deepEqual(third.storage.records.slice(0, second.storage.records.length), second.storage.records);
});
vector("MPS-020", "intent scope binds complete prior state, machine and transaction", () => {
  for (const field of ["expected_state_digest", "transaction_id"]) {
    const h = harness(); h.input.intent[field] = field === "transaction_id" ? "synthetic-tx-10" : hash("foreign");
    sealIntent(h.input.intent); denied(h.write("Reserve").input, "IntentRejected");
  }
  const original = intentFor(baseStorage());
  denied(harness(baseStorage({ machine_id: "synthetic-machine-b" }), original).write("Reserve").input, "IntentRejected");
});
vector("MPS-021", "declined, unknown or substituted synthetic confirmation cannot reserve", () => {
  for (const confirmation of ["Declined", "Unknown"]) {
    const disk = baseStorage(); denied(harness(disk, intentFor(disk, { confirmation })).write("Reserve").input, "ConfirmationRejected");
  }
  const h = harness(); h.input.intent.confirmation_digest = hash("other"); denied(h.write("Reserve").input, "ConfirmationRejected");
});
vector("MPS-022", "completed and compacted requests cannot be replayed against a newer counter", () => {
  const h = harness().full(); const old = copy(h.input.intent);
  for (const disk of [run(h.input).storage, run(h.compact().input).storage]) {
    const result = denied(harness(disk, old).write("Reserve").input, "IntentRejected");
    assert.equal(result.watermarks.counter, 11);
  }
});
vector("MPS-023", "journal corruption, sequence gaps, duplicate or foreign links reject", () => {
  const good = run(harness().full().input);
  for (const change of [x => { x.records[0].record_digest = hash("corrupt"); }, x => { x.records[1].sequence += 1; },
    x => { x.records[1] = copy(x.records[0]); }, x => { x.records[1].previous_digest = hash("other"); }]) {
    const input = harness(good.storage, null).input; change(input.storage);
    const result = denied(input, "StorageInvalid"); assert.equal(result.selection_known, false);
  }
  const resealed = harness(good.storage, null).input;
  resealed.storage.records[1].record_kind = "Commit";
  resealed.storage.records[1].record_digest = digestWithExclusion(resealed.storage.records[1], "record_digest");
  denied(resealed, "OrderRejected");
});
vector("MPS-024", "invalid anchor or impossible selected epoch is not a fresh installation", () => {
  let input = harness().input; input.storage.anchor.anchor_digest = hash("other"); denied(input, "StorageInvalid");
  input = harness(baseStorage(), null).input; input.storage.anchor.security_floor = 6;
  input.storage.anchor.anchor_digest = digestWithExclusion(input.storage.anchor, "anchor_digest"); denied(input, "StorageInvalid");
  input = harness().input; input.storage.anchor.selection_digest = null; invalid(input);
});
vector("MPS-025", "validly checksummed but stale or foreign public head is rejected", () => {
  const done = run(harness().full().input);
  for (const change of [x => { x.head = baseStorage().head; }, x => { x.head.machine_id = "synthetic-machine-b"; resealHead(x); },
    x => { x.head.security_floor = 4; resealHead(x); }]) {
    const input = harness(done.storage, null).input; change(input.storage);
    assert.equal(denied(input, "HeadMismatch").selection_known, false);
  }
});
vector("MPS-026", "externally supplied synthetic lower bounds prevent rollback acceptance", () => {
  for (const field of ["counter", "generation", "security_floor"]) {
    const input = harness().input; input.minimum[field] += 1;
    const result = denied(input, "WatermarkRegression"); assert.equal(result.watermarks[field], input.minimum[field]);
    assert.equal(result.selection_known, false);
  }
});
vector("MPS-027", "a last-good-prefix fallback cannot erase known possible consumption or publication", () => {
  const advanced = run(harness().reserve().block().input);
  const input = harness().input; input.minimum = copy(advanced.watermarks);
  const result = denied(input, "WatermarkRegression"); assert.deepEqual(result.watermarks, advanced.watermarks);
  assert.equal(result.admission_ack, "NotSent"); assert.equal(result.status, "RecoveryRequired");
});
vector("MPS-028", "uninstalled selection and compaction preserve anti-rollback floor", () => {
  const disk = baseStorage({ security_floor: 5, selection_epoch: 5 });
  const result = run(harness(disk, intentFor(disk, { selection_digest: null, selection_epoch: 0 })).full().compact().input);
  assert.equal(result.selection_known, true); assert.equal(result.selected_digest, null); assert.equal(result.watermarks.security_floor, 5);
  const low = intentFor(result.storage, { selection_epoch: 4 });
  denied(harness(result.storage, low).write("Reserve").input, "EpochRejected");
});
vector("MPS-029", "null recovery remains exact, separately confirmed and generation increasing", () => {
  const disk = baseStorage(); const prior = run(harness(disk, intentFor(disk, { selection_digest: null, selection_epoch: 0 })).reserve().block().crash().input);
  const result = run(harness(prior.storage, recoveryIntent(prior.storage)).full().input);
  assert.equal(result.selected_digest, null); assert.equal(result.selection_known, true);
  assert.equal(result.watermarks.generation, 9); assert.equal(result.watermarks.counter, 12);
  const bad = recoveryIntent(prior.storage); bad.selection_digest = hash("not-the-candidate"); bad.selection_epoch = 5; sealIntent(bad);
  denied(harness(prior.storage, bad).write("Reserve").input, "ScopeRejected");
});
vector("MPS-030", "compaction retains counters, floor and latest status without old effects", () => {
  const h = harness().full(); const before = run(h.input); const result = run(h.compact().query(9).input);
  assert.deepEqual(result.watermarks, before.watermarks); assert.equal(result.storage.records.length, 0);
  assert.equal(result.storage.anchor.last_transaction_id, "synthetic-tx-11"); assert.equal(result.last_status, "Retired");
  const restarted = run(harness(result.storage, null).query(11).input);
  assert.equal(restarted.last_status, "Completed"); assert.equal(restarted.watermarks.counter, 11);
});
vector("MPS-031", "crash at every compaction boundary preserves records until retirement completes", () => {
  const h = harness().full(); const start = h.input.events.length; h.compact();
  for (let i = start + 1; i <= h.input.events.length; i += 1) {
    const input = copy(h.input); input.events.length = i; input.events.push({ kind: "Crash" });
    const result = denied(input, "Crash"); assert.equal(result.watermarks.counter, 11); assert.equal(result.watermarks.security_floor, 5);
    if (i < h.input.events.length) { assert.equal(result.storage.records.length, 4); assert.equal(result.status, "RecoveryRequired"); }
    else { assert.equal(result.storage.records.length, 0); assert.equal(result.selection_known, true); }
  }
});
vector("MPS-032", "active lineage or unflushed checkpoint cannot be compacted or retired", () => {
  const h = harness().reserve();
  assert.equal(denied(h.event("WriteCheckpoint", { result: "Complete" }).input, "OrderRejected").storage.records.length, 1);
  for (const h2 of [harness().full(), harness().full().event("WriteCheckpoint", { result: "Complete" })]) {
    assert.equal(denied(h2.event("RetireJournal", { result: "Complete" }).input, "OrderRejected").storage.records.length, 4);
  }
  const completed = run(harness().full().input);
  const statusOnly = harness(completed.storage, null).query(11).event("WriteCheckpoint", { result: "Complete" });
  assert.equal(denied(statusOnly.input, "OrderRejected").storage.records.length, 4);
});
vector("MPS-033", "compaction write/flush/read/retirement failures preserve old journal", () => {
  for (const outcome of ["NotWritten", "Torn", "Unknown"]) {
    const result = denied(harness().full().event("WriteCheckpoint", { result: outcome }).input, outcome === "NotWritten" ? "NotWritten" : "CompactionUncertain");
    assert.equal(result.storage.records.length, 4);
  }
  denied(harness().full().event("WriteCheckpoint", { result: "Complete" }).flush("Checkpoint", "Failed").input, "FlushUncertain");
  denied(harness().full().event("WriteCheckpoint", { result: "Complete" }).flush("Checkpoint").read("Checkpoint", "Mismatch").input, "ReadBackMismatch");
  for (const result of ["NotWritten", "Unknown"]) {
    const h = harness().full().compact(); h.input.events.at(-1).result = result;
    assert.equal(denied(h.input, "CompactionUncertain").storage.records.length, 4);
  }
});
vector("MPS-034", "unknown storage or leftover checkpoint cannot become counter zero on restart", () => {
  const prior = run(harness().full().event("WriteCheckpoint", { result: "Complete" }).flush("Checkpoint").read("Checkpoint").crash().input);
  const input = harness(prior.storage, null).input;
  assert.equal(denied(input, "StorageUnknown").selection_known, false);
  const unknown = harness().input; unknown.storage.integrity = "Unknown"; denied(unknown, "StorageUnknown");
});
vector("MPS-035", "checked counter, generation and sequence arithmetic never wraps", () => {
  const max = Number.MAX_SAFE_INTEGER;
  let disk = baseStorage({ counter: max, last_transaction_id: `synthetic-tx-${max}` });
  denied(harness(disk).write("Reserve").input, "CounterOverflow");
  disk = baseStorage({ generation: max }); denied(harness(disk).write("Reserve").input, "GenerationOverflow");
  disk = baseStorage({ sequence: max }); denied(harness(disk).write("Reserve").input, "SequenceOverflow");
  disk = baseStorage({ generation: max - 1, counter: max - 1, last_transaction_id: `synthetic-tx-${max - 1}` });
  const result = run(harness(disk).full().input); assert.equal(result.watermarks.counter, max); assert.equal(result.watermarks.generation, max);
  disk = baseStorage({ sequence: max - 1 }); assert.equal(run(harness(disk).reserve().input).storage.head.sequence, max);
});
vector("MPS-036", "lineage and retained record limits fail closed without silent trimming", () => {
  let result = run(harness().reserve().block().input);
  for (let i = 1; i < 16; i += 1) result = run(harness(result.storage, recoveryIntent(result.storage)).reserve().block().input);
  const deniedFull = denied(harness(result.storage, recoveryIntent(result.storage)).write("Reserve").input, "LineageFull");
  assert.deepEqual(deniedFull.storage.records, result.storage.records);
  let disk = baseStorage();
  for (let i = 0; i < 16; i += 1) disk = run(harness(disk).full().input).storage;
  assert.equal(disk.records.length, 64);
  assert.equal(denied(harness(disk).write("Reserve").input, "LimitExceeded").storage.records.length, 64);
});
vector("MPS-037", "unsafe API input cannot execute proxy traps, getters or toJSON", () => {
  let touched = false;
  const proxy = new Proxy({}, { ownKeys() { touched = true; throw Error("trap"); } }); invalid(proxy);
  let input = harness().input; Object.defineProperty(input, "intent", { enumerable: true, get() { touched = true; throw Error("getter"); } }); invalid(input);
  input = harness().input; input.toJSON = () => { touched = true; return {}; }; invalid(input);
  for (const change of [x => { x.events = Array(1); }, x => { x.intent = x; }, x => { x.minimum.counter = -0; },
    x => { x.minimum.counter = Infinity; }, x => { x.storage = new Date(); }, x => { x[Symbol("hidden")] = true; }]) {
    input = harness().input; change(input); invalid(input);
  }
  assert.equal(touched, false);
});
vector("MPS-038", "strict schemas reject authority, missing fields, paths, unknown versions and bad dates", () => {
  const original = harness().full().input;
  for (const key of Object.keys(original)) { const input = copy(original); delete input[key]; assert.equal(inputGate(input), false); invalid(input); }
  for (const [key, value] of [["schema_version", "2.0.0"], ["path", "synthetic-forbidden"], ["limits", {}]]) {
    const input = copy(original); input[key] = value; assert.equal(inputGate(input), false); invalid(input);
  }
  const input = copy(original); input.simulated_at = "2026-02-30T12:00:00Z"; invalid(input);
  const result = run(original);
  for (const key of Object.keys(result.effects)) { const changed = copy(result); changed.effects[key] = true; assert.equal(outputGate(changed), false); }
  for (const [key, value] of [["launch_status", "Ready"], ["launcher_status", "Implemented"], ["provenance", "Verified"]]) {
    const changed = copy(result); changed[key] = value; assert.equal(outputGate(changed), false);
  }
  const changed = copy(result); changed.status = "RecoveryRequired"; assert.equal(outputGate(changed), false);
  for (const change of [x => { x.storage.integrity = "Unknown"; }, x => { x.pending_stage = "JournalWritten"; },
    x => { x.selection_known = false; x.selected_digest = null; }]) {
    const changed = copy(result); change(changed); assert.equal(outputGate(changed), false);
  }
  for (const key of Object.keys(result)) { const changed = copy(result); delete changed[key]; assert.equal(outputGate(changed), false); }
});
vector("MPS-039", "deterministic frozen model leaves caller unchanged and all historical launch gates open", async () => {
  const input = harness().full().input; const before = copy(input); const result = run(input);
  assert.deepEqual(result, run(copy(input))); assert.deepEqual(input, before); assert.equal(Object.isFrozen(input), false);
  function frozen(value) { if (value && typeof value === "object") { assert.equal(Object.isFrozen(value), true); Object.values(value).forEach(frozen); } }
  frozen(result); assert.ok(Object.isFrozen(MAINTENANCE_PERSISTENCE_LIMITS));
  for (const name of ["maintenance-persistence-model", "maintenance-persistence-validation"]) {
    const source = await readFile(path.join(root, `tools/lib/${name}.mjs`), "utf8");
    assert.doesNotMatch(source, /node:(?:fs|net|http|child_process)|\b(?:fetch\s*\(|eval\s*\(|process\.|Date\.now\s*\()/u);
  }
  const { planBackendLaunch } = await import("../../src/backend/launch-plan.mjs"); const plan = planBackendLaunch({ operation: "Version" });
  assert.equal(plan.execution_enabled, false);
  assert.deepEqual(plan.blockers.map(item => item.id), ["TL-ADJACENT-DLL", "TL-LINKED-TOKEN", "TL-NON-ELEVATED-MECHANISM", "TL-REPARSE-REPLACEMENT", "TL-INITIAL-INVENTORY", "TL-PREVENTIVE-LOAD-POLICY", "TL-UNKNOWN-MODULES", "TL-IMAGE-BYTE-BINDING", "TL-PRODUCTION-LOAD-CONTEXT"]);
  assert.ok(plan.blockers.every(item => item.status === "Open"));
});
vector("MPS-040", "bounded events, coordinator refusal and status/reply order are enforced", () => {
  const h = harness(baseStorage(), null); for (let i = 0; i < 128; i += 1) h.query(9);
  assert.equal(run(h.input).events_processed, 128); h.query(9); assert.equal(inputGate(h.input), false); invalid(h.input);
  for (const coordinator of ["Busy", "Unknown"]) { const h2 = harness().write("Reserve"); h2.input.coordinator = coordinator; denied(h2.input, "CoordinatorUnavailable"); }
  denied(harness().query(11).input, "StatusRejected");
  denied(harness().reserve().event("Acknowledge", { phase: "Admission", delivery: "Delivered" }).input, "OrderRejected");
  const tooMany = harness().input; tooMany.storage.records = Array(65).fill({}); invalid(tooMany);
});

assert.equal(new Set(cases.map(item => item.id)).size, cases.length);
assert.deepEqual(cases.map(item => item.id).sort(), [...required].sort());
const executed = new Set();
for (const item of cases) test(`${item.id}: ${item.label}`, async () => { await item.fn(); executed.add(item.id); });
test("persistence gate: exact required IDs passed with zero skipped cases", () => {
  assert.deepEqual([...executed].sort(), [...required].sort());
});

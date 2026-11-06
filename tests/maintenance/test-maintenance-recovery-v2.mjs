import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import schema from "../../schemas/development/maintenance-recovery-v2.schema.json" with { type: "json" };
import { AJV_OPTIONS } from "../../tools/lib/constants.mjs";
import { jcs } from "../../tools/lib/jcs.mjs";
import { checkedRecoveryData } from "../../tools/lib/maintenance-recovery-validation.mjs";
import { simulateMaintenanceRecovery as run, prepareRecoveryOffer as offer, inspectRecoverySnapshot as inspect,
  checkRecoveryCapacity as capacity } from "../../tools/lib/maintenance-recovery-model.mjs";
import { encodeRecoveryStore as encode, decodeRecoveryStore as decode } from "../../tools/lib/maintenance-recovery-codec.mjs";
import { checkedPersistenceData } from "../../tools/lib/maintenance-persistence-validation.mjs";
import { encodeMaintenanceStore as encodeV1, decodeMaintenanceStore as decodeV1 } from "../../tools/lib/maintenance-store-codec.mjs";
import { simulateMaintenancePersistence } from "../../tools/lib/maintenance-persistence-model.mjs";
import { baseStorage, harness as harnessV1 } from "./synthetic-persistence.mjs";
import { digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { base, scenario, authorize, harness, admitted, terminal, restart, checkpointInput, document, seal, copy, hash } from "./synthetic-recovery-v2.mjs";

const warnings = [], ajv = new Ajv2020({ ...AJV_OPTIONS, logger: { log() {}, warn(x) { warnings.push(x); }, error(x) { warnings.push(x); } } });
addFormats(ajv, { mode: "full", formats: ["date-time"], keywords: false });
assert.equal(ajv.validateSchema(schema), true); ajv.addSchema(schema);
const gate = ajv.getSchema(schema.$id), projectionGate = ajv.compile({ $ref: `${schema.$id}#/$defs/projection` });
assert.deepEqual(warnings, []);
const required = Object.freeze([
  "RP-001", "RP-002", "RP-003", "RP-004", "RP-005", "RP-006", "RP-007", "RP-008", "RP-009", "RP-010",
  "RP-011", "RP-012", "RP-013", "RP-014", "RP-015", "RP-016", "RP-017", "RP-018", "RP-019", "RP-020",
  "RP-021", "RP-022", "RP-023", "RP-024", "RP-025", "RP-026", "RP-027", "RP-028", "RP-029", "RP-030"
]);
const cases = [], executed = new Set();
const vector = (id, label, fn) => cases.push({ id, label, fn });
const retirement = () => harness(authorize(restart(admitted()), "RetireAdmittedCandidate"));
const compaction = () => harness(authorize(restart(terminal()), "CompactTerminalState"));
const reconcile = published => harness(authorize(checkpointInput(published), "ReconcileCheckpoint"));
function project(h) {
  assert.equal(gate(h.input), true, JSON.stringify(gate.errors));
  const before = copy(h.input), r = h.project();
  assert.deepEqual(h.input, before); assert.equal(projectionGate(r), true, JSON.stringify(projectionGate.errors));
  assert.equal(r.launch_status, "Blocked"); assert.equal(r.launcher_status, "NotImplemented");
  assert.ok(Object.values(r.effects).every(x => x === false));
  return r;
}
function invariant(before, after) {
  const b = inspect(before.storage, before.minimum).state;
  const a = inspect(after.storage, after.minimum).state;
  assert.ok(a && b); assert.deepEqual(a.selection, b.selection);
  for (const key of ["generation", "generation_floor", "security_floor"]) assert.equal(a[key], b[key]);
  assert.ok(a.counter > b.counter);
}
function rejection(h, reason) { const r = project(h); assert.equal(r.status, "RecoveryRequired"); if (reason) assert.equal(r.reason, reason); return r; }
function resealAuth(i) { seal(i.authorization.offer, "offer_digest", "Offer"); i.authorization.confirmation.offer_digest = i.authorization.offer.offer_digest; }
function budget(operation, changes = {}) {
  return { operation, record_count: 0, journal_bytes: 2, sequence: 20, counter: 10, lineage: 0, head_bytes: 512, anchor_bytes: 512, ...changes };
}
function terminal58() {
  let result = run(scenario());
  for (let i = 0; i < 10; i++) {
    const a = harness(authorize(restart(result), "Maintenance", { candidate: result.storage.head.selection })).admit().project();
    result = harness(authorize(restart(a), "RetireAdmittedCandidate")).retire().project();
    assert.equal(result.reason, "None");
  }
  for (let i = 0; i < 7; i++) result = harness(authorize(restart(result), "Maintenance", { candidate: result.storage.head.selection })).full().project();
  assert.equal(result.storage.records.length, 58); assert.equal(result.reason, "None"); return result;
}
let cached58;
const full62 = () => harness(authorize(restart(cached58 ??= terminal58()), "Maintenance", { candidate: cached58.storage.head.selection })).full().project();

vector("RP-001", "fresh retirement preserves deployment and origin", () => {
  const h = retirement(), before = copy(h.input), r = project(h.retire().ack());
  assert.equal(r.status, "Completed"); assert.equal(r.result_ack, "Delivered"); invariant(before, r);
  const s = inspect(r.storage, r.minimum).state;
  assert.equal(s.terminal.outcome, "CandidateRetired"); assert.equal(s.active, null);
  assert.equal(r.storage.records[1].authorization.offer.origin_transaction_id, "synthetic-tx-11");
});
vector("RP-002", "failed first install retains null selection and consumption", () => {
  const a = harness(authorize(scenario(base({ selection: null, security_floor: 0, generation: 0, generation_floor: 0 })), "Maintenance",
    { candidate: { digest: hash("first"), epoch: 1 } })).admit().project();
  const h = harness(authorize(restart(a), "RetireAdmittedCandidate")), r = project(h.retire());
  assert.equal(r.selection_known, true); assert.equal(r.selection, null); invariant(h.input, r);
  assert.equal(r.minimum.counter, 12); assert.equal(r.minimum.generation, 0);
});
vector("RP-003", "publication and recovered Admitted cannot be retired", () => {
  const blocked = harness().admit().stage("Block").project();
  assert.throws(() => offer(restart(blocked), "RetireAdmittedCandidate"), /PublicationUnresolved/);
  const recovered = harness(authorize(restart(blocked), "RecoverPublication", { candidate: { digest: hash("v2"), epoch: 5 }, recovery_target: "FinalizeCandidate" })).admit().project();
  assert.equal(inspect(recovered.storage, recovered.minimum).state.active.stage, "Admitted");
  const status = project(harness(restart(recovered)).query(12));
  assert.equal(status.last_status, "RecoveryRequired"); assert.equal(status.status, "RecoveryRequired");
  assert.throws(() => offer(restart(recovered), "RetireAdmittedCandidate"), /PublicationUnresolved/);
  const uncertain = harness().admit().event("WriteRecord", { record_kind: "Block", result: "Unknown" }).project();
  assert.throws(() => offer(restart(uncertain), "RetireAdmittedCandidate"));
  assert.throws(() => offer(restart(harness().admit().stage("Block").stage("Commit").project()), "RetireAdmittedCandidate"));
});
vector("RP-004", "schema-valid foreign origin lineage selection and trust reject", () => {
  for (const change of [o => { o.origin_transaction_id = "synthetic-tx-9"; }, o => { o.basis.state_digest = hash("foreign-lineage"); },
    o => { o.candidate.digest = hash("foreign-selection"); }, o => { o.candidate.epoch = 0; }]) {
    const h = retirement(); change(h.input.authorization.offer); resealAuth(h.input); rejection(h.admit());
  }
  const untrusted = retirement(); untrusted.input.evidence_trust = "Unknown"; rejection(untrusted.admit(), "UnknownEvidence");
  const stale = retirement(); stale.input.minimum.security_floor++; rejection(stale.admit(), "MinimumConflict");
});
vector("RP-005", "declined expired stale wrong operation and replay reject", () => {
  const declined = retirement(); declined.input.authorization.confirmation.decision = "Declined"; rejection(declined.admit(), "ConfirmationRejected");
  const expired = retirement(); expired.input.authorization.offer.expires_at = "2026-09-29T11:59:59Z"; resealAuth(expired.input); rejection(expired.admit(), "OfferExpired");
  const wrong = retirement(); wrong.input.authorization.offer.operation = "FinishCommittedCleanup"; resealAuth(wrong.input); rejection(wrong.admit());
  const r = project(retirement().retire()), replay = retirement(); replay.input.storage = copy(r.storage); replay.input.minimum = copy(r.minimum);
  rejection(replay.admit(), "OfferChanged");
  const stale = retirement(); stale.input.authorization.confirmation.offer_digest = hash("stale"); rejection(stale.admit(), "ConfirmationRejected");
});
vector("RP-006", "every retirement durable boundary fails closed and keeps origin", () => {
  const initial = retirement().retire().input;
  for (let at = 0; at < initial.events.length; at++) {
    const i = copy(initial), e = i.events[at]; e.result = e.kind === "ReadBack" ? "Mismatch" : "Unknown";
    const r = rejection(harness(i)); assert.ok(r.minimum.counter >= 12); assert.equal(r.result_ack, "NotSent");
    assert.equal(r.storage.records[0].transaction_id, "synthetic-tx-11");
    const decoded = decode(encode(document(r))); assert.equal(decoded.minimum.counter, r.minimum.counter);
  }
  for (let count = 0; count <= initial.events.length; count++) {
    const i = copy(initial); i.events = [...i.events.slice(0, count), { kind: "Crash" }];
    const r = rejection(harness(i), "Crash"); assert.ok(r.minimum.counter >= (count ? 12 : 11));
    assert.equal(r.storage.records[0].transaction_id, "synthetic-tx-11");
    assert.deepEqual(decode(encode(document(r))).storage, r.storage);
  }
});
vector("RP-007", "NotWritten and uncertain admission have different spent minima", () => {
  for (const [result, count, integrity] of [["NotWritten", 11, "Known"], ["Unknown", 12, "Unknown"]]) {
    const h = retirement().event("WriteRecord", { record_kind: "Admission", result }), r = rejection(h);
    assert.equal(r.minimum.counter, count); assert.equal(r.storage.integrity, integrity);
    if (result === "Unknown") assert.throws(() => offer(restart(r), "RetireAdmittedCandidate"));
  }
});
vector("RP-008", "fresh repeated retirement preserves all lineage and caps at sixteen", () => {
  let r = admitted();
  for (let n = 2; n <= 16; n++) {
    const h = harness(authorize(restart(r), "RetireAdmittedCandidate")); h.input.context.session_id = `synthetic-session-${n}`;
    // A changed session cannot use the previous session's offer.
    rejection(harness(copy(h.input)).admit(), "OfferChanged");
    authorize(h.input, "RetireAdmittedCandidate"); r = project(h.admit());
    const a = inspect(r.storage, r.minimum).state.active;
    assert.equal(a.lineage.length, n); assert.equal(a.origin_transaction_id, "synthetic-tx-11");
  }
  assert.throws(() => offer(restart(r), "RetireAdmittedCandidate"), /LineageFull/);
});
vector("RP-009", "exact record admission budgets for every operation", () => {
  for (const [op, max, need] of [["Maintenance", 58, 6], ["RecoverPublication", 58, 6], ["FinishCommittedCleanup", 60, 4],
    ["RetireAdmittedCandidate", 60, 4], ["CompactTerminalState", 62, 2], ["ReconcileCheckpoint", 62, 2]]) {
    assert.equal(capacity(budget(op, { record_count: max })), need);
    assert.throws(() => capacity(budget(op, { record_count: max + 1 })), /CapacityExhausted/);
  }
  const r = full62(); assert.equal(r.storage.records.length, 62); assert.equal(r.status, "Completed");
});
vector("RP-010", "exact byte caps and arithmetic overflow are checked before intake", () => {
  for (const [op, need] of [["Maintenance", 6], ["RetireAdmittedCandidate", 4], ["ReconcileCheckpoint", 2]]) {
    const bytes = 1048576 - need * 16385;
    assert.equal(capacity(budget(op, { journal_bytes: bytes, sequence: Number.MAX_SAFE_INTEGER - need })), need);
    assert.throws(() => capacity(budget(op, { journal_bytes: bytes + 1 })), /CapacityExhausted/);
    assert.throws(() => capacity(budget(op, { sequence: Number.MAX_SAFE_INTEGER - need + 1 })), /CounterOrSequenceOverflow/);
  }
  for (const key of ["head_bytes", "anchor_bytes"]) {
    assert.equal(capacity(budget("Maintenance", { [key]: 8192 })), 6);
    assert.throws(() => capacity(budget("Maintenance", { [key]: 8193 })), /CapacityExhausted/);
  }
  assert.throws(() => capacity(budget("Maintenance", { counter: Number.MAX_SAFE_INTEGER })), /CounterOrSequenceOverflow/);
  assert.throws(() => capacity(budget("Maintenance", { journal_bytes: Number.MAX_SAFE_INTEGER })), /CapacityExhausted/);
});
vector("RP-011", "capacity/state changes invalidate an old preview", () => {
  const h = retirement(), next = project(retirement().admit());
  h.input.storage = copy(next.storage); h.input.minimum = copy(next.minimum);
  rejection(h.admit(), "OfferChanged");
  const forged = retirement(); forged.input.authorization.offer.basis.record_count++; resealAuth(forged.input); rejection(forged.admit(), "OfferChanged");
});
vector("RP-012", "ordinary work cannot take reserved metadata capacity", () => {
  const r = full62(); assert.throws(() => offer(restart(r), "Maintenance"), /CapacityExhausted/);
  const h = harness(authorize(restart(r), "CompactTerminalState")), c = project(h.compact().ack());
  assert.equal(c.storage.records.length, 0); assert.equal(c.result_ack, "Delivered"); invariant(h.input, c);
});
vector("RP-013", "fresh session compaction requires its own confirmation", () => {
  const i = restart(terminal()); i.context.session_id = "synthetic-fresh-session";
  const h = harness(i).query(11).event("WriteRecord", { record_kind: "Admission", result: "Complete" });
  rejection(h, "ConfirmationRequired");
  i.events = []; authorize(i, "CompactTerminalState"); const r = project(harness(i).compact().ack());
  assert.equal(r.status, "Completed"); assert.equal(r.minimum.counter, 12);
});
vector("RP-014", "63/64 record interrupted stores block without trim or reset", () => {
  const i = authorize(restart(full62()), "CompactTerminalState");
  for (const count of [6, 12, 15]) {
    const h = harness(copy(i)).compact(); h.input.events = h.input.events.slice(0, count);
    const r = project(h), before = copy(r.storage);
    assert.ok([63, 64].includes(r.storage.records.length));
    assert.throws(() => offer(restart(r), count === 15 ? "ReconcileCheckpoint" : "CompactTerminalState"));
    const status = run(restart(r)); assert.deepEqual(status.storage, before); assert.equal(status.minimum.counter, r.minimum.counter);
  }
  for (const record_count of [63, 64]) assert.throws(() => capacity(budget("ReconcileCheckpoint", { record_count })), /CapacityExhausted/);
});
vector("RP-015", "compaction preserves spent counters floors selection and retired status", () => {
  const h = compaction(), r = project(h.compact().ack()); invariant(h.input, r);
  assert.equal(r.storage.records.length, 0); assert.equal(r.storage.anchor.counter, 12);
  const q = harness(restart(r)).query(11).project(); assert.equal(q.last_status, "Retired");
  assert.equal(harness(restart(r)).query(12).project().last_status, "Completed");
  assert.equal(run(restart(r)).minimum.counter, 12);
});
vector("RP-016", "prepared checkpoint is read-only classification not authority", () => {
  const i = checkpointInput(false), before = copy(i), v = inspect(i.storage, i.minimum);
  assert.equal(v.classification, "PreparedUnpublished"); assert.deepEqual(i, before);
  const r = project(harness(i)); assert.equal(r.status, "RecoveryRequired"); assert.equal(r.selection_known, false);
});
vector("RP-017", "published checkpoint retains both representations without promotion", () => {
  const i = checkpointInput(true), v = inspect(i.storage, i.minimum);
  assert.equal(v.classification, "PublishedUnretired"); assert.notEqual(i.storage.head.tail_digest, v.state.tail_digest);
  assert.equal(project(harness(i)).selection_known, false); assert.ok(i.storage.records.length > 0);
});
vector("RP-018", "already retired checkpoint reads current status without effects", () => {
  const r = compaction().compact().project(), i = restart(r), before = copy(i.storage);
  const status = project(harness(i).query(12)); assert.deepEqual(status.storage, before);
  assert.equal(status.classification, "Stable"); assert.equal(status.last_status, "Completed"); assert.equal(status.minimum.counter, 12);
});
vector("RP-019", "every candidate binding substitution fails even with corrected hashes", () => {
  const changes = [a => { a.machine_id = "synthetic-machine-b"; }, a => { a.sequence++; }, a => { a.counter++; },
    a => { a.generation++; }, a => { a.generation_floor++; }, a => { a.security_floor++; }, a => { a.selection.digest = hash("other"); },
    a => { a.selection.epoch++; }, a => { a.terminal.transaction_id = "synthetic-tx-9"; }, a => { a.terminal.terminal_digest = hash("other"); }];
  for (const change of changes) {
    const i = checkpointInput(false); change(i.storage.checkpoint_candidate); seal(i.storage.checkpoint_candidate, "anchor_digest", "Anchor");
    assert.equal(gate(i), true); assert.equal(inspect(i.storage, i.minimum).classification, "ConflictOrUnknown");
    assert.equal(project(harness(i)).status, "RecoveryRequired");
  }
});
vector("RP-020", "neither head truncated chain active lineage and uncertain retirement reject", () => {
  for (const change of [i => { i.storage.head.tail_digest = hash("neither"); seal(i.storage.head, "head_digest", "Head"); },
    i => { i.storage.records = i.storage.records.slice(1); }, i => { i.storage.records = []; },
    i => { i.storage.integrity = "Unknown"; }]) {
    const i = checkpointInput(true); change(i); assert.equal(inspect(i.storage, i.minimum).classification, "ConflictOrUnknown");
    rejection(harness(i));
  }
  const i = restart(admitted()); i.storage.checkpoint_candidate = checkpointInput(false).storage.checkpoint_candidate;
  assert.equal(inspect(i.storage, i.minimum).reason, "ActiveLineage");
});
vector("RP-021", "codec checksums and Known labels do not imply durability or permission", () => {
  const i = checkpointInput(false), r = run(i), doc = document(r), decoded = decode(encode(doc));
  assert.deepEqual(decoded, doc); assert.equal(decoded.execution_enabled, false);
  const h = harness(scenario(decoded.storage, decoded.minimum)).event("WriteRecord", { record_kind: "Admission", result: "Complete" });
  rejection(h, "ConfirmationRequired");
  const u = copy(h.input); u.evidence_trust = "Unknown"; rejection(harness(u), "UnknownEvidence");
  const fresh = authorize(scenario(decoded.storage, decoded.minimum), "ReconcileCheckpoint");
  fresh.events = [{ kind: "WriteRecord", record_kind: "Admission", result: "Complete" }, { kind: "Flush", target: "Record", result: "Unknown" }];
  rejection(harness(fresh), "FlushUncertain");
});
vector("RP-022", "reconciliation consumes fresh authority and uses a new checkpoint", () => {
  for (const published of [false, true]) {
    const h = reconcile(published), before = copy(h.input), oldCandidate = copy(h.input.storage.checkpoint_candidate);
    h.compact(); h.input.events.pop(); const pending = project(h);
    assert.equal(pending.storage.checkpoint_candidate.counter, oldCandidate.counter + 1);
    assert.deepEqual(pending.storage.obsolete_checkpoint, oldCandidate);
    assert.equal(pending.storage.records.at(-2).authorization.offer.basis.checkpoint_candidate.anchor_digest, oldCandidate.anchor_digest);
    h.event("RetireJournal", { result: "Complete" }).ack(); const r = project(h);
    assert.equal(r.status, "Completed"); invariant(before, r); assert.equal(r.storage.obsolete_checkpoint, null);
  }
});
vector("RP-023", "all reconciliation interruption boundaries retain evidence or block", () => {
  for (const published of [false, true]) {
    const initial = reconcile(published).compact().input, count = initial.storage.records.length;
    for (let at = 0; at < initial.events.length; at++) {
      const i = copy(initial), e = i.events[at]; e.result = e.kind === "ReadBack" ? "Mismatch" : "Unknown";
      const r = rejection(harness(i)); assert.ok(r.minimum.counter >= 13); assert.ok(r.storage.records.length >= count);
      assert.deepEqual(r.storage.records.slice(0, count), initial.storage.records); assert.equal(r.result_ack, "NotSent");
      assert.deepEqual(decode(encode(document(r))).storage, r.storage);
      const reboot = run(restart(r)); assert.equal(reboot.selection_known, false);
    }
    for (let end = 0; end < initial.events.length; end++) {
      const i = copy(initial); i.events = [...i.events.slice(0, end), { kind: "Crash" }];
      const r = rejection(harness(i)); assert.deepEqual(r.storage.records.slice(0, count), initial.storage.records);
      assert.ok(r.minimum.counter >= (end ? 13 : 12));
      assert.deepEqual(decode(encode(document(r))).minimum, r.minimum);
    }
  }
});
vector("RP-024", "journal retirement waits for checkpoint and head verification", () => {
  const h = reconcile(true).compact(), before = copy(h.input.storage.records);
  for (let end = 12; end < h.input.events.length - 1; end++) {
    const i = copy(h.input); i.events = [...i.events.slice(0, end), { kind: "RetireJournal", result: "Complete" }];
    const r = rejection(harness(i), "OrderRejected"); assert.deepEqual(r.storage.records.slice(0, before.length), before);
  }
  const i = copy(h.input); i.events.at(-1).result = "NotWritten"; const r = rejection(harness(i), "NotWritten");
  assert.deepEqual(r.storage.records.slice(0, before.length), before); assert.equal(r.result_ack, "NotSent");
});
vector("RP-025", "lost replies require exact status and cannot replay effects", () => {
  const h = retirement().admit().ack("Admission", "Lost"); rejection(harness(copy(h.input)).stage("Retire"), "StatusRequired");
  const wrong = harness(copy(h.input)).query(11).stage("Retire"); rejection(wrong, "StatusRequired");
  const r = project(h.query(12).stage("Retire").ack("Result", "Lost").query(12)); assert.equal(r.last_status, "CandidateRetired");
  assert.equal(r.minimum.counter, 12); assert.equal(r.storage.records.length, 3);
  rejection(h.event("WriteRecord", { record_kind: "Admission", result: "Complete" }), "OrderRejected");
});
vector("RP-026", "cancel Busy and unknown quiescence have no cleanup authority", () => {
  for (const key of ["coordinator", "quiescence"]) for (const value of ["Busy", "Unknown"]) {
    const h = retirement(); h.input[key] = value; const before = copy(h.input.storage);
    const r = rejection(h.admit(), "BusyOrUnknownQuiescence"); assert.deepEqual(r.storage, before); assert.equal(r.minimum.counter, 11);
  }
  const h = retirement().event("Cancel").admit(), r = rejection(h, "Cancel"); assert.equal(r.events_processed, 1); assert.equal(r.minimum.counter, 11);
});
vector("RP-027", "serialized losing offers bind policy helper peer and candidate absence", () => {
  for (const [key, value] of [["session_id", "synthetic-next"], ["peer_id", "synthetic-other"], ["approver_id", "synthetic-other"],
    ["challenge", hash("next")], ["helper_digest", hash("next")], ["policy_digest", hash("next")], ["confirmation_text_digest", hash("next")]]) {
    const h = retirement(); h.input.context[key] = value; rejection(h.admit(), "OfferChanged");
  }
  const h = reconcile(false); h.input.storage.head = copy(checkpointInput(true).storage.head); rejection(h.admit(), "OfferChanged");
  const absence = compaction(); absence.input.storage.checkpoint_candidate = checkpointInput(false).storage.checkpoint_candidate; rejection(absence.admit());
  const losing = retirement(), winner = project(retirement().retire()); losing.input.storage = copy(winner.storage); losing.input.minimum = copy(winner.minimum);
  rejection(losing.admit(), "OfferChanged");
  const format = retirement(); format.input.authorization.offer.format = "SyntheticRecovery-v1";
  assert.throws(() => run(format.input), { code: "RECOVERY_V2_INPUT_INVALID" });
});
vector("RP-028", "v1 and v2 reject each other's schema and byte format", () => {
  const r = terminal(), doc = document(r), bytes = encode(doc);
  assert.equal(bytes.subarray(0, 8).toString("ascii"), "SA_MSC02"); assert.throws(() => decodeV1(bytes));
  assert.throws(() => checkedPersistenceData("storage", r.storage));
  assert.throws(() => simulateMaintenancePersistence(scenario()));
  const old = harnessV1(baseStorage(), null).project();
  const oldDoc = { schema_version: "1.0.0", model_kind: "MaintenanceStoreDocument", privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly",
    simulated_at: "2026-09-29T12:00:00Z", usage: "SyntheticReferenceOnly", execution_enabled: false,
    minimum: old.watermarks, storage: old.storage, document_digest: "" };
  oldDoc.document_digest = digestWithExclusion(oldDoc, "document_digest"); assert.throws(() => decode(encodeV1(oldDoc)));
  assert.throws(() => checkedRecoveryData("storage", old.storage));
  for (const format of ["1.0.0", "3.0.0"]) { const i = scenario(); i.schema_version = format; assert.throws(() => run(i)); }
});
vector("RP-029", "no result or metadata authority enables host or deployment effects", () => {
  for (const h of [retirement().retire(), compaction().compact(), reconcile(true).compact()]) {
    const r = project(h); assert.equal(r.status, "Completed");
    const fake = copy(r); fake.effects.backend_execution_enabled = true; assert.equal(projectionGate(fake), false);
  }
  const wrong = retirement(); wrong.input.authorization.offer.effects_scope = "SyntheticDeploymentOnly"; resealAuth(wrong.input); rejection(wrong.admit(), "ScopeRejected");
  rejection(retirement().admit().stage("Block"), "OrderRejected");
  const i = scenario(); i.events = [{ kind: "DeletePayload" }]; assert.throws(() => run(i));
});
vector("RP-030", "bounded immutable deterministic inputs codec and exact gate", () => {
  const h = retirement().retire(), first = project(h), second = project(h); assert.deepEqual(first, second);
  function frozen(x) { if (x && typeof x === "object") { assert.equal(Object.isFrozen(x), true); Object.values(x).forEach(frozen); } }
  frozen(first); const d = document(first), bytes = encode(d), decoded = decode(bytes); assert.deepEqual(decoded, d); frozen(decoded);
  assert.deepEqual(encode(decoded), bytes);
  let calls = 0; const getter = scenario(); Object.defineProperty(getter, "storage", { enumerable: true, get() { calls++; return base(); } });
  assert.throws(() => run(getter)); assert.equal(calls, 0);
  assert.throws(() => run(new Proxy(scenario(), { get() { calls++; throw new Error(); } }))); assert.equal(calls, 0);
  const cycle = scenario(); cycle.events = [cycle]; assert.throws(() => run(cycle));
  const many = scenario(); many.events = Array.from({ length: 129 }, () => ({ kind: "Crash" })); assert.throws(() => run(many));
  for (const mutate of [b => { b[12] ^= 1; }, b => { b[0] ^= 1; }, b => { b.writeUInt32BE(1, 8); }]) {
    const bad = Buffer.from(bytes); mutate(bad); assert.throws(() => decode(bad));
  }
  assert.throws(() => decode(Buffer.concat([bytes, Buffer.from([10])]))); assert.throws(() => decode(bytes.subarray(0, -1)));
  assert.throws(() => decode(new Uint8Array(new SharedArrayBuffer(bytes.length))));
  const hooked = Buffer.from(bytes); Object.defineProperty(hooked, "byteLength", { get() { calls++; return bytes.length; } });
  assert.throws(() => decode(hooked)); assert.equal(calls, 0);
  function frame(text) {
    const payload = Buffer.from(text), header = Buffer.alloc(12); header.write("SA_MSC02"); header.writeUInt32BE(payload.length, 8);
    return Buffer.concat([header, createHash("sha256").update(header).update(payload).digest(), payload]);
  }
  assert.throws(() => decode(frame(`${jcs(d)}\n`)));
  assert.throws(() => decode(frame(jcs(d).replace('"schema_version":"2.0.0"', '"schema_version":"2.0.0","schema_version":"2.0.0"'))));
  const bad = copy(d); bad.minimum.counter = 0; seal(bad, "document_digest", "Document"); assert.throws(() => encode(bad));
  const largerMinimum = scenario(); largerMinimum.minimum.counter++;
  const r = run(largerMinimum); assert.equal(r.minimum.counter, 11); assert.equal(r.reason, "MinimumConflict");
});

for (const c of cases) test(`${c.id} ${c.label}`, () => { c.fn(); assert.equal(executed.has(c.id), false); executed.add(c.id); });
test("RP exact required-ID gate; no omitted, duplicate or unexecuted cases", () => {
  assert.equal(new Set(required).size, required.length); assert.equal(new Set(cases.map(c => c.id)).size, cases.length);
  assert.deepEqual(cases.map(c => c.id).sort(), [...required].sort()); assert.deepEqual([...executed].sort(), [...required].sort());
});

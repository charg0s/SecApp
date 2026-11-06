import test from "node:test";
import assert from "node:assert/strict";
import { jcsSha256, digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { simulateMaintenanceProtocol, maintenanceHeadDigest } from "../../tools/lib/maintenance-protocol-model.mjs";
import { simulateMaintenancePersistence } from "../../tools/lib/maintenance-persistence-model.mjs";
import { checkedProtocolData } from "../../tools/lib/maintenance-protocol-validation.mjs";
import { checkedPersistenceData } from "../../tools/lib/maintenance-persistence-validation.mjs";
import { context, request, harness as protocol, tuple, copy, localEvent } from "./synthetic-protocol.mjs";
import { baseStorage, intentFor, recoveryIntent, sealIntent, harness as persistence } from "./synthetic-persistence.mjs";

const required = Object.freeze([
  "MCC-001", "MCC-002", "MCC-003", "MCC-004", "MCC-005", "MCC-006",
  "MCC-007", "MCC-008", "MCC-009", "MCC-010", "MCC-011", "MCC-012",
  "MCC-013", "MCC-014", "MCC-015", "MCC-016", "MCC-017", "MCC-018",
  "MCC-019", "MCC-020", "MCC-021", "MCC-022", "MCC-023", "MCC-024"
]);
const cases = [];
const vector = (id, label, fn) => cases.push({ id, label, fn });

// Private test correspondence, never an authority adapter or a storage format.
// Both inputs are explicit synthetic hypotheses; neither authorizes the other.
const selected = value => value === null ? null : jcsSha256({ domain: "SecApp-Test-Composition-Tuple-v1", tuple: value });
function run(model, input, check) {
  check("scenario", input); // Every semantic negative is structurally valid.
  const result = model(input);
  check("projection", result);
  assert.equal(result.scenario_digest, jcsSha256(input));
  assert.equal(result.result_digest, digestWithExclusion(result, "result_digest"));
  assert.equal(result.launch_status, "Blocked");
  assert.ok(Object.values(result.effects).every(value => value === false));
  return result;
}
const pr = h => run(simulateMaintenanceProtocol, h.input, checkedProtocolData);
const sr = h => run(simulateMaintenancePersistence, h.input, checkedPersistenceData);
function pair(operation = "Update", epoch = 4) {
  const ctx = context(); ctx.store.selection = tuple(1, epoch); ctx.store.security_floor = epoch;
  const proposal = request(ctx, operation);
  const disk = baseStorage({ selection_digest: selected(ctx.store.selection),
    selection_epoch: ctx.store.selection?.security_epoch ?? 0, security_floor: epoch, last_transaction_id: null });
  const intent = intentFor(disk, { selection_digest: selected(proposal.desired), selection_epoch: proposal.desired?.security_epoch ?? 0 });
  return { ctx, proposal, p: protocol(ctx, proposal), s: persistence(disk, intent) };
}
function admit(t, delivery = "Delivered") { t.p.offer().admit(delivery); t.s.reserve(delivery); return t; }
function block(t) { t.p.payload().publish(); t.s.block(); return t; }
function commit(t) { t.p.commit(); t.s.commit(); return t; }
function complete(t, delivery = "Delivered") { t.p.cleanup().result(delivery); t.s.complete(delivery); return t; }
function full(t) { return complete(commit(block(admit(t)))); }
function compare(t, { counter, generation, floor, selection, pending = false }) {
  const p = pr(t.p), s = sr(t.s);
  assert.equal(p.reason, "None"); assert.equal(s.reason, "None");
  assert.equal(p.counter_floor, counter); assert.equal(s.watermarks.counter, counter);
  assert.equal(p.security_floor, floor); assert.equal(s.watermarks.security_floor, floor);
  assert.equal(s.watermarks.generation, generation);
  if (pending) {
    assert.equal(p.projected_store, null); assert.equal(p.outcome, "Unknown");
    assert.equal(s.selection_known, false); assert.equal(s.selected_digest, null);
  } else {
    assert.equal(p.projected_store.generation, generation);
    assert.deepEqual(p.projected_store.selection, selection);
    assert.equal(s.selection_known, true); assert.equal(s.selected_digest, selected(selection));
  }
  return { p, s };
}

// Fabricate a declared Known restart hypothesis at a stable record boundary.
// In particular, never infer a real store from a null protocol projection.
// Offer/confirmation hashes are copied only as synthetic lineage labels.
function checkpoint(t, boundary) {
  const result = pr(t.p), ctx = copy(t.ctx), store = ctx.store;
  store.counter += 1;
  const entry = { transaction_id: `synthetic-tx-${store.counter}`, counter: store.counter,
    offer_digest: result.offer_digest, confirmation_digest: result.confirmation_digest };
  if (store.journal) store.journal.lineage.push(entry);
  else store.journal = { origin_transaction_id: entry.transaction_id, phase: "Admitted",
    highest_generation: store.generation, reserved_floor: store.security_floor,
    previous: copy(store.selection), candidate: copy(t.proposal.desired), lineage: [entry], journal_digest: "" };
  if (boundary === "Block" || boundary === "Commit") {
    store.journal.highest_generation += 1;
    store.journal.reserved_floor = Math.max(store.journal.reserved_floor, store.selection?.security_epoch ?? 0, t.proposal.desired?.security_epoch ?? 0);
    store.journal.phase = "PublishPending";
  }
  if (boundary === "Commit") {
    store.selection = copy(t.proposal.desired); store.generation = store.journal.highest_generation;
    store.security_floor = store.journal.reserved_floor;
    store.journal.candidate = copy(store.selection); store.journal.phase = "Committed";
  }
  store.journal.journal_digest = digestWithExclusion(store.journal, "journal_digest");
  const disk = sr(t.s).storage;
  assert.equal(disk.integrity, "Known");
  return { ctx, disk };
}
function recover(saved, target = "FinalizeCandidate") {
  const ctx = copy(saved.ctx), journal = ctx.store.journal;
  const desired = target === "FinishCommittedCleanup" ? ctx.store.selection
    : target === "FinalizeCandidate" ? journal.candidate : journal.previous;
  const proposal = { kind: "Recovery", recovery_target: target, original_transaction_id: journal.origin_transaction_id,
    journal_digest: journal.journal_digest, highest_generation: journal.highest_generation,
    expected_head_digest: maintenanceHeadDigest(ctx.store), expected_generation: ctx.store.generation, desired: copy(desired), members: [] };
  return { ctx, proposal, p: protocol(ctx, proposal), s: persistence(saved.disk, recoveryIntent(saved.disk, target)) };
}
function proposeOnly(t) { t.p.bind().wire("ProposeOperation", t.proposal); t.s.write("Reserve"); return { p: pr(t.p), s: sr(t.s) }; }
function query(t, counter) { t.p.wire("QueryStatus", { counter }); t.s.query(counter); return t; }

vector("MCC-001", "five normal operations agree at admission, block, commit and completion", () => {
  for (const operation of ["Install", "Update", "EnrollBackend", "Repair", "Uninstall"]) {
    const t = pair(operation), floor = Math.max(4, t.proposal.desired?.security_epoch ?? 0);
    compare(admit(t), { counter: 11, generation: 7, floor: 4, selection: t.ctx.store.selection });
    compare(block(t), { counter: 11, generation: 8, floor, pending: true });
    compare(commit(t), { counter: 11, generation: 8, floor, selection: t.proposal.desired });
    const { p, s } = compare(complete(t), { counter: 11, generation: 8, floor, selection: t.proposal.desired });
    assert.equal(p.state, "Completed"); assert.equal(s.status, "Completed");
    assert.equal(p.projected_store.journal, null);
    assert.equal(s.storage.head.phase, "Stable");
  }
});
vector("MCC-002", "known unwritten reserve leaves consumption and selection unchanged", () => {
  const t = pair(); t.p.offer().confirm().reserve("NotWritten"); t.s.write("Reserve", "NotWritten");
  const p = pr(t.p), s = sr(t.s);
  assert.equal(p.reason, "AdmissionNotWritten"); assert.equal(s.reason, "NotWritten");
  assert.equal(p.counter_floor, 10); assert.equal(s.watermarks.counter, 10);
  assert.equal(selected(p.projected_store.selection), s.selected_digest);
});
vector("MCC-003", "uncertain reserve preserves possible consumption without selection", () => {
  for (const outcome of ["Torn", "Unknown"]) {
    const t = pair(); t.p.offer().confirm().reserve("Unknown"); t.s.write("Reserve", outcome);
    const p = pr(t.p), s = sr(t.s);
    assert.equal(p.state, "RecoveryRequired"); assert.equal(s.status, "RecoveryRequired");
    assert.equal(p.counter_floor, 11); assert.equal(s.watermarks.counter, 11);
    assert.equal(p.projected_store, null); assert.equal(s.selection_known, false);
  }
});
vector("MCC-004", "abstract transitions cannot skip any of six persistence observations", () => {
  const t = full(pair()), input = t.s.input;
  const starts = input.events.flatMap((event, index) => event.kind === "WriteRecord" ? [index] : []);
  assert.equal(starts.length, 4);
  for (const start of starts) for (let offset = 1; offset < 6; offset += 1) {
    const h = { input: copy(input) }; h.input.events.length = start + offset;
    const prefix = sr(h); assert.equal(prefix.selection_known, false);
    h.input.events.push({ kind: "Acknowledge", phase: start === 0 ? "Admission" : "Result", delivery: "Delivered" });
    const early = sr(h); assert.equal(early.reason, "OrderRejected"); assert.equal(early.status, "RecoveryRequired");
  }
});
vector("MCC-005", "lost admission also blocks local continuation without a status query", () => {
  const t = admit(pair(), "Lost"); t.p.payload().publish().commit().cleanup(); t.s.block();
  const p = pr(t.p), s = sr(t.s);
  assert.equal(p.reason, "ReplayRejected"); assert.equal(s.reason, "StatusRejected");
  assert.equal(p.projected_store.generation, 7); assert.equal(s.storage.head.generation, 7);
  assert.equal(p.counter_floor, 11); assert.equal(s.watermarks.counter, 11);
  const stopped = admit(pair(), "Lost");
  stopped.p.local("Interrupt", { reason: "Crash" }); stopped.s.crash();
  assert.equal(pr(stopped.p).reason, "Crash"); assert.equal(sr(stopped.s).reason, "Crash");
  const progress = admit(pair(), "Lost"); progress.p.wire("Progress", { state: "Admitted" });
  assert.equal(pr(progress.p).reason, "ReplayRejected");
});
vector("MCC-006", "exact current status permits continuation without fresh consumption", () => {
  const t = query(admit(pair(), "Lost"), 11);
  assert.equal(pr(t.p).last_status, "Active"); assert.equal(sr(t.s).last_status, "Active");
  compare(complete(commit(block(t))), { counter: 11, generation: 8, floor: 5, selection: t.proposal.desired });
});
vector("MCC-007", "retired status does not unblock the lost current reply", () => {
  const t = query(admit(pair(), "Lost"), 9);
  assert.equal(pr(t.p).last_status, "Retired"); assert.equal(sr(t.s).last_status, "Retired");
  t.p.payload(); t.s.block();
  assert.equal(pr(t.p).reason, "ReplayRejected"); assert.equal(sr(t.s).reason, "StatusRejected");
});
vector("MCC-008", "lost terminal reply cannot repeat effects or erase known completion", () => {
  const t = complete(commit(block(admit(pair()))), "Lost");
  query(t, 11);
  assert.equal(pr(t.p).last_status, "Completed"); assert.equal(sr(t.s).last_status, "Completed");
  t.p.cleanup(); t.s.write("Reserve");
  const p = pr(t.p), s = sr(t.s);
  assert.equal(p.reason, "OrderRejected"); assert.equal(s.reason, "OrderRejected");
  assert.equal(p.counter_floor, 11); assert.equal(s.watermarks.counter, 11);
  assert.equal(selected(p.projected_store.selection), s.selected_digest);
});
vector("MCC-009", "restart status for unresolved publication requires recovery", () => {
  const saved = checkpoint(block(admit(pair())), "Block");
  const p = protocol(saved.ctx).bind().wire("QueryStatus", { counter: 11 });
  const s = persistence(saved.disk, null).query(11);
  assert.equal(pr(p).last_status, "RecoveryRequired"); assert.equal(sr(s).last_status, "RecoveryRequired");
  assert.equal(pr(p).projected_store, null); assert.equal(sr(s).selection_known, false);
  assert.equal(sr(s).watermarks.counter, 11);
});
vector("MCC-010", "same-session blocked status is Active but reveals no selection", () => {
  const t = query(block(admit(pair())), 11);
  const { p, s } = compare(t, { counter: 11, generation: 8, floor: 5, pending: true });
  assert.equal(p.last_status, "Active"); assert.equal(s.last_status, "Active");
});
vector("MCC-011", "all recovery targets use fresh counter with exact generation rules", () => {
  for (const target of ["FinalizeCandidate", "RestorePermittedPrevious", "FinishCommittedCleanup"]) {
    const first = block(admit(pair("Update", 5)));
    const cleanup = target === "FinishCommittedCleanup";
    if (cleanup) commit(first);
    const t = recover(checkpoint(first, cleanup ? "Commit" : "Block"), target);
    admit(t);
    if (!cleanup) { block(t); commit(t); }
    const { p, s } = compare(complete(t), { counter: 12, generation: cleanup ? 8 : 9, floor: 5, selection: t.proposal.desired });
    assert.equal(p.state, "Completed"); assert.equal(s.status, "Completed");
    const reserves = s.storage.records.filter(record => record.record_kind === "Reserve");
    assert.equal(reserves.length, 2); assert.notEqual(reserves[0].intent.confirmation_digest, reserves[1].intent.confirmation_digest);
  }
});
vector("MCC-012", "restoring a below-floor previous selection is denied by both models", () => {
  const t = recover(checkpoint(block(admit(pair())), "Block"), "RestorePermittedPrevious");
  const { p, s } = proposeOnly(t);
  assert.equal(p.reason, "EpochRejected"); assert.equal(s.reason, "EpochRejected");
  assert.equal(p.counter_floor, 11); assert.equal(s.watermarks.counter, 11);
  assert.equal(p.projected_store, null); assert.equal(s.selection_known, false);
});
vector("MCC-013", "null candidate and null previous recovery preserve known uninstalled state", () => {
  for (const [operation, target] of [["Uninstall", "FinalizeCandidate"], ["Install", "RestorePermittedPrevious"]]) {
    const t = recover(checkpoint(block(admit(pair(operation))), "Block"), target);
    const { p, s } = compare(full(t), { counter: 12, generation: 9, floor: 4, selection: null });
    assert.equal(p.outcome, "Uninstalled"); assert.equal(s.selection_known, true); assert.equal(s.selected_digest, null);
  }
});
vector("MCC-014", "interrupted recovery admission retains original target and publication watermark", () => {
  const first = checkpoint(block(admit(pair("Update", 5))), "Block");
  const second = admit(recover(first, "RestorePermittedPrevious"));
  compare(second, { counter: 12, generation: 8, floor: 5, pending: true });
  const third = recover(checkpoint(second, "Reserve"), "FinalizeCandidate");
  compare(full(third), { counter: 13, generation: 9, floor: 5, selection: tuple(2, 5) });
});
vector("MCC-015", "crash boundaries preserve counters and treat unknown selection conservatively", () => {
  for (const phase of ["Reserve", "Block", "Commit", "Complete"]) {
    const t = admit(pair());
    if (phase !== "Reserve") block(t);
    if (["Commit", "Complete"].includes(phase)) commit(t);
    if (phase === "Complete") complete(t);
    t.p.local("Interrupt", { reason: "Crash" }); t.s.crash();
    const p = pr(t.p), s = sr(t.s);
    assert.equal(p.counter_floor, 11); assert.equal(s.watermarks.counter, 11);
    if (phase === "Reserve") {
      assert.equal(p.state, "Aborted"); assert.equal(s.status, "RecoveryRequired");
      assert.deepEqual(p.projected_store.selection, t.ctx.store.selection); assert.equal(s.selection_known, false);
    } else if (phase === "Block") {
      assert.equal(p.projected_store, null); assert.equal(s.selection_known, false);
    } else {
      assert.equal(selected(p.projected_store.selection), s.selected_digest);
      assert.equal(p.projected_store.generation, 8);
    }
  }
});
vector("MCC-016", "persistence-only compaction preserves terminal and retired status correspondence", () => {
  const t = full(pair()); const before = compare(t, { counter: 11, generation: 8, floor: 5, selection: t.proposal.desired });
  t.s.compact();
  compare(t, { counter: 11, generation: 8, floor: 5, selection: t.proposal.desired });
  assert.notEqual(sr(t.s).storage.head.head_digest, before.s.storage.head.head_digest);
  query(t, 11); assert.equal(pr(t.p).last_status, "Completed"); assert.equal(sr(t.s).last_status, "Completed");
  query(t, 9); assert.equal(pr(t.p).last_status, "Retired"); assert.equal(sr(t.s).last_status, "Retired");
});
vector("MCC-017", "declined confirmation and stale state each prevent admission", () => {
  const t = pair(); t.p.offer().confirm().reserve(); localEvent(t.p.input, "Confirm").data.decision = "Declined";
  t.s.input.intent.confirmation = "Declined"; sealIntent(t.s.input.intent); t.s.write("Reserve");
  assert.equal(pr(t.p).reason, "ConsentDeclined"); assert.equal(sr(t.s).reason, "ConfirmationRejected");
  assert.equal(pr(t.p).counter_floor, 10); assert.equal(sr(t.s).watermarks.counter, 10);
  const stale = pair(); stale.proposal.expected_head_digest = selected(tuple(3));
  stale.p = protocol(stale.ctx, stale.proposal);
  stale.s.input.intent.expected_state_digest = selected(tuple(3)); sealIntent(stale.s.input.intent);
  const results = proposeOnly(stale);
  assert.equal(results.p.reason, "HeadChanged"); assert.equal(results.s.reason, "IntentRejected");
});
vector("MCC-018", "persistence success cannot replace protocol operation-scope validation", () => {
  const t = pair(); t.proposal.desired.backend_id = "synthetic-backend-v1";
  t.p = protocol(t.ctx, t.proposal);
  t.s.input.intent.selection_digest = selected(t.proposal.desired); sealIntent(t.s.input.intent);
  t.p.bind().wire("ProposeOperation", t.proposal); t.s.full();
  assert.equal(pr(t.p).reason, "ScopeRejected"); assert.equal(sr(t.s).status, "Completed");
  assert.equal(sr(t.s).effects.installation_enabled, false);
});
vector("MCC-019", "cross-model confirmation digests are not interchangeable authority", () => {
  const t = pair(); t.p.offer().confirm().reserve(); t.s.reserve();
  const p = pr(t.p), s = sr(t.s);
  assert.notEqual(p.confirmation_digest, s.storage.records[0].intent.confirmation_digest);
  localEvent(t.p.input, "Confirm").data.offer_digest = s.storage.records[0].intent.confirmation_digest;
  t.s.input.intent.confirmation_digest = p.confirmation_digest;
  assert.equal(pr(t.p).reason, "BindingMismatch"); assert.equal(sr(t.s).reason, "ConfirmationRejected");
  assert.equal(pr(t.p).counter_floor, 10); assert.equal(sr(t.s).watermarks.counter, 10);
});
vector("MCC-020", "unknown storage is never promoted through the other model's valid result", () => {
  const t = full(pair()); assert.equal(pr(t.p).state, "Completed"); assert.equal(sr(t.s).status, "Completed");
  t.p.input.context.storage_status = "Unknown"; t.s.input.storage.integrity = "Unknown";
  assert.equal(pr(t.p).state, "RecoveryRequired"); assert.equal(sr(t.s).status, "RecoveryRequired");
  assert.equal(pr(t.p).projected_store, null); assert.equal(sr(t.s).selection_known, false);
});
vector("MCC-021", "sixteen-attempt lineage cap rejects another recovery without trimming", () => {
  let t = block(admit(pair()));
  for (let i = 1; i < 16; i += 1) t = block(admit(recover(checkpoint(t, "Block"))));
  const saved = checkpoint(t, "Block"), last = recover(saved);
  const { p, s } = proposeOnly(last);
  assert.equal(p.reason, "ScopeRejected"); assert.equal(s.reason, "LineageFull");
  assert.equal(p.counter_floor, 26); assert.equal(s.watermarks.counter, 26);
  assert.equal(saved.ctx.store.journal.lineage.length, 16);
  assert.deepEqual(s.storage.records, saved.disk.records);
});
vector("MCC-022", "exhausted counter or generation rejects rather than wrapping", () => {
  for (const field of ["counter", "generation"]) {
    const t = pair(); t.ctx.store[field] = Number.MAX_SAFE_INTEGER;
    t.proposal = request(t.ctx); t.p = protocol(t.ctx, t.proposal);
    const disk = baseStorage({ [field]: Number.MAX_SAFE_INTEGER, last_transaction_id: null });
    t.s = persistence(disk);
    const { p, s } = proposeOnly(t);
    assert.equal(p.reason, field === "counter" ? "ReplayRejected" : "GenerationRejected");
    assert.equal(s.reason, field === "counter" ? "CounterOverflow" : "GenerationOverflow");
  }
});
vector("MCC-023", "ordinary pre-publication admission has no implicit retirement recovery", () => {
  const saved = checkpoint(admit(pair()), "Reserve");
  for (const target of ["FinalizeCandidate", "RestorePermittedPrevious", "FinishCommittedCleanup"]) {
    const { p, s } = proposeOnly(recover(saved, target));
    assert.equal(p.reason, "ScopeRejected"); assert.equal(s.reason, "ScopeRejected");
    assert.equal(p.counter_floor, 11); assert.equal(s.watermarks.counter, 11);
  }
});
vector("MCC-024", "paired evaluations are deterministic immutable non-authority data", () => {
  const t = full(pair()), before = { p: copy(t.p.input), s: copy(t.s.input) };
  const p = pr(t.p), s = sr(t.s);
  assert.deepEqual(p, pr(t.p)); assert.deepEqual(s, sr(t.s));
  assert.deepEqual(t.p.input, before.p); assert.deepEqual(t.s.input, before.s);
  function frozen(value) {
    if (value !== null && typeof value === "object") { assert.equal(Object.isFrozen(value), true); Object.values(value).forEach(frozen); }
  }
  frozen(p); frozen(s);
  assert.equal(p.installer_status, "NotImplemented"); assert.equal(s.launcher_status, "NotImplemented");
});

assert.equal(new Set(required).size, required.length);
assert.equal(new Set(cases.map(item => item.id)).size, cases.length);
assert.deepEqual(cases.map(item => item.id).sort(), [...required].sort());
const executed = new Set();
for (const item of cases) test(`${item.id}: ${item.label}`, async () => { await item.fn(); executed.add(item.id); });
test("composition gate: exact required IDs passed with zero skipped cases", () => {
  assert.deepEqual([...executed].sort(), [...required].sort());
});

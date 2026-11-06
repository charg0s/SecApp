import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { jcs } from "../../tools/lib/jcs.mjs";
import { checkedRecoveryData } from "../../tools/lib/maintenance-recovery-validation.mjs";
import { simulateMaintenanceRecovery as run, inspectRecoverySnapshot as inspect,
  prepareRecoveryOffer as offer, RECOVERY_LIMITS } from "../../tools/lib/maintenance-recovery-model.mjs";
import { encodeRecoveryStore as encode, decodeRecoveryStore as decode } from "../../tools/lib/maintenance-recovery-codec.mjs";
import { base, scenario, authorize, harness, hash, copy, seal, restart, document, admitted,
  terminal, checkpointInput } from "./synthetic-recovery-v2.mjs";
import { context, request, harness as protocolHarness } from "./synthetic-protocol.mjs";

const required = Object.freeze(["MRF-001", "MRF-002", "MRF-003", "MRF-004", "MRF-005", "MRF-006",
  "MRF-007", "MRF-008", "MRF-009", "MRF-010", "MRF-011", "MRF-012"]);
const cases = [], executed = new Set();
const vector = (id, label, fn) => cases.push({ id, label, fn });
function evaluate(input) {
  checkedRecoveryData("scenario", input);
  const before = copy(input), r = run(input);
  checkedRecoveryData("projection", r); assert.deepEqual(input, before);
  assert.equal(r.launch_status, "Blocked"); assert.equal(r.launcher_status, "NotImplemented");
  assert.ok(Object.values(r.effects).every(x => x === false)); return r;
}
function reject(input, reason) {
  const r = evaluate(input); assert.equal(r.status, "RecoveryRequired"); assert.equal(r.reason, reason);
  assert.equal(r.admission_ack, "NotSent"); assert.equal(r.result_ack, "NotSent"); return r;
}
const epochInput = () => scenario(base({ selection: { digest: hash("selected-newer"), epoch: 6 }, security_floor: 4 }));
const target = epoch => ({ digest: hash("target"), epoch });
function resealAuth(auth) { seal(auth.offer, "offer_digest", "Offer"); auth.confirmation.offer_digest = auth.offer.offer_digest; }
function damagedTail(index = 2, integrity = "Unknown", damage = "Link") {
  const complete = harness().full().project();
  const i = scenario(copy(complete.storage), { counter: 10, generation: 7, security_floor: 4 });
  i.storage.head = base().head; i.storage.integrity = integrity;
  const record = i.storage.records[index];
  if (damage === "Digest") record.record_digest = hash("damaged-digest");
  else {
    if (damage === "Link") record.previous_digest = hash("damaged-link");
    else record.record_kind = index === 0 || index === 3 ? "Block" : "Complete";
    seal(record, "record_digest", "Record");
  }
  return i;
}
function uncheckedFrame(doc) {
  const body = Buffer.from(jcs(doc)), prefix = Buffer.alloc(12);
  prefix.write("SA_MSC02", 0, "ascii"); prefix.writeUInt32BE(body.length, 8);
  return Buffer.concat([prefix, createHash("sha256").update(prefix).update(body).digest(), body]);
}

vector("MRF-001", "offer rejects epoch below current selection, permits equal/newer", () => {
  assert.throws(() => offer(epochInput(), "Maintenance", { candidate: target(5) }), /BelowFloor/);
  for (const epoch of [6, 7]) {
    const h = harness(authorize(epochInput(), "Maintenance", { candidate: target(epoch) })).full().ack();
    const r = evaluate(h.input); assert.equal(r.status, "Completed"); assert.equal(r.result_ack, "Delivered");
    assert.equal(r.selection.epoch, epoch); assert.ok(r.selection.epoch >= r.minimum.security_floor);
  }
});
vector("MRF-002", "intake revalidates epoch even when a substituted offer is rehashed", () => {
  const h = harness(authorize(epochInput(), "Maintenance", { candidate: target(6) }));
  h.input.authorization.offer.candidate.epoch = 5; resealAuth(h.input.authorization);
  const r = reject(h.full().ack().input, "BelowFloor");
  assert.equal(r.minimum.counter, 10); assert.equal(r.storage.records.length, 0);
  assert.deepEqual(r.storage, h.input.storage);
});
vector("MRF-003", "historical below-floor completion cannot be replayed or codec-promoted", () => {
  const good = harness(authorize(epochInput(), "Maintenance", { candidate: target(6) })).full().project();
  assert.deepEqual(decode(encode(document(good))), document(good));
  const bad = copy(good.storage);
  bad.records[0].authorization.offer.candidate.epoch = 5; resealAuth(bad.records[0].authorization);
  let previous = bad.anchor.anchor_digest;
  for (const record of bad.records) {
    record.previous_digest = previous; seal(record, "record_digest", "Record"); previous = record.record_digest;
  }
  bad.head.tail_digest = previous; bad.head.selection.epoch = 5; seal(bad.head, "head_digest", "Head");
  const i = scenario(bad, copy(good.minimum));
  const r = reject(i, "BelowFloor"); assert.equal(r.selection_known, false);
  assert.equal(inspect(bad, i.minimum).classification, "ConflictOrUnknown");
  const doc = document({ storage: bad, minimum: i.minimum }); checkedRecoveryData("document", doc);
  assert.throws(() => encode(doc), { code: "RECOVERY_V2_CODEC_INVALID" });
  assert.throws(() => decode(uncheckedFrame(doc)), { code: "RECOVERY_V2_CODEC_INVALID" });
});
vector("MRF-004", "corrupt tail preserves every verified prefix minimum", () => {
  const expected = [
    { counter: 10, generation: 7, security_floor: 4 },
    { counter: 11, generation: 7, security_floor: 4 },
    { counter: 11, generation: 8, security_floor: 5 },
    { counter: 11, generation: 8, security_floor: 5 }
  ];
  for (const integrity of ["Known", "Unknown"]) for (let at = 0; at < expected.length; at++)
    for (const [damage, reason] of [["Link", "ChainInvalid"], ["Digest", "DigestMismatch"], ["Semantic", "OrderRejected"]]) {
    const i = damagedTail(at, integrity, damage), r = reject(i, reason);
    assert.deepEqual(r.minimum, expected[at]); assert.equal(r.selection_known, false);
    assert.deepEqual(r.storage, i.storage); assert.equal(r.events_processed, 0);
    const again = reject(restart(r), reason); assert.deepEqual(again.minimum, r.minimum);
  }
});
vector("MRF-005", "prefix maxima join stronger external observations and never trim data", () => {
  const i = damagedTail(); i.minimum = { counter: 15, generation: 9, security_floor: 6 };
  const r = reject(i, "ChainInvalid"); assert.deepEqual(r.minimum, i.minimum); assert.deepEqual(r.storage, i.storage);
  const lower = damagedTail(), p = reject(lower, "ChainInvalid");
  assert.deepEqual(p.minimum, { counter: 11, generation: 8, security_floor: 5 });
  // The original corrupt chain is preserved, not rewritten to satisfy a codec.
  assert.throws(() => encode(document(p)), { code: "RECOVERY_V2_CODEC_INVALID" });
  assert.throws(() => offer(restart(p), "RecoverPublication", { recovery_target: "FinalizeCandidate", candidate: target(5) }));
});
vector("MRF-006", "invalid records cannot contribute claimed later counters or floors", () => {
  const i = damagedTail(0);
  i.storage.records[0].authorization.offer.transaction_id = "synthetic-tx-999";
  i.storage.records[0].transaction_id = "synthetic-tx-999";
  i.storage.records[0].authorization.offer.candidate.epoch = 999;
  resealAuth(i.storage.records[0].authorization); seal(i.storage.records[0], "record_digest", "Record");
  const r = reject(i, "ChainInvalid"); assert.deepEqual(r.minimum, i.minimum);
  const valid = harness().admit().stage("Block").project();
  const clean = evaluate(restart(valid)); assert.deepEqual(clean.minimum, valid.minimum);
  assert.equal(clean.selection_known, false); assert.equal(clean.status, "RecoveryRequired");
});
vector("MRF-007", "terminal anchor requires equal generation and generation floor", () => {
  for (const [generation, generation_floor] of [[7, 8], [8, 7]]) for (const integrity of ["Known", "Unknown"]) {
    const i = scenario(base({ generation, generation_floor })); i.storage.integrity = integrity;
    const r = reject(i, "AnchorInvalid"); assert.equal(r.selection_known, false);
    assert.equal(r.minimum.generation, Math.max(generation, generation_floor));
    assert.equal(inspect(i.storage, i.minimum).classification, "ConflictOrUnknown");
    assert.throws(() => offer(i, "Maintenance"), /AnchorInvalid/);
  }
  for (const n of [0, 7, Number.MAX_SAFE_INTEGER]) {
    const i = scenario(base({ generation: n, generation_floor: n }));
    const r = evaluate(i); assert.equal(r.status, "Stable"); assert.equal(r.selection_known, true);
  }
});
vector("MRF-008", "codec rejects Known generation-gap anchors without rewriting them", () => {
  const i = scenario(base({ generation: 7, generation_floor: 8 })), doc = document(i);
  checkedRecoveryData("document", doc);
  assert.throws(() => encode(doc), { code: "RECOVERY_V2_CODEC_INVALID" });
  assert.throws(() => decode(uncheckedFrame(doc)), { code: "RECOVERY_V2_CODEC_INVALID" });
  const good = document(evaluate(scenario())); assert.deepEqual(decode(encode(good)), good);
  doc.storage.integrity = "Unknown"; seal(doc, "document_digest", "Document");
  const unknown = decode(encode(doc)); assert.equal(unknown.storage.integrity, "Unknown");
  const r = reject(scenario(unknown.storage, unknown.minimum), "AnchorInvalid"); assert.equal(r.selection_known, false);
});
vector("MRF-009", "active publication gap and freshly confirmed recovery remain supported", () => {
  const blocked = harness().admit().stage("Block").project();
  const state = inspect(blocked.storage, blocked.minimum);
  assert.equal(state.classification, "Active"); assert.equal(state.state.generation, 7); assert.equal(state.state.generation_floor, 8);
  const h = harness(authorize(restart(blocked), "RecoverPublication", {
    recovery_target: "FinalizeCandidate", candidate: { digest: hash("v2"), epoch: 5 }
  })).full().ack();
  const recovered = evaluate(h.input); assert.equal(recovered.status, "Completed");
  assert.equal(recovered.storage.head.generation, 9); assert.equal(recovered.minimum.generation, 9);
  const compact = harness(authorize(restart(recovered), "CompactTerminalState")).compact().ack();
  const done = evaluate(compact.input); assert.equal(done.status, "Completed");
  assert.equal(done.storage.anchor.generation, done.storage.anchor.generation_floor);
  assert.deepEqual(decode(encode(document(done))), document(done));
});
vector("MRF-010", "expiry is exclusive at intake, including metadata operations", () => {
  const expires_at = "2026-09-29T12:05:00Z";
  const inputs = [
    () => authorize(scenario(), "Maintenance", { candidate: target(5), expires_at }),
    () => authorize(restart(admitted()), "RetireAdmittedCandidate", { expires_at }),
    () => authorize(restart(terminal()), "CompactTerminalState", { expires_at }),
    () => authorize(checkpointInput(true), "ReconcileCheckpoint", { expires_at })
  ];
  for (const make of inputs) for (const now of ["2026-09-29T12:04:59Z", expires_at, "2026-09-29T12:05:01Z"]) {
    const i = make(); i.simulated_at = now; const h = harness(i).admit();
    if (now < expires_at) { const r = evaluate(h.input); assert.equal(r.reason, "None"); assert.equal(r.minimum.counter, i.minimum.counter + 1); }
    else { const r = reject(h.input, "OfferExpired"); assert.equal(r.minimum.counter, i.minimum.counter); assert.deepEqual(r.storage, i.storage); }
  }
});
vector("MRF-011", "offer default is five minutes ahead; expired and overflowing offers reject", () => {
  assert.equal(RECOVERY_LIMITS.offer_ms, 300000);
  const i = scenario(), made = offer(i, "Maintenance");
  assert.equal(made.expires_at, "2026-09-29T12:05:00Z"); assert.equal(Object.isFrozen(made), true);
  for (const expires_at of [i.simulated_at, "2026-09-29T11:59:59Z"]) {
    assert.throws(() => offer(i, "Maintenance", { expires_at }), /OfferExpired/);
  }
  const explicit = offer(i, "Maintenance", { expires_at: "2026-09-29T12:00:01Z" });
  assert.equal(explicit.expires_at, "2026-09-29T12:00:01Z");
  const yearEnd = scenario(); yearEnd.simulated_at = "2026-12-31T23:58:00Z";
  assert.equal(offer(yearEnd, "Maintenance").expires_at, "2027-01-01T00:03:00Z");
  yearEnd.simulated_at = "9999-12-31T23:59:59Z";
  assert.throws(() => offer(yearEnd, "Maintenance"), { code: "RECOVERY_V2_INPUT_INVALID" });
  assert.deepEqual(evaluate(i).storage, i.storage);
});
vector("MRF-012", "protocol and v2 agree before, at and after confirmation expiry", () => {
  for (const delta of [-1000, 0, 1000]) {
    const ctx = context(), p = protocolHarness(ctx, request(ctx)).offer();
    const prepared = p.project(), at = prepared.offer_expires_at_ms + delta;
    p.local("Confirm", { decision: "Approved", approver_id: "synthetic-approver-a", offer_digest: prepared.offer_digest }, at);
    const protocol = p.project();
    const i = authorize(scenario(), "Maintenance", { candidate: target(5), expires_at: "2026-09-29T12:05:00Z" });
    i.simulated_at = new Date(Date.parse(i.authorization.offer.expires_at) + delta).toISOString().replace(".000Z", "Z");
    const result = evaluate(harness(i).admit().input);
    if (delta < 0) { assert.equal(protocol.state, "Confirmed"); assert.equal(result.reason, "None"); }
    else { assert.equal(protocol.reason, "Expired"); assert.equal(result.reason, "OfferExpired"); }
    assert.equal(protocol.launch_status, "Blocked"); assert.equal(result.launch_status, "Blocked");
  }
});

for (const c of cases) test(`${c.id} ${c.label}`, () => { c.fn(); assert.equal(executed.has(c.id), false); executed.add(c.id); });
test("MRF exact required-ID gate: no missing, duplicate or unexecuted regressions", () => {
  assert.equal(new Set(required).size, required.length); assert.equal(new Set(cases.map(c => c.id)).size, cases.length);
  assert.deepEqual(cases.map(c => c.id).sort(), [...required].sort()); assert.deepEqual([...executed].sort(), [...required].sort());
});

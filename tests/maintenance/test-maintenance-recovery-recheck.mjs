import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import schema from "../../schemas/development/maintenance-recovery-v2.schema.json" with { type: "json" };
import { AJV_OPTIONS } from "../../tools/lib/constants.mjs";
import { jcs } from "../../tools/lib/jcs.mjs";
import { checkedRecoveryData } from "../../tools/lib/maintenance-recovery-validation.mjs";
import { simulateMaintenanceRecovery as run, inspectRecoverySnapshot as inspect,
  prepareRecoveryOffer as offer } from "../../tools/lib/maintenance-recovery-model.mjs";
import { encodeRecoveryStore as encode, decodeRecoveryStore as decode } from "../../tools/lib/maintenance-recovery-codec.mjs";
import { base, scenario, authorize, harness, hash, copy, seal, restart, document,
  admitted, terminal, checkpointInput } from "./synthetic-recovery-v2.mjs";

// Keep structural validation separate from the application timestamp guard:
// RFC 3339 leap seconds pass this unchanged full schema, but are unsupported
// by the model's canonical ECMAScript time representation.
const warnings = [];
const ajv = new Ajv2020({ ...AJV_OPTIONS, logger: {
  log() {}, warn(x) { warnings.push(x); }, error(x) { warnings.push(x); }
} });
addFormats(ajv, { mode: "full", formats: ["date-time"], keywords: false });
ajv.addSchema(schema);
const gates = Object.fromEntries(["scenario", "storage", "offer", "document", "projection"].map(kind =>
  [kind, ajv.compile({ $ref: `${schema.$id}#/$defs/${kind}` })]));
assert.deepEqual(warnings, []);
const shape = (kind, value) => assert.equal(gates[kind](value), true, JSON.stringify(gates[kind].errors));
const inputError = { code: "RECOVERY_V2_INPUT_INVALID" }, codecError = { code: "RECOVERY_V2_CODEC_INVALID" };
const leap = "2016-12-31T23:59:60Z";
const required = Object.freeze(["MRR-001", "MRR-002", "MRR-003", "MRR-004", "MRR-005",
  "MRR-006", "MRR-007", "MRR-008", "MRR-009", "MRR-010"]);
const cases = [], executed = new Set();
const vector = (id, label, fn) => cases.push({ id, label, fn });
function frozen(value) {
  if (value && typeof value === "object") { assert.ok(Object.isFrozen(value)); Object.values(value).forEach(frozen); }
}
function evaluate(input) {
  shape("scenario", input); checkedRecoveryData("scenario", input);
  const before = copy(input), result = run(input);
  assert.deepEqual(input, before); shape("projection", result); frozen(result);
  assert.equal(result.launch_status, "Blocked"); assert.equal(result.launcher_status, "NotImplemented");
  assert.ok(Object.values(result.effects).every(x => x === false)); return result;
}
function resealAuth(auth) {
  seal(auth.offer, "offer_digest", "Offer"); auth.confirmation.offer_digest = auth.offer.offer_digest;
}
function uncheckedFrame(doc) {
  const body = Buffer.from(jcs(doc)), prefix = Buffer.alloc(12);
  prefix.write("SA_MSC02", 0, "ascii"); prefix.writeUInt32BE(body.length, 8);
  return Buffer.concat([prefix, createHash("sha256").update(prefix).update(body).digest(), body]);
}
function operationInputs() {
  const blocked = harness().admit().stage("Block").project();
  const committed = harness().admit().stage("Block").stage("Commit").project();
  return [
    authorize(scenario(), "Maintenance", { candidate: { digest: hash("v2"), epoch: 5 } }),
    authorize(restart(blocked), "RecoverPublication", { recovery_target: "FinalizeCandidate", candidate: { digest: hash("v2"), epoch: 5 } }),
    authorize(restart(committed), "FinishCommittedCleanup"),
    authorize(restart(admitted()), "RetireAdmittedCandidate"),
    authorize(restart(terminal()), "CompactTerminalState"),
    authorize(checkpointInput(true), "ReconcileCheckpoint")
  ];
}
const outcomes = Object.freeze({ Maintenance: "Completed", RecoverPublication: "Completed",
  FinishCommittedCleanup: "Completed", RetireAdmittedCandidate: "CandidateRetired",
  CompactTerminalState: "MetadataAuthorized", ReconcileCheckpoint: "MetadataAuthorized" });
function anchorInput(operation, outcome) {
  return scenario(base({ terminal: { transaction_id: "synthetic-tx-10", operation, outcome, terminal_digest: hash("terminal") } }));
}
function replaceHistoricalExpiry(result, expires_at) {
  const r = copy(result), disk = r.storage;
  disk.records[0].authorization.offer.expires_at = expires_at;
  resealAuth(disk.records[0].authorization);
  let previous = disk.anchor.anchor_digest;
  for (const record of disk.records) {
    record.previous_digest = previous; seal(record, "record_digest", "Record"); previous = record.record_digest;
  }
  disk.head.tail_digest = previous; seal(disk.head, "head_digest", "Head");
  seal(r, "result_digest", "Projection"); return r;
}

vector("MRR-001", "all six admissions reject nested leap-second expiry before consumption", () => {
  assert.ok(Number.isNaN(Date.parse(leap)));
  for (const i of operationInputs()) {
    i.authorization.offer.expires_at = leap; resealAuth(i.authorization);
    const h = harness(i).admit(), before = copy(h.input);
    shape("scenario", h.input);
    assert.throws(() => checkedRecoveryData("scenario", h.input), inputError);
    assert.throws(() => run(h.input), inputError);
    assert.deepEqual(h.input, before);
  }
});
vector("MRR-002", "unsupported historical times reject at every public container and both codec paths", () => {
  for (const integrity of ["Known", "Unknown"]) {
    const r = replaceHistoricalExpiry(terminal(), leap); r.storage.integrity = integrity;
    seal(r, "result_digest", "Projection");
    const containers = { projection: r, scenario: restart(r), storage: r.storage,
      document: document(r), offer: r.storage.records[0].authorization.offer };
    for (const [kind, value] of Object.entries(containers)) {
      shape(kind, value); const before = copy(value);
      assert.throws(() => checkedRecoveryData(kind, value), inputError); assert.deepEqual(value, before);
    }
    assert.throws(() => inspect(r.storage, r.minimum), inputError);
    assert.throws(() => encode(containers.document), codecError);
    assert.throws(() => decode(uncheckedFrame(containers.document)), codecError);
  }
});
vector("MRR-003", "preparation and all admission operations retain exact supported expiry boundaries", () => {
  assert.throws(() => offer(scenario(), "Maintenance", { expires_at: leap }), inputError);
  const badNow = scenario(); badNow.simulated_at = leap; shape("scenario", badNow);
  assert.throws(() => run(badNow), inputError);
  for (const make of operationInputs()) for (const offset of [-1000, 0, 1000]) {
    const i = copy(make), expiry = i.authorization.offer.expires_at;
    i.simulated_at = new Date(Date.parse(expiry) + offset).toISOString().replace(".000Z", "Z");
    const r = evaluate(harness(i).admit().input);
    assert.equal(r.reason, offset < 0 ? "None" : "OfferExpired");
    assert.equal(r.minimum.counter, i.minimum.counter + (offset < 0 ? 1 : 0));
    if (offset >= 0) { assert.deepEqual(r.storage, i.storage); assert.equal(r.admission_ack, "NotSent"); }
  }
});
vector("MRR-004", "aging a supported historical expiry neither invalidates history nor renews admission", () => {
  const h = harness().full().ack(), original = evaluate(h.input);
  const i = restart(original); i.simulated_at = "2027-01-01T00:00:00Z";
  i.events = [{ kind: "QueryStatus", counter: original.minimum.counter }];
  const r = evaluate(i); assert.equal(r.status, "Stable"); assert.equal(r.last_status, "Completed");
  assert.equal(r.selection_known, true); assert.deepEqual(r.storage, original.storage);
  const doc = document(r); doc.simulated_at = i.simulated_at; seal(doc, "document_digest", "Document");
  assert.deepEqual(decode(encode(doc)), doc);
  const replay = copy(h.input); replay.simulated_at = i.simulated_at;
  const denied = evaluate(replay); assert.equal(denied.reason, "OfferExpired");
  assert.deepEqual(denied.storage, replay.storage); assert.equal(denied.minimum.counter, replay.minimum.counter);
  const fresh = authorize(i, "Maintenance");
  assert.equal(fresh.authorization.offer.expires_at, "2027-01-01T00:05:00Z");
  assert.equal(evaluate(harness(fresh).full().input).reason, "None");
});
vector("MRR-005", "all twelve impossible terminal pairs reject Known and block Unknown anchors", () => {
  for (const [operation, expected] of Object.entries(outcomes)) for (const outcome of ["Completed", "CandidateRetired", "MetadataAuthorized"]) {
    if (outcome === expected) continue;
    for (const integrity of ["Known", "Unknown"]) {
      const i = anchorInput(operation, outcome); i.storage.integrity = integrity;
      i.events = [{ kind: "QueryStatus", counter: 10 }];
      const r = evaluate(i);
      assert.equal(r.reason, "AnchorInvalid"); assert.equal(r.status, "RecoveryRequired");
      assert.equal(r.selection_known, false); assert.equal(r.events_processed, 0);
      assert.deepEqual(r.storage, i.storage); assert.deepEqual(r.minimum, i.minimum);
      assert.equal(inspect(i.storage, i.minimum).classification, "ConflictOrUnknown");
      assert.throws(() => offer(i, "Maintenance"), /AnchorInvalid/);
      const doc = document(r); shape("document", doc);
      if (integrity === "Known") {
        assert.throws(() => encode(doc), codecError); assert.throws(() => decode(uncheckedFrame(doc)), codecError);
      } else {
        const decoded = decode(encode(doc)); assert.deepEqual(decoded, doc);
        assert.equal(evaluate(scenario(decoded.storage, decoded.minimum)).reason, "AnchorInvalid");
      }
    }
  }
});
vector("MRR-006", "six legal terminal pairs, null and real transitions remain valid", () => {
  for (const [operation, outcome] of Object.entries(outcomes)) {
    const i = anchorInput(operation, outcome); i.events = [{ kind: "QueryStatus", counter: 10 }];
    const r = evaluate(i); assert.equal(r.status, "Stable"); assert.equal(r.selection_known, true);
    assert.equal(r.last_status, outcome === "CandidateRetired" ? "CandidateRetired" : "Completed");
    assert.deepEqual(decode(encode(document(r))), document(r));
  }
  assert.equal(evaluate(scenario()).reason, "None");
  for (const i of operationInputs()) {
    const op = i.authorization.offer.operation, h = harness(i);
    if (op === "RetireAdmittedCandidate") h.retire();
    else if (["CompactTerminalState", "ReconcileCheckpoint"].includes(op)) h.compact();
    else if (op === "FinishCommittedCleanup") h.admit().stage("Complete");
    else h.full();
    const r = evaluate(h.ack().input); assert.equal(r.reason, "None"); assert.equal(r.result_ack, "Delivered");
    const inspected = inspect(r.storage, r.minimum); assert.equal(inspected.classification, "Stable");
    assert.equal(inspected.state.terminal.outcome, outcomes[op]);
    assert.deepEqual(decode(encode(document(r))), document(r));
  }
});
vector("MRR-007", "restarted publication preserves unrelated Retired and latest terminal outcomes", () => {
  const starts = [scenario(), anchorInput("Maintenance", "Completed"), anchorInput("RetireAdmittedCandidate", "CandidateRetired")];
  for (const start of starts) {
    const expectedOld = start.storage.anchor.terminal?.outcome ?? "Retired";
    const blocked = harness(authorize(start, "Maintenance")).admit().stage("Block").project();
    for (const [counter, expected] of [[9, "Retired"], [10, expectedOld], [11, "RecoveryRequired"]]) {
      const r = evaluate(harness(restart(blocked)).query(counter).input);
      assert.equal(r.last_status, expected); assert.equal(r.status, "RecoveryRequired");
      assert.equal(r.selection_known, false); assert.deepEqual(r.storage, blocked.storage);
      assert.deepEqual(r.minimum, blocked.minimum);
    }
  }
});
vector("MRR-008", "all unresolved lineage members stay RecoveryRequired on restart, Active in admitted session", () => {
  const blocked = harness().admit().stage("Block").project();
  const i = authorize(restart(blocked), "RecoverPublication", {
    recovery_target: "FinalizeCandidate", candidate: { digest: hash("v2"), epoch: 5 }
  });
  const h = harness(i).admit(), active = evaluate(h.input);
  for (const counter of [9, 10, 11, 12]) {
    const fresh = evaluate(harness(restart(active)).query(counter).input);
    assert.equal(fresh.last_status, counter < 11 ? "Retired" : "RecoveryRequired");
    assert.equal(fresh.status, "RecoveryRequired"); assert.equal(fresh.selection_known, false);
    const sameSession = evaluate(harness(copy(h.input)).query(counter).input);
    assert.equal(sameSession.last_status, counter < 11 ? "Retired" : "Active");
    assert.equal(sameSession.status, "Active"); assert.equal(sameSession.selection_known, false);
  }
});
vector("MRR-009", "incomplete IO and checkpoints still override every transaction status", () => {
  for (const counter of [9, 10, 11]) {
    const pending = harness().admit().event("WriteRecord", { record_kind: "Block", result: "Complete" }).query(counter);
    const r = evaluate(pending.input); assert.equal(r.last_status, "RecoveryRequired"); assert.equal(r.selection_known, false);
    for (const published of [false, true]) {
      const checkpoint = evaluate(harness(checkpointInput(published)).query(counter).input);
      assert.equal(checkpoint.last_status, "RecoveryRequired"); assert.equal(checkpoint.selection_known, false);
    }
  }
});
vector("MRR-010", "retired queries cannot release a lost current reply or authorize effects", () => {
  const blocked = harness().admit().stage("Block").project();
  const i = authorize(restart(blocked), "RecoverPublication", {
    recovery_target: "FinalizeCandidate", candidate: { digest: hash("v2"), epoch: 5 }
  });
  const h = harness(i).admit().ack("Admission", "Lost");
  const unrelated = evaluate(harness(copy(h.input)).query(10).stage("Block").input);
  assert.equal(unrelated.last_status, "Retired"); assert.equal(unrelated.reason, "StatusRequired");
  assert.equal(unrelated.minimum.counter, 12); assert.equal(unrelated.selection_known, false);
  const exact = harness(copy(h.input)).query(12).stage("Block").stage("Commit").stage("Complete").ack();
  assert.equal(evaluate(exact.input).status, "Completed");
  for (const counter of [0, 13]) {
    const r = evaluate(harness(restart(blocked)).query(counter).input);
    assert.equal(r.reason, "StatusRejected"); assert.deepEqual(r.storage, blocked.storage);
  }
  assert.deepEqual(evaluate(exact.input), evaluate(exact.input));
});

for (const c of cases) test(`${c.id} ${c.label}`, () => { c.fn(); assert.equal(executed.has(c.id), false); executed.add(c.id); });
test("MRR exact required-ID gate: no missing, duplicate or unexecuted regressions", () => {
  assert.equal(new Set(required).size, required.length); assert.equal(new Set(cases.map(c => c.id)).size, cases.length);
  assert.deepEqual(cases.map(c => c.id).sort(), [...required].sort()); assert.deepEqual([...executed].sort(), [...required].sort());
});

import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createSchemaRegistry } from "../../tools/lib/schema-registry.mjs";
import { jcsSha256, digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { simulateMaintenanceProtocol, maintenanceHeadDigest, MAINTENANCE_PROTOCOL_LIMITS } from "../../tools/lib/maintenance-protocol-model.mjs";
import { decodeMaintenanceControlFrame } from "../../tools/lib/maintenance-protocol-validation.mjs";
import { hash, copy, tuple, context, request, recovery, harness, messageEvent, localEvent, rehash } from "./synthetic-protocol.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const registry = createSchemaRegistry(root);
const schemas = {};
for (const name of ["deployment-scenario", "maintenance-message", "maintenance-scenario", "maintenance-projection"]) {
  const schema = JSON.parse(await readFile(path.join(root, `schemas/development/${name}.schema.json`), "utf8"));
  assert.equal(registry.ajv.validateSchema(schema), true);
  registry.ajv.addSchema(schema); schemas[name] = schema;
}
const inputGate = registry.ajv.getSchema(schemas["maintenance-scenario"].$id);
const outputGate = registry.ajv.getSchema(schemas["maintenance-projection"].$id);
const messageGate = registry.ajv.getSchema(schemas["maintenance-message"].$id);
assert.deepEqual(registry.warnings, []);
const required = Object.freeze([
  "MPC-001", "MPC-002", "MPC-003", "MPC-004", "MPC-005", "MPC-006", "MPC-007", "MPC-008",
  "MPC-009", "MPC-010", "MPC-011", "MPC-012", "MPC-013", "MPC-014", "MPC-015", "MPC-016",
  "MPC-017", "MPC-018", "MPC-019", "MPC-020", "MPC-021", "MPC-022", "MPC-023", "MPC-024",
  "MPC-025", "MPC-026", "MPC-027", "MPC-028", "MPC-029", "MPC-030", "MPC-031", "MPC-032",
  "MPC-033", "MPC-034", "MPC-035", "MPC-036", "MPC-037", "MPC-038", "MPC-039", "MPC-040",
  "MPC-041", "MPC-042", "MPC-043", "MPC-044", "MPC-045", "MPC-046", "MPC-047", "MPC-048",
  "MPC-049", "MPC-050", "MPC-051", "MPC-052", "MPC-053"
]);
const cases = [];
const vector = (id, label, fn) => cases.push({ id, label, fn });
function run(input) {
  assert.equal(inputGate(input), true, JSON.stringify(inputGate.errors));
  const result = simulateMaintenanceProtocol(input);
  assert.equal(outputGate(result), true, JSON.stringify(outputGate.errors));
  assert.equal(result.scenario_digest, jcsSha256(input));
  assert.equal(result.result_digest, digestWithExclusion(result, "result_digest"));
  assert.ok(Object.values(result.effects).every(value => value === false));
  assert.equal(result.launch_status, "Blocked"); assert.equal(result.installer_status, "NotImplemented");
  return result;
}
function rejected(input, reason) {
  const result = run(input); assert.equal(result.reason, reason); return result;
}
function invalid(input) { assert.throws(() => simulateMaintenanceProtocol(input), { code: "MAINTENANCE_PROTOCOL_INPUT_INVALID" }); }
const member = size => ({ member_id: "synthetic-member-a", size_bytes: size, file_digest: hash("synthetic-file") });

function uninstalledRecovery(target = "FinalizeCandidate") {
  const { ctx, proposal } = recovery(target);
  if (target === "RestorePermittedPrevious") {
    ctx.store.selection = null; ctx.store.journal.previous = null;
  } else {
    ctx.store.journal.candidate = null;
    if (target === "FinishCommittedCleanup") ctx.store.selection = null;
  }
  ctx.store.journal.journal_digest = digestWithExclusion(ctx.store.journal, "journal_digest");
  proposal.desired = null; proposal.journal_digest = ctx.store.journal.journal_digest;
  proposal.expected_head_digest = maintenanceHeadDigest(ctx.store);
  return { ctx, proposal };
}

vector("MPC-001", "all fixed maintenance operations complete without host authority", () => {
  for (const operation of ["Install", "Update", "EnrollBackend", "Repair", "Uninstall"]) {
    const ctx = context(); const proposal = request(ctx, operation);
    const result = run(harness(ctx, proposal).complete().input);
    assert.equal(result.state, "Completed"); assert.equal(result.reason, "None");
    assert.equal(result.projected_store.counter, 11); assert.equal(result.projected_store.generation, 8);
    assert.deepEqual(result.projected_store.selection, proposal.desired);
    assert.equal(result.admission, "ConsumedInModel");
  }
});
vector("MPC-002", "both contracts admit every message type in bounded valid traces", () => {
  const ctx = context(); const h = harness(ctx, request(ctx, "Update", [member(7)])).offer().admit();
  h.wire("Progress", { state: "Admitted" }).wire("QueryStatus", { counter: 11 }).payload().publish().commit().cleanup().result();
  const cancel = harness().offer(); cancel.wire("Cancel", { offer_digest: cancel.project().offer_digest });
  run(h.input); run(cancel.input);
  const types = new Set();
  for (const event of [...h.input.events, ...cancel.input.events]) if (event.kind === "Wire") {
    assert.equal(messageGate(event.message), true); types.add(event.message.type);
  }
  assert.deepEqual([...types].sort(), ["HelperHello", "ClientBind", "ProposeOperation", "VerifiedOffer", "AdmissionRecorded", "PayloadChunk", "Progress", "QueryStatus", "Result", "Cancel"].sort());
});
vector("MPC-003", "UI cannot send helper messages or authority commands", () => {
  for (const type of ["VerifiedOffer", "AdmissionRecorded", "Result"]) {
    const input = harness().complete().input; messageEvent(input, type).message.direction = "UI";
    assert.equal(inputGate(input), false); invalid(input);
  }
  for (const type of ["Approve", "ConfirmOffer", "Commit", "InvokeUac", "Execute"]) {
    const input = harness().complete().input; messageEvent(input, "ProposeOperation").message.type = type;
    assert.equal(inputGate(input), false); invalid(input);
  }
});
vector("MPC-004", "peer hypotheses must match both expected instances", () => {
  for (const [field, value] of [["verdict", "Mismatch"], ["verdict", "Unavailable"], ["client_instance", "synthetic-other"], ["helper_instance", "synthetic-other"]]) {
    const input = harness().complete().input; localEvent(input, "ObservePeers").data[field] = value;
    assert.equal(rejected(input, "PeerRejected").admission, "NotConsumed");
  }
});
vector("MPC-005", "per-direction sequence gaps and replay rejected", () => {
  for (const sequence of [1, 3, Number.MAX_SAFE_INTEGER]) {
    const input = harness().complete().input; messageEvent(input, "ProposeOperation").message.sequence = sequence;
    rejected(input, "SequenceRejected");
  }
});
vector("MPC-006", "foreign channel and transaction IDs rejected", () => {
  for (const field of ["channel_id", "transaction_id"]) {
    const input = harness().complete().input; messageEvent(input, "VerifiedOffer").message[field] = "synthetic-other";
    rejected(input, "BindingMismatch");
  }
});
vector("MPC-007", "payload digests checked rather than trusting a schema-valid hash", () => {
  const input = harness().complete().input; messageEvent(input, "ClientBind").message.payload_digest = hash("forged");
  rejected(input, "DigestMismatch");
});
vector("MPC-008", "offer binds helper identity, machine, policy, consent text and proposal", () => {
  for (const field of ["helper_identity_digest", "policy_digest", "consent_text_digest"]) {
    const input = harness().complete().input; input.context[field] = hash("other");
    rejected(input, "BindingMismatch");
  }
  const input = harness().complete().input;
  const event = messageEvent(input, "ProposeOperation"); event.message.payload.desired.app_id = "synthetic-other"; rehash(event);
  rejected(input, "BindingMismatch");
});
vector("MPC-009", "confirmation decline, substitution and approver binding", () => {
  const input = harness().complete().input; localEvent(input, "Confirm").data.decision = "Declined";
  rejected(input, "ConsentDeclined");
  localEvent(input, "Confirm").data.decision = "Approved"; localEvent(input, "Confirm").data.offer_digest = hash("other");
  rejected(input, "BindingMismatch");
  const first = harness().offer().confirm().reserve().input; const second = copy(first);
  localEvent(second, "Confirm").data.approver_id = "synthetic-approver-b";
  assert.notEqual(run(first).confirmation_digest, run(second).confirmation_digest);
  assert.equal(run(second).projected_store.journal.lineage[0].confirmation_digest, run(second).confirmation_digest);
});
vector("MPC-010", "concurrent head change invalidates confirmed offer before reservation", () => {
  const input = harness().complete().input; localEvent(input, "Reserve").data.head_digest = hash("concurrent");
  const result = rejected(input, "HeadChanged"); assert.equal(result.counter_floor, 10); assert.equal(result.admission, "NotConsumed");
});
vector("MPC-011", "durable modeled admission precedes effects and survives cancellation", () => {
  const h = harness().offer().admit(); h.wire("Cancel", { offer_digest: h.project().offer_digest });
  const result = rejected(h.input, "Cancelled"); assert.equal(result.admission, "ConsumedInModel");
  assert.equal(result.projected_store.counter, 11); assert.equal(result.projected_store.generation, 7);
  assert.equal(result.projected_store.journal.phase, "Admitted");
});
vector("MPC-012", "known unwritten admission cannot emit durable acknowledgement", () => {
  const h = harness().offer().confirm().reserve("NotWritten");
  const result = rejected(h.input, "AdmissionNotWritten"); assert.equal(result.admission, "NotConsumed");
  assert.equal(result.projected_store.counter, 10);
});
vector("MPC-013", "uncertain admission preserves conservative counter without a selected store", () => {
  const result = rejected(harness().offer().confirm().reserve("Unknown").input, "PersistenceUncertain");
  assert.equal(result.state, "RecoveryRequired"); assert.equal(result.admission, "Unknown");
  assert.equal(result.counter_floor, 11); assert.equal(result.projected_store, null);
});
vector("MPC-014", "retired transaction ID and exhausted counter reject", () => {
  const input = harness().complete().input; messageEvent(input, "ProposeOperation").message.transaction_id = "synthetic-tx-10";
  rejected(input, "ReplayRejected");
  const ctx = context(); ctx.store.counter = Number.MAX_SAFE_INTEGER;
  rejected(harness(ctx, request(ctx)).bind().wire("ProposeOperation", request(ctx)).input, "ReplayRejected");
  const completed = run(harness().complete().input);
  const next = context(); next.store = copy(completed.projected_store);
  const replay = harness(next, request(next, "Repair")).bind().wire("ProposeOperation", request(next, "Repair")).input;
  messageEvent(replay, "ProposeOperation").message.transaction_id = "synthetic-tx-11";
  rejected(replay, "ReplayRejected");
});
vector("MPC-015", "generation mismatch and overflow reject", () => {
  const ctx = context(); let proposal = request(ctx); proposal.expected_generation -= 1;
  rejected(harness(ctx, proposal).bind().wire("ProposeOperation", proposal).input, "HeadChanged");
  ctx.store.generation = Number.MAX_SAFE_INTEGER; proposal = request(ctx);
  rejected(harness(ctx, proposal).bind().wire("ProposeOperation", proposal).input, "GenerationRejected");
});
vector("MPC-016", "maintenance operations cannot substitute component scope", () => {
  for (const operation of ["Repair", "Update", "EnrollBackend", "Uninstall"]) {
    const ctx = context(); const proposal = request(ctx, operation);
    if (operation === "Repair") proposal.desired.app_id = "synthetic-other";
    if (operation === "Update") proposal.desired.backend_id = "synthetic-backend-a";
    if (operation === "EnrollBackend") proposal.desired.policy_digest = hash("other");
    if (operation === "Uninstall") proposal.desired = tuple();
    rejected(harness(ctx, proposal).bind().wire("ProposeOperation", proposal).input, "ScopeRejected");
  }
});
vector("MPC-017", "epoch rollback and reinstall floor reset rejected", () => {
  for (const operation of ["Update", "Install"]) {
    const ctx = context(); const proposal = request(ctx, operation); proposal.desired.security_epoch = 3;
    rejected(harness(ctx, proposal).bind().wire("ProposeOperation", proposal).input, "EpochRejected");
  }
});
vector("MPC-018", "challenge replay, reflection and wrong client binding rejected", () => {
  for (const [key, value] of [["helper_challenge", hash("old")], ["client_challenge", hash("helper-challenge")], ["client_challenge", "0".repeat(64)], ["client_instance", "synthetic-other"]]) {
    const input = harness().complete().input; const event = messageEvent(input, "ClientBind"); event.message.payload[key] = value; rehash(event);
    rejected(input, "BindingMismatch");
  }
});
vector("MPC-019", "lost admission reply allows status then continuation without second consumption", () => {
  const h = harness().offer().admit("Lost"); h.wire("QueryStatus", { counter: 11 }).payload().publish().commit().cleanup().result();
  const result = run(h.input); assert.equal(result.state, "Completed"); assert.equal(result.last_status, "Active");
  assert.equal(result.projected_store.counter, 11);
  const wrong = harness().offer().admit("Lost"); wrong.wire("QueryStatus", { counter: 9 });
  assert.equal(run(wrong.input).reply_lost, true);
  wrong.wire("ProposeOperation", request(context())); rejected(wrong.input, "ReplayRejected");
});
vector("MPC-020", "lost result and compacted status never re-execute", () => {
  const h = harness().offer().admit().payload().publish().commit().cleanup().result("Lost");
  h.wire("QueryStatus", { counter: 11 });
  const result = run(h.input); assert.equal(result.last_status, "Completed"); assert.equal(result.projected_store.counter, 11);
  h.wire("QueryStatus", { counter: 9 }); assert.equal(run(h.input).last_status, "Retired");
});
vector("MPC-021", "mutation after lost acknowledgement rejects instead of blind retry", () => {
  const ctx = context(); const proposal = request(ctx, "Update", [member(1)]); const h = harness(ctx, proposal).offer().admit("Lost");
  h.wire("PayloadChunk", { member_id: "synthetic-member-a", offset: 0, length: 1, chunk_digest: hash("chunk") });
  const result = rejected(h.input, "ReplayRejected"); assert.equal(result.payload_bytes, 0); assert.equal(result.counter_floor, 11);
});
vector("MPC-022", "intake and commit are forbidden before durable admission", () => {
  const h = harness().offer(); h.local("Commit", { verdict: "Consistent" }); rejected(h.input, "OrderRejected");
  const h2 = harness().offer(); h2.wire("PayloadChunk", { member_id: "synthetic-member-a", offset: 0, length: 1, chunk_digest: hash("chunk") });
  assert.equal(rejected(h2.input, "OrderRejected").payload_bytes, 0);
});
vector("MPC-023", "payload member, offsets, fixed chunk sizes and short EOF checked", () => {
  for (const [field, value] of [["member_id", "synthetic-other"], ["offset", 1], ["length", 65535]]) {
    const ctx = context(); const h = harness(ctx, request(ctx, "Update", [member(65537)])).offer().admit().payload();
    const event = messageEvent(h.input, "PayloadChunk"); event.message.payload[field] = value; rehash(event);
    rejected(h.input, "PayloadRejected");
  }
  const ctx = context(); const h = harness(ctx, request(ctx, "Update", [member(1)])).offer().admit().local("VerifyPayload", { verdict: "Allowed" });
  rejected(h.input, "PayloadRejected");
});
vector("MPC-024", "intake size limit is lowering-only and exact boundary uses no real payload", () => {
  const ctx = context(); const proposal = request(ctx, "Update", [member(536870912)]);
  const h = harness(ctx, proposal).offer().admit().payload(); const result = run(h.input);
  assert.equal(result.payload_bytes, 536870912); assert.equal(result.payload_frames, 8192); assert.equal(result.state, "PayloadVerified");
  proposal.members.push({ ...member(1), member_id: "synthetic-member-b" });
  rejected(harness(ctx, proposal).bind().wire("ProposeOperation", proposal).input, "LimitExceeded");
});
vector("MPC-025", "pairing, offer and payload deadlines cannot be extended by caller", () => {
  let input = harness().complete().input; localEvent(input, "ObservePeers").at_ms = 30001; rejected(input, "Expired");
  input = harness().complete().input; localEvent(input, "Confirm").at_ms = localEvent(input, "ReviewOffer").at_ms + 300000; rejected(input, "Expired");
  const ctx = context(); const h = harness(ctx, request(ctx, "Update", [member(1)])).offer().admit();
  h.wire("PayloadChunk", { member_id: "synthetic-member-a", offset: 0, length: 1, chunk_digest: hash("chunk") }, { at: 40000 });
  rejected(h.input, "Expired");
  const total = harness().offer().admit().local("VerifyPayload", { verdict: "Allowed" }, 600010);
  rejected(total.input, "Expired");
});
vector("MPC-026", "clock rollback, unknown clock and invalid UTC timestamp fail closed", () => {
  const input = harness().complete().input; messageEvent(input, "ClientBind").at_ms = 0; rejected(input, "ClockRejected");
  const h = harness().offer().local("Interrupt", { reason: "ClockUncertain" }); rejected(h.input, "ClockUncertain");
  input.simulated_at = "2026-02-30T12:00:00Z"; invalid(input);
});
vector("MPC-027", "cancellation at each publication boundary retains consumption and floor", () => {
  for (let boundary = 0; boundary < 4; boundary += 1) {
    const h = harness().offer(); if (boundary > 0) h.admit().payload(); if (boundary > 1) h.publish(); if (boundary > 2) h.commit();
    h.wire("Cancel", { offer_digest: h.project().offer_digest });
    const result = rejected(h.input, "Cancelled");
    assert.equal(result.state, ["Rejected", "Aborted", "RecoveryRequired", "CleanupPending"][boundary]);
    assert.equal(result.counter_floor, boundary === 0 ? 10 : 11);
    if (boundary > 1) assert.equal(result.security_floor, 5);
  }
});
vector("MPC-028", "crash/disconnect do not manufacture rollback or fresh authority", () => {
  for (const reason of ["Crash", "Disconnect"]) for (let boundary = 0; boundary < 3; boundary += 1) {
    const h = harness().offer().admit().payload(); if (boundary > 0) h.publish(); if (boundary > 1) h.commit();
    h.local("Interrupt", { reason }); const result = rejected(h.input, reason);
    assert.equal(result.state, ["Aborted", "RecoveryRequired", "CleanupPending"][boundary]); assert.equal(result.counter_floor, 11);
  }
});
vector("MPC-029", "cannot skip verification, quiescence or commit", () => {
  let h = harness().offer().admit().publish(); rejected(h.input, "OrderRejected");
  h = harness().offer().admit().payload().local("BeginPublish", { quiescence: "Busy" }); rejected(h.input, "RuntimeBusy");
  h = harness().offer().admit().payload().cleanup(); rejected(h.input, "OrderRejected");
  h = harness().offer().admit().payload().publish().local("Commit", { verdict: "Unknown" }); rejected(h.input, "PersistenceUncertain");
});
vector("MPC-030", "loss of trust after commit requires recovery", () => {
  const h = harness().offer().admit().payload().publish().commit().local("Interrupt", { reason: "TrustUnavailable" });
  const result = rejected(h.input, "TrustUnavailable"); assert.equal(result.state, "RecoveryRequired"); assert.equal(result.projected_store, null);
});
vector("MPC-031", "cleanup failure retains committed selection and journal", () => {
  const result = rejected(harness().offer().admit().payload().publish().commit().cleanup("Failed").result().input, "CleanupIncomplete");
  assert.equal(result.state, "CleanupPending"); assert.equal(result.projected_store.generation, 8);
  assert.equal(result.projected_store.journal.phase, "Committed");
});
vector("MPC-032", "candidate recovery is a newly confirmed transaction", () => {
  const { ctx, proposal } = recovery(); const result = run(harness(ctx, proposal).complete().input);
  assert.equal(result.state, "Completed"); assert.equal(result.projected_store.generation, 9);
  assert.equal(result.projected_store.counter, 11); assert.equal(result.projected_store.selection.app_id, "synthetic-app-v2");
});
vector("MPC-033", "restoring previous bytes publishes a newer generation", () => {
  const { ctx, proposal } = recovery("RestorePermittedPrevious"); const result = run(harness(ctx, proposal).complete().input);
  assert.equal(result.projected_store.selection.app_id, "synthetic-app-v1");
  assert.equal(result.projected_store.generation, 9); assert.equal(result.security_floor, 5);
});
vector("MPC-034", "recovery cannot restore below reserved floor", () => {
  const { ctx, proposal } = recovery("RestorePermittedPrevious", 4);
  ctx.store.security_floor = 4; proposal.expected_head_digest = maintenanceHeadDigest(ctx.store);
  rejected(harness(ctx, proposal).bind().wire("ProposeOperation", proposal).input, "EpochRejected");
});
vector("MPC-035", "cleanup recovery consumes fresh authority without republishing", () => {
  const { ctx, proposal } = recovery("FinishCommittedCleanup");
  const result = run(harness(ctx, proposal).offer().admit().cleanup().result().input);
  assert.equal(result.state, "Completed"); assert.equal(result.projected_store.generation, 8); assert.equal(result.projected_store.counter, 11);
});
vector("MPC-036", "recovery is a disjoint request, never a Repair flag", () => {
  const { ctx } = recovery(); const proposal = request(ctx, "Repair");
  rejected(harness(ctx, proposal).bind().wire("ProposeOperation", proposal).input, "ScopeRejected");
  const input = harness().complete().input; const event = messageEvent(input, "ProposeOperation"); event.message.payload.recovery_target = "FinalizeCandidate"; rehash(event);
  assert.equal(inputGate(input), false); invalid(input);
});
vector("MPC-037", "old recovery confirmation and journal identity cannot be reused", () => {
  const { ctx, proposal } = recovery(); const h = harness(ctx, proposal).offer().admit();
  localEvent(h.input, "Confirm").data.offer_digest = ctx.store.journal.lineage[0].offer_digest;
  rejected(h.input, "BindingMismatch");
  proposal.journal_digest = hash("foreign"); rejected(harness(ctx, proposal).bind().wire("ProposeOperation", proposal).input, "ScopeRejected");
});
vector("MPC-038", "unknown/corrupt store cannot be treated as first install", () => {
  const ctx = context(); ctx.storage_status = "Unknown";
  assert.equal(rejected(harness(ctx, request(ctx)).input, "StorageUnknown").projected_store, null);
  const r = recovery(); r.ctx.store.journal.journal_digest = hash("corrupt");
  rejected(harness(r.ctx, r.proposal).input, "StorageInvalid");
});
vector("MPC-039", "recovery retains original lineage and rejects a full lineage", () => {
  const { ctx, proposal } = recovery(); const result = run(harness(ctx, proposal).offer().admit().input);
  // Unresolved publication intentionally exposes no selected store.
  assert.equal(result.projected_store, null); assert.equal(result.counter_floor, 11);
  const committed = run(harness(ctx, proposal).offer().admit().payload().publish().commit().input);
  const journal = committed.projected_store.journal;
  assert.equal(journal.origin_transaction_id, ctx.store.journal.origin_transaction_id);
  assert.equal(journal.lineage.length, 2);
  assert.deepEqual(journal.lineage[0], ctx.store.journal.lineage[0]);
  assert.deepEqual(journal.lineage[1], { transaction_id: committed.transaction_id, counter: 11,
    offer_digest: committed.offer_digest, confirmation_digest: committed.confirmation_digest });
  ctx.store.counter = 25;
  ctx.store.journal.lineage = Array.from({ length: 16 }, (_, index) => ({ transaction_id: `synthetic-tx-${10 + index}`, counter: 10 + index, offer_digest: hash(`offer-${index}`), confirmation_digest: hash(`confirm-${index}`) }));
  ctx.store.journal.journal_digest = digestWithExclusion(ctx.store.journal, "journal_digest");
  proposal.journal_digest = ctx.store.journal.journal_digest; proposal.expected_head_digest = maintenanceHeadDigest(ctx.store);
  rejected(harness(ctx, proposal).bind().wire("ProposeOperation", proposal).input, "ScopeRejected");
});
vector("MPC-040", "projection schema rejects every host authority promotion", () => {
  const result = run(harness().complete().input);
  for (const key of Object.keys(result.effects)) { const changed = copy(result); changed.effects[key] = true; assert.equal(outputGate(changed), false); }
  for (const [key, value] of [["launch_status", "Ready"], ["installer_status", "Implemented"], ["provenance", "Verified"]]) {
    const changed = copy(result); changed[key] = value; assert.equal(outputGate(changed), false);
  }
  const changed = copy(result); changed.admission = "NotConsumed"; assert.equal(outputGate(changed), false);
  changed.admission = "ConsumedInModel"; changed.projected_store = null; assert.equal(outputGate(changed), false);
});
vector("MPC-041", "control body decoder rejects malformed UTF-8, BOM, duplicates, depth and size", () => {
  const message = messageEvent(harness().bind().input, "HelperHello").message;
  const valid = JSON.stringify(message); assert.deepEqual(decodeMaintenanceControlFrame(Buffer.from(valid)), message);
  assert.deepEqual(decodeMaintenanceControlFrame(Buffer.from(valid.padEnd(65536, " "))), message);
  for (const bytes of [Buffer.from([0xc3, 0x28]), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(valid)]),
    Buffer.from(valid.replace('"protocol_version":1', '"protocol_version":1,"protocol_version":1')),
    Buffer.from('{"a":'.repeat(10) + '0' + '}'.repeat(10)), Buffer.alloc(65537, 32), Buffer.from(valid.slice(0, -1))]) {
    assert.throws(() => decodeMaintenanceControlFrame(bytes), { code: "MAINTENANCE_PROTOCOL_INPUT_INVALID" });
  }
});
vector("MPC-042", "unsafe direct API objects rejected without getter/proxy execution", () => {
  let touched = false; const proxy = new Proxy({}, { get() { touched = true; throw Error("trap"); }, ownKeys() { touched = true; throw Error("trap"); } });
  invalid(proxy);
  let input = harness().complete().input; input.context = proxy; invalid(input);
  input = harness().complete().input; Object.defineProperty(input, "events", { enumerable: true, get() { touched = true; throw Error("getter"); } }); invalid(input);
  assert.equal(touched, false);
  for (const mutate of [x => { x.events = Array(1); }, x => { x.events[0] = x; }, x => { x.extra = Symbol("x"); },
    x => { x.context = new Date(); }, x => { x.context.store.counter = -0; }, x => { x.context.store.counter = NaN; }, x => { x[Symbol("x")] = true; }]) {
    input = harness().complete().input; mutate(input); invalid(input);
  }
});
vector("MPC-043", "control-count and schema bounds are enforced", () => {
  const h = harness().offer().admit();
  for (let i = 0; i < 123; i += 1) h.wire("Progress", { state: "Admitted" });
  assert.equal(run(h.input).control_frames, 128);
  h.wire("Progress", { state: "Admitted" }); rejected(h.input, "LimitExceeded");
  const input = harness().input; input.events = Array(8393).fill({}); assert.equal(inputGate(input), false); invalid(input);
});
vector("MPC-044", "deterministic deeply frozen projections leave callers untouched", () => {
  const input = harness().complete().input; const before = copy(input); const result = run(input);
  assert.deepEqual(result, run(copy(input))); assert.deepEqual(input, before); assert.equal(Object.isFrozen(input), false);
  function frozen(value) { if (value && typeof value === "object") { assert.equal(Object.isFrozen(value), true); Object.values(value).forEach(frozen); } }
  frozen(result); assert.throws(() => { result.effects.uac_enabled = true; }, TypeError);
  assert.ok(Object.isFrozen(MAINTENANCE_PROTOCOL_LIMITS));
});
vector("MPC-045", "no native/host API imports and historical launch blockers stay open", async () => {
  for (const name of ["maintenance-protocol-model", "maintenance-protocol-validation"]) {
    const source = await readFile(path.join(root, `tools/lib/${name}.mjs`), "utf8");
    assert.doesNotMatch(source, /node:(?:fs|net|http|child_process)|\b(?:fetch\s*\(|eval\s*\(|process\.|Date\.now\s*\()/u);
  }
  const { planBackendLaunch } = await import("../../src/backend/launch-plan.mjs"); const plan = planBackendLaunch({ operation: "Version" });
  assert.equal(plan.execution_enabled, false);
  assert.deepEqual(plan.blockers.map(item => item.id), ["TL-ADJACENT-DLL", "TL-LINKED-TOKEN", "TL-NON-ELEVATED-MECHANISM", "TL-REPARSE-REPLACEMENT", "TL-INITIAL-INVENTORY", "TL-PREVENTIVE-LOAD-POLICY", "TL-UNKNOWN-MODULES", "TL-IMAGE-BYTE-BINDING", "TL-PRODUCTION-LOAD-CONTEXT"]);
  assert.ok(plan.blockers.every(item => item.status === "Open"));
});
vector("MPC-046", "required metadata, unknown versions and arbitrary paths rejected", () => {
  const original = harness().complete().input;
  for (const key of Object.keys(original)) { const input = copy(original); delete input[key]; assert.equal(inputGate(input), false); invalid(input); }
  for (const [key, value] of [["protocol_version", 2], ["path", "synthetic-forbidden"], ["command", "synthetic-forbidden"], ["force", true]]) {
    const input = copy(original); messageEvent(input, "ProposeOperation").message[key] = value; assert.equal(inputGate(input), false); invalid(input);
  }
  const result = run(original);
  for (const key of Object.keys(result)) { const changed = copy(result); delete changed[key]; assert.equal(outputGate(changed), false); }
});
vector("MPC-047", "declared metadata verification is not proof of real bytes or signatures", () => {
  let h = harness().bind().wire("ProposeOperation", request(context())).local("ReviewOffer", { verdict: "Revoked" }); rejected(h.input, "TrustRejected");
  h = harness().offer().admit().local("VerifyPayload", { verdict: "Rejected" }); rejected(h.input, "PayloadRejected");
  const result = run(harness().complete().input); assert.equal(result.provenance, "SyntheticModelOnly");
});
vector("MPC-048", "recovery rejects inconsistent selection and unknown/overflowing high-watermark", () => {
  let r = recovery("FinishCommittedCleanup"); r.ctx.store.selection = tuple(7, 5); rejected(harness(r.ctx, r.proposal).input, "StorageInvalid");
  r = recovery(); r.proposal.highest_generation = 7; rejected(harness(r.ctx, r.proposal).bind().wire("ProposeOperation", r.proposal).input, "ScopeRejected");
  r = recovery(); r.ctx.store.journal.highest_generation = Number.MAX_SAFE_INTEGER;
  r.ctx.store.journal.journal_digest = digestWithExclusion(r.ctx.store.journal, "journal_digest");
  r.proposal.highest_generation = Number.MAX_SAFE_INTEGER; r.proposal.journal_digest = r.ctx.store.journal.journal_digest;
  r.proposal.expected_head_digest = maintenanceHeadDigest(r.ctx.store);
  rejected(harness(r.ctx, r.proposal).bind().wire("ProposeOperation", r.proposal).input, "GenerationRejected");
});

vector("MPC-049", "interrupted uninstall can finalize exact null candidate with fresh generation", () => {
  const { ctx, proposal } = uninstalledRecovery();
  const result = run(harness(ctx, proposal).complete().input);
  assert.equal(result.state, "Completed"); assert.equal(result.reason, "None");
  assert.equal(result.outcome, "Uninstalled"); assert.equal(result.projected_store.selection, null);
  assert.equal(result.projected_store.counter, 11); assert.equal(result.projected_store.generation, 9);
  assert.equal(result.security_floor, 5); assert.equal(result.payload_bytes, 0);
  assert.equal(result.admission, "ConsumedInModel");
});
vector("MPC-050", "failed first install can restore exact uninstalled state without resetting floor", () => {
  const { ctx, proposal } = uninstalledRecovery("RestorePermittedPrevious");
  const result = run(harness(ctx, proposal).complete().input);
  assert.equal(result.state, "Completed"); assert.equal(result.outcome, "Uninstalled");
  assert.equal(result.projected_store.selection, null); assert.equal(result.projected_store.generation, 9);
  assert.equal(result.projected_store.counter, 11); assert.equal(result.projected_store.security_floor, 5);
  const next = context(); next.store = copy(result.projected_store);
  const install = request(next, "Install");
  assert.equal(rejected(harness(next, install).bind().wire("ProposeOperation", install).input, "EpochRejected").admission, "NotConsumed");
});
vector("MPC-051", "null recovery cannot accept payload or substitute a different journal selection", () => {
  for (const target of ["FinalizeCandidate", "RestorePermittedPrevious", "FinishCommittedCleanup"]) {
    let r = uninstalledRecovery(target); r.proposal.members = [member(1)];
    assert.equal(rejected(harness(r.ctx, r.proposal).bind().wire("ProposeOperation", r.proposal).input, "ScopeRejected").admission, "NotConsumed");
    r = uninstalledRecovery(target); r.proposal.desired = tuple(7, 5);
    rejected(harness(r.ctx, r.proposal).bind().wire("ProposeOperation", r.proposal).input, "ScopeRejected");
    r = recovery(target); r.proposal.desired = null;
    rejected(harness(r.ctx, r.proposal).bind().wire("ProposeOperation", r.proposal).input, "ScopeRejected");
  }
});
vector("MPC-052", "null recovery still rejects declined, foreign and replayed confirmation", () => {
  for (const variant of ["Declined", "OldOffer", "ReplayedTransaction"]) {
    const { ctx, proposal } = uninstalledRecovery(); const h = harness(ctx, proposal).offer().admit();
    if (variant === "Declined") localEvent(h.input, "Confirm").data.decision = "Declined";
    if (variant === "OldOffer") localEvent(h.input, "Confirm").data.offer_digest = ctx.store.journal.lineage[0].offer_digest;
    if (variant === "ReplayedTransaction") messageEvent(h.input, "ProposeOperation").message.transaction_id = "synthetic-tx-10";
    const result = rejected(h.input, { Declined: "ConsentDeclined", OldOffer: "BindingMismatch", ReplayedTransaction: "ReplayRejected" }[variant]);
    assert.equal(result.admission, "NotConsumed"); assert.equal(result.counter_floor, 10);
    assert.equal(result.projected_store, null); assert.equal(result.state, "RecoveryRequired");
  }
});
vector("MPC-053", "null recovery preserves uncertainty and allows committed cleanup without republish", () => {
  let r = uninstalledRecovery();
  let result = rejected(harness(r.ctx, r.proposal).offer().admit().payload().publish().local("Interrupt", { reason: "Crash" }).input, "Crash");
  assert.equal(result.state, "RecoveryRequired"); assert.equal(result.projected_store, null);
  assert.equal(result.counter_floor, 11); assert.equal(result.security_floor, 5);
  r = uninstalledRecovery("FinishCommittedCleanup");
  result = run(harness(r.ctx, r.proposal).offer().admit().cleanup().result().input);
  assert.equal(result.state, "Completed"); assert.equal(result.outcome, "Uninstalled");
  assert.equal(result.projected_store.selection, null); assert.equal(result.projected_store.generation, 8);
  assert.equal(result.projected_store.counter, 11); assert.equal(result.security_floor, 5);
});

assert.equal(new Set(cases.map(item => item.id)).size, cases.length);
assert.deepEqual(cases.map(item => item.id).sort(), [...required].sort());
const executed = new Set();
for (const item of cases) test(`${item.id}: ${item.label}`, async () => { await item.fn(); executed.add(item.id); });
test("maintenance contract gate: exact required IDs passed with zero skipped vectors", () => {
  assert.deepEqual([...executed].sort(), [...required].sort());
});

import test from "node:test";
import assert from "node:assert/strict";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import deploymentSchema from "../../schemas/development/deployment-scenario.schema.json" with { type: "json" };
import projectionSchema from "../../schemas/development/deployment-projection.schema.json" with { type: "json" };
import consentFixtures from "../contracts/consent-receipt/consent.json" with { type: "json" };
import { AJV_OPTIONS } from "../../tools/lib/constants.mjs";
import { jcsSha256, digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { simulateDeployment, maintenanceBindingDigest, MAINTENANCE_OPERATIONS } from "../../tools/lib/deployment-model.mjs";
import { simulateMaintenanceProtocol, maintenanceHeadDigest } from "../../tools/lib/maintenance-protocol-model.mjs";
import { boundedProtocolCopy, checkedProtocolData } from "../../tools/lib/maintenance-protocol-validation.mjs";
import { simulateMaintenanceRecovery, inspectRecoverySnapshot } from "../../tools/lib/maintenance-recovery-model.mjs";
import { checkedRecoveryData, recoveryDigest } from "../../tools/lib/maintenance-recovery-validation.mjs";
import { encodeRecoveryStore, decodeRecoveryStore } from "../../tools/lib/maintenance-recovery-codec.mjs";
import { planBackendLaunch } from "../../src/backend/launch-plan.mjs";
import { context, request, harness as protocol, tuple, hash, copy, messageEvent, localEvent } from "./synthetic-protocol.mjs";
import { base, scenario, authorize, harness as recovery, seal, restart, admitted, terminal, checkpointInput, document } from "./synthetic-recovery-v2.mjs";

const warnings = [];
const ajv = new Ajv2020({ ...AJV_OPTIONS, logger: {
  log() {}, warn(x) { warnings.push(x); }, error(x) { warnings.push(x); }
} });
addFormats(ajv, { mode: "full", formats: ["date-time"], keywords: false });
ajv.addSchema(deploymentSchema);
const deploymentGates = { scenario: ajv.getSchema(deploymentSchema.$id), projection: ajv.compile(projectionSchema) };
assert.deepEqual(warnings, []);
const checkDeployment = (kind, value) => assert.equal(deploymentGates[kind](value), true, JSON.stringify(deploymentGates[kind].errors));
const models = { deployment: [simulateDeployment, checkDeployment],
  protocol: [simulateMaintenanceProtocol, checkedProtocolData], recovery: [simulateMaintenanceRecovery, checkedRecoveryData] };
const boundaries = Object.freeze(["Admitted", "Blocked", "Committed", "Completed"]);
const deploymentEvents = Object.freeze(["Prepare", "Stage", "Verify", "BeginPublish", "Commit", "BeginCleanup", "Finish"]);
const deploymentCounts = [1, 4, 5, 7];
const required = Object.freeze([
  "CBC-001", "CBC-002", "CBC-003", "CBC-004", "CBC-005", "CBC-006", "CBC-007", "CBC-008", "CBC-009", "CBC-010",
  "CBC-011", "CBC-012", "CBC-013", "CBC-014", "CBC-015", "CBC-016", "CBC-017", "CBC-018", "CBC-019", "CBC-020",
  "CBC-021", "CBC-022", "CBC-023", "CBC-024", "CBC-025", "CBC-026", "CBC-027", "CBC-028", "CBC-029", "CBC-030"
]);
const cases = [], executed = new Set();
const vector = (id, label, fn) => cases.push({ id, label, fn });
const selected = t => t === null ? null : { digest: jcsSha256({ domain: "SecApp-Test-Composed-Boundary-Tuple-v1", tuple: t }), epoch: t.security_epoch };
const at = (origin, ms) => {
  assert.ok(Number.isSafeInteger(ms) && ms >= 0 && ms % 1000 === 0);
  const n = Date.parse(origin) + ms;
  assert.ok(Number.isSafeInteger(n));
  return new Date(n).toISOString().replace(".000Z", "Z");
};
function session(p) {
  const hello = messageEvent(p, "HelperHello"), bind = messageEvent(p, "ClientBind");
  return { session_id: hello.message.channel_id, peer_id: p.context.client_instance,
    approver_id: localEvent(p, "Confirm").data.approver_id,
    challenge: jcsSha256({ domain: "SecApp-Test-Composed-Boundary-Session-v1",
      helper_instance: p.context.helper_instance, client_instance: p.context.client_instance,
      channel: hello.message.channel_id, helper_challenge: hello.message.payload.helper_challenge,
      client_challenge: bind.message.payload.client_challenge }),
    helper_digest: p.context.helper_identity_digest, policy_digest: p.context.policy_digest,
    confirmation_version: "SyntheticMetadataConsent-v2", confirmation_text_digest: p.context.consent_text_digest };
}
function confirmDeployment(d) {
  d.confirmation = { kind: "SyntheticMaintenanceConfirmation", decision: "Approved", operation: d.intent.operation,
    machine_id: d.machine_id, expected_generation: d.snapshot.generation,
    binding_digest: maintenanceBindingDigest({ machine_id: d.machine_id, snapshot: d.snapshot, intent: d.intent }),
    nonce: "synthetic-nonce-a", issued_at: "2026-09-29T12:00:04Z", expires_at: "2026-09-29T12:05:02Z" };
}
function traceRecovery(input, boundary) {
  const h = recovery(input).admit(), rank = boundaries.indexOf(boundary);
  if (rank >= 1) h.stage("Block");
  if (rank >= 2) h.stage("Commit");
  if (rank >= 3) h.stage("Complete").ack();
  return h.input;
}
function fixture(operation = "Update", boundary = "Completed", change = () => {}) {
  const ctx = context(), proposal = request(ctx, operation);
  change(ctx, proposal); proposal.expected_head_digest = maintenanceHeadDigest(ctx.store);
  proposal.expected_generation = ctx.store.generation;
  const h = protocol(ctx, proposal).bind().wire("ProposeOperation", proposal, { at: 1000 })
    .local("ReviewOffer", { verdict: "Allowed" }, 2000);
  const offer = h.project();
  h.wire("VerifiedOffer", { offer_digest: offer.offer_digest, expires_at_ms: offer.offer_expires_at_ms }, { at: 3000 })
    .local("Confirm", { offer_digest: offer.offer_digest, approver_id: "synthetic-approver-a", decision: "Approved" }, 4000)
    .local("Reserve", { head_digest: maintenanceHeadDigest(ctx.store), result: "Durable" }, 5000)
    .wire("AdmissionRecorded", { counter: ctx.store.counter + 1, offer_digest: offer.offer_digest }, { at: 6000 });
  const rank = boundaries.indexOf(boundary);
  if (rank >= 1) h.local("VerifyPayload", { verdict: "Allowed" }, 7000).local("BeginPublish", { quiescence: "Quiescent" }, 8000);
  if (rank >= 2) h.local("Commit", { verdict: "Consistent" }, 9000);
  if (rank >= 3) h.local("Cleanup", { result: "Complete" }, 10000).result();
  const d = { schema_version: "1.0.0", model_kind: "DeploymentScenario", privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly",
    simulated_at: at(h.input.simulated_at, 5000), machine_id: ctx.store.machine_id,
    snapshot: { generation: ctx.store.generation, security_floor: ctx.store.security_floor, selection: copy(ctx.store.selection) },
    intent: { operation, expected_generation: ctx.store.generation, next_generation: ctx.store.generation + 1, desired: copy(proposal.desired) },
    confirmation: null, used_nonces: [], events: deploymentEvents.slice(0, deploymentCounts[rank]) };
  confirmDeployment(d);
  const r = scenario(base({ machine_id: ctx.store.machine_id, counter: ctx.store.counter, generation: ctx.store.generation,
    generation_floor: ctx.store.generation, security_floor: ctx.store.security_floor, selection: selected(ctx.store.selection) }));
  r.simulated_at = d.simulated_at; r.context = session(h.input);
  authorize(r, "Maintenance", { candidate: selected(proposal.desired), expires_at: d.confirmation.expires_at });
  return { boundary, deployment: d, protocol: h.input, recovery: traceRecovery(r, boundary), claims: null };
}
function project(bundle) {
  return Object.fromEntries(Object.entries(models).map(([name, [run, check]]) => {
    check("scenario", bundle[name]); const output = run(bundle[name]); check("projection", output);
    assert.equal(output.launch_status, "Blocked"); assert.ok(Object.values(output.effects).every(x => x === false));
    return [name, output];
  }));
}
function shape(bundle) { for (const [name, [, check]] of Object.entries(models)) check("scenario", bundle[name]); }
function same(a, b, rule) { assert.deepEqual(a, b, rule); }

// Private executable correspondence specification, NOT a production adapter.
// Inputs are three original synthetic scenarios; no projection grants authority.
// Keep every model's own admission/confirmation validation and digest domain.
function compareBoundary(value) {
  try {
    const b = boundedProtocolCopy(value, 16 * 1024 * 1024, 24);
    same(Object.keys(b).sort(), ["boundary", "claims", "deployment", "protocol", "recovery"], "closed wrapper");
    const rank = boundaries.indexOf(b.boundary); assert.ok(rank >= 0, "boundary");
    const outputs = project(b), d = b.deployment, p = b.protocol, r = b.recovery;
    const dp = outputs.deployment, pp = outputs.protocol, rp = outputs.recovery;
    if (b.claims !== null) {
      same(Object.keys(b.claims).sort(), Object.keys(models).sort(), "closed claims");
      for (const [name, [, check]] of Object.entries(models)) check("projection", b.claims[name]);
      same(b.claims, outputs, "full recomputed outputs, not labels or hashes");
    }
    const one = (kind, key, name) => {
      const found = p.events.filter(e => e.kind === kind && (kind === "Wire" ? e.message[key] : e[key]) === name);
      same(found.length, 1, `one ${name}`); return found[0];
    };
    const proposal = one("Wire", "type", "ProposeOperation").message.payload;
    const confirmation = one("Local", "action", "Confirm"), reserve = one("Local", "action", "Reserve");
    const verified = one("Wire", "type", "VerifiedOffer");
    one("Wire", "type", "HelperHello"); one("Wire", "type", "ClientBind");
    same(proposal.kind, "Maintenance", "ordinary protocol operation only");
    same(proposal.operation, d.intent.operation, "operation");
    same(proposal.members, [], "this contract models no payload bytes");
    same(r.authorization?.offer.operation, "Maintenance", "no implicit recovery/metadata analogue");
    same(r.authorization.offer.recovery_target, "None", "no recovery target");
    same(r.authorization.offer.origin_transaction_id, null, "fresh origin");
    same(p.context.storage_status, "Known", "protocol initial storage");
    same(p.context.store.journal, null, "no active protocol lineage");
    same(p.context.store.last_result, null, "historical terminal correspondence is out of scope");
    same(r.storage.records, [], "declared initial anchor only, not a historical bridge");
    same(r.storage.anchor.terminal, null, "no implicit historical terminal mapping");
    const initial = inspectRecoverySnapshot(r.storage, r.minimum);
    same(initial.classification, "Stable", "stable v2 initial state");
    const old = initial.state; assert.ok(old); same(old.active, null, "no active v2 lineage");
    same(d.machine_id, p.context.store.machine_id, "deployment/protocol machine");
    same(old.machine_id, d.machine_id, "v2 machine");
    same(d.snapshot, { generation: p.context.store.generation, security_floor: p.context.store.security_floor,
      selection: p.context.store.selection }, "entire old tuple and snapshot");
    same(d.intent.desired, proposal.desired, "entire desired tuple");
    same(old.selection, selected(d.snapshot.selection), "v2 old full-tuple mapping");
    same(r.authorization.offer.candidate, selected(d.intent.desired), "v2 desired full-tuple mapping");
    same(old.counter, p.context.store.counter, "counter (deployment has no counter)");
    same(old.generation, d.snapshot.generation, "initial generation");
    same(old.generation_floor, old.generation, "no generation gap");
    same(old.security_floor, d.snapshot.security_floor, "initial floor");
    same(d.intent.expected_generation, proposal.expected_generation, "expected generation");
    same(d.intent.next_generation, old.generation + 1, "next generation");
    const tx = `synthetic-tx-${old.counter + 1}`;
    same(r.authorization.offer.transaction_id, tx, "v2 transaction"); same(pp.transaction_id, tx, "protocol transaction");
    same(r.context, session(p), "session/peer/helper/challenges/policy/confirmation-text binding");
    same(r.authorization.offer.context, r.context, "own v2 offer context");
    same(d.simulated_at, at(p.simulated_at, reserve.at_ms), "admission clock origin");
    same(r.simulated_at, d.simulated_at, "v2 admission clock");
    same(d.confirmation?.issued_at, at(p.simulated_at, confirmation.at_ms), "confirmation time");
    same(d.confirmation.expires_at, at(p.simulated_at, verified.message.payload.expires_at_ms), "expiry time");
    same(r.authorization.offer.expires_at, d.confirmation.expires_at, "v2 expiry");
    for (const output of Object.values(outputs)) same(output.reason, "None", "own model must accept");
    same(d.events, deploymentEvents.slice(0, deploymentCounts[rank]), "deployment boundary trace");
    const canonicalRecovery = copy(r); canonicalRecovery.events = [];
    same(r.events, traceRecovery(canonicalRecovery, b.boundary).events, "complete v2 I/O boundary, no pending/lost reply");
    same(dp.state, ["Prepared", "PublishPending", "Committed", "Completed"][rank], "deployment phase");
    same(pp.state, ["Admitted", "PublishPending", "Committed", "Completed"][rank], "protocol phase");
    same(pp.admission, "ConsumedInModel", "protocol admission"); same(pp.reply_lost, false, "no lost protocol reply");
    same(dp.confirmation_consumed_in_model, true, "deployment admission");
    same(rp.status, rank === 3 ? "Completed" : "Active", "v2 phase");
    same(rp.events_processed, r.events.length, "all v2 events processed");
    const end = inspectRecoverySnapshot(rp.storage, rp.minimum);
    same(end.classification, rank === 3 ? "Stable" : "Active", "v2 replay boundary");
    const s = end.state, floor = rank === 0 ? old.security_floor
      : Math.max(old.security_floor, d.snapshot.selection?.security_epoch ?? 0, d.intent.desired?.security_epoch ?? 0);
    const generation = rank >= 2 ? d.intent.next_generation : old.generation;
    same(pp.counter_floor, old.counter + 1, "protocol counter consumed once");
    same(s.counter, old.counter + 1, "v2 counter consumed once");
    same(s.generation, generation, "v2 generation");
    same(s.generation_floor, rank >= 1 ? d.intent.next_generation : old.generation, "v2 generation floor");
    for (const actual of [dp.minimum_security_floor, pp.security_floor, s.security_floor]) same(actual, floor, "preserved floor");
    same(s.selection, selected(rank >= 2 ? d.intent.desired : d.snapshot.selection), "replayed selection");
    if (rank === 3) same(s.active, null, "terminal lineage");
    else {
      same(s.active.transaction_id, tx, "active transaction"); same(s.active.origin_transaction_id, tx, "active origin");
      same(s.active.stage, ["Admitted", "Blocked", "Committed"][rank], "active stage");
      same(s.active.previous, selected(d.snapshot.selection), "active previous");
      same(s.active.candidate, selected(d.intent.desired), "active candidate");
      same(s.active.target_generation, d.intent.next_generation, "active target generation");
    }
    if (rank === 1) { same(dp.projected_snapshot, null, "deployment unknown"); same(pp.projected_store, null, "protocol unknown"); }
    else {
      const expected = { generation, security_floor: floor, selection: rank >= 2 ? d.intent.desired : d.snapshot.selection };
      same(dp.projected_snapshot, expected, "deployment selected state");
      same({ generation: pp.projected_store.generation, security_floor: pp.projected_store.security_floor,
        selection: pp.projected_store.selection }, expected, "protocol selected state");
    }
    // v2 deliberately withholds externally known selection even at Commit.
    same(rp.selection_known, rank === 0 || rank === 3, "v2 publication uncertainty preserved");
    same(rp.selection, rp.selection_known ? s.selection : null, "no cross-model promotion of Unknown");
    return Object.freeze({ comparison: "MatchedSyntheticBoundary", boundary: b.boundary,
      execution_enabled: false, launch_status: "Blocked", authority: "None" });
  } catch {
    const error = new Error("Synthetic composed boundary mismatch."); error.code = "COMPOSED_BOUNDARY_MISMATCH"; throw error;
  }
}
function rejects(b, structural = false) {
  if (!structural) shape(b);
  assert.throws(() => compareBoundary(b), { code: "COMPOSED_BOUNDARY_MISMATCH" });
}
function reauthorize(b, candidate = b.recovery.authorization.offer.candidate) {
  const expires_at = b.recovery.authorization.offer.expires_at;
  authorize(b.recovery, "Maintenance", { candidate, expires_at });
}
function acceptedSeparately(b) { for (const o of Object.values(project(b))) assert.equal(o.reason, "None"); }
function changedTuple(t, key) {
  const n = copy(t); n[key] = key === "security_epoch" ? t[key] + 1
    : key.endsWith("digest") ? hash(`substitute-${key}`) : `synthetic-other-${key.replaceAll("_", "-")}`;
  return n;
}

for (const [i, operation] of MAINTENANCE_OPERATIONS.entries()) vector(required[i], `${operation}: four explicit non-authority boundaries`, () => {
  for (const boundary of boundaries) {
    const b = fixture(operation, boundary), before = copy(b), result = compareBoundary(b);
    same(b, before); same(result, compareBoundary(b)); assert.ok(Object.isFrozen(result));
    same(result, { comparison: "MatchedSyntheticBoundary", boundary, execution_enabled: false, launch_status: "Blocked", authority: "None" });
    b.claims = project(b); same(compareBoundary(b), result);
  }
});
vector("CBC-006", "every desired tuple field is bound, even when each model accepts separately", () => {
  for (const key of Object.keys(tuple())) {
    const b = fixture(); reauthorize(b, selected(changedTuple(b.deployment.intent.desired, key)));
    acceptedSeparately(b); rejects(b);
  }
});
vector("CBC-007", "every old tuple field is bound across deployment and protocol", () => {
  for (const key of Object.keys(tuple())) {
    const b = fixture(), other = fixture("Update", "Completed", (ctx, proposal) => {
      ctx.store.selection = changedTuple(ctx.store.selection, key);
      if (key === "backend_id") proposal.desired.backend_id = ctx.store.selection.backend_id;
    });
    b.protocol = other.protocol; acceptedSeparately(b); rejects(b);
    const v2 = fixture(); v2.recovery = other.recovery; acceptedSeparately(v2); rejects(v2);
  }
});
vector("CBC-008", "individually valid operations cannot be spliced", () => {
  const b = fixture(); b.deployment = fixture("Repair").deployment; acceptedSeparately(b); rejects(b);
  // Reproduce the reviewed abstraction gap: v2 alone cannot distinguish an
  // illicit enrollment hidden inside Update from an opaque digest replacement.
  const gap = fixture(), ctx = context(), proposal = request(ctx);
  proposal.desired.backend_id = "synthetic-backend-v1";
  gap.deployment.intent.desired = copy(proposal.desired); confirmDeployment(gap.deployment);
  gap.protocol = protocol(ctx, proposal).bind().wire("ProposeOperation", proposal).local("ReviewOffer", { verdict: "Allowed" }).input;
  reauthorize(gap, selected(proposal.desired));
  const outputs = project(gap);
  same(outputs.deployment.reason, "OperationScopeMismatch"); same(outputs.protocol.reason, "ScopeRejected");
  same(outputs.recovery.status, "Completed");
  const decoded = decodeRecoveryStore(encodeRecoveryStore(document(outputs.recovery)));
  same(decoded.storage.integrity, "Known"); same(decoded.execution_enabled, false); rejects(gap);
});
vector("CBC-009", "null is exact for Install and Uninstall, not a wildcard", () => {
  for (const operation of ["Install", "Uninstall"]) {
    const b = fixture(operation); reauthorize(b, b.recovery.authorization.offer.candidate === null ? selected(tuple(2, 5)) : null);
    acceptedSeparately(b); rejects(b);
  }
});
vector("CBC-010", "valid foreign machine transcript cannot cross the boundary", () => {
  const b = fixture(); b.protocol = fixture("Update", "Completed", ctx => { ctx.store.machine_id = "synthetic-machine-b"; }).protocol;
  acceptedSeparately(b); rejects(b);
});
vector("CBC-011", "counter and transaction identity have no deployment-derived default", () => {
  const b = fixture(); b.recovery = fixture("Update", "Completed", ctx => { ctx.store.counter++; }).recovery;
  acceptedSeparately(b); rejects(b);
});
vector("CBC-012", "generation and floor cannot be borrowed from a different valid run", () => {
  for (const key of ["generation", "security_floor"]) {
    const b = fixture(); b.recovery = fixture("Update", "Completed", ctx => { ctx.store[key]--; }).recovery;
    acceptedSeparately(b); rejects(b);
  }
});
vector("CBC-013", "every v2 session field is compared after independent reauthorization", () => {
  for (const key of Object.keys(fixture().recovery.context).filter(k => k !== "confirmation_version")) {
    const b = fixture(); b.recovery.context[key] = key.endsWith("digest") || key === "challenge" ? hash(key) : "synthetic-foreign-session";
    reauthorize(b); acceptedSeparately(b); rejects(b);
  }
  const b = fixture(); b.recovery.context.confirmation_version = "SyntheticMetadataConsent-v1"; rejects(b, true);
});
vector("CBC-014", "deployment, protocol and v2 confirmation domains are not interchangeable", () => {
  for (const domain of Object.keys(models)) {
    const b = fixture(), p = project(b);
    if (domain === "deployment") b.deployment.confirmation.binding_digest = p.protocol.offer_digest;
    if (domain === "protocol") localEvent(b.protocol, "Confirm").data.offer_digest = b.recovery.authorization.offer.offer_digest;
    if (domain === "recovery") b.recovery.authorization.confirmation.offer_digest = b.deployment.confirmation.binding_digest;
    assert.notEqual(project(b)[domain].reason, "None"); rejects(b);
  }
});
vector("CBC-015", "audit consent receipts are foreign structures, never maintenance consent", () => {
  const receipt = consentFixtures.vectors.find(x => x.vector_id === "CONSENT_ADMIN_VALID").instance;
  for (const domain of Object.keys(models)) {
    const b = fixture();
    if (domain === "deployment") b.deployment.confirmation = copy(receipt);
    if (domain === "protocol") localEvent(b.protocol, "Confirm").data = copy(receipt);
    if (domain === "recovery") b.recovery.authorization.confirmation = copy(receipt);
    rejects(b, true);
  }
});
vector("CBC-016", "each independent consent domain must approve", () => {
  for (const domain of Object.keys(models)) {
    const b = fixture();
    if (domain === "deployment") b.deployment.confirmation.decision = "Declined";
    if (domain === "protocol") localEvent(b.protocol, "Confirm").data.decision = "Declined";
    if (domain === "recovery") b.recovery.authorization.confirmation.decision = "Declined";
    rejects(b);
  }
});
vector("CBC-017", "expiry at admission rejects in all three domains", () => {
  for (const domain of Object.keys(models)) {
    const b = fixture();
    if (domain === "deployment") b.deployment.confirmation.expires_at = b.deployment.simulated_at;
    if (domain === "protocol") {
      const reserve = localEvent(b.protocol, "Reserve"), delta = 302000 - reserve.at_ms;
      for (const e of b.protocol.events.filter(e => e.at_ms >= reserve.at_ms)) e.at_ms += delta;
    }
    if (domain === "recovery") {
      b.recovery.authorization.offer.expires_at = b.recovery.simulated_at;
      seal(b.recovery.authorization.offer, "offer_digest", "Offer");
      b.recovery.authorization.confirmation.offer_digest = b.recovery.authorization.offer.offer_digest;
    }
    assert.notEqual(project(b)[domain].reason, "None"); rejects(b);
  }
});
vector("CBC-018", "used nonce and stale offers do not gain authority from other models", () => {
  const b = fixture(); b.deployment.used_nonces.push(b.deployment.confirmation.nonce); rejects(b);
  const stale = fixture(), fresh = fixture("Update", "Completed", ctx => { ctx.store.generation++; });
  stale.recovery.storage = fresh.recovery.storage; stale.recovery.minimum = fresh.recovery.minimum;
  assert.notEqual(project(stale).recovery.reason, "None"); rejects(stale);
});
vector("CBC-019", "transaction and origin substitutions are rejected after rehashing", () => {
  for (const key of ["transaction_id", "origin_transaction_id"]) {
    const b = fixture(); b.recovery.authorization.offer[key] = "synthetic-tx-12";
    seal(b.recovery.authorization.offer, "offer_digest", "Offer");
    b.recovery.authorization.confirmation.offer_digest = b.recovery.authorization.offer.offer_digest; rejects(b);
  }
});
vector("CBC-020", "stale or invented next generation is denied", () => {
  for (const key of ["expected_generation", "next_generation"]) {
    const b = fixture(); b.deployment.intent[key]--; confirmDeployment(b.deployment); rejects(b);
  }
});
vector("CBC-021", "Unknown storage or evidence cannot be promoted by another model", () => {
  for (const slot of ["protocol", "storage", "trust"]) {
    const b = fixture();
    if (slot === "protocol") b.protocol.context.storage_status = "Unknown";
    if (slot === "storage") b.recovery.storage.integrity = "Unknown";
    if (slot === "trust") b.recovery.evidence_trust = "Unknown";
    rejects(b);
  }
});
vector("CBC-022", "every incomplete v2 I/O prefix rejects the claimed Completed boundary", () => {
  const full = fixture();
  for (let n = 0; n < full.recovery.events.length; n++) {
    const b = copy(full); b.recovery.events = b.recovery.events.slice(0, n); rejects(b);
  }
  for (const boundary of boundaries.slice(0, -1)) { const b = fixture("Update", boundary); b.boundary = "Completed"; rejects(b); }
  const lostV2 = fixture(); lostV2.recovery.events.at(-1).delivery = "Lost"; rejects(lostV2);
  const lostProtocol = fixture(); messageEvent(lostProtocol.protocol, "Result").delivery = "Lost"; rejects(lostProtocol);
});
vector("CBC-023", "prepared and published-but-unretired checkpoints have no ordinary mapping", () => {
  for (const published of [false, true]) {
    const b = fixture(); b.recovery = checkpointInput(published);
    const result = simulateMaintenanceRecovery(b.recovery); assert.equal(result.selection_known, false); rejects(b);
  }
});
vector("CBC-024", "valid rehashed projection claims must still match every recomputed field", () => {
  for (const domain of Object.keys(models)) {
    const b = fixture(); b.claims = copy(project(b));
    b.claims[domain].simulated_at = "2026-09-29T12:00:06Z";
    b.claims[domain].result_digest = domain === "recovery" ? recoveryDigest(b.claims[domain], "result_digest", "Projection")
      : digestWithExclusion(b.claims[domain], "result_digest");
    models[domain][1]("projection", b.claims[domain]); rejects(b);
  }
});
vector("CBC-025", "Completed claims cannot override denial in any original scenario", () => {
  for (const domain of Object.keys(models)) {
    const b = fixture(); b.claims = copy(project(b));
    if (domain === "deployment") b.deployment.confirmation = null;
    if (domain === "protocol") localEvent(b.protocol, "Confirm").data.decision = "Declined";
    if (domain === "recovery") b.recovery.authorization = null;
    rejects(b);
  }
});
vector("CBC-026", "Known codec snapshots are not original scenarios or session authority", () => {
  const b = fixture(), output = project(b).recovery, decoded = decodeRecoveryStore(encodeRecoveryStore(document(output)));
  assert.equal(decoded.storage.integrity, "Known"); assert.equal(decoded.execution_enabled, false);
  b.recovery = decoded; rejects(b, true); rejects(decoded, true);
});
vector("CBC-027", "all recovery/metadata operations require a separate future correspondence", () => {
  const blocked = recovery().admit().stage("Block").project(), committed = recovery().admit().stage("Block").stage("Commit").project();
  const inputs = [
    authorize(restart(blocked), "RecoverPublication", { recovery_target: "FinalizeCandidate", candidate: blocked.storage.records[0].authorization.offer.candidate }),
    authorize(restart(committed), "FinishCommittedCleanup"), authorize(restart(admitted()), "RetireAdmittedCandidate"),
    authorize(restart(terminal()), "CompactTerminalState"), authorize(checkpointInput(true), "ReconcileCheckpoint")
  ];
  for (const r of inputs) {
    const h = recovery(r).admit(); assert.equal(h.project().reason, "None");
    const b = fixture("Update", "Admitted"); b.recovery = h.input; rejects(b);
  }
});
vector("CBC-028", "comparison, projections and decoded documents never unlock the planner", () => {
  const b = fixture(), outputs = project(b), decoded = decodeRecoveryStore(encodeRecoveryStore(document(outputs.recovery)));
  for (const value of [compareBoundary(b), ...Object.values(outputs), decoded]) {
    assert.throws(() => planBackendLaunch(value), { code: "LAUNCH_PLAN_INPUT_INVALID" });
    for (const key of ["readiness", "consent", "execution_enabled"]) {
      assert.throws(() => planBackendLaunch({ operation: "Version", [key]: value }), { code: "LAUNCH_PLAN_INPUT_INVALID" });
    }
  }
  const plan = planBackendLaunch({ operation: "Version" }); assert.equal(plan.execution_enabled, false);
  same(plan.blockers.map(x => x.id), ["TL-ADJACENT-DLL", "TL-LINKED-TOKEN", "TL-NON-ELEVATED-MECHANISM",
    "TL-REPARSE-REPLACEMENT", "TL-INITIAL-INVENTORY", "TL-PREVENTIVE-LOAD-POLICY",
    "TL-UNKNOWN-MODULES", "TL-IMAGE-BYTE-BINDING", "TL-PRODUCTION-LOAD-CONTEXT"]);
  assert.ok(plan.blockers.every(x => x.status === "Open"));
});
vector("CBC-029", "hostile wrappers reject before access; plain inputs stay immutable and deterministic", () => {
  let accessed = 0;
  const getter = Object.defineProperty({}, "boundary", { enumerable: true, get() { accessed++; throw new Error("must not run"); } });
  const proxy = new Proxy({}, { ownKeys() { accessed++; throw new Error("must not run"); } });
  const cycle = {}; cycle.self = cycle;
  for (const value of [null, [], getter, proxy, cycle, Object.create({ boundary: "Completed" }), { ...fixture(), extra: true }]) rejects(value, true);
  assert.equal(accessed, 0);
  const b = fixture(), before = copy(b), result = compareBoundary(b);
  same(b, before); same(compareBoundary(b), result); assert.throws(() => { result.execution_enabled = true; }, TypeError);
});
vector("CBC-030", "clock origins and subsecond admission cannot silently coerce to matching time", () => {
  const shifted = fixture(); shifted.protocol.simulated_at = "2026-09-29T12:00:01Z"; acceptedSeparately(shifted); rejects(shifted);
  const fractional = fixture(); localEvent(fractional.protocol, "Reserve").at_ms++; acceptedSeparately(fractional); rejects(fractional);
  const b = fixture("Uninstall", "Completed", ctx => { ctx.store.selection.security_epoch = 9; });
  compareBoundary(b); assert.equal(project(b).recovery.minimum.security_floor, 9);
});

for (const c of cases) test(`${c.id}: ${c.label}`, () => { c.fn(); executed.add(c.id); });
test("CBC completeness: immutable exact IDs, executed once, zero skips", () => {
  same(cases.map(c => c.id).sort(), [...required].sort()); same([...executed].sort(), [...required].sort());
  assert.equal(new Set(cases.map(c => c.id)).size, required.length);
});

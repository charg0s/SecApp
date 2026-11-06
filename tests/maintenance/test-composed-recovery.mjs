import test from "node:test";
import assert from "node:assert/strict";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import deploymentSchema from "../../schemas/development/deployment-scenario.schema.json" with { type: "json" };
import projectionSchema from "../../schemas/development/deployment-projection.schema.json" with { type: "json" };
import { AJV_OPTIONS } from "../../tools/lib/constants.mjs";
import { jcsSha256, digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { simulateDeployment, maintenanceBindingDigest } from "../../tools/lib/deployment-model.mjs";
import { simulateMaintenanceProtocol as runP, maintenanceHeadDigest } from "../../tools/lib/maintenance-protocol-model.mjs";
import { boundedProtocolCopy, checkedProtocolData } from "../../tools/lib/maintenance-protocol-validation.mjs";
import { simulateMaintenanceRecovery as runR, inspectRecoverySnapshot as inspect } from "../../tools/lib/maintenance-recovery-model.mjs";
import { checkedRecoveryData, recoveryDigest } from "../../tools/lib/maintenance-recovery-validation.mjs";
import { encodeRecoveryStore, decodeRecoveryStore } from "../../tools/lib/maintenance-recovery-codec.mjs";
import { planBackendLaunch } from "../../src/backend/launch-plan.mjs";
import { context, request, harness as protocol, tuple, copy, hash, messageEvent, localEvent, rehash } from "./synthetic-protocol.mjs";
import { base, scenario, authorize, harness as recovery, seal, restart, document } from "./synthetic-recovery-v2.mjs";

const warnings = [];
const ajv = new Ajv2020({ ...AJV_OPTIONS, logger: { log() {}, warn(x) { warnings.push(x); }, error(x) { warnings.push(x); } } });
addFormats(ajv, { mode: "full", formats: ["date-time"], keywords: false });
ajv.addSchema(deploymentSchema);
const dg = { scenario: ajv.getSchema(deploymentSchema.$id), projection: ajv.compile(projectionSchema) };
assert.deepEqual(warnings, []);
const checkD = (kind, x) => assert.equal(dg[kind](x), true, JSON.stringify(dg[kind].errors));
const same = (a, b, reason) => assert.deepEqual(a, b, reason);
const selected = tuple => tuple === null ? null : { digest: jcsSha256({ domain: "SecApp-Test-Composed-Boundary-Tuple-v1", tuple }), epoch: tuple.security_epoch };
const phases = Object.freeze(["Admitted", "Blocked", "Committed", "Completed"]);
const ordinary = Object.freeze(["Install", "Update", "EnrollBackend", "Repair", "Uninstall"]);
const targets = Object.freeze(["FinalizeCandidate", "RestorePermittedPrevious", "FinishCommittedCleanup"]);
const dEvents = Object.freeze(["Prepare", "Stage", "Verify", "BeginPublish", "Commit", "BeginCleanup", "Finish"]);
const dCounts = [1, 4, 5, 7];
const stamp = (origin, ms) => {
  assert.ok(Number.isSafeInteger(ms) && ms >= 0 && ms % 1000 === 0);
  const n = Date.parse(origin) + ms; assert.ok(Number.isSafeInteger(n));
  return new Date(n).toISOString().replace(".000Z", "Z");
};
const closed = (x, keys) => same(Object.keys(x).sort(), [...keys].sort(), "closed shape");
function proposalOf(p) { return messageEvent(p, "ProposeOperation").message.payload; }
function session(p) {
  const hello = messageEvent(p, "HelperHello").message, bind = messageEvent(p, "ClientBind").message;
  return { session_id: hello.channel_id, peer_id: p.context.client_instance, approver_id: localEvent(p, "Confirm").data.approver_id,
    challenge: jcsSha256({ domain: "SecApp-Test-Composed-Boundary-Session-v1", helper_instance: p.context.helper_instance,
      client_instance: p.context.client_instance, channel: hello.channel_id,
      helper_challenge: hello.payload.helper_challenge, client_challenge: bind.payload.client_challenge }),
    helper_digest: p.context.helper_identity_digest, policy_digest: p.context.policy_digest,
    confirmation_version: "SyntheticMetadataConsent-v2", confirmation_text_digest: p.context.consent_text_digest };
}
function protocolTrace(ctx, proposal, boundary, index) {
  const h = protocol(ctx, proposal), channel = `synthetic-channel-${index}`;
  h.input.simulated_at = stamp("2026-09-30T12:00:00Z", index * 600000);
  const wire = (type, data, at) => { h.wire(type, data, { at }); h.input.events.at(-1).message.channel_id = channel; };
  h.local("ObservePeers", { verdict: "Matched", helper_instance: ctx.helper_instance, client_instance: ctx.client_instance }, 1);
  wire("HelperHello", { helper_instance: ctx.helper_instance, helper_challenge: hash(`helper-${index}`) }, 2);
  wire("ClientBind", { client_instance: ctx.client_instance, helper_challenge: hash(`helper-${index}`), client_challenge: hash(`client-${index}`) }, 3);
  wire("ProposeOperation", proposal, 1000); h.local("ReviewOffer", { verdict: "Allowed" }, 2000);
  const offered = h.project(); assert.equal(offered.reason, "None");
  wire("VerifiedOffer", { offer_digest: offered.offer_digest, expires_at_ms: offered.offer_expires_at_ms }, 3000);
  h.local("Confirm", { offer_digest: offered.offer_digest, approver_id: "synthetic-approver-a", decision: "Approved" }, 4000)
    .local("Reserve", { head_digest: maintenanceHeadDigest(ctx.store), result: "Durable" }, 5000);
  wire("AdmissionRecorded", { counter: ctx.store.counter + 1, offer_digest: offered.offer_digest }, 6000);
  const rank = phases.indexOf(boundary), cleanup = proposal.recovery_target === "FinishCommittedCleanup";
  if (rank >= 1 && !cleanup) h.local("VerifyPayload", { verdict: "Allowed" }, 7000).local("BeginPublish", { quiescence: "Quiescent" }, 8000);
  if (rank >= 2 && !cleanup) h.local("Commit", { verdict: "Consistent" }, 9000);
  if (rank === 3) {
    h.local("Cleanup", { result: "Complete" }, 10000);
    const result = h.project(); wire("Result", { state: result.state, store_digest: maintenanceHeadDigest(result.projected_store), execution_enabled: false }, 11000);
  }
  return h.input;
}
function recoveryEvents(boundary, cleanup = false) {
  const h = recovery(), rank = phases.indexOf(boundary); h.input.events = []; h.admit();
  if (rank >= 1 && !cleanup) h.stage("Block");
  if (rank >= 2 && !cleanup) h.stage("Commit");
  if (rank === 3) h.stage("Complete").ack();
  return h.input.events;
}
function authorizeFor(r, p, operation, target, candidate) {
  r.context = session(p); r.simulated_at = stamp(p.simulated_at, localEvent(p, "Reserve").at_ms);
  authorize(r, operation, { candidate: selected(candidate), recovery_target: target,
    expires_at: stamp(p.simulated_at, messageEvent(p, "VerifiedOffer").message.payload.expires_at_ms) });
}
function confirm(d) {
  d.confirmation = { kind: "SyntheticMaintenanceConfirmation", decision: "Approved", operation: d.intent.operation,
    machine_id: d.machine_id, expected_generation: d.snapshot.generation, nonce: "synthetic-nonce-origin",
    binding_digest: maintenanceBindingDigest({ machine_id: d.machine_id, snapshot: d.snapshot, intent: d.intent }),
    issued_at: "2026-09-30T12:00:04Z", expires_at: "2026-09-30T12:05:02Z" };
}
function initial(operation = "Update", boundary = "Blocked", change = () => {}) {
  const ctx = context(); if (operation === "Update") ctx.store.selection.security_epoch = 5;
  const proposal = request(ctx, operation); change(ctx, proposal); proposal.expected_head_digest = maintenanceHeadDigest(ctx.store);
  const p = protocolTrace(ctx, proposal, boundary, 0), r = scenario(base({ machine_id: ctx.store.machine_id,
    counter: ctx.store.counter, generation: ctx.store.generation, generation_floor: ctx.store.generation,
    security_floor: ctx.store.security_floor, selection: selected(ctx.store.selection) }));
  authorizeFor(r, p, "Maintenance", "None", proposal.desired); r.events = recoveryEvents(boundary);
  const d = { schema_version: "1.0.0", model_kind: "DeploymentScenario", privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly",
    simulated_at: r.simulated_at, machine_id: ctx.store.machine_id,
    snapshot: { generation: ctx.store.generation, security_floor: ctx.store.security_floor, selection: copy(ctx.store.selection) },
    intent: { operation, expected_generation: ctx.store.generation, next_generation: ctx.store.generation + 1, desired: copy(proposal.desired) },
    confirmation: null, used_nonces: [], events: dEvents.slice(0, dCounts[phases.indexOf(boundary)]) };
  confirm(d); return { deployment: d, steps: [{ boundary, protocol: p, recovery: r }], observations: [], claims: null };
}
function runPair(step) {
  checkedProtocolData("scenario", step.protocol); checkedRecoveryData("scenario", step.recovery);
  const p = runP(step.protocol), r = runR(step.recovery);
  checkedProtocolData("projection", p); checkedRecoveryData("projection", r);
  for (const result of [p, r]) {
    same(result.launch_status, "Blocked"); assert.ok(Object.values(result.effects).every(x => x === false));
  }
  return { protocol: p, recovery: r };
}

// A declared restart HYPOTHESIS for this private test, not a real Known store.
// At PublishPending the model returns null. Keep that output null; derive the
// expected declaration from original full tuples and the accepted event trace.
function declaredStore(step, p) {
  const s = copy(step.protocol.context.store), q = proposalOf(step.protocol), rank = phases.indexOf(step.boundary);
  const cleanup = q.recovery_target === "FinishCommittedCleanup";
  const next = cleanup ? s.generation : (s.journal?.highest_generation ?? s.generation) + 1;
  const entry = { transaction_id: p.transaction_id, counter: s.counter + 1, offer_digest: p.offer_digest, confirmation_digest: p.confirmation_digest };
  s.counter++;
  if (s.journal) s.journal.lineage.push(entry);
  else s.journal = { origin_transaction_id: entry.transaction_id, phase: "Admitted", highest_generation: s.generation,
    reserved_floor: s.security_floor, previous: copy(s.selection), candidate: copy(q.desired), lineage: [entry], journal_digest: "" };
  if (rank >= 1 && !cleanup) {
    s.journal.highest_generation = next;
    s.journal.reserved_floor = Math.max(s.journal.reserved_floor, s.security_floor, s.selection?.security_epoch ?? 0, q.desired?.security_epoch ?? 0);
    s.journal.phase = "PublishPending";
  }
  if (rank >= 2 && !cleanup) {
    s.selection = copy(q.desired); s.generation = next; s.security_floor = s.journal.reserved_floor;
    s.journal.candidate = copy(q.desired); s.journal.phase = "Committed";
  }
  if (rank === 3) {
    s.last_result = { transaction_id: p.transaction_id, counter: s.counter, offer_digest: p.offer_digest,
      outcome: s.selection === null ? "Uninstalled" : s.selection.backend_id === null ? "BackendNotEnrolled" : "InstalledLaunchBlocked" };
    s.journal = null;
  } else s.journal.journal_digest = digestWithExclusion(s.journal, "journal_digest");
  checkedProtocolData("store", s); return s;
}
function append(b, target = "FinalizeCandidate", boundary = "Completed") {
  const prior = b.steps.at(-1), out = runPair(prior), ctx = copy(prior.protocol.context);
  ctx.store = declaredStore(prior, out.protocol);
  const j = ctx.store.journal; assert.ok(j);
  const desired = target === "FinishCommittedCleanup" ? ctx.store.selection : target === "FinalizeCandidate" ? j.candidate : j.previous;
  const proposal = { kind: "Recovery", recovery_target: target, original_transaction_id: j.origin_transaction_id,
    journal_digest: j.journal_digest, highest_generation: j.highest_generation,
    expected_head_digest: maintenanceHeadDigest(ctx.store), expected_generation: ctx.store.generation, desired: copy(desired), members: [] };
  const p = protocolTrace(ctx, proposal, boundary, b.steps.length), r = restart(out.recovery);
  const cleanup = target === "FinishCommittedCleanup";
  authorizeFor(r, p, cleanup ? target : "RecoverPublication", cleanup ? "None" : target, desired);
  r.events = recoveryEvents(boundary, cleanup); b.steps.push({ boundary, protocol: p, recovery: r }); return b;
}
function observe(b, counter) {
  const last = b.steps.at(-1), out = runPair(last), ctx = copy(last.protocol.context);
  ctx.store = declaredStore(last, out.protocol);
  const p = protocol(ctx).bind().wire("QueryStatus", { counter }).input;
  p.simulated_at = stamp(last.protocol.simulated_at, 600000);
  const r = restart(out.recovery); r.simulated_at = p.simulated_at; r.events = [{ kind: "QueryStatus", counter }];
  b.observations.push({ counter, protocol: p, recovery: r }); return b;
}
function shape(b) {
  checkD("scenario", b.deployment);
  for (const step of [...b.steps, ...b.observations]) {
    checkedProtocolData("scenario", step.protocol); checkedRecoveryData("scenario", step.recovery);
  }
}
function computed(b) {
  shape(b); const d = simulateDeployment(b.deployment); checkD("projection", d);
  return { deployment: d, steps: b.steps.map(runPair), observations: b.observations.map(runPair) };
}
function checkTrace(step) {
  const p = step.protocol, q = proposalOf(p), cleanup = q.recovery_target === "FinishCommittedCleanup", rank = phases.indexOf(step.boundary);
  assert.ok(rank >= 0 && (!cleanup || [0, 3].includes(rank)), "supported phase");
  const names = ["ObservePeers", "HelperHello", "ClientBind", "ProposeOperation", "ReviewOffer", "VerifiedOffer", "Confirm", "Reserve", "AdmissionRecorded"];
  if (rank >= 1 && !cleanup) names.push("VerifyPayload", "BeginPublish");
  if (rank >= 2 && !cleanup) names.push("Commit");
  if (rank === 3) names.push("Cleanup", "Result");
  same(p.events.map(e => e.kind === "Local" ? e.action : e.message.type), names, "complete protocol trace");
  assert.ok(p.events.filter(e => e.kind === "Wire").every(e => e.delivery === "Delivered"), "no unresolved reply loss");
  same(step.recovery.events, recoveryEvents(step.boundary, cleanup), "complete recovery I/O trace");
}
function bindings(step, prior, seen) {
  const p = step.protocol, r = step.recovery, o = r.authorization.offer, q = proposalOf(p);
  same(q.members, [], "no payload-byte mapping"); same(p.context.storage_status, "Known");
  same(r.context, session(p), "session binding"); same(o.context, r.context);
  same(r.simulated_at, stamp(p.simulated_at, localEvent(p, "Reserve").at_ms));
  same(o.expires_at, stamp(p.simulated_at, messageEvent(p, "VerifiedOffer").message.payload.expires_at_ms));
  same(o.candidate, selected(q.desired), "entire target tuple");
  const unique = [r.context.session_id, messageEvent(p, "HelperHello").message.payload.helper_challenge,
    messageEvent(p, "ClientBind").message.payload.client_challenge];
  for (const [i, value] of unique.entries()) {
    const used = seen[i === 0 ? 0 : 1]; // Challenges share one freshness domain across both roles.
    assert.ok(!used.has(value), "fresh session label"); used.add(value);
  }
  if (prior) {
    assert.ok(Date.parse(p.simulated_at) > Date.parse(prior.protocol.simulated_at) + prior.protocol.events.at(-1).at_ms, "restart after prior trace");
    for (const key of ["helper_instance", "client_instance", "helper_identity_digest", "policy_digest", "consent_text_digest"]) {
      same(p.context[key], prior.protocol.context[key], "fixed participant/policy scope");
    }
    same(localEvent(p, "Confirm").data.approver_id, localEvent(prior.protocol, "Confirm").data.approver_id);
  }
}
function checkState(step, out, root, origin, lineage) {
  const s = declaredStore(step, out.protocol), r = out.recovery, state = inspect(r.storage, r.minimum).state;
  assert.ok(state); const q = proposalOf(step.protocol), rank = phases.indexOf(step.boundary);
  same(state.counter, s.counter); same(out.protocol.counter_floor, s.counter);
  same(state.machine_id, s.machine_id); same(state.generation, s.generation);
  same(state.generation_floor, s.journal?.highest_generation ?? s.generation);
  same(state.security_floor, Math.max(s.security_floor, s.journal?.reserved_floor ?? 0));
  same(out.protocol.security_floor, state.security_floor); same(state.selection, selected(s.selection));
  same(out.protocol.projected_store, s.journal?.phase === "PublishPending" ? null : s, "no projection promotion");
  same(r.status, rank === 3 ? "Completed" : "Active");
  same(out.protocol.state, ["Admitted", "PublishPending", "Committed", "Completed"][rank]);
  if (s.journal) {
    const a = state.active; assert.ok(a);
    same(a.origin_transaction_id, origin); same(a.transaction_id, out.protocol.transaction_id);
    same(a.previous, selected(root.snapshot.selection)); same(a.original_candidate, selected(root.intent.desired));
    same(a.candidate, selected(q.desired)); same(a.lineage, lineage);
    same(a.stage, q.recovery_target === "FinishCommittedCleanup" ? "Committed" : ["Admitted", "Blocked", "Committed"][rank]);
    const expectedTarget = q.recovery_target === "FinishCommittedCleanup" ? s.generation
      : rank === 0 ? state.generation_floor + 1 : state.generation_floor;
    same(a.target_generation, expectedTarget);
    same(r.selection_known, !a.publication_seen); same(r.selection, r.selection_known ? state.selection : null);
  } else {
    same(state.active, null); same(state.terminal.transaction_id, out.protocol.transaction_id);
    same(state.terminal.operation, step.recovery.authorization.offer.operation); same(state.terminal.outcome, "Completed");
    same(r.selection_known, true); same(r.selection, selected(s.selection));
  }
  return s;
}

// Private executable history correspondence. Nothing is exported or persisted.
// Full original scenarios supply provenance; Known snapshots/claims never do.
function compareHistory(value) {
  try {
    const b = boundedProtocolCopy(value, 16 * 1024 * 1024, 24);
    closed(b, ["deployment", "steps", "observations", "claims"]);
    assert.ok(Array.isArray(b.steps) && b.steps.length >= 2 && b.steps.length <= 4);
    assert.ok(Array.isArray(b.observations) && b.observations.length <= 4);
    for (const s of b.steps) closed(s, ["boundary", "protocol", "recovery"]);
    for (const o of b.observations) closed(o, ["counter", "protocol", "recovery"]);
    const outputs = computed(b), d = b.deployment, first = b.steps[0], initialStore = first.protocol.context.store;
    if (b.claims !== null) same(b.claims, outputs, "every claim field must match recomputation");
    same(outputs.deployment.reason, "None"); same(outputs.deployment.confirmation_consumed_in_model, true);
    same(outputs.deployment.launch_status, "Blocked"); assert.ok(Object.values(outputs.deployment.effects).every(x => x === false));
    same(d.events, dEvents.slice(0, dCounts[phases.indexOf(first.boundary)]));
    same(d.machine_id, initialStore.machine_id); same(d.snapshot, { generation: initialStore.generation,
      security_floor: initialStore.security_floor, selection: initialStore.selection });
    same(initialStore.journal, null); same(initialStore.last_result, null);
    same(proposalOf(first.protocol).kind, "Maintenance"); same(proposalOf(first.protocol).operation, d.intent.operation);
    same(proposalOf(first.protocol).desired, d.intent.desired);
    same(d.simulated_at, first.recovery.simulated_at);
    same(d.confirmation.issued_at, stamp(first.protocol.simulated_at, localEvent(first.protocol, "Confirm").at_ms));
    same(d.confirmation.expires_at, first.recovery.authorization.offer.expires_at);
    const seed = inspect(first.recovery.storage, first.recovery.minimum);
    same(seed.classification, "Stable"); same(first.recovery.storage.records, []); same(seed.state.terminal, null);
    same(seed.state.machine_id, d.machine_id); same(seed.state.counter, initialStore.counter);
    same(seed.state.generation, initialStore.generation); same(seed.state.generation_floor, initialStore.generation);
    same(seed.state.security_floor, initialStore.security_floor); same(seed.state.selection, selected(initialStore.selection));
    let previousStore = null; const seen = [new Set(), new Set()], lineage = [];
    const origin = `synthetic-tx-${initialStore.counter + 1}`;
    for (const [i, step] of b.steps.entries()) {
      checkTrace(step); const out = outputs.steps[i], p = step.protocol, r = step.recovery, o = r.authorization.offer, q = proposalOf(p);
      for (const result of Object.values(out)) { same(result.reason, "None"); same(result.events_processed, result === out.protocol ? p.events.length : r.events.length); }
      same(out.protocol.admission, "ConsumedInModel"); same(out.protocol.reply_lost, false);
      bindings(step, b.steps[i - 1], seen);
      const tx = `synthetic-tx-${p.context.store.counter + 1}`; same(o.transaction_id, tx); same(out.protocol.transaction_id, tx);
      if (i === 0) { same(o.operation, "Maintenance"); same(o.recovery_target, "None"); same(o.origin_transaction_id, null); }
      else {
        const previous = outputs.steps[i - 1].recovery;
        same(p.context.store, previousStore, "entire protocol restart hypothesis, including historical lineage");
        same(r.storage, previous.storage, "exact historical v2 bytes-as-objects"); same(r.minimum, previous.minimum);
        same(q.kind, "Recovery"); assert.ok(targets.includes(q.recovery_target));
        const cleanup = q.recovery_target === "FinishCommittedCleanup";
        same(o.operation, cleanup ? q.recovery_target : "RecoverPublication");
        same(o.recovery_target, cleanup ? "None" : q.recovery_target);
        same(o.origin_transaction_id, origin); same(q.original_transaction_id, origin);
        const journal = previousStore.journal; assert.ok(journal);
        const desired = cleanup ? previousStore.selection : q.recovery_target === "FinalizeCandidate" ? journal.candidate : journal.previous;
        same(q.desired, desired, "recovery target is exact, including null");
        same(q.journal_digest, journal.journal_digest); same(q.highest_generation, journal.highest_generation);
      }
      lineage.push({ transaction_id: tx, offer_digest: o.offer_digest });
      previousStore = checkState(step, out, d, origin, lineage);
    }
    const last = b.steps.at(-1), lastR = outputs.steps.at(-1).recovery;
    for (const [i, o] of b.observations.entries()) {
      const p = o.protocol, r = o.recovery, out = outputs.observations[i];
      same(p.context.store, previousStore); same(p.context.storage_status, "Known");
      same(r.storage, lastR.storage); same(r.minimum, lastR.minimum); same(r.authorization, null);
      same(p.events.map(e => e.kind === "Wire" ? e.message.type : e.action), ["ObservePeers", "HelperHello", "ClientBind", "QueryStatus"]);
      same(messageEvent(p, "QueryStatus").message.payload.counter, o.counter);
      same(r.events, [{ kind: "QueryStatus", counter: o.counter }]);
      assert.ok(Number.isSafeInteger(o.counter) && o.counter > 0 && o.counter <= previousStore.counter);
      assert.ok(Date.parse(p.simulated_at) > Date.parse(last.protocol.simulated_at) + last.protocol.events.at(-1).at_ms);
      same(r.simulated_at, p.simulated_at);
      for (const v of Object.values(out)) same(v.reason, "None");
      same(out.protocol.admission, "NotConsumed"); same(out.recovery.storage, lastR.storage); same(out.recovery.minimum, lastR.minimum);
      same(out.protocol.counter_floor, previousStore.counter); same(out.protocol.security_floor, lastR.minimum.security_floor);
      same(out.protocol.projected_store, previousStore.journal?.phase === "PublishPending" ? null : previousStore);
      same(out.protocol.events_processed, p.events.length); same(out.recovery.events_processed, r.events.length);
      const active = previousStore.journal?.lineage.some(x => x.counter === o.counter);
      const expectedP = previousStore.last_result?.counter === o.counter ? "Completed"
        : active ? previousStore.journal.phase === "PublishPending" ? "RecoveryRequired" : "Active" : "Retired";
      const expectedR = active ? "RecoveryRequired" : previousStore.last_result?.counter === o.counter ? "Completed" : "Retired";
      same(out.protocol.last_status, expectedP); same(out.recovery.last_status, expectedR);
      same(out.recovery.selection_known, previousStore.journal === null);
    }
    return Object.freeze({ comparison: "MatchedSyntheticRecoveryHistory", steps: b.steps.length,
      execution_enabled: false, launch_status: "Blocked", authority: "None" });
  } catch {
    const e = new Error("Synthetic recovery history mismatch."); e.code = "COMPOSED_RECOVERY_MISMATCH"; throw e;
  }
}
function reject(b, structural = false) { if (!structural) shape(b); assert.throws(() => compareHistory(b), { code: "COMPOSED_RECOVERY_MISMATCH" }); }
function good(b) { const before = copy(b), result = compareHistory(b); same(b, before); same(compareHistory(b), result); assert.ok(Object.isFrozen(result)); return result; }
const required = Object.freeze(["CRH-001", "CRH-002", "CRH-003", "CRH-004", "CRH-005", "CRH-006", "CRH-007", "CRH-008",
  "CRH-009", "CRH-010", "CRH-011", "CRH-012", "CRH-013", "CRH-014", "CRH-015", "CRH-016",
  "CRH-017", "CRH-018", "CRH-019", "CRH-020", "CRH-021", "CRH-022", "CRH-023", "CRH-024", "CRH-025"]);
const cases = [], executed = new Set();
const vector = (id, title, fn) => cases.push({ id, title, fn });

vector("CRH-001", "five origins finalize at each of four complete recovery boundaries", () => {
  for (const op of ordinary) for (const boundary of phases) good(append(initial(op), "FinalizeCandidate", boundary));
});
vector("CRH-002", "permitted previous and exact null restore at each boundary", () => {
  for (const op of ordinary) for (const boundary of phases) good(append(initial(op), "RestorePermittedPrevious", boundary));
});
vector("CRH-003", "cleanup after committed origins consumes a new counter, not generation", () => {
  for (const op of ordinary) for (const boundary of ["Admitted", "Completed"]) good(append(initial(op, "Committed"), "FinishCommittedCleanup", boundary));
});
vector("CRH-004", "repeated recovery retains original target, previous, origin and exact lineage", () => {
  for (const first of targets.slice(0, 2)) {
    const b = append(append(append(initial(), first, "Blocked"), "FinalizeCandidate", "Committed"), "FinishCommittedCleanup");
    good(b); b.claims = computed(b); good(b);
  }
});
vector("CRH-005", "terminal history queries distinguish current completion and retired ancestors", () => {
  const b = append(initial()); for (const counter of [10, 11, 12]) observe(b, counter); good(b);
});
vector("CRH-006", "unresolved history queries preserve committed protocol/v2 asymmetry", () => {
  for (const boundary of ["Admitted", "Blocked", "Committed"]) {
    const b = append(initial(), "FinalizeCandidate", boundary); for (const counter of [10, 11, 12]) observe(b, counter); good(b);
  }
});
vector("CRH-007", "a valid foreign full-tuple history cannot be substituted", () => {
  for (const key of Object.keys(tuple())) {
    const b = append(initial()), other = append(initial("Update", "Blocked", (ctx, q) => {
      const value = key === "security_epoch" ? 6 : key.endsWith("digest") ? hash(`foreign-${key}`) : "synthetic-foreign";
      ctx.store.selection[key] = value; q.desired[key] = value;
      if (key === "manifest_digest") q.desired[key] = hash("foreign-target-manifest");
    }));
    b.steps[1] = other.steps[1]; reject(b);
    assert.equal(runPair(other.steps[1]).protocol.reason, "None"); assert.equal(runPair(other.steps[1]).recovery.reason, "None");
  }
});
vector("CRH-008", "lost, reordered or duplicated history is not repaired", () => {
  const full = append(append(initial(), "FinalizeCandidate", "Blocked"), "FinalizeCandidate");
  for (const steps of [[full.steps[0], full.steps[2]], [full.steps[0], full.steps[2], full.steps[1]], [full.steps[0], full.steps[1], full.steps[1]]]) {
    const b = copy(full); b.steps = copy(steps); reject(b);
  }
});
vector("CRH-009", "terminal and active snapshots without original provenance reject", () => {
  const b = append(initial()), outputs = computed(b);
  b.steps[1].recovery = restart(outputs.steps[1].recovery); reject(b);
  const standalone = append(initial()); standalone.steps.shift(); reject(standalone);
  reject(document(outputs.steps[1].recovery), true);
});
vector("CRH-010", "rehashed historical storage and minimum mutations reject", () => {
  for (const key of ["counter", "generation", "security_floor"]) {
    const b = append(initial()); b.steps[1].recovery.minimum[key]++; reject(b);
  }
  const b = append(initial()); b.steps[1].recovery.storage.records[0].authorization.offer.context.peer_id = "synthetic-other-peer";
  seal(b.steps[1].recovery.storage.records[0].authorization.offer, "offer_digest", "Offer"); reject(b);
  const foreign = append(initial("Update", "Blocked", ctx => { ctx.helper_identity_digest = hash("different-historical-helper"); }));
  const splice = append(initial()); splice.steps[1].recovery = foreign.steps[1].recovery;
  same(runR(splice.steps[1].recovery).reason, "None"); reject(splice);
});
vector("CRH-011", "protocol historical lineage, origin and generation are exact", () => {
  for (const key of ["origin_transaction_id", "highest_generation", "reserved_floor", "lineage"]) {
    const b = append(initial()), j = b.steps[1].protocol.context.store.journal;
    if (key === "lineage") j.lineage[0].offer_digest = hash("foreign-prior-offer");
    else j[key] = typeof j[key] === "number" ? j[key] + 1 : "synthetic-tx-9";
    j.journal_digest = digestWithExclusion(j, "journal_digest"); reject(b);
  }
});
vector("CRH-012", "fresh valid authority for the wrong recovery target does not match", () => {
  const b = append(initial(), "FinalizeCandidate"), other = append(initial(), "RestorePermittedPrevious");
  b.steps[1].recovery = other.steps[1].recovery;
  assert.equal(runPair(b.steps[1]).recovery.reason, "None"); reject(b);
});
vector("CRH-013", "root operation validation still rejects hidden enrollment", () => {
  const b = append(initial()); b.deployment.intent.desired.backend_id = "synthetic-backend-v1"; confirm(b.deployment);
  same(simulateDeployment(b.deployment).reason, "OperationScopeMismatch"); reject(b);
});
vector("CRH-014", "below-floor restoration is denied before any recovery comparison", () => {
  const b = initial("Update", "Blocked", ctx => { ctx.store.selection.security_epoch = 4; });
  assert.throws(() => append(b, "RestorePermittedPrevious"));
  const splice = append(initial(), "RestorePermittedPrevious"); splice.deployment = b.deployment; splice.steps[0] = b.steps[0]; reject(splice);
});
vector("CRH-015", "fresh confirmation cannot be borrowed from a prior session or another model", () => {
  for (const slot of ["protocol", "recovery", "cross"]) {
    const b = append(initial());
    if (slot === "protocol") localEvent(b.steps[1].protocol, "Confirm").data = copy(localEvent(b.steps[0].protocol, "Confirm").data);
    if (slot === "recovery") b.steps[1].recovery.authorization = copy(b.steps[0].recovery.authorization);
    if (slot === "cross") b.steps[1].recovery.authorization.confirmation.offer_digest = runP(b.steps[1].protocol).offer_digest;
    reject(b);
  }
});
vector("CRH-016", "independently approved foreign session context is not historical binding", () => {
  for (const key of ["session_id", "peer_id", "approver_id", "helper_digest", "policy_digest", "challenge", "confirmation_text_digest"]) {
    const b = append(initial()), r = b.steps[1].recovery, offer = r.authorization.offer;
    r.context[key] = key.endsWith("digest") || key === "challenge" ? hash(`other-${key}`) : "synthetic-other-session";
    authorize(r, offer.operation, { candidate: offer.candidate, recovery_target: offer.recovery_target, expires_at: offer.expires_at });
    same(runR(r).reason, "None"); reject(b);
  }
});
vector("CRH-017", "decline, expired current offer and changed restart clock reject", () => {
  for (const slot of ["protocol", "recovery", "expired", "clock"]) {
    const b = append(initial()), r = b.steps[1].recovery;
    if (slot === "protocol") localEvent(b.steps[1].protocol, "Confirm").data.decision = "Declined";
    if (slot === "recovery") r.authorization.confirmation.decision = "Declined";
    if (slot === "clock") b.steps[1].protocol.simulated_at = b.steps[0].protocol.simulated_at;
    if (slot === "expired") { r.authorization.offer.expires_at = r.simulated_at; seal(r.authorization.offer, "offer_digest", "Offer"); r.authorization.confirmation.offer_digest = r.authorization.offer.offer_digest; }
    reject(b);
  }
});
vector("CRH-018", "every incomplete recovery I/O prefix and both lost replies reject", () => {
  for (const target of targets) {
    const full = append(initial("Update", target === "FinishCommittedCleanup" ? "Committed" : "Blocked"), target);
    for (let n = 0; n < full.steps[1].recovery.events.length; n++) {
      const b = copy(full); b.steps[1].recovery.events.length = n; reject(b);
    }
    const b = copy(full); b.steps[1].recovery.events.at(-1).delivery = "Lost"; reject(b);
    const p = copy(full); messageEvent(p.steps[1].protocol, "Result").delivery = "Lost"; reject(p);
  }
});
vector("CRH-019", "Unknown history remains blocked, not reclassified as a restart", () => {
  for (const slot of ["storage", "trust", "protocol", "coordinator", "quiescence"]) {
    const b = append(initial()), r = b.steps[1].recovery;
    if (slot === "storage") r.storage.integrity = "Unknown";
    if (slot === "trust") r.evidence_trust = "Unknown";
    if (slot === "protocol") b.steps[1].protocol.context.storage_status = "Unknown";
    if (slot === "coordinator") r.coordinator = "Unknown";
    if (slot === "quiescence") r.quiescence = "Unknown";
    reject(b);
  }
});
vector("CRH-020", "metadata-only v2 histories have no protocol/deployment authority analogue", () => {
  const retired = initial("Update", "Admitted"), completed = initial("Update", "Completed");
  const r1 = authorize(restart(runR(retired.steps[0].recovery)), "RetireAdmittedCandidate"); recovery(r1).retire();
  const r2 = authorize(restart(runR(completed.steps[0].recovery)), "CompactTerminalState"); recovery(r2).compact();
  const interrupted = copy(r2); interrupted.events = interrupted.events.slice(0, -1);
  const r3 = authorize(restart(runR(interrupted)), "ReconcileCheckpoint"); recovery(r3).compact();
  for (const r of [r1, r2, r3]) {
    same(runR(r).reason, "None"); const b = append(initial()); b.steps[1].recovery = r; reject(b);
  }
});
vector("CRH-021", "full rehashed claims cannot hide historical denial or altered outputs", () => {
  for (const domain of ["protocol", "recovery"]) {
    const b = append(initial()); b.claims = copy(computed(b)); const claim = b.claims.steps[1][domain];
    claim.simulated_at = "2026-09-30T12:10:06Z";
    claim.result_digest = domain === "protocol" ? digestWithExclusion(claim, "result_digest") : recoveryDigest(claim, "result_digest", "Projection");
    (domain === "protocol" ? checkedProtocolData : checkedRecoveryData)("projection", claim); reject(b);
  }
  const b = append(initial()); b.claims = copy(computed(b)); b.deployment.confirmation = null; reject(b);
});
vector("CRH-022", "status-only observations cannot mutate, consume authority or hide future counters", () => {
  for (const slot of ["counter", "authorization", "event", "store"]) {
    const b = observe(append(initial()), 12), o = b.observations[0];
    if (slot === "counter") o.counter = 13;
    if (slot === "authorization") o.recovery.authorization = copy(b.steps[1].recovery.authorization);
    if (slot === "event") o.recovery.events.push({ kind: "WriteHead", result: "Complete" });
    if (slot === "store") o.protocol.context.store.last_result.offer_digest = hash("changed-terminal");
    reject(b);
  }
});
vector("CRH-023", "bounded hostile inputs reject without getters and caller mutation", () => {
  let reads = 0;
  const getter = Object.defineProperty({}, "steps", { enumerable: true, get() { reads++; throw new Error("must not run"); } });
  const proxy = new Proxy({}, { ownKeys() { reads++; throw new Error("must not run"); } });
  const cycle = {}; cycle.self = cycle;
  for (const x of [null, [], getter, proxy, cycle, { ...append(initial()), authority: true }]) reject(x, true);
  same(reads, 0); const b = append(initial()); b.steps = [...b.steps, ...copy(b.steps), copy(b.steps[1])]; reject(b);
  const marker = good(append(initial())); assert.throws(() => { marker.execution_enabled = true; }, TypeError);
});
vector("CRH-024", "history, projections and Known codec round trips never enable launch", () => {
  const b = append(initial()), outputs = computed(b), doc = decodeRecoveryStore(encodeRecoveryStore(document(outputs.steps[1].recovery)));
  same(doc.storage.integrity, "Known"); same(doc.execution_enabled, false);
  for (const value of [good(b), outputs.deployment, ...Object.values(outputs.steps[1]), doc]) {
    assert.throws(() => planBackendLaunch(value), { code: "LAUNCH_PLAN_INPUT_INVALID" });
    for (const key of ["readiness", "consent", "execution_enabled"]) assert.throws(() => planBackendLaunch({ operation: "Version", [key]: value }), { code: "LAUNCH_PLAN_INPUT_INVALID" });
  }
  const plan = planBackendLaunch({ operation: "Version" }); same(plan.execution_enabled, false);
  same(plan.blockers.map(x => x.id), ["TL-ADJACENT-DLL", "TL-LINKED-TOKEN", "TL-NON-ELEVATED-MECHANISM", "TL-REPARSE-REPLACEMENT",
    "TL-INITIAL-INVENTORY", "TL-PREVENTIVE-LOAD-POLICY", "TL-UNKNOWN-MODULES", "TL-IMAGE-BYTE-BINDING", "TL-PRODUCTION-LOAD-CONTEXT"]);
  assert.ok(plan.blockers.every(x => x.status === "Open"));
});
vector("CRH-025", "challenge freshness spans both roles, even after legitimate reauthorization", () => {
  const b = append(initial()), prior = b.steps[0].protocol, p = b.steps[1].protocol;
  const hello = messageEvent(p, "HelperHello"), bind = messageEvent(p, "ClientBind");
  hello.message.payload.helper_challenge = messageEvent(prior, "ClientBind").message.payload.client_challenge;
  bind.message.payload.helper_challenge = hello.message.payload.helper_challenge;
  bind.message.payload.client_challenge = messageEvent(prior, "HelperHello").message.payload.helper_challenge;
  rehash(hello); rehash(bind);
  const reviewed = copy(p); reviewed.events.length = 5;
  const offer = runP(reviewed); same(offer.reason, "None");
  for (const type of ["VerifiedOffer", "AdmissionRecorded"]) {
    const event = messageEvent(p, type); event.message.payload.offer_digest = offer.offer_digest; rehash(event);
  }
  localEvent(p, "Confirm").data.offer_digest = offer.offer_digest;
  const completed = copy(p); completed.events.pop(); const output = runP(completed);
  const result = messageEvent(p, "Result"); result.message.payload.store_digest = maintenanceHeadDigest(output.projected_store); rehash(result);
  const r = b.steps[1].recovery, oldOffer = r.authorization.offer;
  authorizeFor(r, p, oldOffer.operation, oldOffer.recovery_target, proposalOf(p).desired);
  same(runP(p).reason, "None"); same(runR(r).reason, "None"); reject(b);
  good(append(initial()));
});
for (const c of cases) test(`${c.id}: ${c.title}`, () => { c.fn(); executed.add(c.id); });
test("CRH completeness: immutable exact IDs, unique registration, successful execution, zero skips", () => {
  same(cases.map(c => c.id).sort(), [...required].sort()); same([...executed].sort(), [...required].sort());
  same(new Set(cases.map(c => c.id)).size, required.length);
});

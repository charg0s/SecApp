import { jcsSha256, digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { simulateMaintenanceProtocol, maintenanceHeadDigest } from "../../tools/lib/maintenance-protocol-model.mjs";

export const hash = (label) => jcsSha256({ synthetic_label: label });
export const copy = (value) => structuredClone(value);
export function tuple(version = 1, epoch = 4) {
  return { app_id: `synthetic-app-v${version}`, supervisor_id: "synthetic-supervisor-v1",
    backend_id: null, policy_id: "synthetic-policy-v1", compatibility_id: "synthetic-contract-v1",
    security_epoch: epoch, manifest_digest: hash(`manifest-${version}`), policy_digest: hash("policy-v1") };
}
export function context() {
  return { helper_instance: "synthetic-helper-a", client_instance: "synthetic-client-a",
    helper_identity_digest: hash("helper-v1"), policy_digest: hash("maintenance-policy-v1"),
    consent_text_digest: hash("consent-text-v1"), storage_status: "Known",
    store: { machine_id: "synthetic-machine-a", counter: 10, generation: 7, security_floor: 4,
      selection: tuple(), journal: null, last_result: null } };
}
export function request(ctx, operation = "Update", members = []) {
  let desired = tuple(2, 5);
  if (operation === "Install") { ctx.store.selection = null; desired = tuple(); }
  if (operation === "Uninstall") desired = null;
  if (operation === "Repair") desired = copy(ctx.store.selection);
  if (operation === "EnrollBackend") desired = { ...tuple(), backend_id: "synthetic-backend-v1", manifest_digest: hash("with-backend") };
  return { kind: "Maintenance", operation, expected_head_digest: maintenanceHeadDigest(ctx.store),
    expected_generation: ctx.store.generation, desired, members };
}
export function recovery(target = "FinalizeCandidate", previousEpoch = 5) {
  const ctx = context();
  ctx.store.security_floor = 5; ctx.store.selection = tuple(1, previousEpoch);
  ctx.store.journal = { origin_transaction_id: "synthetic-tx-10", phase: "PublishPending",
    highest_generation: 8, reserved_floor: 5, previous: tuple(1, previousEpoch), candidate: tuple(2, 5),
    lineage: [{ transaction_id: "synthetic-tx-10", counter: 10, offer_digest: hash("prior-offer"), confirmation_digest: hash("prior-confirmation") }], journal_digest: "" };
  if (target === "FinishCommittedCleanup") {
    ctx.store.generation = 8; ctx.store.selection = tuple(2, 5); ctx.store.journal.phase = "Committed";
  }
  ctx.store.journal.journal_digest = digestWithExclusion(ctx.store.journal, "journal_digest");
  const desired = target === "RestorePermittedPrevious" ? ctx.store.journal.previous : ctx.store.journal.candidate;
  const proposal = { kind: "Recovery", recovery_target: target, original_transaction_id: "synthetic-tx-10",
    journal_digest: ctx.store.journal.journal_digest, highest_generation: 8,
    expected_head_digest: maintenanceHeadDigest(ctx.store), expected_generation: ctx.store.generation,
    desired: copy(desired), members: [] };
  return { ctx, proposal };
}

const helperMessages = new Set(["HelperHello", "VerifiedOffer", "AdmissionRecorded", "Progress", "Result"]);
export function harness(ctx = context(), proposal = request(ctx)) {
  let clock = 0;
  const seq = { Helper: 0, UI: 0 };
  const input = { schema_version: "1.0.0", model_kind: "MaintenanceProtocolScenario",
    privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly", simulated_at: "2026-09-29T12:00:00Z",
    context: copy(ctx), events: [] };
  const h = {
    input,
    project() { return simulateMaintenanceProtocol(input); },
    local(action, data, at = ++clock) {
      clock = at; input.events.push({ kind: "Local", at_ms: at, action, data: copy(data) }); return h;
    },
    wire(type, payload, options = {}) {
      const direction = helperMessages.has(type) ? "Helper" : "UI";
      const at = options.at ?? ++clock; clock = at;
      const counter = type === "QueryStatus" ? payload.counter : ctx.store.counter + 1;
      input.events.push({ kind: "Wire", at_ms: at, delivery: options.delivery ?? "Delivered",
        message: { schema_version: "1.0.0", protocol_version: 1, privacy_class: "PublicSynthetic",
          provenance: "SyntheticModelOnly", type, direction, channel_id: "synthetic-channel-a",
          transaction_id: ["HelperHello", "ClientBind"].includes(type) ? null : `synthetic-tx-${counter}`,
          sequence: ++seq[direction], payload: copy(payload), payload_digest: jcsSha256(payload) } });
      return h;
    },
    bind() {
      return h.local("ObservePeers", { verdict: "Matched", helper_instance: ctx.helper_instance, client_instance: ctx.client_instance })
        .wire("HelperHello", { helper_challenge: hash("helper-challenge"), helper_instance: ctx.helper_instance })
        .wire("ClientBind", { helper_challenge: hash("helper-challenge"), client_challenge: hash("client-challenge"), client_instance: ctx.client_instance });
    },
    offer() {
      h.bind().wire("ProposeOperation", proposal).local("ReviewOffer", { verdict: "Allowed" });
      const result = h.project();
      return h.wire("VerifiedOffer", { offer_digest: result.offer_digest, expires_at_ms: result.offer_expires_at_ms });
    },
    confirm() { return h.local("Confirm", { offer_digest: h.project().offer_digest, approver_id: "synthetic-approver-a", decision: "Approved" }); },
    reserve(result = "Durable") { return h.local("Reserve", { head_digest: maintenanceHeadDigest(ctx.store), result }); },
    admit(delivery = "Delivered") {
      h.confirm().reserve();
      return h.wire("AdmissionRecorded", { counter: ctx.store.counter + 1, offer_digest: h.project().offer_digest }, { delivery });
    },
    payload() {
      for (const member of proposal.members) for (let offset = 0; offset < member.size_bytes; offset += 65536) {
        h.wire("PayloadChunk", { member_id: member.member_id, offset,
          length: Math.min(65536, member.size_bytes - offset), chunk_digest: hash("synthetic-chunk-hypothesis") });
      }
      return h.local("VerifyPayload", { verdict: "Allowed" });
    },
    publish() { return h.local("BeginPublish", { quiescence: "Quiescent" }); },
    commit() { return h.local("Commit", { verdict: "Consistent" }); },
    cleanup(result = "Complete") { return h.local("Cleanup", { result }); },
    result(delivery = "Delivered") {
      const projected = h.project();
      return h.wire("Result", { state: projected.state, store_digest: maintenanceHeadDigest(projected.projected_store), execution_enabled: false }, { delivery });
    },
    complete() { return h.offer().admit().payload().publish().commit().cleanup().result(); }
  };
  return h;
}

export function messageEvent(input, type) { return input.events.find(event => event.kind === "Wire" && event.message.type === type); }
export function localEvent(input, action) { return input.events.find(event => event.kind === "Local" && event.action === action); }
export function rehash(event) { event.message.payload_digest = jcsSha256(event.message.payload); }

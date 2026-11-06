import { jcsSha256 } from "../../tools/lib/jcs.mjs";
import { recoveryDigest } from "../../tools/lib/maintenance-recovery-validation.mjs";
import { simulateMaintenanceRecovery, prepareRecoveryOffer } from "../../tools/lib/maintenance-recovery-model.mjs";

export const copy = x => structuredClone(x);
export const hash = label => jcsSha256({ synthetic: label });
export const seal = (x, key, domain) => { x[key] = recoveryDigest(x, key, domain); return x; };
export function base(changes = {}) {
  const anchor = seal({ machine_id: "synthetic-machine-a", sequence: 20, counter: 10, generation: 7,
    generation_floor: 7, security_floor: 4, selection: { digest: hash("v1"), epoch: 4 }, terminal: null, ...changes }, "anchor_digest", "Anchor");
  const { anchor_digest, terminal, ...head } = anchor;
  return { anchor, records: [], head: seal({ ...head, phase: "Stable", tail_digest: anchor_digest }, "head_digest", "Head"),
    checkpoint_candidate: null, obsolete_checkpoint: null, integrity: "Known" };
}
export function scenario(storage = base(), minimum = null) {
  return { schema_version: "2.0.0", model_kind: "MaintenanceRecoveryScenario", privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly",
    simulated_at: "2026-09-29T12:00:00Z", storage: copy(storage), minimum: minimum ?? { counter: storage.head.counter,
      generation: storage.head.generation_floor, security_floor: storage.head.security_floor },
    context: { session_id: "synthetic-session-a", peer_id: "synthetic-requester", approver_id: "synthetic-approver",
      challenge: hash("challenge"), helper_digest: hash("helper"), policy_digest: hash("policy"), confirmation_version: "SyntheticMetadataConsent-v2",
      confirmation_text_digest: hash("confirmation-text") },
    evidence_trust: "TrustedSynthetic", coordinator: "Held", quiescence: "Quiescent", authorization: null, events: [] };
}
export function authorize(input, operation, options = {}) {
  const offer = prepareRecoveryOffer(input, operation, options);
  input.authorization = { offer: copy(offer), confirmation: { decision: "ApprovedSynthetic", offer_digest: offer.offer_digest } };
  return input;
}
export function harness(input = authorize(scenario(), "Maintenance", { candidate: { digest: hash("v2"), epoch: 5 } })) {
  const h = { input,
    project() { return simulateMaintenanceRecovery(input); },
    event(kind, fields = {}) { input.events.push({ kind, ...fields }); return h; },
    stage(record_kind) { return h.event("WriteRecord", { record_kind, result: "Complete" }).event("Flush", { target: "Record", result: "DurableHypothesis" })
      .event("ReadBack", { target: "Record", result: "Matches" }).event("WriteHead", { result: "Complete" })
      .event("Flush", { target: "Head", result: "DurableHypothesis" }).event("ReadBack", { target: "Head", result: "Matches" }); },
    admit() { return h.stage("Admission"); },
    full() { return h.admit().stage("Block").stage("Commit").stage("Complete"); },
    retire() { return h.admit().stage("Retire"); },
    checkpoint() { return h.event("WriteCheckpoint", { result: "Complete" }).event("Flush", { target: "Checkpoint", result: "DurableHypothesis" })
      .event("ReadBack", { target: "Checkpoint", result: "Matches" }).event("WriteHead", { result: "Complete" })
      .event("Flush", { target: "Head", result: "DurableHypothesis" }).event("ReadBack", { target: "Head", result: "Matches" })
      .event("RetireJournal", { result: "Complete" }); },
    compact() { return h.admit().stage("AuthorizeCheckpoint").checkpoint(); },
    ack(phase = "Result", delivery = "Delivered") { return h.event("Acknowledge", { phase, delivery }); },
    query(counter = input.authorization?.offer.transaction_id ? Number(input.authorization.offer.transaction_id.slice(13)) : input.minimum.counter) {
      return h.event("QueryStatus", { counter });
    }
  }; return h;
}
export function admitted() { return harness().admit().project(); }
export function terminal() { return harness().full().project(); }
export function restart(result) { return scenario(result.storage, copy(result.minimum)); }
export function checkpointInput(published = false) {
  const h = harness(authorize(restart(terminal()), "CompactTerminalState")).compact();
  h.input.events = h.input.events.slice(0, published ? -1 : -4);
  const r = h.project(); return restart(r);
}
export function document(result) {
  return seal({ schema_version: "2.0.0", model_kind: "MaintenanceRecoveryStoreDocument", privacy_class: "PublicSynthetic",
    provenance: "SyntheticModelOnly", simulated_at: "2026-09-29T12:00:00Z", usage: "SyntheticReferenceOnly",
    execution_enabled: false, storage: copy(result.storage), minimum: copy(result.minimum) }, "document_digest", "Document");
}

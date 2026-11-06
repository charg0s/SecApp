import { jcsSha256, digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { persistenceStateDigest, simulateMaintenancePersistence } from "../../tools/lib/maintenance-persistence-model.mjs";

export const hash = label => jcsSha256({ synthetic_label: label });
export const copy = value => structuredClone(value);
export function baseStorage(changes = {}) {
  const anchor = { machine_id: "synthetic-machine-a", sequence: 20, counter: 10, generation: 7,
    security_floor: 4, selection_digest: hash("synthetic-v1"), selection_epoch: 4,
    last_transaction_id: "synthetic-tx-10", ...changes, anchor_digest: "" };
  anchor.anchor_digest = digestWithExclusion(anchor, "anchor_digest");
  const head = { machine_id: anchor.machine_id, sequence: anchor.sequence, tail_digest: anchor.anchor_digest,
    counter: anchor.counter, generation: anchor.generation, generation_floor: anchor.generation,
    security_floor: anchor.security_floor, phase: "Stable", selection_digest: anchor.selection_digest,
    selection_epoch: anchor.selection_epoch, head_digest: "" };
  head.head_digest = digestWithExclusion(head, "head_digest");
  return { anchor, records: [], head, integrity: "Known", checkpoint_candidate: null };
}
export function sealIntent(intent) {
  const { intent_digest, confirmation_digest, ...scope } = intent;
  intent.intent_digest = jcsSha256({ domain: "SecApp-Synthetic-Persistence-Intent-v1", scope });
  intent.confirmation_digest = jcsSha256({ domain: "SecApp-Synthetic-Persistence-Confirmation-v1",
    intent_digest: intent.intent_digest, transaction_id: intent.transaction_id });
  return intent;
}
export function intentFor(storage, changes = {}) {
  const intent = { kind: "Maintenance", transaction_id: `synthetic-tx-${storage.head.counter + 1}`,
    origin_transaction_id: null, recovery_target: null, expected_state_digest: persistenceStateDigest(storage),
    selection_digest: hash("synthetic-v2"), selection_epoch: 5, confirmation: "ApprovedSynthetic", ...changes };
  return sealIntent(intent);
}
export function recoveryIntent(storage, target = "FinalizeCandidate") {
  const first = storage.records.find(record => record.record_kind === "Reserve");
  const selected = target === "FinalizeCandidate" ? first.intent
    : target === "RestorePermittedPrevious" ? storage.anchor : storage.head;
  return intentFor(storage, { kind: "Recovery", origin_transaction_id: first.transaction_id,
    recovery_target: target, selection_digest: selected.selection_digest, selection_epoch: selected.selection_epoch });
}
export function harness(storage = baseStorage(), intent = intentFor(storage)) {
  const input = { schema_version: "1.0.0", model_kind: "MaintenancePersistenceScenario",
    privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly", simulated_at: "2026-09-29T12:00:00Z",
    storage: copy(storage), minimum: { counter: storage.head.counter, generation: storage.head.generation_floor,
      security_floor: storage.head.security_floor }, intent: copy(intent), coordinator: "Held", events: [] };
  const h = {
    input,
    project() { return simulateMaintenancePersistence(input); },
    event(kind, fields = {}) { input.events.push({ kind, ...fields }); return h; },
    write(record_kind, result = "Complete") { return h.event("WriteRecord", { record_kind, result }); },
    flush(target, result = "DurableHypothesis") { return h.event("Flush", { target, result }); },
    read(target, result = "Matches") { return h.event("ReadBack", { target, result }); },
    head(result = "Complete") { return h.event("WriteHead", { result }); },
    stage(kind) { return h.write(kind).flush("Journal").read("Journal").head().flush("Head").read("Head"); },
    reserve(delivery = "Delivered") { return h.stage("Reserve").event("Acknowledge", { phase: "Admission", delivery }); },
    block() { return h.event("ObserveQuiescence", { result: "Quiescent" }).stage("Block"); },
    commit() { return h.stage("Commit"); },
    complete(delivery = "Delivered") { return h.stage("Complete").event("Acknowledge", { phase: "Result", delivery }); },
    full() { return h.reserve().block().commit().complete(); },
    compact() { return h.event("WriteCheckpoint", { result: "Complete" }).flush("Checkpoint").read("Checkpoint")
      .head().flush("Head").read("Head").event("RetireJournal", { result: "Complete" }); },
    query(counter = storage.head.counter + 1) { return h.event("QueryStatus", { transaction_id: `synthetic-tx-${counter}`, counter }); },
    crash() { return h.event("Crash"); }
  };
  return h;
}

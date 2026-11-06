import { jcsSha256, digestWithExclusion } from "./jcs.mjs";
import { checkedPersistenceData, persistenceBytes } from "./maintenance-persistence-validation.mjs";

export const MAINTENANCE_PERSISTENCE_LIMITS = Object.freeze({
  events: 128, records: 64, lineage: 16, record_bytes: 16384,
  journal_bytes: 1048576, head_bytes: 8192, scenario_bytes: 4194304
});
const effects = Object.freeze(Object.fromEntries([
  "filesystem_writes_enabled", "ipc_enabled", "installation_enabled", "backend_execution_enabled",
  "uac_enabled", "network_enabled", "reboot_enabled", "user_data_deletion_enabled", "automatic_recovery_enabled", "native_apis_enabled"
].map(key => [key, false])));
const clone = value => structuredClone(value);
const tx = counter => `synthetic-tx-${counter}`;
const same = (a, b) => jcsSha256(a) === jcsSha256(b);
class Problem extends Error { constructor(reason) { super(reason); this.reason = reason; } }
const problem = reason => { throw new Problem(reason); };
function freeze(value) {
  if (value !== null && typeof value === "object") { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function stateDigest(state) { return jcsSha256({ domain: "SecApp-Synthetic-Persistence-State-v1", state }); }
function intentDigest(intent) {
  const { intent_digest, confirmation_digest, ...scope } = intent;
  return jcsSha256({ domain: "SecApp-Synthetic-Persistence-Intent-v1", scope });
}
function confirmationDigest(intent) {
  return jcsSha256({ domain: "SecApp-Synthetic-Persistence-Confirmation-v1",
    intent_digest: intent.intent_digest, transaction_id: intent.transaction_id });
}
function fromAnchor(anchor) {
  if (anchor.anchor_digest !== digestWithExclusion(anchor, "anchor_digest")
    || (anchor.last_transaction_id !== null && anchor.last_transaction_id !== tx(anchor.counter))
    || (anchor.selection_digest !== null && anchor.selection_epoch < anchor.security_floor)) problem("StorageInvalid");
  return { machine_id: anchor.machine_id, sequence: anchor.sequence, tail_digest: anchor.anchor_digest,
    counter: anchor.counter, generation: anchor.generation, generation_floor: anchor.generation,
    security_floor: anchor.security_floor, selection_digest: anchor.selection_digest,
    selection_epoch: anchor.selection_epoch, last_transaction_id: anchor.last_transaction_id, active: null };
}
function headFor(state) {
  const blocked = state.active?.publication_pending === true;
  const head = { machine_id: state.machine_id, sequence: state.sequence, tail_digest: state.tail_digest,
    counter: state.counter, generation: state.generation, generation_floor: state.generation_floor,
    security_floor: state.security_floor,
    phase: blocked ? "Blocked" : state.active?.stage ?? "Stable",
    selection_digest: blocked ? null : state.selection_digest,
    selection_epoch: blocked ? 0 : state.selection_epoch, head_digest: "" };
  head.head_digest = digestWithExclusion(head, "head_digest");
  return head;
}
function advance(current, kind, intent, transactionId) {
  const state = clone(current);
  if (kind === "Reserve") {
    if (!intent || intent.intent_digest !== intentDigest(intent) || intent.expected_state_digest !== stateDigest(state)) problem("IntentRejected");
    if (intent.confirmation !== "ApprovedSynthetic" || intent.confirmation_digest !== confirmationDigest(intent)) problem("ConfirmationRejected");
    if (state.counter === Number.MAX_SAFE_INTEGER) problem("CounterOverflow");
    if (transactionId !== tx(state.counter + 1) || intent.transaction_id !== transactionId) problem("IntentRejected");
    const old = state.active;
    if (intent.kind === "Maintenance" && old !== null) problem("ScopeRejected");
    if (intent.kind === "Recovery" && (!old || intent.origin_transaction_id !== old.origin_transaction_id)) problem("ScopeRejected");
    const cleanup = intent.recovery_target === "FinishCommittedCleanup";
    if (old) {
      if (old.lineage.length >= MAINTENANCE_PERSISTENCE_LIMITS.lineage) problem("LineageFull");
      if (cleanup ? old.stage !== "Committed" || old.publication_pending : !old.publication_pending) problem("ScopeRejected");
      const expected = cleanup ? [state.selection_digest, state.selection_epoch]
        : intent.recovery_target === "FinalizeCandidate" ? [old.original_candidate_digest, old.original_candidate_epoch]
          : [old.previous_selection_digest, old.previous_selection_epoch];
      if (!same(expected, [intent.selection_digest, intent.selection_epoch])) problem("ScopeRejected");
    }
    if (intent.selection_digest !== null && intent.selection_epoch < Math.max(state.security_floor, state.selection_epoch)) problem("EpochRejected");
    if (!cleanup && state.generation_floor === Number.MAX_SAFE_INTEGER) problem("GenerationOverflow");
    state.counter += 1;
    state.active = {
      transaction_id: transactionId, origin_transaction_id: old?.origin_transaction_id ?? transactionId,
      stage: cleanup ? "Committed" : "Admitted", publication_pending: old?.publication_pending ?? false,
      cleanup_only: cleanup, target_generation: cleanup ? state.generation : state.generation_floor + 1,
      candidate_digest: intent.selection_digest, candidate_epoch: intent.selection_epoch,
      original_candidate_digest: old ? old.original_candidate_digest : intent.selection_digest,
      original_candidate_epoch: old ? old.original_candidate_epoch : intent.selection_epoch,
      previous_selection_digest: old ? old.previous_selection_digest : state.selection_digest,
      previous_selection_epoch: old ? old.previous_selection_epoch : state.selection_epoch,
      lineage: [...(old?.lineage ?? []), { transaction_id: transactionId, intent_digest: intent.intent_digest, confirmation_digest: intent.confirmation_digest }]
    };
    return state;
  }
  const active = state.active;
  if (!active || active.transaction_id !== transactionId || intent !== null) problem("OrderRejected");
  if (kind === "Block") {
    if (active.stage !== "Admitted" || active.cleanup_only) problem("OrderRejected");
    active.stage = "Blocked"; active.publication_pending = true;
    state.generation_floor = active.target_generation;
    state.security_floor = Math.max(state.security_floor, state.selection_epoch, active.candidate_epoch);
  } else if (kind === "Commit") {
    if (active.stage !== "Blocked") problem("OrderRejected");
    state.generation = active.target_generation;
    state.selection_digest = active.candidate_digest; state.selection_epoch = active.candidate_epoch;
    active.stage = "Committed"; active.publication_pending = false;
  } else if (kind === "Complete") {
    if (active.stage !== "Committed") problem("OrderRejected");
    state.last_transaction_id = transactionId; state.active = null;
  } else problem("OrderRejected");
  return state;
}
function replay(storage) {
  let state = fromAnchor(storage.anchor);
  for (const record of storage.records) {
    if (state.sequence === Number.MAX_SAFE_INTEGER || record.sequence !== state.sequence + 1
      || record.previous_digest !== state.tail_digest
      || record.record_digest !== digestWithExclusion(record, "record_digest")) problem("StorageInvalid");
    state = advance(state, record.record_kind, record.intent, record.transaction_id);
    state.sequence = record.sequence; state.tail_digest = record.record_digest;
  }
  return state;
}
// Public helper for SYNTHETIC fixtures only; a digest never authenticates state.
export function persistenceStateDigest(value) {
  const storage = checkedPersistenceData("storage", value);
  if (storage.integrity !== "Known" || storage.checkpoint_candidate !== null) problem("StorageUnknown");
  const state = replay(storage);
  if (!same(storage.head, headFor(state))) problem("HeadMismatch");
  return stateDigest(state);
}

export function simulateMaintenancePersistence(value) {
  const input = checkedPersistenceData("scenario", value);
  const disk = input.storage;
  const result = { schema_version: "1.0.0", model_kind: "MaintenancePersistenceProjection",
    privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly", simulated_at: input.simulated_at,
    status: "Stable", reason: "None", watermarks: clone(input.minimum), selection_known: false,
    selected_digest: null, pending_stage: "None", storage: disk, admission_ack: "NotSent", result_ack: "NotSent",
    last_status: "NotQueried", events_processed: 0, effects: { ...effects }, launcher_status: "NotImplemented",
    launch_status: "Blocked", scenario_digest: jcsSha256(input), result_digest: "" };
  let state = null, pending = null, checkpointVerified = false, checkpointPublished = false;
  let headRequired = false, quiescent = false, sessionReserved = false, waitingStatus = false;
  let stopped = false, crashed = false;
  const raise = s => {
    result.watermarks.counter = Math.max(result.watermarks.counter, s.counter);
    result.watermarks.generation = Math.max(result.watermarks.generation, s.generation_floor ?? s.generation);
    result.watermarks.security_floor = Math.max(result.watermarks.security_floor, s.security_floor);
  };
  raise(disk.anchor);
  const headMatches = () => state !== null && same(disk.head, headFor(state));
  function finish() {
    if (pending) {
      result.pending_stage = `${pending.target}${pending.flushed ? "Flushed" : "Written"}`;
      // An interrupted prefix is not a restartable Known snapshot.
      disk.integrity = "Unknown";
    } else if (disk.checkpoint_candidate) result.pending_stage = checkpointPublished ? "CheckpointPublished" : "CheckpointVerified";
    if (!stopped) result.status = pending || headRequired || disk.checkpoint_candidate ? "InProgress"
      : state?.active?.publication_pending ? "PublicationBlocked" : state?.active?.stage ?? (sessionReserved ? "Completed" : "Stable");
    result.selection_known = state !== null && disk.integrity === "Known" && !pending && !disk.checkpoint_candidate
      && headMatches() && !state.active?.publication_pending && !["RecoveryRequired", "InProgress", "PublicationBlocked"].includes(result.status);
    result.selected_digest = result.selection_known ? state.selection_digest : null;
    result.result_digest = digestWithExclusion(result, "result_digest");
    checkedPersistenceData("projection", result);
    return freeze(result);
  }
  function stop(reason, uncertain = false) {
    result.reason = reason; stopped = true;
    if (uncertain) disk.integrity = "Unknown";
    result.status = uncertain || pending || disk.checkpoint_candidate || !headMatches() || state?.active?.publication_pending
      ? "RecoveryRequired" : state?.active?.stage === "Committed" ? "CleanupPending"
        : state?.active ? "RecoveryRequired" : crashed ? "Stopped" : "Rejected";
  }
  try {
    if (disk.integrity !== "Known" || disk.checkpoint_candidate) problem("StorageUnknown");
    state = replay(disk); raise(state);
    if (state.counter < input.minimum.counter || state.generation_floor < input.minimum.generation
      || state.security_floor < input.minimum.security_floor) problem("WatermarkRegression");
    if (!headMatches()) problem("HeadMismatch");
  } catch (error) {
    if (!(error instanceof Problem)) throw error;
    stop(error.reason, true); return finish();
  }
  for (const event of input.events) {
    if (stopped) break;
    result.events_processed += 1;
    try {
      if (waitingStatus && !["QueryStatus", "Crash"].includes(event.kind)) problem("StatusRejected");
      if (!["QueryStatus", "Crash"].includes(event.kind) && input.coordinator !== "Held") problem("CoordinatorUnavailable");
      switch (event.kind) {
        case "WriteRecord": {
          if (pending || headRequired || disk.checkpoint_candidate) problem("OrderRejected");
          if (event.record_kind === "Reserve" ? sessionReserved : !sessionReserved) problem("OrderRejected");
          if (event.record_kind === "Block" && !quiescent) problem("RuntimeBusy");
          if (state.sequence === Number.MAX_SAFE_INTEGER) problem("SequenceOverflow");
          if (disk.records.length >= MAINTENANCE_PERSISTENCE_LIMITS.records) problem("LimitExceeded");
          const recordIntent = event.record_kind === "Reserve" ? input.intent : null;
          const transactionId = input.intent?.transaction_id;
          const next = advance(state, event.record_kind, recordIntent, transactionId);
          const record = { sequence: state.sequence + 1, record_kind: event.record_kind,
            transaction_id: transactionId, intent: recordIntent, previous_digest: state.tail_digest, record_digest: "" };
          record.record_digest = digestWithExclusion(record, "record_digest");
          next.sequence = record.sequence; next.tail_digest = record.record_digest;
          if (persistenceBytes(record) > MAINTENANCE_PERSISTENCE_LIMITS.record_bytes
            || persistenceBytes([...disk.records, record]) > MAINTENANCE_PERSISTENCE_LIMITS.journal_bytes) problem("LimitExceeded");
          if (event.result === "NotWritten") { stop("NotWritten"); break; }
          raise(next);
          if (event.result !== "Complete") { stop("WriteUncertain", true); break; }
          pending = { target: "Journal", flushed: false, record, next };
          break;
        }
        case "Flush":
          if (!pending || pending.target !== event.target || pending.flushed) problem("OrderRejected");
          if (event.result !== "DurableHypothesis") { stop("FlushUncertain", true); break; }
          if (pending.target === "Journal") {
            disk.records.push(pending.record); state = pending.next;
            if (pending.record.record_kind === "Reserve") sessionReserved = true;
          } else if (pending.target === "Head") disk.head = pending.head;
          pending.flushed = true;
          break;
        case "ReadBack":
          if (!pending || pending.target !== event.target || !pending.flushed) problem("OrderRejected");
          if (event.result !== "Matches") { stop("ReadBackMismatch", true); break; }
          if (pending.target === "Journal") headRequired = true;
          else if (pending.target === "Head") {
            headRequired = false;
            if (pending.checkpoint) checkpointPublished = true;
          } else checkpointVerified = true;
          pending = null;
          break;
        case "WriteHead": {
          if (pending || (!headRequired && !checkpointVerified) || checkpointPublished) problem("OrderRejected");
          if (event.result === "NotWritten") { stop("NotWritten"); break; }
          if (event.result !== "Complete") { stop("WriteUncertain", true); break; }
          const head = headFor(checkpointVerified ? fromAnchor(disk.checkpoint_candidate) : state);
          pending = { target: "Head", flushed: false, head, checkpoint: checkpointVerified };
          break;
        }
        case "ObserveQuiescence":
          if (pending || headRequired || !sessionReserved || state.active?.stage !== "Admitted") problem("OrderRejected");
          if (event.result !== "Quiescent") { stop("RuntimeBusy"); break; }
          quiescent = true;
          break;
        case "Acknowledge":
          if (pending || headRequired || disk.checkpoint_candidate || !headMatches() || !sessionReserved) problem("OrderRejected");
          if (event.phase === "Admission") {
            if (!state.active || !["Admitted", "Committed"].includes(state.active.stage)
              || result.admission_ack !== "NotSent") problem("OrderRejected");
            result.admission_ack = event.delivery;
          } else {
            if (state.active || state.last_transaction_id !== input.intent?.transaction_id || result.result_ack !== "NotSent") problem("OrderRejected");
            result.result_ack = event.delivery;
          }
          waitingStatus = event.delivery === "Lost";
          break;
        case "QueryStatus":
          if (event.transaction_id !== tx(event.counter) || event.counter > state.counter) problem("StatusRejected");
          result.last_status = pending || headRequired || !headMatches() || disk.checkpoint_candidate ? "RecoveryRequired"
            : event.transaction_id === state.last_transaction_id ? "Completed"
              : state.active?.lineage.some(entry => entry.transaction_id === event.transaction_id)
                ? state.active.publication_pending && !sessionReserved ? "RecoveryRequired" : "Active"
                : "Retired";
          if (event.transaction_id === input.intent?.transaction_id && event.counter === state.counter) waitingStatus = false;
          break;
        case "Crash":
          crashed = true; stop("Crash"); break;
        case "WriteCheckpoint": {
          if (pending || headRequired || disk.checkpoint_candidate || state.active || !headMatches()
            || !sessionReserved || state.last_transaction_id !== input.intent?.transaction_id
            || disk.records.length === 0) problem("OrderRejected");
          if (event.result === "NotWritten") { stop("NotWritten"); break; }
          if (event.result !== "Complete") { stop("CompactionUncertain", true); break; }
          const anchor = { machine_id: state.machine_id, sequence: state.sequence, counter: state.counter, generation: state.generation,
            security_floor: state.security_floor, selection_digest: state.selection_digest, selection_epoch: state.selection_epoch,
            last_transaction_id: state.last_transaction_id, anchor_digest: "" };
          anchor.anchor_digest = digestWithExclusion(anchor, "anchor_digest");
          disk.checkpoint_candidate = anchor;
          pending = { target: "Checkpoint", flushed: false };
          break;
        }
        case "RetireJournal":
          if (pending || !checkpointPublished || !checkpointVerified || !disk.checkpoint_candidate || state.active) problem("OrderRejected");
          if (event.result !== "Complete") { stop("CompactionUncertain", event.result === "Unknown"); break; }
          disk.anchor = disk.checkpoint_candidate; disk.checkpoint_candidate = null; disk.records = [];
          state = fromAnchor(disk.anchor); checkpointVerified = false; checkpointPublished = false;
          break;
      }
    } catch (error) {
      if (!(error instanceof Problem)) throw error;
      stop(error.reason);
    }
  }
  return finish();
}

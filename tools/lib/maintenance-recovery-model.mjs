import { jcsSha256 } from "./jcs.mjs";
import { checkedRecoveryData, recoveryBytes, recoveryDigest, freezeRecovery } from "./maintenance-recovery-validation.mjs";
import { boundedProtocolCopy } from "./maintenance-protocol-validation.mjs";

// Pure, synthetic, in-memory hypotheses. No native API, paths, executor or IO.
export const RECOVERY_LIMITS = Object.freeze({ records: 64, lineage: 16, record_bytes: 16384,
  journal_bytes: 1048576, object_bytes: 8192, events: 128, offer_ms: 300000 });
const clone = x => structuredClone(x);
const same = (a, b) => jcsSha256(a) === jcsSha256(b);
const tx = n => `synthetic-tx-${n}`;
const meta = op => ["RetireAdmittedCandidate", "CompactTerminalState", "ReconcileCheckpoint"].includes(op);
const checkpointOp = op => ["CompactTerminalState", "ReconcileCheckpoint"].includes(op);
const terminalOutcomes = Object.freeze({ Maintenance: "Completed", RecoverPublication: "Completed",
  FinishCommittedCleanup: "Completed", RetireAdmittedCandidate: "CandidateRetired",
  CompactTerminalState: "MetadataAuthorized", ReconcileCheckpoint: "MetadataAuthorized" });
const costs = op => ["Maintenance", "RecoverPublication"].includes(op) ? 6 : checkpointOp(op) ? 2 : 4;
const effects = Object.freeze(Object.fromEntries(["filesystem_writes_enabled", "ipc_enabled", "installation_enabled",
  "backend_execution_enabled", "uac_enabled", "network_enabled", "reboot_enabled", "user_data_deletion_enabled",
  "automatic_recovery_enabled", "native_apis_enabled", "system_settings_changes_enabled"].map(k => [k, false])));
class Problem extends Error { constructor(reason) { super(reason); this.reason = reason; } }
const fail = reason => { throw new Problem(reason); };
const sealed = (x, key, domain) => ({ ...x, [key]: recoveryDigest(x, key, domain) });
const verify = (x, key, domain) => { if (x[key] !== recoveryDigest(x, key, domain)) fail("DigestMismatch"); };
const stateHash = state => jcsSha256({ domain: "SecApp-Synthetic-Recovery-v2-State", state });

function fromAnchor(a) {
  verify(a, "anchor_digest", "Anchor");
  // Anchors contain terminal state only. A publication gap requires a retained
  // active journal; it cannot be treated as a stable compacted anchor.
  if (a.generation !== a.generation_floor || (a.selection && a.selection.epoch < a.security_floor)
    || (a.terminal && (a.terminal.transaction_id !== tx(a.counter)
      || a.terminal.outcome !== terminalOutcomes[a.terminal.operation]))) fail("AnchorInvalid");
  const { anchor_digest, ...body } = a;
  return { ...body, tail_digest: anchor_digest, active: null };
}
function headFor(s) {
  return sealed({ machine_id: s.machine_id, sequence: s.sequence, counter: s.counter, generation: s.generation,
    generation_floor: s.generation_floor, security_floor: s.security_floor,
    selection: s.active?.publication_seen && s.active.stage !== "Committed" ? null : s.selection,
    phase: s.active?.stage ?? "Stable", tail_digest: s.tail_digest }, "head_digest", "Head");
}
function compactAnchor(s) {
  if (s.active) fail("ActiveLineage");
  const { tail_digest, active, ...body } = s;
  return sealed(body, "anchor_digest", "Anchor");
}
function checkMin(s, minimum) {
  if (s.counter !== minimum.counter || s.generation_floor !== minimum.generation
    || s.security_floor !== minimum.security_floor) fail("MinimumConflict");
}
function classify(disk, s, minimum) {
  if (disk.integrity !== "Known") fail("UnknownEvidence");
  checkMin(s, minimum);
  verify(disk.head, "head_digest", "Head");
  const candidate = disk.checkpoint_candidate;
  if (!candidate) {
    if (disk.obsolete_checkpoint || !same(disk.head, headFor(s))) fail("HeadMismatch");
    return s.active ? "Active" : s.terminal?.outcome === "MetadataAuthorized" && disk.records.length
      ? "CheckpointPending" : "Stable";
  }
  if (s.active) fail("ActiveLineage");
  if (!same(candidate, compactAnchor(s))) fail("CheckpointConflict");
  if (disk.obsolete_checkpoint) {
    const admission = disk.records.findLast(r => r.record_kind === "Admission");
    if (admission?.authorization.offer.operation !== "ReconcileCheckpoint"
      || !same(disk.obsolete_checkpoint, admission.authorization.offer.basis.checkpoint_candidate)) fail("CheckpointConflict");
  }
  if (same(disk.head, headFor(s))) return "PreparedUnpublished";
  if (same(disk.head, headFor(fromAnchor(candidate)))) return "PublishedUnretired";
  fail("HeadMismatch");
}

// Scalar admission budget used by every operation, including historical replay.
// Exported to exercise exact byte/sequence boundaries without huge allocations.
export function checkRecoveryCapacity(value) {
  const v = checkedCapacityCopy(value);
  const b = costs(v.operation);
  for (const k of ["record_count", "journal_bytes", "sequence", "counter", "lineage", "head_bytes", "anchor_bytes"]) {
    if (!Number.isSafeInteger(v[k]) || v[k] < 0) fail("CapacityInvalid");
  }
  if (v.record_count > 64 - b || v.journal_bytes > 1048576 - b * 16385
    || v.head_bytes > 8192 || v.anchor_bytes > 8192) fail("CapacityExhausted");
  if (v.sequence > Number.MAX_SAFE_INTEGER - b || v.counter === Number.MAX_SAFE_INTEGER) fail("CounterOrSequenceOverflow");
  if (v.lineage >= 16) fail("LineageFull");
  return b;
}
function checkedCapacityCopy(v) {
  // Same hostile-object guard as the schema entrypoints, with a tiny closed shape.
  const x = boundedProtocolCopy(v, 4096, 2);
  const names = ["operation", "record_count", "journal_bytes", "sequence", "counter", "lineage", "head_bytes", "anchor_bytes"];
  if (!x || Array.isArray(x) || Object.keys(x).length !== names.length || !names.every(k => Object.hasOwn(x, k))
    || !["Maintenance", "RecoverPublication", "FinishCommittedCleanup", "RetireAdmittedCandidate", "CompactTerminalState", "ReconcileCheckpoint"].includes(x.operation)) fail("CapacityInvalid");
  return x;
}
function capacity(disk, s, operation) {
  return checkRecoveryCapacity({ operation, record_count: disk.records.length, journal_bytes: recoveryBytes(disk.records),
    sequence: s.sequence, counter: s.counter, lineage: s.active?.lineage.length ?? 0,
    head_bytes: recoveryBytes(disk.head), anchor_bytes: recoveryBytes(disk.anchor) });
}
function basisFor(disk, s, minimum) {
  return { anchor_digest: disk.anchor.anchor_digest, records_digest: jcsSha256(disk.records), head: clone(disk.head),
    checkpoint_candidate: clone(disk.checkpoint_candidate), obsolete_checkpoint: clone(disk.obsolete_checkpoint),
    minimum: clone(minimum), state_digest: stateHash(s), classification: classify(disk, s, minimum),
    journal_bytes: recoveryBytes(disk.records), record_count: disk.records.length };
}
function validateScope(s, offer) {
  const op = offer.operation, old = s.active, cls = offer.basis.classification;
  if (offer.origin_transaction_id !== (old?.origin_transaction_id ?? null)) fail("OriginMismatch");
  if (offer.effects_scope !== (meta(op) ? "MetadataOnly" : "SyntheticDeploymentOnly")) fail("ScopeRejected");
  if (op !== "RecoverPublication" && offer.recovery_target !== "None") fail("ScopeRejected");
  if (op === "Maintenance") {
    if (old || cls !== "Stable") fail("ScopeRejected");
  } else if (op === "RecoverPublication") {
    if (!old?.publication_seen || old.stage === "Committed") fail("ScopeRejected");
    const expected = offer.recovery_target === "FinalizeCandidate" ? old.original_candidate
      : offer.recovery_target === "RestorePermittedPrevious" ? old.previous : undefined;
    if (expected === undefined || !same(expected, offer.candidate)) fail("ScopeRejected");
  } else if (op === "FinishCommittedCleanup") {
    if (old?.stage !== "Committed" || !same(offer.candidate, s.selection)) fail("ScopeRejected");
  } else if (op === "RetireAdmittedCandidate") {
    if (!old || old.original_operation !== "Maintenance" || old.stage !== "Admitted" || old.publication_seen
      || !same(old.previous, s.selection) || !same(offer.candidate, s.selection)) fail("PublicationUnresolved");
  } else {
    if (old || !same(offer.candidate, s.selection)) fail("ScopeRejected");
    if (op === "CompactTerminalState" ? cls !== "Stable" || offer.basis.record_count === 0
      : !["PreparedUnpublished", "PublishedUnretired"].includes(cls) || offer.basis.obsolete_checkpoint !== null) fail("CheckpointConflict");
  }
  // Admission must not downgrade either the persisted floor or the selected
  // epoch. Block will preserve their maximum; checking only the floor here
  // could otherwise commit a candidate below the newly preserved floor.
  if (offer.candidate && offer.candidate.epoch < Math.max(s.security_floor, s.selection?.epoch ?? 0)) fail("BelowFloor");
  if (!meta(op) && op !== "FinishCommittedCleanup" && s.generation_floor === Number.MAX_SAFE_INTEGER) fail("GenerationOverflow");
}
function validateAuthorization(disk, s, auth) {
  if (!auth) fail("ConfirmationRequired");
  const o = auth.offer;
  verify(o, "offer_digest", "Offer");
  if (auth.confirmation.decision !== "ApprovedSynthetic" || auth.confirmation.offer_digest !== o.offer_digest) fail("ConfirmationRejected");
  if (!same(o.basis, basisFor(disk, s, o.basis.minimum))) fail("OfferChanged");
  if (o.required_records !== capacity(disk, s, o.operation) || o.transaction_id !== tx(s.counter + 1)) fail("OfferChanged");
  validateScope(s, o);
}
function advance(s, record, disk) {
  const n = clone(s), kind = record.record_kind;
  if (kind === "Admission") {
    validateAuthorization(disk, s, record.authorization);
    const o = record.authorization.offer, old = s.active;
    if (record.transaction_id !== o.transaction_id) fail("OriginMismatch");
    n.counter++;
    n.active = { transaction_id: o.transaction_id, origin_transaction_id: old?.origin_transaction_id ?? o.transaction_id,
      operation: o.operation, original_operation: old?.original_operation ?? o.operation,
      stage: o.operation === "FinishCommittedCleanup" ? "Committed" : "Admitted",
      publication_seen: old?.publication_seen ?? false,
      target_generation: meta(o.operation) || o.operation === "FinishCommittedCleanup" ? n.generation : n.generation_floor + 1,
      candidate: clone(o.candidate), original_candidate: clone(old ? old.original_candidate : o.candidate),
      previous: clone(old ? old.previous : s.selection),
      lineage: [...(old?.lineage ?? []), { transaction_id: o.transaction_id, offer_digest: o.offer_digest }] };
    return n;
  }
  const a = n.active;
  if (!a || record.authorization !== null || record.transaction_id !== a.transaction_id) fail("OrderRejected");
  if (kind === "Block") {
    if (!["Maintenance", "RecoverPublication"].includes(a.operation) || a.stage !== "Admitted") fail("OrderRejected");
    a.stage = "Blocked"; a.publication_seen = true; n.generation_floor = a.target_generation;
    n.security_floor = Math.max(n.security_floor, a.candidate?.epoch ?? 0, n.selection?.epoch ?? 0);
  } else if (kind === "Commit") {
    if (a.stage !== "Blocked") fail("OrderRejected");
    n.generation = a.target_generation; n.selection = clone(a.candidate); a.stage = "Committed";
  } else {
    const valid = kind === "Retire" ? a.operation === "RetireAdmittedCandidate" && a.stage === "Admitted" && !a.publication_seen
      : kind === "AuthorizeCheckpoint" ? checkpointOp(a.operation) && a.stage === "Admitted"
        : kind === "Complete" && a.stage === "Committed";
    if (!valid) fail("OrderRejected");
    n.terminal = { transaction_id: a.transaction_id, operation: a.operation,
      outcome: kind === "Retire" ? "CandidateRetired" : kind === "AuthorizeCheckpoint" ? "MetadataAuthorized" : "Completed",
      terminal_digest: jcsSha256({ domain: "SecApp-Synthetic-Recovery-v2-Terminal", before: stateHash(s), kind }) };
    n.active = null;
  }
  return n;
}
// Reconstruct the complete old chain independently of the published head or
// candidate. Historical admissions include the exact observed representations;
// these are checked against the reconstructed prefix, never accepted as truth.
function reconstruct(disk, observe = () => {}) {
  let s = fromAnchor(disk.anchor);
  observe(s);
  const records = [];
  for (const r of disk.records) {
    verify(r, "record_digest", "Record");
    if (s.sequence === Number.MAX_SAFE_INTEGER || r.sequence !== s.sequence + 1 || r.previous_digest !== s.tail_digest) fail("ChainInvalid");
    const b = r.authorization?.offer.basis;
    const historical = { anchor: disk.anchor, records, integrity: "Known", head: b?.head ?? headFor(s),
      checkpoint_candidate: b?.checkpoint_candidate ?? null, obsolete_checkpoint: b?.obsolete_checkpoint ?? null };
    s = advance(s, r, historical); s.sequence = r.sequence; s.tail_digest = r.record_digest; records.push(r);
    // Preserve each fully verified prefix before examining the next record.
    // A bad tail cannot erase its possible effects; no record after the first
    // invalid link/digest/semantic transition is observed or repaired.
    observe(s);
  }
  return s;
}
export function inspectRecoverySnapshot(storage, minimum) {
  const disk = checkedRecoveryData("storage", storage);
  // Validate minima through the strict offer-free document shape.
  const m = checkedMinimum(minimum);
  try {
    const s = reconstruct(disk), classification = classify(disk, s, m);
    return freezeRecovery({ classification, reason: "None", state: s });
  } catch (e) {
    if (!(e instanceof Problem)) throw e;
    return freezeRecovery({ classification: "ConflictOrUnknown", reason: e.reason, state: null });
  }
}
function checkedMinimum(m) {
  const copy = boundedProtocolCopy(m, 1024, 1);
  if (!copy || Array.isArray(copy) || Object.keys(copy).length !== 3
    || !["counter", "generation", "security_floor"].every(k => Object.hasOwn(copy, k) && Number.isSafeInteger(copy[k]) && copy[k] >= 0)) fail("MinimumConflict");
  return copy;
}
export function prepareRecoveryOffer(value, operation, options = {}) {
  const input = checkedRecoveryData("scenario", value);
  const opts = boundedProtocolCopy(options, 4096, 3);
  if (!opts || Array.isArray(opts) || Object.keys(opts).some(k => !["candidate", "recovery_target", "expires_at"].includes(k))) fail("ScopeRejected");
  if (input.evidence_trust !== "TrustedSynthetic") fail("UnknownEvidence");
  const s = reconstruct(input.storage), basis = basisFor(input.storage, s, input.minimum);
  const o = checkedRecoveryData("offer", sealed({ format: "SyntheticRecovery-v2", operation,
    transaction_id: tx(s.counter + 1), origin_transaction_id: s.active?.origin_transaction_id ?? null,
    candidate: Object.hasOwn(opts, "candidate") ? opts.candidate : s.selection,
    recovery_target: opts.recovery_target ?? "None", effects_scope: meta(operation) ? "MetadataOnly" : "SyntheticDeploymentOnly",
    basis, context: input.context, required_records: capacity(input.storage, s, operation),
    expires_at: opts.expires_at ?? new Date(Date.parse(input.simulated_at) + RECOVERY_LIMITS.offer_ms)
      .toISOString().replace(".000Z", "Z") }, "offer_digest", "Offer"));
  if (!(Date.parse(o.expires_at) > Date.parse(input.simulated_at))) fail("OfferExpired");
  validateScope(s, o);
  return freezeRecovery(o);
}

export function simulateMaintenanceRecovery(value) {
  const input = checkedRecoveryData("scenario", value), disk = input.storage;
  const result = { schema_version: "2.0.0", model_kind: "MaintenanceRecoveryProjection", privacy_class: "PublicSynthetic",
    provenance: "SyntheticModelOnly", simulated_at: input.simulated_at, status: "Stable", reason: "None",
    classification: "ConflictOrUnknown", storage: disk, minimum: clone(input.minimum), selection_known: false,
    selection: null, admission_ack: "NotSent", result_ack: "NotSent", last_status: "NotQueried", events_processed: 0,
    effects: { ...effects }, launcher_status: "NotImplemented", launch_status: "Blocked", scenario_digest: jcsSha256(input), result_digest: "" };
  let s, pending = null, headRequired = false, admitted = false, stopped = false, waiting = false, initialAccepted = false;
  let checkpointVerified = false, checkpointPublished = false, completedCheckpoint = false;
  const raise = n => { result.minimum.counter = Math.max(result.minimum.counter, n.counter);
    result.minimum.generation = Math.max(result.minimum.generation, n.generation, n.generation_floor);
    result.minimum.security_floor = Math.max(result.minimum.security_floor, n.security_floor); };
  // Even conflicting observations cannot be forgotten on a rejected restart.
  for (const part of [disk.anchor, disk.head, disk.checkpoint_candidate, disk.obsolete_checkpoint].filter(Boolean)) raise(part);
  function stop(reason, uncertain = false) {
    stopped = true; result.reason = reason;
    if (uncertain) disk.integrity = "Unknown";
    result.status = "RecoveryRequired";
  }
  try {
    // The observer is private to reconstruction, not caller-supplied authority.
    // If a later record fails, already verified minima survive that exception.
    s = reconstruct(disk, raise);
    result.classification = classify(disk, s, input.minimum);
    if (input.evidence_trust !== "TrustedSynthetic") fail("UnknownEvidence");
    initialAccepted = true;
  } catch (e) { if (!(e instanceof Problem)) throw e; stop(e.reason); }
  for (const e of input.events) {
    if (stopped) break;
    result.events_processed++;
    try {
      if (e.kind === "Crash" || e.kind === "Cancel") { stop(e.kind); break; }
      if (waiting && e.kind !== "QueryStatus") fail("StatusRequired");
      if (e.kind !== "QueryStatus" && (input.coordinator !== "Held" || input.quiescence !== "Quiescent")) fail("BusyOrUnknownQuiescence");
      switch (e.kind) {
        case "WriteRecord": {
          if (pending || headRequired || checkpointVerified || (e.record_kind === "Admission" ? admitted : !admitted)) fail("OrderRejected");
          if (e.record_kind === "Admission") {
            const auth = input.authorization;
            if (!auth) fail("ConfirmationRequired");
            if (!same(auth.offer.context, input.context) || !same(auth.offer.basis.minimum, input.minimum)) fail("OfferChanged");
            if (!(Date.parse(auth.offer.expires_at) > Date.parse(input.simulated_at))) fail("OfferExpired");
          }
          if (s.sequence === Number.MAX_SAFE_INTEGER || disk.records.length >= 64) fail("CapacityExhausted");
          const r = sealed({ sequence: s.sequence + 1, record_kind: e.record_kind,
            transaction_id: input.authorization?.offer.transaction_id ?? tx(0),
            authorization: e.record_kind === "Admission" ? input.authorization : null, previous_digest: s.tail_digest }, "record_digest", "Record");
          const next = advance(s, r, disk); next.sequence = r.sequence; next.tail_digest = r.record_digest;
          if (recoveryBytes(r) > 16384 || recoveryBytes([...disk.records, r]) > 1048576 || recoveryBytes(headFor(next)) > 8192) fail("CapacityExhausted");
          if (e.result === "NotWritten") { stop("NotWritten"); break; }
          raise(next);
          if (e.result !== "Complete") { stop("WriteUncertain", true); break; }
          pending = { target: "Record", flushed: false, record: r, next }; break;
        }
        case "Flush": {
          if (!pending || pending.target !== e.target || pending.flushed) fail("OrderRejected");
          if (e.result !== "DurableHypothesis") { stop("FlushUncertain", true); break; }
          if (pending.target === "Record") { disk.records.push(pending.record); s = pending.next;
            if (pending.record.record_kind === "Admission") admitted = true;
          } else if (pending.target === "Head") disk.head = pending.head;
          else { disk.obsolete_checkpoint = disk.checkpoint_candidate; disk.checkpoint_candidate = pending.anchor; }
          pending.flushed = true; break;
        }
        case "ReadBack": {
          if (!pending || pending.target !== e.target || !pending.flushed) fail("OrderRejected");
          if (e.result !== "Matches") { stop("ReadBackMismatch", true); break; }
          if (pending.target === "Record") headRequired = true;
          else if (pending.target === "Head") { headRequired = false; if (pending.checkpoint) checkpointPublished = true; }
          else checkpointVerified = true;
          pending = null; break;
        }
        case "WriteHead": {
          if (pending || (!headRequired && !checkpointVerified) || checkpointPublished) fail("OrderRejected");
          if (e.result !== "Complete") { stop(e.result === "NotWritten" ? "NotWritten" : "WriteUncertain", e.result === "Unknown"); break; }
          pending = { target: "Head", flushed: false, checkpoint: checkpointVerified,
            head: headFor(checkpointVerified ? fromAnchor(disk.checkpoint_candidate) : s) }; break;
        }
        case "WriteCheckpoint": {
          if (pending || headRequired || !admitted || s.active || !checkpointOp(s.terminal?.operation)
            || s.terminal.transaction_id !== input.authorization.offer.transaction_id || !same(disk.head, headFor(s))
            || disk.obsolete_checkpoint || checkpointVerified || completedCheckpoint) fail("OrderRejected");
          if (e.result !== "Complete") { stop(e.result === "NotWritten" ? "NotWritten" : "WriteUncertain", e.result === "Unknown"); break; }
          const anchor = compactAnchor(s);
          if (recoveryBytes(anchor) > 8192) fail("CapacityExhausted");
          pending = { target: "Checkpoint", flushed: false, anchor }; break;
        }
        case "RetireJournal": {
          if (pending || headRequired || !checkpointVerified || !checkpointPublished || s.active) fail("OrderRejected");
          if (e.result !== "Complete") { stop(e.result === "NotWritten" ? "NotWritten" : "RetirementUnknown", e.result === "Unknown"); break; }
          disk.anchor = disk.checkpoint_candidate; disk.records = []; disk.checkpoint_candidate = null; disk.obsolete_checkpoint = null;
          s = fromAnchor(disk.anchor); completedCheckpoint = true; checkpointVerified = false; checkpointPublished = false; break;
        }
        case "Acknowledge": {
          if (pending || headRequired || !admitted || !same(disk.head, headFor(s))) fail("OrderRejected");
          if (e.phase === "Admission") {
            if (!s.active || result.admission_ack !== "NotSent") fail("OrderRejected");
            result.admission_ack = e.delivery;
          } else {
            if (s.active || s.terminal?.transaction_id !== input.authorization.offer.transaction_id || result.result_ack !== "NotSent"
              || (checkpointOp(s.terminal.operation) && !completedCheckpoint)) fail("OrderRejected");
            result.result_ack = e.delivery;
          }
          waiting = e.delivery === "Lost"; break;
        }
        case "QueryStatus": {
          if (e.counter > s.counter || e.counter === 0) fail("StatusRejected");
          let cls;
          try { cls = classify(disk, s, result.minimum); } catch { cls = "ConflictOrUnknown"; }
          result.last_status = pending || headRequired || !["Stable", "Active"].includes(cls)
            ? "RecoveryRequired"
            : s.active?.lineage.some(x => x.transaction_id === tx(e.counter))
              ? s.active.publication_seen && !admitted ? "RecoveryRequired" : "Active"
              : s.terminal?.transaction_id === tx(e.counter) ? s.terminal.outcome === "CandidateRetired" ? "CandidateRetired" : "Completed" : "Retired";
          if (e.counter === s.counter && tx(e.counter) === input.authorization?.offer.transaction_id) waiting = false;
          break;
        }
      }
    } catch (e) { if (!(e instanceof Problem)) throw e; stop(e.reason); }
  }
  if (pending || headRequired) disk.integrity = "Unknown";
  try {
    const classified = inspectRecoverySnapshot(disk, result.minimum);
    result.classification = classified.classification;
    if (!stopped) result.status = pending || headRequired || !["Stable", "Active"].includes(classified.classification)
      || (s.active?.publication_seen && !admitted)
      ? "RecoveryRequired" : s.active ? "Active" : admitted ? "Completed" : "Stable";
    result.selection_known = initialAccepted && !pending && !headRequired
      && ["Stable", "Active"].includes(classified.classification) && !s.active?.publication_seen;
    result.selection = result.selection_known ? clone(s.selection) : null;
  } catch { result.selection_known = false; result.selection = null; }
  result.result_digest = recoveryDigest(result, "result_digest", "Projection");
  checkedRecoveryData("projection", result);
  return freezeRecovery(result);
}

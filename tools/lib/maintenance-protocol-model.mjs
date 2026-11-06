import { jcsSha256, digestWithExclusion } from "./jcs.mjs";
import { checkedProtocolData } from "./maintenance-protocol-validation.mjs";

export const MAINTENANCE_PROTOCOL_LIMITS = Object.freeze({
  control_bytes: 65536, control_frames: 128, payload_chunk_bytes: 65536,
  payload_frames: 8200, payload_members: 8, payload_bytes: 536870912,
  pairing_ms: 30000, offer_ms: 300000, payload_idle_ms: 30000, intake_ms: 600000,
  local_events: 64, lineage: 16
});
const limits = MAINTENANCE_PROTOCOL_LIMITS;
const effects = Object.freeze(Object.fromEntries([
  "filesystem_writes_enabled", "ipc_enabled", "installation_enabled", "backend_execution_enabled",
  "uac_enabled", "network_enabled", "reboot_enabled", "user_data_deletion_enabled", "automatic_recovery_enabled"
].map(key => [key, false])));
const same = (a, b) => jcsSha256(a) === jcsSha256(b);
const txId = (counter) => `synthetic-tx-${counter}`;
function freeze(value) {
  if (value !== null && typeof value === "object") { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
export function maintenanceHeadDigest(store) { return jcsSha256(checkedProtocolData("store", store)); }
function seal(journal) { journal.journal_digest = digestWithExclusion(journal, "journal_digest"); }
function storeProblem(store) {
  const journal = store.journal;
  if (store.selection && store.selection.security_epoch < store.security_floor) return true;
  if (store.last_result && (store.last_result.counter > store.counter
    || store.last_result.transaction_id !== txId(store.last_result.counter))) return true;
  if (!journal) return false;
  if (journal.journal_digest !== digestWithExclusion(journal, "journal_digest")
    || journal.highest_generation < store.generation || journal.reserved_floor < store.security_floor
    || journal.origin_transaction_id !== journal.lineage[0].transaction_id) return true;
  let prior = 0;
  for (const entry of journal.lineage) {
    if (entry.counter <= prior || entry.transaction_id !== txId(entry.counter) || entry.counter > store.counter) return true;
    prior = entry.counter;
  }
  if (prior !== store.counter) return true;
  if (store.last_result && store.last_result.counter >= journal.lineage[0].counter) return true;
  if (journal.phase === "Admitted" && (journal.highest_generation !== store.generation
    || journal.reserved_floor !== store.security_floor || !same(journal.previous, store.selection))) return true;
  if (journal.phase === "Committed" && (journal.highest_generation !== store.generation
    || journal.reserved_floor !== store.security_floor || !same(journal.candidate, store.selection))) return true;
  return false;
}
function normalScope(store, request) {
  const before = store.selection, after = request.desired;
  if (store.journal) return false;
  switch (request.operation) {
    case "Install": return before === null && after !== null && after.backend_id === null;
    case "Uninstall": return before !== null && after === null && request.members.length === 0;
    case "Repair": return before !== null && same(before, after);
    case "Update": return before !== null && after !== null && before.backend_id === after.backend_id
      && before.manifest_digest !== after.manifest_digest;
    case "EnrollBackend": return before !== null && after !== null && before.backend_id === null
      && after.backend_id !== null && before.manifest_digest !== after.manifest_digest
      && ["app_id", "supervisor_id", "policy_id", "policy_digest", "compatibility_id", "security_epoch"].every(key => before[key] === after[key]);
    default: return false;
  }
}
function recoveryScope(store, request) {
  const journal = store.journal;
  if (!journal || request.original_transaction_id !== journal.origin_transaction_id
    || request.journal_digest !== journal.journal_digest || request.highest_generation !== journal.highest_generation
    || journal.lineage.length >= limits.lineage) return false;
  if (request.recovery_target === "FinishCommittedCleanup") return journal.phase === "Committed"
    && same(request.desired, store.selection) && request.members.length === 0;
  if (journal.phase !== "PublishPending") return false;
  const desired = request.recovery_target === "FinalizeCandidate" ? journal.candidate : journal.previous;
  // Null is an exact journal-bound uninstalled selection, not a wildcard or
  // permission to intake bytes/delete data. Recovery still needs new admission.
  return same(request.desired, desired) && (desired !== null || request.members.length === 0);
}

// All facts, peers, payload hashes, confirmation and durability outcomes below
// are declared synthetic hypotheses. This model has no native or storage API.
export function simulateMaintenanceProtocol(value) {
  const input = checkedProtocolData("scenario", value);
  const context = input.context;
  const store = context.store;
  const initialHead = maintenanceHeadDigest(store);
  const result = {
    schema_version: "1.0.0", model_kind: "MaintenanceProtocolProjection",
    privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly", simulated_at: input.simulated_at,
    state: "AwaitPeer", reason: "None", offer_digest: null, confirmation_digest: null, offer_expires_at_ms: null,
    transaction_id: null, admission: "NotConsumed", counter_floor: store.counter,
    security_floor: Math.max(store.security_floor, store.journal?.reserved_floor ?? 0),
    projected_store: store, outcome: "NotCommitted", control_frames: 0, payload_frames: 0,
    payload_bytes: 0, events_processed: 0, last_status: "NotQueried", reply_lost: false,
    installer_status: "NotImplemented", launch_status: "Blocked", effects: { ...effects },
    scenario_digest: jcsSha256(input), result_digest: ""
  };
  const finish = () => {
    result.result_digest = digestWithExclusion(result, "result_digest");
    checkedProtocolData("projection", result);
    return freeze(result);
  };
  const recover = (reason) => {
    result.state = "RecoveryRequired"; result.reason = reason;
    result.projected_store = null; result.outcome = "Unknown";
  };
  if (context.storage_status !== "Known") { recover("StorageUnknown"); return finish(); }
  if (storeProblem(store)) { recover("StorageInvalid"); return finish(); }
  let channel = null, helperChallenge = null, clientChallenge = null, proposal = null;
  let lastTime = 0, localCount = 0, offeredAt = null, intakeAt = null, payloadAt = null;
  let nextGeneration = null, received = [], memberIndex = 0;
  const sequences = { Helper: 0, UI: 0 };
  let terminal = false;
  function fail(reason) {
    if (result.state === "PublishPending" || ["PersistenceUncertain", "TrustUnavailable"].includes(reason)
      || (result.admission === "NotConsumed" && store.journal)) recover(reason);
    else if (result.state === "Completed") { result.reason = reason; }
    else if (["Committed", "CleanupPending"].includes(result.state)) {
      result.state = "CleanupPending"; result.reason = reason;
    } else { result.state = result.admission === "ConsumedInModel" ? "Aborted" : "Rejected"; result.reason = reason; }
    terminal = true;
  }
  function requireState(...states) {
    if (!states.includes(result.state)) { fail("OrderRejected"); return false; }
    return true;
  }
  function complete() {
    store.last_result = { transaction_id: result.transaction_id, counter: store.counter,
      offer_digest: result.offer_digest, outcome: result.outcome };
    store.journal = null; result.state = "Completed";
  }
  function outcome() {
    return store.selection === null ? "Uninstalled" : store.selection.backend_id === null ? "BackendNotEnrolled" : "InstalledLaunchBlocked";
  }
  for (const event of input.events) {
    if (terminal) break;
    result.events_processed += 1;
    if (event.at_ms < lastTime) { fail("ClockRejected"); break; }
    lastTime = event.at_ms;
    if (["AwaitPeer", "AwaitHello", "AwaitBind"].includes(result.state) && lastTime > limits.pairing_ms) { fail("Expired"); break; }
    if (["Reviewed", "Offered", "Confirmed"].includes(result.state) && lastTime >= result.offer_expires_at_ms) { fail("Expired"); break; }
    if (result.state === "Admitted" && (lastTime - intakeAt > limits.intake_ms
      || (memberIndex < received.length && lastTime - payloadAt > limits.payload_idle_ms))) { fail("Expired"); break; }
    // A lost reply suspends local progress as well as UI mutations. Shutdown
    // remains possible; only exact current status can restore this session.
    if (result.reply_lost && !(event.kind === "Local" && event.action === "Interrupt")
      && !(event.kind === "Wire" && event.message.type === "QueryStatus")) { fail("ReplayRejected"); break; }
    if (event.kind === "Local") {
      if (++localCount > limits.local_events) { fail("LimitExceeded"); break; }
      const data = event.data;
      switch (event.action) {
        case "ObservePeers":
          if (!requireState("AwaitPeer")) break;
          if (data.verdict !== "Matched" || data.helper_instance !== context.helper_instance
            || data.client_instance !== context.client_instance) fail("PeerRejected");
          else result.state = "AwaitHello";
          break;
        case "ReviewOffer":
          if (!requireState("Proposed")) break;
          if (data.verdict !== "Allowed") { fail("TrustRejected"); break; }
          if (lastTime > Number.MAX_SAFE_INTEGER - limits.offer_ms) { fail("ClockRejected"); break; }
          offeredAt = lastTime; result.offer_expires_at_ms = lastTime + limits.offer_ms;
          result.offer_digest = jcsSha256({ domain: "SecApp-Synthetic-Maintenance-Offer-v1",
            context, channel, transaction_id: result.transaction_id, helper_challenge: helperChallenge,
            client_challenge: clientChallenge, proposal, issued_at_ms: offeredAt,
            expires_at_ms: result.offer_expires_at_ms, limits });
          result.state = "Reviewed";
          break;
        case "Confirm":
          if (!requireState("Offered")) break;
          if (data.offer_digest !== result.offer_digest) { fail("BindingMismatch"); break; }
          if (data.decision !== "Approved") { fail("ConsentDeclined"); break; }
          result.confirmation_digest = jcsSha256({ domain: "SecApp-Synthetic-Maintenance-Confirmation-v1",
            offer_digest: result.offer_digest, approver_id: data.approver_id, confirmed_at_ms: lastTime,
            channel_id: channel, transaction_id: result.transaction_id });
          result.state = "Confirmed";
          break;
        case "Reserve": {
          if (!requireState("Confirmed")) break;
          if (data.head_digest !== initialHead || maintenanceHeadDigest(store) !== initialHead) { fail("HeadChanged"); break; }
          if (data.result === "NotWritten") { fail("AdmissionNotWritten"); break; }
          result.counter_floor = store.counter + 1;
          if (data.result === "Unknown") { result.admission = "Unknown"; fail("PersistenceUncertain"); break; }
          store.counter += 1; result.admission = "ConsumedInModel";
          const entry = { transaction_id: result.transaction_id, counter: store.counter,
            offer_digest: result.offer_digest, confirmation_digest: result.confirmation_digest };
          if (proposal.kind === "Recovery") store.journal.lineage.push(entry);
          else store.journal = { origin_transaction_id: result.transaction_id, phase: "Admitted",
            highest_generation: store.generation, reserved_floor: store.security_floor,
            previous: store.selection, candidate: proposal.desired, lineage: [entry], journal_digest: "" };
          seal(store.journal); result.state = "Admitted";
          intakeAt = payloadAt = lastTime;
          received = proposal.members.map(member => ({ ...member, received: 0 }));
          break;
        }
        case "VerifyPayload":
          if (!requireState("Admitted")) break;
          if (memberIndex !== received.length || data.verdict !== "Allowed") { fail("PayloadRejected"); break; }
          if (proposal.kind === "Recovery" && proposal.recovery_target === "FinishCommittedCleanup") { fail("OrderRejected"); break; }
          result.state = "PayloadVerified";
          break;
        case "BeginPublish":
          if (!requireState("PayloadVerified")) break;
          if (data.quiescence !== "Quiescent") { fail("RuntimeBusy"); break; }
          result.security_floor = Math.max(result.security_floor, store.selection?.security_epoch ?? 0, proposal.desired?.security_epoch ?? 0);
          store.journal.reserved_floor = result.security_floor;
          store.journal.highest_generation = nextGeneration;
          store.journal.phase = "PublishPending"; seal(store.journal);
          result.state = "PublishPending";
          break;
        case "Commit":
          if (!requireState("PublishPending")) break;
          if (data.verdict !== "Consistent") { fail("PersistenceUncertain"); break; }
          store.selection = proposal.desired; store.generation = nextGeneration; store.security_floor = result.security_floor;
          store.journal.candidate = proposal.desired; store.journal.phase = "Committed"; seal(store.journal);
          result.outcome = outcome(); result.state = "Committed";
          break;
        case "Cleanup":
          if (!(result.state === "Committed" || (result.state === "Admitted" && proposal.kind === "Recovery"
            && proposal.recovery_target === "FinishCommittedCleanup"))) { fail("OrderRejected"); break; }
          result.outcome = outcome();
          if (data.result === "Failed") { result.state = "CleanupPending"; result.reason = "CleanupIncomplete"; }
          else complete();
          break;
        case "Interrupt": fail(event.data.reason); break;
      }
      continue;
    }
    const message = event.message;
    checkedProtocolData("message", message);
    if (message.payload_digest !== jcsSha256(message.payload)) { fail("DigestMismatch"); break; }
    if (message.type === "PayloadChunk") {
      if (++result.payload_frames > limits.payload_frames) { fail("LimitExceeded"); break; }
    } else if (++result.control_frames > limits.control_frames) { fail("LimitExceeded"); break; }
    if (message.sequence !== sequences[message.direction] + 1) { fail("SequenceRejected"); break; }
    sequences[message.direction] = message.sequence;
    if (channel !== null && message.channel_id !== channel) { fail("BindingMismatch"); break; }
    if (event.delivery === "Lost" && !["AdmissionRecorded", "Result"].includes(message.type)) { fail("OrderRejected"); break; }
    if (! ["HelperHello", "ClientBind", "ProposeOperation", "QueryStatus"].includes(message.type)
      && message.transaction_id !== result.transaction_id) { fail("BindingMismatch"); break; }
    const payload = message.payload;
    switch (message.type) {
      case "HelperHello":
        if (!requireState("AwaitHello")) break;
        if (payload.helper_instance !== context.helper_instance || /^0+$/u.test(payload.helper_challenge)) { fail("PeerRejected"); break; }
        helperChallenge = payload.helper_challenge; channel = message.channel_id; result.state = "AwaitBind";
        break;
      case "ClientBind":
        if (!requireState("AwaitBind")) break;
        if (payload.client_instance !== context.client_instance || payload.helper_challenge !== helperChallenge
          || payload.client_challenge === helperChallenge || /^0+$/u.test(payload.client_challenge)) { fail("BindingMismatch"); break; }
        clientChallenge = payload.client_challenge; result.state = "Bound";
        break;
      case "ProposeOperation": {
        if (!requireState("Bound")) break;
        if (store.counter === Number.MAX_SAFE_INTEGER || message.transaction_id !== txId(store.counter + 1)) { fail("ReplayRejected"); break; }
        if (payload.expected_head_digest !== initialHead || payload.expected_generation !== store.generation) { fail("HeadChanged"); break; }
        if (!(payload.kind === "Maintenance" ? normalScope(store, payload) : recoveryScope(store, payload))) { fail("ScopeRejected"); break; }
        const floor = Math.max(result.security_floor, store.selection?.security_epoch ?? 0);
        if (payload.desired && payload.desired.security_epoch < floor) { fail("EpochRejected"); break; }
        let total = 0; const names = new Set();
        for (const member of payload.members) { total += member.size_bytes; names.add(member.member_id); }
        if (total > limits.payload_bytes || names.size !== payload.members.length) { fail("LimitExceeded"); break; }
        const cleanup = payload.kind === "Recovery" && payload.recovery_target === "FinishCommittedCleanup";
        const highest = store.journal?.highest_generation ?? store.generation;
        if (!cleanup && highest === Number.MAX_SAFE_INTEGER) { fail("GenerationRejected"); break; }
        nextGeneration = cleanup ? store.generation : highest + 1;
        proposal = payload; result.transaction_id = message.transaction_id; result.state = "Proposed";
        break;
      }
      case "VerifiedOffer":
        if (!requireState("Reviewed")) break;
        if (payload.offer_digest !== result.offer_digest || payload.expires_at_ms !== result.offer_expires_at_ms) { fail("BindingMismatch"); break; }
        result.state = "Offered";
        break;
      case "AdmissionRecorded":
        if (!requireState("Admitted")) break;
        if (payload.counter !== store.counter || payload.offer_digest !== result.offer_digest) { fail("BindingMismatch"); break; }
        result.reply_lost = event.delivery === "Lost";
        break;
      case "PayloadChunk": {
        if (!requireState("Admitted")) break;
        const member = received[memberIndex];
        if (!member || payload.member_id !== member.member_id || payload.offset !== member.received
          || payload.length !== Math.min(limits.payload_chunk_bytes, member.size_bytes - member.received)) { fail("PayloadRejected"); break; }
        member.received += payload.length; result.payload_bytes += payload.length; payloadAt = lastTime;
        if (member.received === member.size_bytes) memberIndex += 1;
        break;
      }
      case "Cancel":
        if (!requireState("Offered", "Confirmed", "Admitted", "PayloadVerified", "PublishPending", "Committed", "CleanupPending")) break;
        if (payload.offer_digest !== result.offer_digest) { fail("BindingMismatch"); break; }
        fail("Cancelled"); break;
      case "QueryStatus":
        if (["AwaitPeer", "AwaitHello", "AwaitBind"].includes(result.state)) { fail("OrderRejected"); break; }
        if (message.transaction_id !== txId(payload.counter) || payload.counter > store.counter) { fail("BindingMismatch"); break; }
        result.last_status = store.last_result?.counter === payload.counter ? "Completed"
          : store.journal?.lineage.some(entry => entry.counter === payload.counter)
            ? store.journal.phase === "PublishPending" && result.admission === "NotConsumed" ? "RecoveryRequired" : "Active"
            : "Retired";
        if (payload.counter === store.counter && message.transaction_id === result.transaction_id) result.reply_lost = false;
        break;
      case "Progress":
        if (!requireState("Admitted", "PayloadVerified", "PublishPending", "Committed", "CleanupPending")) break;
        if (payload.state !== result.state) fail("BindingMismatch");
        break;
      case "Result":
        if (!requireState("Completed", "CleanupPending")) break;
        if (payload.state !== result.state || payload.store_digest !== maintenanceHeadDigest(store)) { fail("BindingMismatch"); break; }
        result.reply_lost = event.delivery === "Lost";
        break;
    }
  }
  // Never advertise a selected store while publication is uncertain. Incomplete
  // recovery sessions also cannot turn their old unresolved store into success.
  if (result.state === "PublishPending" || store.journal?.phase === "PublishPending") {
    result.projected_store = null; result.outcome = "Unknown";
  }
  return finish();
}

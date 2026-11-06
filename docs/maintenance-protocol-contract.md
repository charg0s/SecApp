# MAINTENANCE-PROTOCOL-CONTRACT1

Status: implemented development-only message/scenario/projection contracts and
pure in-memory reference model. Not a production protocol, helper, IPC endpoint,
installer, authenticated consent system or durable store. The
[design proposal](maintenance-protocol-design.md), all 28 MP native acceptance
cases, all 22 PI cases and all nine launch blockers retain their previous status.

## Files and entry points

Three Draft 2020-12 schemas under `schemas/development/` use immutable
`https://schemas.secapp.dev/v1/development/` identifiers:

- `maintenance-message.schema.json`: exact direction-specific message union,
  including disjoint Maintenance and Recovery proposal payloads;
- `maintenance-scenario.schema.json`: synthetic context/store and ordered wire
  messages versus local helper-event hypotheses;
- `maintenance-projection.schema.json`: deeply immutable model result with all
  host effects disabled and no Ready/Implemented status.

The existing deployment schemas and core ConsentReceipt/ActionLog contracts are
unchanged. These development-only PublicSynthetic inputs contain fixed synthetic
machine names and bounded synthetic IDs, never real identities, evidence or
credentials. A model projection or its digests are not an authority token.

`tools/lib/maintenance-protocol-model.mjs` exports
`simulateMaintenanceProtocol(scenario)`, `maintenanceHeadDigest(store)` and frozen
`MAINTENANCE_PROTOCOL_LIMITS`. `maintenance-protocol-validation.mjs` statically
imports the schema assets and compiles them using the existing pinned dev-only
Ajv2020 in strict offline mode; no runtime dependency or remote schema loader is
introduced. The model operates on checked copies, does not mutate caller data,
and reads no host state, clock, files, pipes or processes while evaluating them.

`decodeMaintenanceControlFrame(bytes)` validates one already-materialized control
JSON body, bounded before decoding. It reuses the existing strict parser and
rejects invalid UTF-8, BOM, duplicate keys, deep/oversized JSON, unknown fields,
wrong directions and mismatched payload digests. It is **not** a native framing
reader, streaming decoder or payload transfer implementation. PayloadChunk is
rejected by this control-body API and is represented only as metadata in a
synthetic scenario. Parser file-reading exports are never called by this API.

## Message authority and ordering

The normal sequence is ObservePeers (local hypothesis), HelperHello, ClientBind,
ProposeOperation, ReviewOffer (local), VerifiedOffer, Confirm (local), Reserve
(local), then AdmissionRecorded and any declared payload chunks. Payload
verification, publication, commit and cleanup are also local hypotheses. The UI
has no Approve, ConfirmOffer, Commit, InvokeUac or arbitrary-command message.

Wire messages bind a channel, direction, per-direction monotonically increasing
sequence and transaction. HelperHello and ClientBind have no transaction ID.
The model rejects zero/reflected challenges, wrong instance/challenge echoes,
channel/transaction substitution, bad order and sequence gaps/replays. Synthetic
transaction IDs are derived exactly as `synthetic-tx-<next counter>`; they are a
test discipline, not the production transaction-ID format. The model never
queries a real token, PID, named-pipe identity or signature.

ReviewOffer's Allowed verdict is a **declared hypothesis**, not authentication
of a release descriptor. The offer digest binds the complete initial context
and head, helper/policy/consent-text identities, both challenges, channel,
transaction, full proposal, issue/expiry times and fixed limits. The internal
confirmation digest additionally binds approver ID and confirmation time. Both
use explicit synthetic domain strings and JCS/SHA-256. A changed approver creates
a different confirmation record; no caller-generated digest proves user presence.

Maintenance scope mirrors the separate deployment model: Install cannot
overwrite an existing selection or add a backend, Update cannot change backend
identity, EnrollBackend cannot replace one or alter unrelated components,
Repair preserves the exact tuple, and Uninstall has no payload and preserves
the security floor. Complete manifests must change for Update/EnrollBackend.
The exact manifest bytes, signatures, current revocation status and copied image
are not checked by this model. No arbitrary paths, handles or executable source
content are accepted as protocol data.

## Consumption, losses and status

Reserve compares the confirmed initial head with the declared re-read head:

| Hypothetical persistence result | Projection |
|---|---|
| Durable | Increment counter exactly once and append the confirmation-bound lineage entry before intake |
| NotWritten | Reject without consuming; end this scenario, not retry/renew the offer |
| Unknown | RecoveryRequired, null selected store, Unknown admission and conservative counter floor |

No reservation writes to disk. Repeating the same input intentionally returns
the same output. This is not a persistent single-use guarantee. Modeling another
session requires a new explicit synthetic context; old transaction IDs and old
head/offer bindings are rejected against its advanced counter/head.

AdmissionRecorded and Result can be marked Lost in a scenario. Until exact
current status is queried, only QueryStatus or a local Interrupt is permitted;
local progress and other wire messages are rejected, not only UI mutations.
QueryStatus can report Active, Completed, Retired or RecoveryRequired without
executing anything. Querying an unrelated retired
transaction cannot clear uncertainty about the current reply. An acknowledged
current status permits the remaining already-admitted flow, not a new admission.
Compacted result details never cause old effects to be re-executed.

The projection separates protocol validity (`reason: None`) from already
committed state. A later malformed sequence cannot undo a known completed
transaction; its reason becomes a protocol error while the committed store is
preserved. Trust/persistence uncertainty instead yields RecoveryRequired. Do not
interpret state alone, a process exit code, or a schema-valid Result as authority.

## Failure and recovery

Before admission, denial leaves the counter unchanged. After admission but before
publish, abort preserves consumption and the old selection plus unresolved
candidate journal. At PublishPending, selection is unknown and the maximum
reserved security floor is preserved. A post-commit interruption/cleanup failure
keeps the committed tuple; trust/persistence uncertainty hides it and requires
recovery. Busy/unknown quiescence cannot advance publication.

Recovery proposals are disjoint from ordinary maintenance, including Repair.
They bind the original transaction, complete current journal/head digests and
the highest possibly published generation. They require a new offer, local
confirmation and admission counter. A journal checksum is only corruption
detection inside a supplied hypothesis; it does not authenticate a host store.

| Recovery target | Required state and outcome |
|---|---|
| FinalizeCandidate | Known PublishPending journal; exact candidate and permitted epoch; publish a fresh greater generation |
| RestorePermittedPrevious | Same, but exact previous tuple; never lower the maximum floor or restore its old generation number |
| FinishCommittedCleanup | Known consistent Committed journal; exact selected tuple and no payload; consume new authority without republishing |

The selected journal tuple may be null: FinalizeCandidate can finish an
interrupted Uninstall, and RestorePermittedPrevious can return an interrupted
first Install to its exact prior uninstalled state. Null requires an empty
member list, is never a wildcard and preserves the floor. Publication recovery
still uses a fresh greater generation; cleanup-only recovery retains the current
generation. Neither authorizes user-data deletion. This
reference-model correction and MPC-049..053 are recorded in
[the mechanism review](maintenance-mechanism-review.md).

The original transaction and confirmation-bound recovery lineage are retained
until completion. Unknown/corrupt state, conflicting counter/selection, an
exhausted counter/generation or 16-entry lineage cannot be silently reset or
discarded. An unfinished recovery over a pending journal exposes no selected
store even before it reaches publication. Below-floor or revoked-target
hypotheses are rejected. This stage does not implement an emergency reset or
abandonment/retirement operation for a pre-publish Admitted candidate; it stays
unresolved rather than inventing deletion authority.

## Implemented limits and deliberate omissions

The model enforces 64 KiB canonical message bodies, 128 control frames, eight
members, 8200 payload-metadata frames and 512 MiB total **declared** intake.
Nonfinal chunks must be exactly 64 KiB with exact sequential member/offset/size
binding. No payload bytes are allocated, read or authenticated: even the
512 MiB boundary test uses only small metadata objects. A full-byte verifier and
its failure modes remain native implementation requirements.

Pairing is limited to 30 seconds, offer confirmation/reservation to 300 seconds,
payload inactivity to 30 seconds and total admitted intake to 600 seconds, all
using supplied monotonic millisecond offsets. Backward time, invalid UTC labels,
restart/clock-uncertainty events and overflow fail closed. Whole control bodies
are bounded by the decoder; fragmented-frame deadlines are not implemented.

Additional reference bounds are 64 local events, 8392 total events, 200000 data
nodes, 16 MiB canonical scenario data, depth 12 for the scenario wrapper and 8
for messages, 4096-byte strings and 16 lineage entries. Unknown fields and input
limit overrides reject. Unsafe direct-API data (proxies, getters, exotic
prototypes, cycles, sparse arrays, hidden/symbol keys, negative zero and unsafe
numbers) is rejected before schema traversal or hashing, with the controlled
MAINTENANCE_PROTOCOL_INPUT_INVALID error and no original values in the message.

The 1 MiB physical journal / 8 KiB compact-head persistence policy, real storage
compaction, source acquisition, release-signature verification, peer/confirmation
integrity, phase-specific native watchdogs, bootstrapping and OS admission/leases
are not implemented. Metadata hypotheses cannot test MSI/selector atomicity,
physical power-loss durability or security against a same-user process.

Every output disables filesystem writes, IPC, installation, backend execution,
UAC, network, reboot, user-data deletion and automatic recovery. Installer status
is NotImplemented and launch status is Blocked. `scenario_digest` covers the
entire initial scenario; `result_digest` excludes only itself. Full relational
validation requires recomputing and comparing the complete model projection,
not merely checking JSON Schema or recalculating an untrusted digest.

## Gate and next boundary

Run `npm run test:maintenance-protocol`, also included in `npm test`. All three
new schemas and semantic cases are exercised with the pinned strict offline
Ajv registry. MPC-001 through MPC-053 are an exact required set, followed by a
completeness check; they are **not** MP-001 through MP-028 native acceptance runs.
See [test coverage](../tests/maintenance/README.md).

The subsequent [author review](maintenance-mechanism-review.md) records concrete
design candidates and remaining blockers; it is not independent acceptance.
The subsequent [pure persistence fault model](maintenance-persistence-model.md)
separates write/flush/head/reply observations without implementing storage.
The subsequent [composition review](maintenance-composition-review.md) pins
shared boundaries, corrects lost-reply suspension and documents intentional
abstraction differences. Its paired tests are not a production authority bridge
or independent acceptance. Native helper startup trust, confirmation integrity,
protected-store durability and runtime leases remain open. A
native helper/IPC implementation, UAC, installation, backend execution or new
dependencies still require explicit authorization and prerequisite review. This
stage does not silently proceed to those operations.

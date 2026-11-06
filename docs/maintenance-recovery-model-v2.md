# MAINTENANCE-RECOVERY-MODEL2

Status: implemented **pure synthetic development model**, not a Windows store,
installer, production launcher or independent security acceptance.

The model implements the bounded policy in
[MAINTENANCE-RECOVERY-POLICY1](maintenance-recovery-policy.md). Run:

```text
npm run test:maintenance-recovery-v2
```

RP-001..030 plus an exact-ID completeness test execute with full strict offline
Ajv Draft 2020-12 validation and zero skips. These are 31 Node tests, not native
acceptance evidence. All existing v1 schemas, models, codecs and test suites are
unchanged; the new suite is appended to npm test. Dependencies are unchanged.

The subsequent [MAINTENANCE-RECOVERY-FIX1](maintenance-recovery-fixes.md) corrects
four additional author-review counterexamples. MRF-001..012 plus completeness
now join the same recovery command (44 tests total); the original RP suite and
all schemas remain unchanged. Independent acceptance is still pending.

[MAINTENANCE-RECOVERY-FIX2](maintenance-recovery-recheck.md) addresses three findings
from the subsequent separate review. MRR-001..010 plus completeness bring the
recovery command to 55 tests. Its bounded recheck is distinct from broader native
or composed trust-boundary acceptance.

```text
RecoveryModel = SyntheticV2Implemented
RecoveryExecutor = NotImplemented
ProtectedStore = NotImplemented
NativeImplementation = BlockedPendingIndependentReview
AutomaticRecovery = Disabled
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
```

## Contract and compatibility

The separate immutable development family is
`https://schemas.secapp.dev/v2/development/maintenance-recovery.schema.json`,
with schema_version 2.0.0. The checked-in document is
`schemas/development/maintenance-recovery-v2.schema.json`; its definitions cover
the scenario, storage, authority offer, confirmation, records, projection and
snapshot document. This is not a major-version change to the production audit
contracts or a migration of any v1 object.

Pure entrypoints:

- `prepareRecoveryOffer`: validates synthetic evidence and proposes exact scope;
  it does not consume a counter or grant native authority.
- `simulateMaintenanceRecovery`: evaluates bounded ordered observations.
- `inspectRecoverySnapshot`: reconstructs the complete old chain independently
  of the current published head/candidate, then classifies agreement.
- `checkRecoveryCapacity`: checks closed scalar budget facts; it is also used by
  admission and historical replay, not a runtime reservation API.
- `encodeRecoveryStore` / `decodeRecoveryStore`: canonical whole-snapshot bytes
  in memory only. No paths, handles, streams, writer or file operations.

The strict schema rejects unknown fields/enums/major versions. Public data
entrypoints use the existing bounded plain-data guard before Ajv or hashing:
no getters, proxies, cycles, sparse arrays or unsafe integers. Inputs are not
mutated; model/decoded outputs are deeply frozen. Encoded buffers are fresh
mutable byte copies. Timestamps are UTC, whole-second RFC 3339 values.
All current and historical timestamp slots must also round-trip exactly through
the supported finite ECMAScript representation. Unsupported leap seconds reject
rather than normalize, including nested offers and Unknown snapshot documents.

Digests have separate `SecApp-Synthetic-Recovery-v2-*` domains for anchors,
heads, records, state, offers, terminal outcomes, projections and documents.
Offer/record/anchor/head digests are not signatures or protected trust anchors.

## Authority and operations

Each admission binds its new counter-derived transaction separately from its
original target, exact anchor and complete journal digest, published head,
candidate and obsolete-candidate presence/content, reconstructed state (including
full active lineage), conservative minima, selection, operation, capacity,
helper/policy identities, session/peer/approver/challenge, confirmation version
and expiry. The decision must be ApprovedSynthetic for that exact offer digest.
Historical records retain this binding. Changing observed state, policy, peer,
capacity or candidate invalidates the old offer; no operation substitution.
New default offers expire five minutes after simulated_at. Preparation and
admission both reject now >= expires_at, with no automatic renewal. A candidate
epoch must meet both the persisted floor and the current selected epoch.
Historical expiry is checked for supported representation, not re-expired at the
time of inspection. A valid old history cannot authorize a new admission.

`TrustedSynthetic`, `Held`, `Quiescent`, `ApprovedSynthetic` and
`DurableHypothesis` are independent test hypotheses, **not independently measured
host facts**. Authenticating their native equivalents remains MMR-001..004.
The synthetic persistence family does not replace the full installer/maintenance
protocol's operation-specific Install/Update/Uninstall capability review.

| Operation | Logical record path | Required free records |
|---|---|---:|
| Maintenance / RecoverPublication | Admission, Block, Commit, Complete | 6 |
| FinishCommittedCleanup | Admission, Complete | 4 |
| RetireAdmittedCandidate | Admission, Retire | 4 |
| CompactTerminalState / ReconcileCheckpoint | Admission, AuthorizeCheckpoint | 2 |

The extra two records for the first four operations are a nominal future
metadata-maintenance reserve. Admission uses the conservative 1 MiB journal
formula `current_bytes + required_records * 16385 <= 1048576`, checked safe
sequence/counter arithmetic, separate 8 KiB object caps, 16 KiB records and a
16-admission active lineage cap. The schema retains 64 records and 128 events.
No budget depends on optimistic exact future record sizes. Metadata operations
do not increment the generation or floor or change the selection, including null.

Retirement applies only to a complete ordinary Admitted lineage with no possible
publication and a still-valid exact prior selection. A later Admitted recovery
does not hide an earlier publication. Repeated retirement admissions retain the
original transaction and all attempts; the old counter never becomes reusable.
Retire marks CandidateRetired, not Installed/Uninstalled, and touches no payload.

Each record has six distinct observations: WriteRecord, Flush(Record),
ReadBack(Record), WriteHead, Flush(Head), ReadBack(Head). Complete writes do not
establish durability. Known NotWritten does not consume the attempted admission;
uncertain writes raise conservative minima and block. Incomplete record/head
prefixes serialize as Unknown, not a restartable Known snapshot.
Each fully verified replay prefix contributes conservative minima immediately;
a subsequent corrupt record cannot erase them. The corrupt chain is preserved
and blocked, not trimmed or repaired for serialization.

An admission reply is allowed only after its matching head is checked. A terminal
reply is allowed only after the appropriate terminal path. A lost reply suspends
effects until an exact current-transaction status query; status cannot re-admit.
Fresh status for the queried unresolved publication lineage remains RecoveryRequired;
unrelated retained terminal/retired transactions keep their own status. Global
recovery uncertainty and the lost-current-reply fence are not cleared by those
unrelated queries. Incomplete I/O/checkpoints still override all transaction
statuses. Busy or unknown
coordination/quiescence never terminates runtime holders or forces cleanup.

## Checkpoint control states

Classification checks the complete reconstructed terminal state against every
candidate field and against either exact old-chain head or exact compact head.
Minima must agree, not merely be lower bounds that can be silently discarded.
Terminal anchors require generation == generation_floor. Publication gaps are
represented only by a retained active journal, never an unexplained stable anchor.
Their non-null terminal operation/outcome pair must also match a legal transition:
ordinary/publication/cleanup operations complete, retirement yields CandidateRetired,
and checkpoint operations yield MetadataAuthorized. Consistency is not authenticity.

- Stable: consistent normal state or an already retired checkpoint.
- Active: coherent unresolved lineage; publication still requires recovery.
- CheckpointPending: terminal metadata authorization recorded, but no candidate.
- PreparedUnpublished: exact candidate with the old-chain head.
- PublishedUnretired: exact candidate with its compact head and old chain retained.
- ConflictOrUnknown: uncertain, conflicting, corrupt, missing or active checkpoint
  evidence; no selected-state promotion or automatic repair.

Eligible incomplete checkpoint reconciliation uses a fresh offer/counter and
appends Admission and AuthorizeCheckpoint to the retained old journal. The offer
freezes both original representations. It then writes/flushes/re-reads a **new**
counter-bound candidate, writes/flushes/re-reads its head, and only then observes
RetireJournal completion. The previous candidate becomes an explicitly retained
obsolete checkpoint. Until retirement completes, original records and anchor are
retained. A terminal authorization alone is not a completion reply.

An interrupted control prefix can deliberately remain blocked rather than
fabricate a resumable state. An already retained obsolete checkpoint forbids
another reconciliation admission; the bounded format never silently drops one
representation to make room for another. At 63/64 records, or after exhausted
retry capacity, fresh metadata admission is denied. There is no rotate-first,
emergency journal, anchor reset, implicit replay or availability guarantee.

This is a logical multi-representation fault model, not a choice of physical
atomicity primitive. Torn native writes, filesystem identity, real flush behavior,
crash quiescence and a protected coordinator require separate evidence. The
obsolete-candidate field does not prescribe a new native sidecar or second journal.

## Snapshot codec v2

The frame uses eight ASCII bytes `SA_MSC02`, a big-endian uint32 payload length,
32 raw SHA-256 bytes covering the first 12 bytes plus payload, then canonical
UTF-8 JSON at offset 44. Maximum payload is 4 MiB; JSON depth is at most 20.
The checksum is corruption detection, not authenticity. v1 (`SA_MSC01`) and v2
readers reject each other's frames; there is no downgrade or migration.

Document/component digests, chain sequence/links and declared minima are checked.
Known snapshots without a candidate must pass semantic reconstruction. Incomplete
candidate/control representations and Unknown retain their blocked state; decoding
does not grant confirmation, durability, quiescence or session authority. A caller
cannot use a decoded Known label to authorize effects. Noncanonical spelling,
duplicates, trailing bytes, invalid length/checksum, shared/resizable backing and
caller byte-view hooks reject. No raw machine data or frame files are stored.

## Evidence and remaining work

RP-006 and RP-023 exercise every retirement/reconciliation write, flush, readback,
head and retirement interruption plus crash prefixes; snapshots round-trip without
losing origin/minima. RP-009/010 check exact numeric budgets; RP-012 also exercises
a real synthetic 58-record terminal journal through ordinary completion at 62 and
separately confirmed compaction at 64. RP-028 proves old-reader rejection. RP-030
checks bounded hostile objects, canonical framing and immutability. The fixed
required-ID gate rejects omissions, duplicates and unexecuted cases.

Self-review added restart-status and incomplete-head serialization regressions.
This is not independent review, exhaustive fuzzing, physical durability proof or
closure of any MMR/TL blocker. Next: independent review of the v2 protocol/codec
and their composition with maintenance consent and deployment semantics, followed
by decisions on the remaining native trust boundary before native implementation.

The user separately permitted read-only Velociraptor execution, while forbidding
creation/deletion/change of system settings. That permission does not close trust
gates or authorize installation, services, registry/ACL/PATH changes, UAC, network,
remediation or arbitrary collectors. This stage does not invoke Velociraptor,
compile native code, run native probes, change Windows, commit or push.

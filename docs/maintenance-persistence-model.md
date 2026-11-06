# MAINTENANCE-PERSISTENCE-MODEL1

Status: implemented development-only, deterministic in-memory fault model.
This is not a filesystem writer, durable database, native helper, IPC endpoint,
installer or production persistence algorithm. It does not close MMR-001..006,
the nine launch blockers, or any native IT/PI/MP case. Independent acceptance
of the composed trust boundary remains pending.

```text
PersistenceModel = SyntheticReferenceOnly
ProtectedStore = NotImplemented
NativeImplementation = Blocked
AutomaticRecovery = Disabled
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
```

## Contract and boundaries

New immutable development identifiers under
`https://schemas.secapp.dev/v1/development/` are
`maintenance-persistence-scenario.schema.json` and
`maintenance-persistence-projection.schema.json`, both Draft 2020-12/version
1.0.0. Existing protocol, deployment and core audit schemas are unchanged.
No Administrative ConsentReceipt is accepted as maintenance authority.

`tools/lib/maintenance-persistence-model.mjs` exports
`simulateMaintenancePersistence(scenario)`, `persistenceStateDigest(storage)`
and frozen `MAINTENANCE_PERSISTENCE_LIMITS`. The digest helper is for synthetic
fixtures, not signing or authenticating a store. The separate reference validator
uses the existing pinned offline strict Ajv2020 and the established guarded
plain-data copier. Static schema imports are code assets; model evaluation reads
no host files, clocks, registry, identities, processes, locks or network state.
No dependencies or lockfile changes are introduced.

All input/output is PublicSynthetic/SyntheticModelOnly, with fixed synthetic
machine IDs and transaction IDs. Real journal, peer, machine or consent metadata
must not be relabeled with those classifications. There is no command, path,
file handle, executable content or source-byte intake in this model.

The input contains a synthetic storage image, externally supplied minimum
counter/generation/floor observations, one optional intent, a coordinator
hypothesis and an ordered event list. Selected component sets are represented
by opaque digests and security epochs, not production component tuples.
Maintenance versus Recovery is disjoint, but normal Install/Update/Enroll/Repair
scope checking remains the separate protocol/deployment model's responsibility.
This persistence model does not accept their projections as authorization and
does not implement a bridge between them.

## Journal and state binding

The storage image contains a compact anchor, bounded record chain, published
head, integrity classification and optional incomplete checkpoint candidate.
Each record binds its exact sequence, previous digest, transaction and kind.
Reserve also binds the complete synthetic intent. Anchor, record and head
digests each exclude only their own digest field; all other fields remain in
the hash. Arrays retain order. The implementation uses the existing JCS/SHA-256
helpers, not a new canonicalization or cryptographic algorithm.

A Reserve intent binds the reconstructed private state digest, synthetic machine
through that state, next counter-derived transaction ID, selection digest/epoch,
maintenance/recovery scope and confirmation classification. The synthetic intent
and confirmation digests have separate explicit domain strings. Declined,
Unknown, stale, replayed or mismatched confirmation cannot reserve. These are
binding checks on supplied facts, not proof of a user's presence or approval.
An attacker who can replace all facts and recompute all digests is not defeated
by this simulator.

| Record | Required modeled transition |
|---|---|
| Reserve | Fresh exact intent and next counter; authority consumption precedes later effects |
| Block | Current session admitted, quiescence declared, maximum generation/floor intent established; published selection hidden |
| Commit | Block record and matching blocked head fully verified; select exactly the admitted candidate at its fresh generation |
| Complete | Known committed state; retain latest terminal transaction summary and clear active recovery lineage |

Every record transition follows six distinct events:
WriteRecord, Flush(Journal), ReadBack(Journal), WriteHead, Flush(Head),
ReadBack(Head). Another record cannot bypass the corresponding head update.
Admission and Result acknowledgments are separate events after the required
state becomes consistent. Metadata equality or a successful read alone cannot
skip a flush hypothesis or convert a stale public head into a current one.

## Outcome semantics and crash safety claims

The event vocabulary deliberately distinguishes knowledge from API success:

| Declared observation | Interpretation in this model |
|---|---|
| Write Complete | A complete volatile write is hypothesized, not durability |
| Write NotWritten | Explicit knowledge that this attempt wrote nothing; not equivalent to a failed native call |
| Write Torn/Unknown | Possible effects; preserve conservative watermarks and require recovery |
| Flush DurableHypothesis | An explicit persistence assumption for this target, not a tested FlushFileBuffers result |
| Flush Failed/Unknown | Persistence is uncertain; do not relabel it NotWritten |
| ReadBack Matches | Separate re-read assumption, accepted only after the appropriate flush |
| ReadBack Mismatch/Unknown | Integrity/visibility is unresolved, even if flush was previously declared durable |

Watermarks are monotonically raised before a potentially effective write, but
not for a known NotWritten attempt. The generation watermark means the highest
**possibly published** generation, which may exceed the currently selected
generation. The security floor never drops when selection becomes uninstalled.
Querying status or compacting details cannot make an old counter reusable.

An input prefix with unverified pending I/O produces an Unknown storage image;
it cannot be treated as a Known restart snapshot. A crash terminates processing
of that scenario, including any supplied later mutation events. Uncertain I/O,
stale head, ambiguous checkpoint or pending publication yields RecoveryRequired
with no known selection. A consistent committed state survives as CleanupPending.
An idle/completed crash does not undo its already-known state.

Restart validates the whole retained chain and exact reconstructed head. It
rejects missing/corrupt/inconsistent state, invalid sequence/links, epoch
contradictions and regression below the supplied minimum observations. There
is no last-good-prefix fallback, counter-zero initialization or directory scan.
Minimum observations are themselves supplied synthetic assumptions: replacing
both the disk image and every external minimum with older values is outside
the model's ability to detect. No protection against administrator/offline disk
rollback, cloned machines or restored system images is claimed.

`selection_known` distinguishes an explicit uninstalled null selection from
an unknown selection. Schema constraints reject Completed/Stable claims with
unknown storage or pending I/O; full relational validation still requires
recomputing the model, not only passing JSON Schema or rewriting a digest.
All outputs disable filesystem writes, native APIs, IPC, installation, backend
execution, UAC, network, reboot, user-data deletion and automatic recovery.

## Lost replies and fresh recovery

A Lost admission/result acknowledgment records the loss and permits only a
status query or crash until the exact current transaction is queried. A query
for an older retired transaction does not clear current uncertainty. Status can
be Active, Completed, Retired or RecoveryRequired; none is execution authority.
Another reservation within the same scenario is rejected. A fresh scenario
must use the advanced protected-state hypothesis and a newly bound intent.
When a fresh session queries retained publication-pending lineage before its
own recovery admission, status is RecoveryRequired rather than Active. Within
an already-admitted session, Active is only progress and exposes no pending
selection. This distinction is pinned by the subsequent composition review.

Recovery over known pending publication retains the original transaction,
original candidate, previous selection and complete bounded attempt lineage.
FinalizeCandidate and RestorePermittedPrevious publish a generation strictly
above the highest possibly published one. Restore cannot cross the maximum
reserved security floor. A previously uninstalled or candidate-null selection
remains exact, not a wildcard. FinishCommittedCleanup consumes a new counter
without republishing. Interrupted recovery before its own Block can be retried
only through another freshly bound Recovery intent while retaining the original
pending publication and all intervening admissions.

The model intentionally does not retire an ordinary pre-publication Admitted
candidate, recover an Unknown/torn journal, or reconcile an incomplete checkpoint.
Those cases stay blocked; no implicit reset, deletion or reuse is invented.
Physical evidence reconstruction and the missing retirement authority remain
open design obligations, not functionality hidden behind a success label.

## Compaction and bounds

Compaction is allowed only for a consistent terminal state with no active
lineage, within the same freshly admitted transaction session. A read-only
status/restart session cannot compact old metadata without a separate reviewed
authority path; none is implemented here. It models WriteCheckpoint,
Flush(Checkpoint), ReadBack(Checkpoint),
WriteHead, Flush(Head), ReadBack(Head), then RetireJournal. The old records remain
until retirement completes. Any interrupted candidate on restart blocks instead
of guessing which anchor won. RetireJournal Complete is a declared known logical
retirement outcome; its physical deletion/durability implementation is absent.

The new anchor retains sequence, counter, generation, security floor, synthetic
machine binding, known selected digest/epoch and latest terminal transaction ID.
Older compacted result detail becomes Retired, never a request to re-execute.
An intent bound to the old anchor/chain is stale after compaction. This is a
single bounded abstract journal; it does not implement the proposed physical
one-active/one-terminal journal layout, MSI storage or version/payload retention.

Limits are 128 events, 64 retained records, 16 active-lineage admissions,
16 KiB canonical record size, 1 MiB canonical record-array size, 8 KiB head or
anchor, and 4 MiB scenario/projection data. Shape/count limits may reject before
byte caps are reachable. The shared guard additionally bounds data depth to 12,
nodes to 200000, strings to 4096 UTF-8 bytes and plain-object key counts to 32.
Most strings have much tighter schema bounds. Safe-integer overflow rejects
before advancing any sequence, counter or generation. No caller limit overrides
or silent trimming are accepted.

## Test gate and remaining work

Run `npm run test:maintenance-persistence`, also included in `npm test`.
MPS-001..040 are an exact required set, followed by a completeness check. Tests
validate each semantic negative against the full strict Draft 2020-12 scenario
schema before evaluation. Positive scenarios and targeted output-shape negatives
exercise both new schemas. Every normal I/O and compaction prefix has crash
coverage; hostile direct API objects are rejected without executing their code.
The original MPC protocol cases and all other existing gates are retained.
See [coverage](../tests/maintenance/README.md).

These cases do not simulate real sectors, actual torn bytes, OS caches, storage
firmware, atomic rename, power loss, cross-process locks or surviving jobs.
Coordinator Held and Quiescent are explicit assumptions; they do not resolve
the crash-to-quiescence gap from [the mechanism review](maintenance-mechanism-review.md).
There is no concrete record framing/decoder, trust signature, native filesystem
support matrix, protected state bootstrap, MSI transaction reconciliation or
recovery executor. No dependency installation or network request is needed by
this gate.

The subsequent [composition review](maintenance-composition-review.md) compares
the two abstractions and records remaining authority-binding obligations. It
does not create an adapter or weaken persistence uncertainty. The subsequent
[store codec](maintenance-store-codec.md) adds a development-only complete
snapshot format with in-memory bytes, not per-record append framing, a host
writer or recovery executor. It preserves Unknown/checkpoint hypotheses and
conservative minima, and rejects inconsistent Known snapshots without repair.
Native helper/storage implementation and host experiments remain blocked on
independent trust-boundary review and separate explicit authorization.

The subsequent [recovery policy](maintenance-recovery-policy.md) defines proposed
retirement, reserved-capacity and checkpoint-reconciliation rules for a new
versioned model. They are not retrofitted into this v1 model: its per-append cap,
missing ordinary-Admitted retirement and incomplete-checkpoint denial remain
unchanged. New operations/authority records require new immutable contracts.

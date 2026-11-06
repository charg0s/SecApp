# MAINTENANCE-COMPOSITION-REVIEW1

Status: author self-review and executable synthetic correspondence checks.
This is not independent acceptance, a formal refinement proof, a production
protocol/storage bridge, or permission for native implementation. The two
reference models remain separate. All MMR-001..006, nine launch blockers and
native IT/PI/MP acceptance cases retain their previous open/Planned/NotRun status.

```text
CompositionReview = SyntheticCorrespondenceOnly
IndependentAcceptance = Pending
ProtectedStore = NotImplemented
NativeImplementation = Blocked
AutomaticRecovery = Disabled
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
```

## Review boundary

The review compares the [protocol model](maintenance-protocol-contract.md) with
the [persistence fault model](maintenance-persistence-model.md). Both consume
declared synthetic facts, not authenticated peers, consent or durable host state.
The comparison checks a bounded set of shared semantic boundaries rather than
equating every event, status name, digest or serialized representation.

The only implementation changes are two reference-model fail-closed corrections
below and a test-only paired-scenario gate. No existing schema is changed; no
new schema, dependency, runtime adapter, file writer, native source, installer,
IPC endpoint or consent receipt is introduced. The test uses the existing strict
offline Draft 2020-12 validators before each semantic evaluation and validates
the output. Its private fixture helpers are not exported or used by application
code. No synthetic projection becomes another model's authority.

## Correspondence at stable boundaries

Each persistence record below abbreviates all six required observations:
WriteRecord, Flush(Journal), ReadBack(Journal), WriteHead, Flush(Head),
ReadBack(Head). A partial prefix is not the corresponding completed protocol
transition, even if some hashes already match.

| Protocol hypothesis | Persistence hypothesis | Shared invariant |
|---|---|---|
| Reserve Durable | Verified Reserve record/head | Consume exactly the next counter; retain original recovery lineage |
| Reserve NotWritten | Reserve write known NotWritten | No counter consumption; no admission acknowledgment |
| Reserve Unknown | Possibly effective Torn/Unknown reserve | Preserve possible consumption; no known selected store |
| BeginPublish | Verified Block record/head | Require declared quiescence, reserve the next generation and maximum floor, hide selection |
| Commit Consistent | Verified Commit record/head | Select exactly the admitted target at the reserved generation |
| Cleanup Complete | Verified Complete record/head | Retain terminal transaction, retire active lineage, preserve generation/floor |
| AdmissionRecorded / Result | Corresponding Acknowledge | Reply does not create admission or repeat effects |
| Fresh recovery proposal/confirmation | Fresh recovery intent/confirmation | New counter; newer publication generation except cleanup-only |

Protocol `security_floor` is the maximum of the selected store floor and any
journal-reserved floor. Persistence advances that same maximum in its replayed
state at Block. Its `watermarks.generation` is the highest possibly published
generation, not necessarily the currently selected generation. Null selection
means known uninstalled only when selection is known; it is never a wildcard.

For test comparison only, a full synthetic component tuple is mapped to an
opaque digest using `SecApp-Test-Composition-Tuple-v1`; null remains null. The
epoch is compared separately. This is not a production identity format. Known
protocol restart snapshots are explicitly fabricated fixture hypotheses at
stable boundaries. A null protocol projection is never decoded into a real
store or treated as permission to recover.

## Reproduced discrepancies and corrections

### MCC-F001: local progress after a lost reply

Before correction, Lost AdmissionRecorded blocked subsequent UI mutation, but
local VerifyPayload/BeginPublish/Commit/Cleanup could still reach Completed
without an exact current QueryStatus. A no-payload trace reproduced this with
`reason: None`. The persistence model already suspended further mutations.

The protocol now permits only QueryStatus or a local Interrupt after either
lost reply. This includes helper progress/repeated replies and local work, not
only UI commands. An older retired query cannot clear the current loss. An
exact current query permits the already-admitted remainder without another
counter; interruption still stops the flow safely. MCC-005 and MCC-007 failed
on the old implementation; MCC-006 verifies the allowed continuation.

This is conservative simulated scheduling, not a real transport loss detector
or a proposal to trust a client-supplied acknowledgment as authority.

### MCC-F002: pending-publication status after restart

Before correction, persistence QueryStatus returned Active for a retained
publication-pending lineage in a fresh status-only session. The protocol
returned RecoveryRequired. Neither exposed a known selection, but the status
disagreement could encourage an unsafe future resume policy.

Persistence now returns RecoveryRequired for that lineage until the new session
has its own fresh admitted recovery. Within an already-admitted session, Active
remains a progress status with unknown selection, never launch authority.
Queries about unrelated retired transactions retain their own classification.
MCC-009 failed on the old implementation; MCC-010 covers same-session Active.

## Intentional differences and unresolved integration obligations

- The persistence model has opaque target digests and cannot validate Install,
  Update, EnrollBackend, Repair or Uninstall component scope. MCC-018 deliberately
  supplies a protocol-invalid Update whose independent persistence hypothesis
  completes. This must never be treated as composite acceptance. A future
  reviewed integration must validate both scopes and bind the exact intent;
  no such bridge is implemented.
- Protocol offer/confirmation and persistence intent/confirmation use different
  complete inputs and digest domains. They must not be substituted for each
  other. MCC-019 rejects cross-model digest substitutions. Hash agreement is
  not a signature, trusted peer, protected state or proof of user presence.
- A protocol pre-publication crash can retain the old selected store as Aborted;
  the persistence crash model conservatively hides selection as RecoveryRequired
  with an unresolved admitted record. MCC-015 pins this difference. The stricter
  uncertainty wins in any future composition; an abstract protocol success may
  not override uncertain I/O, head or checkpoint state.
- Protocol Cleanup Failed and persistence Complete NotWritten/Unknown are not
  interchangeable. The former is a high-level cleanup outcome; the latter
  describes knowledge of a specific metadata write. Physical cleanup ordering,
  payload retention and deletion authority remain unimplemented.
- Compaction has no protocol wire operation. MCC-016 checks that it preserves
  counters, selection and current/retired status while changing the internal
  storage digest. It is allowed only within the persistence model's same
  freshly admitted completed session, not an arbitrary status session.
- Protocol completion and persistence Rejected/Stopped can coexist with a known
  completed store after a later invalid event or crash. Inspect reason, storage
  certainty, pending I/O and retained lineage; a status label alone is not a
  composite verdict. No combined success/Ready output is added.

The shared unresolved boundaries are unchanged: ordinary Admitted-candidate
retirement, Unknown/torn-store reconstruction, interrupted checkpoint recovery,
full-journal capacity recovery, whole-machine rollback, physical durability,
helper bootstrap, confirmation integrity and crash-to-quiescence. These are
not bypassed by successful synthetic correspondence checks.

## Gate and next step

Run `npm run test:maintenance-composition`, also included in `npm test`.
MCC-001..024 is an exact immutable required-ID set, followed by a completeness
check; registration, successful execution and zero skips are required. It covers
all five ordinary operations, stable boundaries, partial-I/O acknowledgment
denial, lost replies, restart status, all three recovery targets, below-floor
denial, null targets, interrupted attempts, crash conservatism, compaction,
confirmation/scope separation, lineage bounds, arithmetic and immutable output.
These are not native MP, PI or IT acceptance runs and do not exhaustively
enumerate all event interleavings or prove a formal refinement relation.

The next bounded development step is MAINTENANCE-STORE-CODEC1: a development-only
serialized-store format and strict in-memory byte encoder/decoder contract with
synthetic malformed-input tests. It must preserve this review's uncertainty and
non-authority boundaries and introduce no file writer or recovery executor.
It is not implemented by this review; the subsequent
[store codec stage](maintenance-store-codec.md) supplies the separate
whole-snapshot format without physical persistence or authority promotion.
Native work, system changes, UAC,
installation and backend execution remain subject to separate explicit
authorization and independent prerequisite review.

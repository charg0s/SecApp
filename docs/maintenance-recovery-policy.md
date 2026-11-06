# MAINTENANCE-RECOVERY-POLICY1

Status: policy originated as documentation-only MAINTENANCE-RECOVERY-POLICY1.
The subsequent [MAINTENANCE-RECOVERY-MODEL2](maintenance-recovery-model-v2.md)
implements these rules in a separate synthetic v2 family. The requirements below
remain the policy; v1 schemas, models, codec and tests are unchanged. There is
no native recovery executor or authorization for host changes. Independent
review remains pending. The acceptance table now records synthetic execution.

```text
RecoveryPolicy = ImplementedInSyntheticV2Model
RecoveryExecutor = NotImplemented
AutomaticRecovery = Disabled
ProtectedStore = NotImplemented
NativeImplementation = Blocked
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
```

## 1. Decisions and compatibility boundary

This policy addresses three gaps recorded by the
[persistence model](maintenance-persistence-model.md),
[composition review](maintenance-composition-review.md) and
[snapshot codec](maintenance-store-codec.md):

| Gap | Selected rule for further modeling | Current v1 behavior |
|---|---|---|
| Ordinary Admitted candidate never reached publication | A separately confirmed metadata-only retirement, preserving the old valid selection and all consumed authority | No retirement operation; stays unresolved |
| Journal can fill before another fresh recovery admission | Reserve completion and metadata-maintenance capacity before admission; refuse when unavailable | Checks each append against the cap; does not reserve this future budget |
| Checkpoint interrupted across candidate/head/retirement boundaries | Classify exact old/new state agreement, then require fresh explicit reconciliation; never infer durability from hashes | Candidate checkpoint blocks restart; codec preserves it without recovery |

Logical operation names introduced here are RetireAdmittedCandidate,
CompactTerminalState and ReconcileCheckpoint. They are design vocabulary, not
accepted v1 message types, command-line switches, record kinds or consent enums.
Repair, Cancel, QueryStatus, FinishCommittedCleanup and collection consent cannot
stand in for them. No old schema ID or document may be edited to add these
operations. A new major-family development contract must define the complete
authority/state/record changes before a pure implementation is accepted, following
[the compatibility policy](schema-compatibility.md). No migration is implemented
or inferred from a successful v1 decode.

## 2. Shared authority and invariants

All three operations require an explicitly requested maintenance session and
a new helper-derived offer and local confirmation for exactly one operation.
No timer, crash handler, status query, UI acknowledgment, UAC result, snapshot
checksum or previously consumed approval grants this authority.

The offer must bind the current supported format/policy/helper identities,
machine/deployment binding, full current anchor/journal/head digests, candidate
checkpoint presence and digest (including exact absence), original transaction
and complete retained recovery lineage, current and conservative minimum
counters/generations/floors, selected tuple or explicit null, exact operation,
metadata-only effects, capacity budget, confirmation text/version and expiry.
Bind the new counter-derived transaction separately from its original target.
The existing peer/challenge/approver bindings remain required; requester and
approver may differ. No caller-generated verified flag authenticates these facts.

Before consuming authority, the future helper must revalidate that exact offer
under the protected writer coordinator. Head, candidate, lineage, policy, trust
or capacity change invalidates it. Decline, expiry or Busy causes no admission.
Known NotWritten ends that attempt without consumption; an uncertain reservation
conservatively preserves possible consumption and blocks, not retries the offer.
Any fresh attempt needs fresh confirmation against the newly established state.

Required invariants:

- Counters never decrease or become reusable. An old transaction remains spent
  even when its candidate was never selected or its detailed result was compacted.
- Metadata-only operations never change the selected tuple, deployment generation,
  highest possibly published generation or security floor. They do not turn an
  unknown selection into a known one. Publication recovery remains a different
  operation with its existing strictly greater generation requirement.
- Preserve complete unresolved lineage until a verified terminal record/head
  supersedes it. A retired outcome is not Installed, Uninstalled, rollback or a
  successful collection result. Compacted status is Retired, never NotFound/free.
- Metadata authority does not delete payloads, version directories, user data,
  audit results or executable files; it does not install, execute or remediate.
  Physical payload retention/reclamation remains the separate MMR-005 problem.
- Counter, sequence, byte, record and lineage arithmetic is checked before
  allocation or admission. Exhaustion rejects; no wrap, trimming or emergency
  reset. The 16-attempt active-lineage cap is not reset by changing operation.
- Hold the required protected coordination identities through the operation.
  Runtime gate/quiescence requirements cannot be weakened because the change is
  metadata-only; a gate handle alone still does not establish crash quiescence.

These are future native requirements, not facts established by the synthetic
labels Known, Held, ApprovedSynthetic or DurableHypothesis.

## 3. Retiring an ordinary pre-publication candidate

Eligibility requires a complete independently trusted and internally consistent
ordinary maintenance lineage that is still Admitted and has never recorded or
possibly performed Block/BeginPublish, publication, MSI effects or selected-image
replacement. The prior selection must still be independently valid and exactly
match the journal's previous selection, including null for an interrupted first
Install. Incomplete/torn evidence of whether publication began is not eligible.

Do not decide eligibility from only the latest state label: a recovery admission
over an older PublishPending operation is still publication-pending. A Committed
operation instead needs its existing committed-cleanup path. Below-floor,
revoked/untrusted, conflicting or unknown prior state remains blocked. A null
previous selection is not permission to manufacture a first-install identity.

Proposed logical sequence for the new pure model:

1. Validate the exact retirement offer and capacity; reserve a new counter in a
   dedicated metadata-maintenance admission record bound to the original lineage.
2. Establish that admission and its corresponding head before reporting admission.
   Preserve the original candidate/lineage while the retirement is in flight.
3. Append a terminal retirement record that identifies the unpublished candidate
   and original spent admission, explicitly states that no publication was
   performed, and preserves selection/generation/floor. Verify its matching head.
4. Report the new transaction's terminal retirement result. Only then may bounded
   terminal-detail retention replace active lineage; staged bytes are untouched.

These two logical records are not encodable by v1. Their concrete new schema,
digest domains, durable boundaries and crash states must be implemented and tested
in the next pure-model stage. A failed terminal write keeps both consumptions and
the unresolved original lineage. A crash cannot resume either old approval.
Repeated retirement recovery, when eligible, appends another fresh attempt;
it cannot replace the origin or erase the earlier retirement admission.

## 4. Capacity before consumption

Keep the existing abstract limits: 64 retained records, 1 MiB canonical journal
array, 16 KiB canonical record, 8 KiB head/anchor, and 16 active-lineage admissions.
Do not enlarge them as a response to exhaustion. The physical one-active/one-
terminal layout and actual disk-space reservation remain unimplemented.

The next pure model must reserve a whole logical completion budget before any
new admission. Ordinary maintenance/publication recovery needs four records;
cleanup-only recovery and proposed retirement need two. In addition, preserve
two records for one separately confirmed metadata-compaction operation after
successful completion. This is a finite nominal-path budget, not a guarantee
of recovery through arbitrary repeated failures.

These record costs are a design candidate, not a proved crash-consistent record
protocol. The next model must demonstrate that every required binding and state
transition fits; if more records are needed, revise this policy and all boundary
cases before acceptance. Do not merge durability steps or omit recovery evidence
to preserve the proposed counts.

| Proposed admission | Completion records | Additional protected reserve | Required free records | Greatest existing record count |
|---|---:|---:|---:|---:|
| Ordinary maintenance / publication recovery | 4 | 2 | 6 | 58 |
| Cleanup-only recovery / RetireAdmittedCandidate | 2 | 2 | 4 | 60 |
| CompactTerminalState / ReconcileCheckpoint | 2 | 0 | 2 | 62 |

For a journal whose current canonical array size is J bytes, a conservative
budget of B records also requires `J + B * (16384 + 1) <= 1048576`, using checked
safe-integer arithmetic. The extra byte per record accounts conservatively for
array separators, including one harmless excess byte for an initially empty
array. Known exact encodings may not silently reduce this reservation in the
first model. Head/checkpoint objects must separately fit their own caps. If a
new record format cannot satisfy these bounds, reject the design rather than
admit and hope to compact later. Serialization metadata, signatures and framing
outside this abstract array need their own physical budget; these limits are not
a disk-space proof.

The protected reserve is not available to ordinary intake, progress or retry
records. Recheck count, bytes, safe sequence range, counter, lineage and trust
under the coordinator immediately before admission. Any potentially effective
write charges its possible effects until an independently justified state proves
otherwise. Log output and payload storage cannot borrow the journal reserve.

At a consistent terminal state, insufficient space for another ordinary operation
may produce a **proposal** for CompactTerminalState. It must not compact as a side
effect of planning, status or the rejected ordinary request. A fresh session
needs a fresh metadata-only confirmation and counter; the current v1 exception
for compaction within its same admitted completed session is not transferable.
The proposed two records are metadata admission and terminal authorization for
the exact checkpoint plan. That terminal authorization is not a claim that
checkpoint publication/retirement already succeeded. A Result is withheld until
the corresponding checkpoint/head/retirement sequence is verified.

A full legacy/v1 journal with 63 or 64 records cannot fit this fresh two-record
operation. Keep it blocked with its known counters and retained data. Do not
rotate first and record authority later, discard a tail, reset an anchor, claim
a status request authorized compaction, or create an unbounded emergency journal.
No out-of-band full-store repair mechanism is selected here. If interruption
uses the last reserved capacity, further attempts can likewise be blocked.
Safety takes precedence over an unproven availability guarantee.

## 5. Interrupted checkpoint classification

Classification is a read-only evidence step, not a write permission or proof of
durability. Let A be the retained old anchor, R its complete retained record
chain, H the observed published head, and C the candidate compact anchor.
Independently validate the old chain/intent semantics and reconstruct its terminal
state S without assuming H or C is truthful. The new model needs a dedicated
pure reconstruction primitive; deleting checkpoint_candidate and pretending an
arbitrary supplied snapshot is Known is not an accepted implementation shortcut.

S must have no unresolved active lineage. Derive the exact old-chain head
H_old(S), the expected compact anchor C_expected(S), and its head H_new(C).
The candidate must equal C_expected in **every** field: machine, sequence,
counter, generation, floor, selection digest/epoch, latest terminal transaction
and digest. Independent minimum observations must agree; no component may lower
them. Mere agreement of the selected tuple is insufficient.

| Complete evidence relationship | Classification for the future model | Permitted next direction |
|---|---|---|
| C absent; exact old state/head consistent | No incomplete checkpoint | Normal policy, not inferred recovery |
| C exactly C_expected; H exactly H_old | PreparedUnpublished | Offer a fresh restart of metadata compaction |
| C exactly C_expected; H exactly H_new; complete old chain still retained | PublishedUnretired | Offer fresh metadata-only reconciliation; no generation rollback |
| Old journal already known retired and current anchor/head fully consistent | No incomplete checkpoint | Read current terminal status; never rerun the previous operation |
| Candidate differs, H is neither exact form, old chain missing/corrupt/active, minimum conflicts, or evidence is uncertain | ConflictOrUnknown | RecoveryRequired; no selected-state promotion or automatic repair |

Presence of C or H_new does not prove their flush/re-read succeeded. The snapshot
codec deliberately does not retain those observations or session authority.
Authenticity, object identity and durability prerequisites remain separate gates.
If old journal retirement is only possible/unknown rather than established,
the absence of files is not the fourth row; it belongs to ConflictOrUnknown.

For either eligible incomplete classification, proposed reconciliation requires
fresh confirmation bound to A, all of R, H, C, S, minima and the exact class.
Reserve the new counter durably before changing either checkpoint or retiring
anything. Use a new checkpoint derived from the newly consumed metadata
transaction; the old candidate cannot carry a counter that it never recorded.
Retain the old representations until the new checkpoint and matching head are
verified and their exact old-journal retirement is known complete. Selection,
generation and floor stay unchanged; admission counter and sequence advance.

The next format must explicitly represent the fresh reconciliation admission,
its frozen old-state binding and an obsolete-but-retained checkpoint. It must
define the order of new control records, head publication and new checkpoint so
there is no phase interpreted as both unused authority and completed repair.
This multi-representation crash protocol is **not** implemented or claimed proven
by this prose. No sidecar/control file, second journal, ACL recipe or physical
atomicity primitive is silently adopted. Unknown admission, lost evidence,
insufficient reserve, repeated interruption or another writer stops the operation.

## 6. Denial and user-visible outcomes

Use fixed, bounded status explanations rather than exposing paths or raw journal
data. A fresh-model design should distinguish confirmation needed, changed-state
offer invalidation, capacity exhausted, unresolved publication, checkpoint
conflict, and unknown durability. These are proposed explanations, not new v1
enum values. Status alone must never enable a button that executes a helper or
backend without its separately approved workflow.

Decline preserves the existing state; failed or uncertain recovery reports
RecoveryRequired and retains the strongest minimum observations. An explicitly
completed retirement says the unpublished candidate was retired logically and
staged bytes were retained, not that files were securely deleted. A completed
metadata compaction reports retained counter/floor and superseded metadata only.
Known committed deployment is not undone because later metadata cleanup failed.

## 7. Required acceptance plan for the next model

RP-001..030 originated as Planned/NotRun requirements. They now execute in the
separate v2 suite, with status **PassedSynthetic**, plus exact-ID completeness.
The 31 new Node tests use full strict schema validation, schema-valid semantic
negatives and zero skips. This is not native acceptance evidence; the existing
312 Node tests retain their original scope.

| ID | Required case | Status |
|---|---|---|
| RP-001 | Retire ordinary Admitted candidate with fresh authority; preserve prior tuple/generation/floor | PassedSynthetic |
| RP-002 | Retire failed first Install while preserving exact null prior selection and consumed counters | PassedSynthetic |
| RP-003 | Deny retirement after any possible Block/publication/MSI effect, including a later Admitted recovery | PassedSynthetic |
| RP-004 | Deny foreign origin/lineage/selection and below-floor or untrusted previous state | PassedSynthetic |
| RP-005 | Declined, stale, expired, wrong-operation and previously consumed confirmation cannot retire | PassedSynthetic |
| RP-006 | Every retirement admission/terminal record and head crash boundary preserves both consumptions and origin | PassedSynthetic |
| RP-007 | Known NotWritten versus uncertain admission remain distinct; no counter reuse after uncertainty | PassedSynthetic |
| RP-008 | Repeated retirement attempt needs fresh binding and cannot exceed retained lineage cap | PassedSynthetic |
| RP-009 | Record budgets accept 58/60/62 boundaries and reject their respective next counts | PassedSynthetic |
| RP-010 | Byte budget exact boundary/overflow, separate head caps and sequence/counter overflow reject before admission | PassedSynthetic |
| RP-011 | Capacity changes between preview and admission invalidate the offer under serialization | PassedSynthetic |
| RP-012 | Ordinary work cannot consume the reserved metadata-maintenance capacity | PassedSynthetic |
| RP-013 | Terminal compaction is separately confirmed in a new session; QueryStatus does not authorize it | PassedSynthetic |
| RP-014 | Legacy 63/64-record full state and exhausted retry reserve block without trimming/reset/emergency journal | PassedSynthetic |
| RP-015 | Metadata compaction preserves spent admissions, floor, selection and latest/retired status | PassedSynthetic |
| RP-016 | Exact prepared-unpublished checkpoint classified without effects or readiness | PassedSynthetic |
| RP-017 | Exact published-unretired checkpoint classified without selecting a conflicting old representation | PassedSynthetic |
| RP-018 | Already retired consistent checkpoint returns current status without replaying old effects | PassedSynthetic |
| RP-019 | Candidate machine/sequence/counter/generation/floor/selection/terminal-ID substitution rejects | PassedSynthetic |
| RP-020 | Neither-head-match, missing/truncated chain, active lineage and unknown retirement block | PassedSynthetic |
| RP-021 | Correct checksums and decodable Known labels alone cannot supply durability or confirmation authority | PassedSynthetic |
| RP-022 | Reconciliation binds both representations and uses a newly counter-bound checkpoint | PassedSynthetic |
| RP-023 | Every reconciliation write/flush/re-read/head/retirement interruption retains sufficient original evidence or blocks | PassedSynthetic |
| RP-024 | No old bytes/records retired before new head/checkpoint and exact retirement completion are verified | PassedSynthetic |
| RP-025 | Lost reply permits status, not repeated admission or replay of metadata effects | PassedSynthetic |
| RP-026 | Cancellation, Busy and uncertain quiescence cannot force cleanup or terminate runtime holders | PassedSynthetic |
| RP-027 | Concurrent offers serialize; changed head/candidate/format/policy invalidates the losing offer | PassedSynthetic |
| RP-028 | v1 readers reject new operations/formats; no silent schema edit, migration, downgrade or defaulting | PassedSynthetic |
| RP-029 | All results retain disabled host effects; metadata scope cannot delete data, install or execute | PassedSynthetic |
| RP-030 | Bounded immutable synthetic inputs, deterministic digests and complete exact-ID gate | PassedSynthetic |

Existing executable regressions remain useful but prove narrower current fences:
MCC-023 denies implicit retirement; MPS-032 denies status-only compaction;
MPS-036 enforces existing hard count/lineage caps; MPS-031/034 and MSC-004/029
retain interrupted checkpoints and block restart. Their success must not be
relabeled as implementation or passing evidence for the RP plan above.

## 8. Next bounded implementation and remaining gates

MAINTENANCE-RECOVERY-MODEL2 now supplies the separate pure development contract,
model, codec and synthetic tests for these operations and recovery-control states.
Old schemas and suites remain byte-identical. Authority/state/digest and codec
changes are versioned together with different identifiers/magic and explicit
old-reader rejection. No migration, host adapter or automatic execution is added.
Next is independent review of the v2 recovery/codec and composed trust boundary.

This policy narrows the design scope of MMR-006 and supplies additional MMR-004
requirements; neither blocker is closed. Physical admission durability, torn
evidence reconstruction, runtime quiescence, helper/confirmation trust and
payload/MSI retention remain independently reviewable prerequisites. The native
IT/PI/MP plans and all nine launch blockers are unchanged. Native implementation,
installation/UAC and real recovery still require separate authorization and
independent prerequisite acceptance. Read-only Velociraptor execution now has
user permission, but its technical prerequisites remain unsatisfied; changes to
system settings remain forbidden.

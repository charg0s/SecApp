# MAINTENANCE-MECHANISM-REVIEW1

Current precedence: [D-058 / TRUSTED-HOST-MVP1](trusted-host-mvp.md) maps each MMR
area to retained first-release obligations and deferred absent workflows/stronger
assurance. This remains the historical generic-maintenance review, not an accepted
narrow installer. Define and review a distinct initial-install/uninstall contract;
do not weaken published schemas/models or reinterpret their records as authority.

Date: 2026-09-29. Scope: author self-review of the synthetic maintenance contract,
one bounded model correction, and Windows mechanism selection **for further
design**. This is not an independent security acceptance or native experiment.
Microsoft Learn was the only network research source; no software was acquired.

```text
MechanismSelection = CandidateForDesign
IndependentSecurityReview = Pending
NativeImplementation = Blocked
MaintenanceHelper = NotImplemented
HostInstallAuthorization = NotGranted
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
```

## 1. Contract review and correction

Reviewed the message/scenario/projection schemas, reference validator/model,
synthetic cases, and maintenance/installation/image-trust design documents.
The model distinguishes UI requests from helper-local hypotheses; no model
output grants execution authority. Schema validation and JCS digests do not
authenticate peers, confirmation, source bytes or persisted state.

Found an availability defect in `recoveryScope`: both publication-recovery
targets required a non-null tuple. Consequently, a correctly bound interrupted
Uninstall could not finalize its null candidate, and an interrupted first
Install could not restore its null previous selection. A schema-valid synthetic
reproduction returned ScopeRejected before consuming authority.

The corrected rule permits null only when it exactly matches the journal field
chosen by the fixed recovery target and the member list is empty. It retains
fresh offer/confirmation/admission, head and journal binding, a strictly newer
generation for publication, and the maximum security floor. Null is an explicit
uninstalled state, not a wildcard, missing evidence or permission to delete
user data. FinishCommittedCleanup already supported null; regression coverage
now checks that it does not republish. All output effects remain false.

MPC-049..053 add positive cases and targeted denials for payload injection,
tuple/null substitution, declined/old confirmation, transaction replay, a
below-floor reinstall and interruption. Original MPC-001..048 are retained.
The exact 53-case set plus completeness test passes; no schema, dependency,
native source, trust-launch expected result or historical evidence is changed.

Clarification: a QueryStatus on the same still-live, already-admitted session
can resolve a lost acknowledgment and allow its remaining intake. It does not
reserve another counter or resume a disconnected/crashed session. A new session
needs the documented fresh recovery flow. Pre-publish Admitted-journal retirement
remains unimplemented; the null-selection fix does not invent that operation.

## 2. Helper startup, transport and confirmation

Retain the short-lived, protected installed helper as the design candidate.
An explicit maintenance request may eventually use ShellExecuteExW with the
runas verb and require a retained, unambiguous process handle. Microsoft documents
both administrative launch and cases where SEE_MASK_NOCLOSEPROCESS does not
yield a handle. Missing binding must reject, not switch to a PID-only match.
[Shell execution contract](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow).

SecApp requirements, not demonstrated API guarantees: fixed executable identity,
fixed routing arguments, protected working directory and startup dependencies,
no shell command/URL/PATH lookup or environment expansion, no portable helper
extraction and no automatic download. First installation still requires its
separate reviewed signed bootstrap/MSI flow. This maintenance route is neither
the Standard backend launch mechanism nor Elevated collection consent.

Retain one helper-owned local named-pipe instance, explicit descriptor,
FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_REJECT_REMOTE_CLIENTS and bounded overlapped
I/O. Microsoft documents these controls; pipe buffer sizes are advisory, so they
cannot substitute for application frame/byte/count caps. PIPE_NOWAIT is not the
selected asynchronous-I/O mechanism.
[CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew).

Exact descriptors, process/logon/session binding, identification-only inspection,
reversion failure handling and source intake remain as specified in the
[protocol proposal](maintenance-protocol-design.md). No SDDL or runnable native
configuration is supplied by this review. Same-user process interference remains
in scope; public rendezvous values are not secrets or authorization.

Confirmation remains helper-local, using fixed resources and an independently
derived offer. Windows returns from its default secure-desktop elevation prompt
to the user desktop. Therefore a later helper dialog is not automatically a
secure-desktop confirmation of SecApp's operation.
[UAC behavior](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works).
**Open blocker:** demonstrate the required interaction integrity under the
same-user attacker model. No custom credential UI, host-policy change, automatic
approval, or weaker threat model is selected to bypass it.

## 3. Coordination candidate: separate ownership from liveness

Prefer two distinct installer-provisioned, stable protected files for further
design, not public named mutexes or PID files. They are logical object classes;
this document creates none and specifies no caller-chosen paths.

| Object | Candidate use | What it does not prove |
|---|---|---|
| Private writer coordinator | Maintenance-only OPEN_EXISTING read/write handle with share mode zero, retained through the transaction | Durable consumption, valid journal or runtime quiescence |
| Published runtime gate | Standard supervisor opens read-only with FILE_SHARE_READ; maintenance needs an incompatible exclusive read/write open before publication/removal | Same-user process isolation, absence of surviving descendants after supervisor crash |
| Private journal and compact published state | Separate bounded data records; never the replaceable identity of either coordination file | Atomicity across all files or MSI |

CreateFile sharing compatibility applies for the lifetime of open handles.
This motivates the candidate, but does not authenticate the opened object.
[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
Require independently validated protected ancestors and file identity, no
reparse/alias substitution, no delete sharing, and no runtime creation or
replacement. Do not rotate a coordination file when publishing a new selector.
Absent or unsafe objects require recovery; never CREATE_ALWAYS/OPEN_ALWAYS as
an implicit repair. All writers must follow one lock order: writer coordinator,
then runtime gate, then publication. Standard takes only the runtime gate and
validates the selected generation while holding it.

Use bounded acquisition and Busy/defer, not killing holders or weakening sharing.
Multiple readers may delay maintenance; an ordinary hostile reader may cause
denial of service, not obtain privileged write authority. This candidate favors
safety over availability and does not promise starvation-free maintenance.
Setup/uninstall must preserve the identity and disclosed anti-rollback metadata
needed to recognize a prior installation; MSI authoring for this is unresolved.

Microsoft warns that an attacker can pre-create a named mutex. LockFileEx also
does not block mapped-view access, and inherited handles do not simply transfer
its locked-region access. Accordingly neither a public mutex name nor a byte
lock is selected as an authentication or executable-byte protection boundary.
[CreateMutexW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw),
[LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex).

### Unresolved crash-to-quiescence boundary

A surviving supervisor must retain its generation gate until its owned tree is
reaped. A crashed supervisor may lose its gate handle before another process
has established that all descendants are gone. Kill-on-job-close describes Job
termination behavior; it does not document an atomic ordering with release of
an unrelated file handle. This is a SecApp composition gap, not a claim that
Windows Job termination failed.
[Job object lifetime](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

Do not infer Quiescent from a now-openable gate, a missing PID, a fixed delay or
the earlier synthetic Job results. Simply making the gate inheritable is not an
accepted fix: complete tree coverage, early handle closure and duplication would
need proof. Runtime lease retention across crash and same-user interference
remains a native-design blocker. No service, broker or separate account is
silently added; any requirement for one needs a separate product decision.

## 4. Protected storage candidate and failure ordering

Select a bounded append-record private journal plus compact protected published
head for the next **pure fault model**. Each record should bind version, bounded
length, sequence, previous-record digest, transaction/counter, generation/floor,
phase and exact intent. A checksum detects damage, not authenticity. Ownership
and independently trusted policy remain essential. No real key or storage
backend is introduced, and no anti-rollback claim covers a malicious admin,
offline disk rollback or whole-machine restore.

Model write completion, flush, read-back, head publication and reply separately.
FlushFileBuffers operates on its specified handle; its pipe behavior is not
journal durability. A successful read-back may still read cached state.
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
The candidate must specify supported local filesystem/storage assumptions and
native fault evidence before any of these observations becomes Durable.

Required ordering to evaluate, not an implemented persistence algorithm:

1. Under writer serialization, authenticate current state and compare the
   exact confirmed head. Reserve one next counter in the private journal.
2. Establish its durability and corresponding compact head before acknowledging
   admission or beginning intake. Any partial/uncertain outcome blocks; it is
   not NotWritten merely because an API reported failure or the reply was lost.
3. Before publication, hold the runtime gate with independently proven
   quiescence. Persist a runtime-visible blocked state and the maximum floor/
   generation intent before changing the selected tuple. The exact cross-file
   ordering and recognition of this barrier are unresolved model obligations.
4. Publish only a complete consistent tuple/head. Unknown/torn/conflicting
   records require recovery; no last-good-prefix fallback may lower a possibly
   consumed counter, published generation or reserved floor.
5. Retire journal details only after the retained head is durable and no active
   recovery references them. Preserve the original unresolved lineage, one
   active/one terminal journal within the proposed 1 MiB each and 8 KiB head cap.
   Quota exhaustion blocks; never truncate ambiguity to fit the cap.

ReplaceFileW is not a cross-file transaction. Its write-through flag is
unsupported, failures have distinct possible file states, and preservation of
attributes/streams requires review. Never set ignore-ACL/merge-error flags to
force a publish, or claim atomic durable head/journal/MSI commitment from a
successful replacement alone.
[ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
Do not adopt TxF as a shortcut; Microsoft recommends alternatives instead of a
new dependency on it.
[TxF alternatives](https://learn.microsoft.com/en-us/windows/win32/fileio/deprecation-of-txf).

No registry-based replay store, DPAPI-only authority, extra database dependency,
volume flush or host-side storage experiment is selected. A file-based candidate
is not yet a production-safe implementation; if its obligations cannot be met,
reopen the design rather than weakening the persistence claim.

## 5. Remaining blockers and next bounded work

| ID | Required evidence before native acceptance |
|---|---|
| MMR-001 | Trusted bootstrap/helper image, dependencies and process/peer binding; original launch gates remain open |
| MMR-002 | Exact operation-confirmation integrity, including another administrator's credentials and same-user interference |
| MMR-003 | Stable coordination identities and a generation lease that cannot report quiescence while an owned tree survives a crash |
| MMR-004 | Counter/floor/head/journal write ordering, torn-write recovery, compaction and filesystem/storage durability matrix |
| MMR-005 | Signed packaging/MSI ownership, retained version/payload bounds and cross-domain recovery, including uninstall tombstones |
| MMR-006 | Explicit scope for retiring an Admitted pre-publish candidate; no currently implemented abandonment path |

All six are Open. They organize existing unresolved obligations; they do not
replace or close any of the nine TL, 16 IT, 22 PI or 28 MP native cases. This
author review does not satisfy independent ARCH-REVIEW6 or composed-boundary
acceptance. Actual native implementation remains blocked.

Next safe implementation slice: MAINTENANCE-PERSISTENCE-MODEL1, a separate
development-only model of ordered write/flush/head/reply/crash observations.
Use synthetic records and exact positive/negative cases for counter/floor
regression, stale public state, ambiguous tail, lost reply, compaction and
interrupted recovery. No file writer, native IPC, UAC, installation or backend
invocation; no conversion of hypotheses into host evidence. Approval for those
actions, and independent review of the remaining boundary, are still required.

The subsequent [MAINTENANCE-PERSISTENCE-MODEL1](maintenance-persistence-model.md)
implements that pure fault-model slice with two development schemas and an
exact 40-case synthetic gate. Its flush, coordinator and quiescence facts remain
hypotheses. Incomplete/torn state still blocks; this does not close MMR-004 or
any other native obligation above.

The subsequent [MAINTENANCE-RECOVERY-POLICY1](maintenance-recovery-policy.md)
narrows MMR-006's proposed retirement scope and adds MMR-004 capacity/checkpoint
requirements. It is documentation only, with 30 Planned/NotRun acceptance cases.
All six MMR blockers remain Open until versioned modeling, implementation where
authorized, and independent review supply the required evidence.

The subsequent [MAINTENANCE-RECOVERY-MODEL2](maintenance-recovery-model-v2.md)
implements that synthetic v2 model/codec and RP-001..030 gate, without changing v1.
It supplies additional logical MMR-004/MMR-006 evidence, not native closure.
All six blockers remain Open; independent composed-boundary review is still next.

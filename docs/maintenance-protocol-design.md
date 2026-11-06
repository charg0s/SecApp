# MAINTENANCE-PROTOCOL-DESIGN1

Current precedence: [D-058 / TRUSTED-HOST-MVP1](trusted-host-mvp.md) specifies a
narrow first-install/uninstall scope and trusted-host assumption. The stronger
generic-maintenance protocol below is retained research, not an implementation
requirement for absent MVP features. A separate narrow effects/authority contract
is required before initial-install implementation; no old schema/model/result
becomes relaxed runtime authority. Exact scope, UAC, trust and ownership remain.

Status: design proposal, researched 2026-09-29 against official Microsoft Learn
documentation. Not independently accepted, implemented, or tested natively.
This stage changes documents only; it does not add a helper, pipe, installer,
production schema, dependency, key, protected store, service or scheduled task.

The subsequent [MAINTENANCE-PROTOCOL-CONTRACT1](maintenance-protocol-contract.md)
implements development-only message/state schemas and a pure reference model.
It does not implement this native protocol or change the Planned/NotRun status
of the acceptance cases below.

```text
MaintenanceProtocolStatus = DesignOnly
MaintenanceHelper = NotImplemented
HostInstallAuthorization = NotGranted
AutomaticMaintenance = Disabled
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
```

Normal SecApp use remains Standard. Optional Elevated collection remains a
separate future read-only workflow with its own exact user consent; maintenance
cannot grant it. The existing [pure deployment model](deployment-plan-contract.md)
and immutable core ConsentReceipt/ActionLog schemas are unchanged.

## 1. Trust boundary and scope

The adversary includes an ordinary process in the requesting user's session,
malicious IPC input, source replacement, duplicate requests, process crashes and
stale state. Do not remove same-user interference from the threat model. A
compromised administrator/kernel or restored whole-machine image cannot be
defeated by a local JSON digest, DPAPI blob or ordinary filesystem journal.

The ordinary UI is an **untrusted requester**, not an authority issuer. Its
identity can restrict routing, but cannot prove its process is unmodified. The
maintenance helper independently resolves approved manifests and protected
state, enforces fixed operations and owns final operation confirmation. Import,
assessment and report parsers must never run in the elevated helper.

| Party | Owns | Cannot authorize |
|---|---|---|
| Standard UI | Preview, untrusted proposal, cancellation request, bounded source-byte delivery | Elevation, package trust, commit, replay reset or arbitrary writes |
| Windows elevation flow | Administrative process creation under host policy | SecApp operation/manifest scope or future collection |
| Short-lived maintenance helper | Independent validation, operation confirmation, private transaction record, fixed maintenance effects | Network, reboot, audit collection, user-data deletion or policy bypass |
| Protected state store | Deployment identity, counters, floor and durable transaction state | Authentication merely because supplied data claims to be a store record |

The signed x64 per-machine MSI remains a proposed packaging target. First
installation has no already-installed helper to trust: a separately reviewed,
explicitly launched signed bootstrap/MSI flow must establish that root and use
the same scope rules. The ordinary UI cannot extract a helper into a writable
directory and declare it trusted. Missing, corrupt or stale installed helper
means blocked/manual recovery, not an automatic download or portable fallback.

## 2. Proposed Windows transport, with explicit limitations

Use one short-lived, local, helper-owned named-pipe instance for one maintenance
transaction. This is the preferred candidate for review, not a validated native
implementation. No TCP listener, gRPC server, persistent service or UI-owned
privileged command server is introduced.

Microsoft documents first-instance creation and automatic rejection of remote
clients in CreateNamedPipeW. SecApp proposes FILE_FLAG_FIRST_PIPE_INSTANCE,
PIPE_REJECT_REMOTE_CLIENTS, one instance, non-inheritable handles and bounded
overlapped I/O. Name collision or uncertain ownership rejects the attempt; it
must not attach to the existing server or retry without the flags.
[CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew).

An explicit descriptor must restrict the client to the intended requester's
logon identity, with only required read/write rights. Do not use the default
pipe descriptor or a broad Users/Everyone ACE. Microsoft warns that generic
write includes the pipe-instance creation right; use reviewed individual rights
instead. Exact DACL, mandatory label, cross-account behavior and access masks
remain native-test gates, not an SDDL string supplied here.
[Named-pipe access control](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

Client connections propose SECURITY_SQOS_PRESENT with SECURITY_IDENTIFICATION,
not delegation. If the server temporarily impersonates solely to inspect client
identity, it must check success, read only bounded identity metadata, then check
RevertToSelf before any maintenance. No package/file/registry operation executes
while impersonating. Failed impersonation rejects; failed reversion terminates
the helper, leaving recovery state if an operation was already admitted.
[CreateFileW SQOS](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient),
[RevertToSelf](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself).

### Peer binding is not code authentication

GetNamedPipeClientProcessId and GetNamedPipeServerProcessId report endpoint PIDs.
The proposed protocol must bind them to live retained process handles and
OS-observed token/logon/session identities, not trust PID/SID fields in a frame.
A failed identity query, exited peer, reused PID, foreign session or changed
connection aborts pairing. A second connection cannot inherit the first one's
authorization. These APIs alone do not prove signer, mapped bytes, process
integrity, user presence or an authentic UI.
[Client PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid),
[server PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid).

An already-installed helper may eventually be launched through an explicit
ShellExecuteExW runas action against its protected, independently verified
identity, with a retained process handle. Microsoft documents that runas invokes
administrative launch and that SEE_MASK_NOCLOSEPROCESS does not guarantee a
handle in every invocation form. This design rejects missing/ambiguous process
binding; it does not fall back to shell associations, PATH search, URL handlers,
environment expansion or zone-check bypass.
[Shell execution contract](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfoa).

Bootstrap arguments may contain only a fixed mode, protocol version, bounded
public rendezvous identifier and requester PID hint. These are untrusted routing
hints, never a bearer secret, command, path or authorization. The helper derives
the proposed requester logon identity through OS observations and rechecks the
actual connecting peer. The UI compares the server against the helper process
it launched. Guessing/racing the rendezvous can cause denial, not approval.
Cross-elevation bootstrap, process-handle binding and startup image trust still
require implementation and independent testing; no mutual-authentication claim
is made until those gates pass.

Another process with the same token may still interfere with the UI, steal its
handles or submit its own proposal. Therefore even a correctly paired client
cannot send an authoritative Approve/Commit command. Trust in helper startup,
its protected code/loader context and its confirmation interaction is essential;
all existing image/launch blockers remain open.

## 3. Confirmation, including another administrator's credentials

The UI first previews the fixed operation and lets the user explicitly request
maintenance. UAC cancellation/failure ends that attempt without a prompt loop.
No bootstrap arguments contain credentials, and SecApp never draws a credential
entry form. Being already elevated does not waive scoped confirmation.

Windows normally presents its elevation prompt on the secure desktop and then
returns to the interactive desktop. **Design consequence:** a helper-owned
operation dialog after UAC is not thereby a Windows secure-desktop dialog or
proof against every UI-spoofing attack. User-presence/input integrity remains a
review gate. Do not silently weaken host UAC policy to make pairing work.
[Microsoft UAC behavior](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works).

Before any package intake or protected transaction mutation, the helper must:

1. Independently authenticate its policy, approved release manifest and current
   deployment head/floor. The UI cannot supply a trust key or a verified flag.
2. Derive an exact offer: operation; old and desired complete tuples; manifest,
   policy and payload digests/sizes; expected generation; allowed location
   classes; limits; preserved user data; cancellation and recovery consequences.
3. Display this offer itself using fixed local text/resources. Do not render
   caller HTML, executable markup, arbitrary paths, prompts or descriptions.
4. Obtain explicit confirmation in that helper-owned interaction, bind it to
   the offer digest and observed approver context, then recheck all mutable
   prerequisites under maintenance serialization before consuming authority.

The requester and maintenance administrator can be different accounts. Record
their distinct OS-observed identities privately; neither a claimed same SID nor
an inferred parent-process relationship substitutes for verification. Show the
requesting context to the approver. No audit storage is created in either
administrator profile, and no UI/backend is launched from the elevated context.
Unsupported cross-account/session binding fails closed without broadening ACLs.

An internal confirmation record is helper-created, not client-submitted. It
binds protocol/build/policy identity, machine/deployment identity, both peer
instances, channel challenges, transaction ID, exact operation/tuple/manifest
digest, generation, floor, limits, consent text/version, approver context and
expiry. A response may acknowledge its record digest but cannot export a reusable
authority token. No shared signing/HMAC secret is shipped to the ordinary UI.

## 4. Message and resource profile (proposal, not a shipped wire schema)

Use protocol version 1 only; unknown version/type/field rejects with no downgrade
negotiation. Control messages use strict UTF-8 JSON with no BOM, duplicate keys,
non-finite numbers or noncanonical dates. Positive integer counters use checked
safe-integer arithmetic; no coercion, ignored extra field or executable payload.
JCS/SHA-256 binds data, but is not a peer-authentication algorithm.

Common envelope: protocol version, message type, helper-issued channel ID,
request/transaction ID where applicable, per-direction sequence, payload and
payload digest. Hello has its own exact shape before a transaction is assigned.
The helper supplies a fresh 256-bit random challenge; ClientBind echoes it and
adds a fresh client challenge. Bind the full handshake transcript and observed
peers to the offer. Challenges and sequence numbers prevent mix-ups/replays only
after peer binding; they do not make an untrusted endpoint authentic.

| Message | Direction | Meaning and restriction |
|---|---|---|
| HelperHello / ClientBind | Helper to UI / UI to helper | Exact version, challenges and instance pairing; no effects |
| ProposeOperation | UI to helper | One fixed intent, component IDs, bounded candidate release descriptor and expected generation; no caller destination |
| VerifiedOffer | Helper to UI | Helper-derived preview; still no authority from the UI |
| AdmissionRecorded | Helper to UI | Private durable admission was recorded after local confirmation; not a reusable receipt |
| PayloadChunk | UI to helper | Only during admitted intake, exact declared member/offset/length; not a command |
| Cancel | UI to helper | Bound cancellation request, never a force-terminate or rollback command |
| Progress / Result | Helper to UI | Bounded status codes for this transaction; never backend readiness |
| QueryStatus | UI to helper | Read-only bounded status for an authorized transaction; cannot retry/resume it |

ConfirmOffer, Verify, BeginPublish, Commit and recovery selection are **local
helper decisions**, not callable wire messages. This is deliberately different
from synthetic deployment events. A normal UI cannot promote a projection to
an execution request. Status queries never auto-launch a helper or UAC; an
existing authenticated channel or an explicitly requested maintenance session
is required for private status. No enumeration of other users' transaction data.

Clarification from the reference-contract review: resolving a lost admission
reply on the same live session may permit its already-admitted remaining intake.
This is not resuming a disconnected/crashed session or reserving new authority.

Initial review bounds: 64 KiB per control frame, 128 control frames total in both
directions, nesting depth 8, strings at most 4096 UTF-8 bytes with smaller
field-specific limits, and 64-byte ASCII symbolic IDs. Use a bounded length/type
frame header and reject excess before allocation. Payload frames are separate,
at most 64 KiB of data each, with exactly 64 KiB except the final chunk of each
member. Require exact sequential offsets, at most 8200 payload frames, eight
manifest-owned members and 512 MiB combined intake, additionally bounded by
authenticated exact member sizes. Reject duplicates, surplus bytes, short EOF
and arithmetic overflow.
Do not concatenate payload into control JSON or accept arbitrary archives.

The UI reads explicitly selected sources with its ordinary rights; the helper
does not open a caller-supplied path/URL/device or duplicate a caller-selected
numeric file handle. Intake is opaque bytes copied to new private candidate
objects only after durable admission. All copied bytes and metadata are verified
independently before any installation step. Changed content rejects; a claimed
digest or initial UI verification never substitutes for destination verification.
The candidate release descriptor in ProposeOperation is untrusted metadata within
the control-frame cap, not the installation payload. Authenticate it against
existing protected policy before deriving the offer; it cannot add a trust key,
choose the verification algorithm or update that policy through its own claims.
Unknown or oversized release metadata rejects instead of triggering acquisition.
Existing staged artifacts may be reused only by exact helper-owned journal
identity and independent revalidation, never by path/cache hints. No network
acquisition, archive extraction or backend health-check execution is implied.

Proposed deadlines: 30 seconds for pairing/partial-frame completion, 300 seconds
for an offer to be confirmed and admission recorded, and 30 seconds without
payload progress, with 600 seconds maximum total intake. A partial-frame deadline
is absolute from its first byte, not restarted on each fragment. Use helper-owned
monotonic deadlines within the live session,
plus UTC timestamps for private records; clock uncertainty, restart or lost
session invalidates unconsumed approval. A long operation's phase limits come
from reviewed operation policy, not UI extensions. Expiry before admission denies;
after admission, cancellation/failure rules apply rather than renewing approval.
These bounds require compatibility/resource review before a production schema.

## 5. Durable single use, not a caller-supplied nonce list

All admitted writers share one protected maintenance coordinator. It must also
close runtime admission and observe actual generation leases before publication;
the ordinary UI cannot assert quiescence. Serialization must be anti-squatting,
cross-session and bound to a retained OS object/handle. Its native primitive is
not selected by this prose; Busy/uncertainty defers without killing applications.

Proposed protected control state contains a random installation/machine binding,
monotonic admission counter, deployment generation, security floor, minimum
accepted helper/policy identity and current transaction head. It survives
uninstall as disclosed security metadata. Missing/unreadable/conflicting state
must not become counter/floor zero or a fresh installation. First-install
initialization and post-uninstall recognition require separate bootstrap tests.

After confirmation, under the coordinator:

1. Re-read and compare the exact current head, generation, policy and floor with
   the approved offer. Any change invalidates the offer; no silent rebinding.
2. Reserve the next counter and append an Admission record binding the internal
   confirmation, transaction and complete intent. Counter overflow rejects.
3. Make the consumption/head record durably consistent and re-read it. Only then
   acknowledge AdmissionRecorded and permit candidate intake or package effects.
4. A consumed counter/confirmation is never made reusable after error, timeout,
   declined cleanup, disconnect or crash. Uncertain persistence blocks progress
   and requires explicit recovery; the UI never resubmits to "make sure".

This requires a storage operation with serialized compare-and-reserve, durable
commit and unambiguous recovery semantics. It is a required contract, **not an
implemented atomic primitive**. A JSON write, rename, mutex or successful API
return is not accepted as proof of all those properties. A native implementation
must specify torn-write detection and file/metadata persistence ordering on a
reviewed filesystem/storage matrix. Microsoft documents FlushFileBuffers for
the specified handle, including different semantics for pipes; flushing a pipe
is not persisting a deployment journal or a cross-file transaction.
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).

Replay checks use this protected head/counter plus exact transaction and offer
bindings. Duplicate mutation frames return a controlled replay/protocol failure,
not a second execution. After a lost reply, only QueryStatus is allowed. If a
historical result has been compacted, return ResultUnavailable/Retired without
replaying it. A new operation requires new confirmation and the current head.

Proposed control retention is bounded by one active and one most recent terminal
transaction journal (at most 1 MiB each, including confirmation metadata), plus
a compact head/tombstone at most 8 KiB. Retire older result details only after
the new head is durable and no recovery references them. Never drop an active
or ambiguous journal to fit the cap; quota exhaustion blocks maintenance.
Counter/floor tombstones outlive journal compaction and uninstall. This is not
permission to purge user data or an approved audit-data retention policy;
payload/version storage limits remain a separate unresolved packaging gate.

DPAPI machine scope is not administrator-only access: Microsoft states that
other users on that computer can decrypt a machine-scoped blob. The design
therefore cannot substitute DPAPI, a local hash or random machine ID for protected
ownership, replay state or anti-rollback storage. No key provisioning is selected
here, and no claim is made against administrator/offline disk rollback or clones.
[CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

## 6. Disconnects, cancellation and explicit recovery

Journal records bind full tuples, object ownership, generation, reserved floor,
admission counter and MSI/selector subtransaction states. Checksums can detect
damage but do not authenticate attacker-controlled records. Filesystem directory
names, process exit codes and UI acknowledgments never determine commitment.

| Durable boundary at interruption | Required behavior |
|---|---|
| No admission, no protected mutation | End session; unconsumed offer expires; no automatic UAC/retry |
| Admission known, before publish intent | Authority remains consumed; stop staging; abandon only identified candidates; old selection requires independent validity |
| Admission persistence uncertain | RecoveryRequired; no candidate execution or fresh-counter assumption |
| Publish intent/floor reservation or selector publication ambiguous | RecoveryRequired; no selected tuple asserted, no floor reduction |
| Complete commit, cleanup incomplete | Keep committed tuple/floor; report CleanupPending; no rollback or claimed deletion |
| Journal/selector inconsistency or trust unavailable after commit | RecoveryRequired, even if an earlier message reported success |

On disconnect the helper must not start another irreversible phase. If a
previously authorized native/MSI phase is already in flight, request supported
cancellation and contain it under reviewed limits; do not equate transport loss
with a successful abort. Preserve durable evidence and classify the resulting
state before exiting. Crash/timeout may leave RecoveryRequired. There is no
forced app shutdown, arbitrary kill, reboot or scheduled resumption fallback.

Recovery is a **new maintenance transaction**, not Repair or reuse of the old
approval. A future disjoint recovery request binds the original transaction,
observed journal/head digest, current floor, both tuples, ownership evidence and
exact recovery target. Proposed fixed targets are FinalizeCandidate,
RestorePermittedPrevious and FinishCommittedCleanup; no arbitrary path, script,
floor reset or emergency downgrade. Abort before publish is limited to identified
unpublished candidates, never recursive cleanup of a caller location.

The helper independently reconstructs evidence, presents the exact recovery
choice and obtains fresh local confirmation. It reserves a new counter, while
the old one remains consumed. The one active journal retains the unresolved
original transaction plus linked recovery-attempt records; a recovery attempt
has a new transaction ID and counter, not permission to overwrite its parent.
Only one recovery attempt can be active. The same journal byte cap applies;
failure to retain the complete lineage blocks recovery rather than discarding
ambiguous evidence. A previous tuple must still satisfy current
trust/revocation/compatibility policy and the maximum reserved/persisted floor;
if none qualifies, remain blocked. Restoring prior bytes must never restore an
old generation number: publish a fresh greater generation, rejecting overflow.
Journal and native evidence must establish the highest possibly published
generation; if that cannot be determined, recovery remains blocked rather than
guessing. Completed commit is not undone merely because cleanup failed.

MSI and selector/backend enrollment remain different transaction domains.
Recovery must reconcile both, not infer one from the other's success/rollback.
Recovery execution and these new request variants are not added to the current
deployment-model operation enum or any existing v1 schema in this stage.

The later [recovery policy](maintenance-recovery-policy.md) further narrows
pre-publication abandonment to a newly confirmed logical metadata retirement;
it does not authorize deletion of staged bytes or user data. It also specifies
future capacity reservation and checkpoint-reconciliation requirements. These
are new-version design requirements, not extra accepted v1 recovery targets or
permission to reinterpret Cancel, Repair or QueryStatus as maintenance authority.

## 7. Privacy and result handling

Real peer SIDs, logon identities, machine bindings and confirmation metadata are
private security metadata, not PublicSynthetic or a public export. Keep them
only in the bounded protected records under reviewed storage policy. Do not send
credentials, audit evidence, raw stdout/stderr, memory dumps or arbitrary error
text through this protocol or into logs/MSI properties. Return enumerated status,
transaction correlation, selected generation/floor when known and record digests;
never source paths, secrets or an installation/launch capability.

Progress and Result are correlated to the exact live channel/transaction and
checked by the UI. A forged/stale result cannot authorize a future operation;
the next helper always re-reads protected state. All launch gates are rechecked
by a future launcher independently. Enrollment/installation never invokes
Velociraptor for version/help, creates an audit receipt or starts an elevated UI.

## 8. Acceptance plan and remaining implementation blockers

Every MP case below is **Planned / NotRun**. These are requirements, not new pass
evidence. Pure DP tests cannot establish native peer identity, user presence,
storage durability or Windows elevation behavior.

| ID | Required positive and/or targeted denial |
|---|---|
| MP-001 | Exact local session pairs; remote/foreign-session client is rejected |
| MP-002 | Squatted name/second pipe instance cannot replace the helper or trigger relaxed retry |
| MP-003 | Pipe DACL denies instance creation, security changes and unintended principals |
| MP-004 | Client/server PID substitution, reuse, exit and missing handle abort pairing |
| MP-005 | Same-SID attacker/caller verified flag cannot issue authoritative approval/commit |
| MP-006 | Identification-only inspection succeeds; impersonation/reversion failures fail closed |
| MP-007 | Wrong/stale helper build, writable root or unknown mapped image is not accepted |
| MP-008 | UAC decline/failure/already-elevated parent never substitutes for scoped confirmation |
| MP-009 | Alternate-admin credentials preserve requester/approver separation without profile writes |
| MP-010 | Forged helper dialog/result and unsupported user-presence assumptions are not trusted |
| MP-011 | Foreign operation/tuple/manifest/policy/generation/floor/text/limits invalidates approval |
| MP-012 | Unknown versions/messages/fields, duplicate keys, malformed UTF-8 and lengths reject |
| MP-013 | Replayed/transposed challenges, sequences or transaction/channel IDs reject |
| MP-014 | Source swapping, surplus/truncated/out-of-order payload and numeric handles/paths reject |
| MP-015 | Every frame/count/byte/depth/deadline bound has valid-boundary and over-limit vectors |
| MP-016 | Expiry, clock uncertainty, restart and lost session cannot renew unused approval |
| MP-017 | Concurrent admissions reserve at most one current-head transition; loser gets no mutation |
| MP-018 | Crash/torn write at every admission persistence boundary cannot reuse authority |
| MP-019 | Lost admission/result reply permits status inquiry but no duplicate execution |
| MP-020 | Journal compaction/uninstall/reinstall preserve counter, floor and retired-request denial |
| MP-021 | Live generation lease or uncertain quiescence defers without termination |
| MP-022 | Cancel/disconnect/crash before, during and after publish yield the boundary-specific result |
| MP-023 | Recovery requires fresh exact confirmation; original approval and Repair cannot substitute |
| MP-024 | Revoked/below-floor rollback, unknown generation and recovery overflow remain blocked |
| MP-025 | MSI/selector divergence cannot be hidden by a successful process exit or rollback label |
| MP-026 | Cleanup failure retains committed tuple; loss of trust requires RecoveryRequired |
| MP-027 | Private metadata stays bounded; no raw evidence, secrets, public identity leakage or auto network |
| MP-028 | No path grants backend execution, elevated collection, reboot, user-data deletion or automatic maintenance |

Before a native prototype: independently review helper bootstrap/image trust,
same-user/process interference and confirmation interaction; select/test exact
pipe descriptors and cross-account binding; define the protected store and
admission/lease primitives with crash consistency; finalize payload/MSI bounds,
signing identities and supported Windows/filesystem matrix. Unknown remains a
blocker; a plausible API list is not proof that the boundary is implementable.

The subsequent bounded implementation slice MAINTENANCE-PROTOCOL-CONTRACT1 now
provides separate development-only message/state schemas and synthetic tests for exact message
direction/order, offer binding, consume-once persistence hypotheses, lost replies
and disjoint recovery requests. Keep it free of sockets/pipes, processes, storage
writers and UAC. Do not retrofit production authority into DP's synthetic
confirmation or start installer/native experiments implicitly.

The subsequent [mechanism review](maintenance-mechanism-review.md) narrows the
helper, coordination-file and journal candidates and records unresolved crash,
confirmation and durability obligations. It is author self-review, not
independent acceptance or a change to any native-case status.

# SERVICE-LAUNCH-BROKER-DESIGN1

Deferred from the MVP by [D-062 / DIRECT-STANDARD-MVP1](direct-standard-mvp.md).
The user selected a direct same-user Standard first release. This service design
and its unresolved gates remain historical research, not prerequisites for that
separate route and not permission to install a service.

Date: 2026-10-11. User-approved direction: continue designing the service-based
launcher, without installing anything or changing system settings. This is an
author design, not an independently accepted mechanism or an implementation.

Current MVP overlay: [D-058 / TRUSTED-HOST-MVP1](trusted-host-mvp.md) specifies
the broader trusted-host scope and current development/install permission envelope,
superseding the narrower D-056 note and blanket NotAuthorized statuses below.
Retain D-056's ordinary exact Standard intent protocol, never a UI readiness
override. D-058 explicitly maps LS/TL/MMR requirements: basic broker/worker rights,
peer/command binding, private/offline data handling and lifetime remain required;
pre-existing same-user-malware resistance is not claimed. The service is still
not implemented, installed or technically accepted. The body is the earlier design.

Current account proposal after D-061: a per-service virtual account, with
necessary targeted rights considered only for a future separately confirmed
installation. This supersedes the LocalService/no-grant candidate from
[BACKEND-TRUST-LAUNCH-SLICE1](backend-trust-launch-slice-review.md), not its open
technical findings. The [current rights table and installer boundaries](broker-bootstrap-contract.md#8-d-061-scoped-service-account-rights-proposal)
retain the four-privilege ceiling and separate service-logon eligibility.
The earlier no-grant language in the body is historical: runtime grants remain
forbidden, while an exact future installer-owned delta may now be proposed.
No installed-account change, native acceptance or ready token handoff is implied.
The Standard supervisor/worker, profile, lifetime and offline/effects gaps remain.

[BROKER-BOOTSTRAP-CONTRACT1](broker-bootstrap-contract.md) now specifies candidate
object masks, discovery versus logon-scoped IPC, pairing order and bounded
supervisor-only resources. It also identifies unresolved pre-exposure token-
server binding and SCM-created object ownership. Its section 9 adds a concrete
V4/local-RPC settings candidate, per-call checks and cancellation requirements,
while keeping exact-instance binding and creation-time evidence unresolved.
This is documentary refinement, not native implementation, deployment or
execution admission.

```text
LaunchArchitecture = SeparateIdentityScmBroker
ProductDecision = ApprovedForDesign
ServiceDesign = DraftForReview
ServiceImplementation = NotAuthorized
HostDeployment = NotAuthorized
NativeAcceptance = fail_with_blockers
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
VelociraptorInvocationFromSecApp = BlockedPendingTechnicalGates
```

D-052 resolves the product choice in
[mechanism selection](backend-launch-mechanism-selection.md). All nine TL gates
and the maintenance (MMR) blockers remain Open. No C#/PowerShell/Node runtime,
schema, dependency or historical experiment result changes in this stage.

## 1. Selected architecture and authority boundaries

Use one demand-start, noninteractive, own-process launch broker, bootstrapped
by SCM from protected installed code. No boot/logon scan, scheduled task,
updater, remote listener, automatic repair or restart-and-resume behavior.
Starting the service only establishes an idle control boundary; it never
authorizes collection. The existing import/report path remains usable when
the service is absent or launch is blocked.

| Component | Proposed responsibility | Forbidden authority |
|---|---|---|
| Standard UI | Propose a registered action, show progress, request cancellation | Assert trusted consent/readiness, choose executable/VQL/path/token, modify service configuration |
| SCM launch broker, separate identity | Validate installed generation and peer/action bindings; own admission and outer process-tree lifetime | Collect as its service account, install/update/repair, parse evidence or render reports |
| Per-run Standard supervisor, requester's session | Enforce fixed launch policy, create the constrained backend, bound/drain streams, reap the tree | Elevate, perform maintenance, accept arbitrary commands or transfer privileged handles to UI/backend |
| Unmodified Velociraptor worker | Execute one independently reviewed, fixed read-only operation under an accepted Standard token | Inherit service rights, expand profile/scope, access a broker network or filesystem proxy |
| Unprivileged parser/assessment/report | Validate bounded untrusted output and produce honest coverage/results | Turn exit zero, a digest or service status into trust/authorization |
| Separate maintenance helper | Explicitly approved installation/maintenance only | Authorize collection or share its privileged token with the launch path |

The supervisor is part of the trusted launch boundary, not a general plugin
host. Its Standard identity does not by itself protect it against other
same-user processes. Broker, supervisor, worker, threads, tokens and retained
handles all require a reviewed owner/effective-access matrix from creation.
The existing NB-005 result is a negative for default same-user descriptors,
not a test of this proposed architecture. File protection alone is insufficient.

## 2. Broker identity and privilege budget

Preferred account candidate for review: a per-service virtual account, with
explicit service identity and reviewed service-SID restrictions. Do not use
a shared service process or silently substitute LocalSystem/NetworkService.
The exact service name, descriptor and supported Windows matrix are not frozen.
Microsoft documents virtual-account configuration through CreateServiceW;
omitting the account selects LocalSystem, so SecApp must reject an omitted
account in a future installation plan. Own-process/demand-start are explicit
settings, not a claim of no persistent registration.
[Service creation contract](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew).

Virtual accounts avoid a manually maintained service password but can use
computer credentials on the network. They are not an offline sandbox.
No domain membership, password capture/storage or new network capability is
selected. A compatible OS-level offline boundary for broker and worker remains
required, with no broker proxy bypass.
[Service-account properties](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts).

| Capability to evaluate | Why it may be needed | Design constraint |
|---|---|---|
| SeImpersonatePrivilege | Obtain a requesting user's context through a separately authenticated token channel | High-trust capability; no generic impersonation endpoint, delegation or arbitrary I/O while impersonating |
| SeAssignPrimaryTokenPrivilege | Create a process with a different user's primary token | Do not apply the restricted-own-token exception to an arbitrary client's token |
| SeIncreaseQuotaPrivilege | CreateProcessAsUserW resource requirements | Account must already have the reviewed right; no runtime policy grant or retry with another account |
| SeChangeNotifyPrivilege | Windows compatibility residual in service privilege filtering | Account for it explicitly; an omitted name is not proof of absence |

These are a candidate maximum to justify, not proof that the virtual account
has them or that they are sufficient. Remove unnecessary privileges in the
reviewed service configuration and verify the effective token; fail on a missing
requirement or unexpected capability. Exclude SeTcb, SeDebug, backup/restore,
take-ownership and driver-loading privileges from this candidate. If an owner
or launch design needs them, revisit the architecture rather than adding them.
Service privilege filtering removes unneeded privileges; it does not justify
granting new ones, and shared-process services can combine requirements.
[Required service privileges](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow).

WTSQueryUserToken is not the default token source: its documented LocalSystem
and SeTcb requirement conflicts with this candidate. No enumeration of sessions
to pick an unrelated user's token, password logon, token supplied as a numeric
handle by the UI, or fallback to a service-owned worker token is allowed.
[WTSQueryUserToken requirements](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken).

## 3. User token, session and supervisor bootstrap

Preserve the authenticated requesting user's Standard identity and logon/session
binding. Do not relabel service HKCU/profile observations as user observations.
An elevated caller must return to a separately verified Standard flow; no token
downgrade guess, linked-token shortcut or automatic UAC is selected here.
The existing linked-token acceptance criterion is not weakened.

Keep two distinct purposes:

1. **Control channel:** local identification-only peer binding, fixed requests
   and cancellation/status. Reuse security requirements from the
   [maintenance protocol design](maintenance-protocol-design.md), not its wire
   messages, receipts or authority. No silent SQOS upgrade.
2. **Token acquisition candidate:** a separate, locally authenticated,
   one-request channel deliberately permitting SecurityImpersonation, never
   SecurityDelegation. Independently bind the trusted server and requesting
   process before exposing that capability; pipe name/SID/PID/nonce alone are
   insufficient. The exact handshake and anti-impersonation proof remain a
   blocker, not an approved API recipe.

Identification allows identity inspection, not execution in the client's
context. Windows documents client impersonation followed by duplication to a
primary token as a process-creation route. SecApp proposes investigating that
route only on the second channel; a type conversion is not proof of Standard
rights, linked-token compliance, genuine user intent or safe peer identity.
[Impersonation levels](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels),
[client process context](https://learn.microsoft.com/en-us/windows/win32/secauthz/processes-in-the-client-security-context),
[DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex).

For that candidate, isolate token acquisition on a dedicated bounded thread:
read only the bound exchange, inspect/duplicate the token with exact rights,
then revert before normal broker work. No callbacks, path access, parsing of
backend output or await/dispatch while impersonating. An impersonation failure
must reject, never continue under the broker identity. Revert failure stops
admission and terminates the broker under its fail-closed lifetime design.
Token handles are non-inheritable and never returned to the UI or backend.
[Named-pipe impersonation failure](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient),
[RevertToSelf failure](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself).

The creation candidate is CreateProcessAsUserW with the independently checked,
constrained primary token and explicit fixed application, arguments, environment,
working directory, object security and creation-time policies. The API requires
specific token rights and caller privileges; its own-token exception is narrow.
It places the process in the token's session and forbids cross-session handle
inheritance. Therefore the service must not copy the synthetic harness's three
inherited stream handles directly into a user-session child.
[Process-creation contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).

Proposed topology: service in Session 0 -> protected per-run supervisor in the
requester's existing session, created without inherited handles -> constrained
backend in that same session, with only the supervisor's exact stream handles.
Service/supervisor control uses bounded local IPC with retained process-instance
binding. No worker move to Session 0, TokenSessionId rewrite, interactive-service
UI, desktop ACL expansion, or automatic profile load to make launch succeed.
Inaccessible profile/session means blocked or honest missing coverage.

Creation-time protection must cover supervisor bootstrap before it processes
IPC, as well as the backend before workload. The outer Job belongs only to the
broker; its ownership must survive no hidden duplicate in the UI/supervisor/
worker. Assignment before resume, cross-session Job behavior, same-session
stream setup, safe desktop access and supervisor self-token access all require
native evidence. No child runs first and is secured afterward. No raw backend
data traverses a privileged evidence parser; opaque bounded transport, storage
ownership and encryption still need the private-storage review.

## 4. Bounded launch-control contract (design only)

The future broker resolves a protected operation registry itself. First
integration remains Version/Help, then separately reviewed constant synthetic
collection, then the useful read-only protection profile. This document adds
no collection ID, VQL, executable entrypoint or production schema.

| Request | Allowed purpose | Does not grant |
|---|---|---|
| GetCapabilities | Bounded installed-generation and supported-operation summary | Launch readiness or a list of private runs/users |
| ProposeAction | Registered operation/profile ID, exact action bindings and lowering-only limits | Authority to execute, arbitrary arguments or output destination |
| GetActionStatus | Status of the caller's bound action | Recovery, resume or a reusable authorization receipt |
| CancelAction | Stop only that admitted action and its owned tree | Global service stop, cancellation by guessed run ID, or deletion of reports |

Offers, progress and terminal status are server-generated. No wire-level
Approve, ExecuteArbitrary, SetReady, Resume, Install, Repair, Update, Export or
Elevate command. A proposal is not an approval. The exact action binds the
observed requesting identity/logon/session, host and deployment generation,
run/pass/action, operation/collector and approved digests, privilege mode,
data scope, limits, broker instance, fresh nonce and expiry. Foreign-domain
maintenance or Elevated receipts are rejected, even when structurally valid.

Use local-only first-instance named-pipe control as the transport candidate,
with explicit narrowly reviewed rights, rejection of remote clients, retained
peer-instance binding and bounded asynchronous I/O. All malformed, unknown,
duplicate-key, out-of-order, replayed or over-limit input rejects without an
effect. Name collision is failure, not a retry under an attacker-chosen name.
An arbitrary same-user process must not acquire a launch capability merely
because it can connect. The detailed Windows pipe constraints remain those in
the linked maintenance design; their native acceptance is still outstanding.

Initial review limits: one global active action, no queued collection; at most
four pending control connections with five-second handshake deadlines; 16 KiB
per control frame, 64 frames and 1 MiB total per action in both directions;
nesting depth eight, ASCII IDs up to 64 bytes, strings up to 1,024 UTF-8 bytes.
Use strict UTF-8 and checked arithmetic before allocation. Cap the aggregate
control allocation at 2 MiB, coalesce progress, reject excess with Busy and
never allocate unbounded rejection/log state. These are proposed limits, not
implemented constants or protection against every local denial of service.

Offers expire after 30 seconds on a monotonic clock; failed/expired confirmation
does not refresh itself. Diagnostic workload limits remain 10 seconds and
64 KiB each for stdout/stderr (lowering only), as in the current planner.
Collection limits require their own profile review; control limits never widen
them. Idle service exit target is 60 seconds only after confirmed quiescence.
The bounded cleanup target is five seconds; failure to establish quiescence
blocks further admission, not a claim that every Windows process can always
be reaped within five seconds.

**Exact human confirmation is still unresolved.** The ordinary UI, a valid pipe
client, a nonce, a signed executable name or service startup does not prove it.
A service is not a trusted interactive dialog. The authority-owning confirmation
component, protected display/input path and exact binding must be accepted
against same-user interference before launch. A normal-desktop modal dialog is
not silently treated as that boundary. The target of no per-check UAC for
Standard use is conditional on this gate; there is no automatic UAC workaround.

[LAUNCH-CONFIRMATION-DESIGN1](launch-confirmation-design.md) now specifies the
frozen offer, complete scope display, separate confirmation-component channel
and broker-internal consumed-once admission. Its private DecisionBound message
is not a public UI Approve command or bearer permit. The display/input mechanism
remains NotSelected and NativeApproval remains Disabled; the protocol alone
does not close the exact-human-confirmation gate.

## 5. Admission, termination and recovery

Required sequence: verified idle broker -> bound proposal -> independently
validated offer -> trusted exact confirmation -> atomic single-use admission
with deployment lease -> constrained suspended creation -> pre-resume checks ->
explicit resume -> bounded draining -> whole-tree reap -> unprivileged parsing.
No backend is created merely to show a consent dialog or capabilities.

Before admission, disconnect/decline/expiry invalidates the offer. After
admission, disconnect, logoff/session change, cancellation, timeout, malformed
control, output overflow or policy/identity failure triggers bounded stop of
the owned supervisor/backend tree. A second connection cannot take over a live
action by supplying its IDs. No detached background completion, automatic retry
or service-restart resume is in this first slice.

Broker death must close the sole outer kill-on-close Job ownership; supervisor
death must not leave a backend running. A stop request from SCM/maintenance
stops admission and drains or cancels owned work through the reviewed boundary,
never by trusting a UI assertion of completion. If cleanup cannot be proved,
retain recovery uncertainty and block launch/maintenance publication. Do not
clear durable run ownership just because a process ID disappeared or a pipe
closed. The existing native cleanup observations do not prove atomic admission,
cross-session behavior or maintenance quiescence.

A restarted service performs no collection and consumes no old consent. It
must reconcile outstanding run/lease state through the reviewed recovery
mechanism; Unknown stays blocked. Monotonic offer expiry is instance-local and
must not be restored as a valid deadline after restart. The admission/journal
boundary remains tied to the existing maintenance composition blockers, not
implemented by inventing another JSON ready flag. Status/logs contain redacted
codes and bounded bindings, never raw stdout/stderr, tokens, secrets or reports.

## 6. Installation delta and review exit

Future installation would need one fixed service registration and explicit
account/SID/privilege configuration, protected signed broker/supervisor/policy
files, reviewed object descriptors and bounded private coordination state.
That is a real system change, requiring a separately reviewed mutation manifest
and explicit installation approval. Ordinary users may at most receive reviewed
start/status access, not change-config, write-owner/DACL, delete or global stop
rights. The service cannot rewrite its binary, policy or registration. No
installer-driven backend health check or automatic audit is allowed.

The [installer design](protected-installation-design.md) is amended only by this
scoped design delta. Maintenance stays a separate short-lived authority. No
general service manager, automatic updater, firewall exception, trust-store
change, task, driver or device-wide loader policy is added. Future optional
Elevated read-only collection is preserved, but this Standard service protocol
cannot request it or reuse installation approval for it.

The next bounded design review must resolve LS-001/002/003 together: exact
account/effective privilege list; authenticated token handoff without credential
exposure; secure process/thread/token ownership; supervisor bootstrap/session
transport; and exact human-confirmation feasibility. If the constraints cannot
be met, reject this candidate or obtain an explicit revised product decision,
not a silent fallback. No more synthetic model suites are required merely to
record that these issues are open.

Required negative scenarios for that review include a spoofed service endpoint,
malicious same-user client, elevated/foreign-session token, impersonation/revert
failure, stolen/replayed offer, dangerous supervisor/worker access, accidental
cross-session inheritance, disconnect/crash at each admission boundary and
maintenance racing a live or uncertain run. They are **Planned / NotRun**.
This elaborates LS-001/002/003/007, not independent proof of their completion.

LS-004/005/006/008 remain separate prerequisites: source-to-mapped-image binding,
reparse/replacement protection, preventive initial/future module policy with no
Unknown, offline/private storage, useful coverage and independent native review.
Only after technical acceptance and appropriate execution authorization may
real backend Version/Help and the read-only end-to-end slice run. Nothing in
this design installs a service, changes Windows, starts Velociraptor or closes
the current fail_with_blockers gate.

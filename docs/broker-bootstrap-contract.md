# BROKER-BOOTSTRAP-CONTRACT1

Date: 2026-11-06. Concrete design follow-up to
[the trust/launch slice](backend-trust-launch-slice-review.md) under
[D-058](trusted-host-mvp.md). This specifies candidate object rights, IPC pairing
and a bounded **supervisor-only** bootstrap. It is not an executable policy,
installation manifest, accepted native implementation or backend entrypoint.

Current account overlay: [D-061](decision-log.md) permits targeted service-only
rights in the design of a future separately confirmed installation. Section 8
proposes a per-service virtual account; sections 1-7 retain the prior LocalService
research and its limitations. No transport or native mechanism is accepted by
this account-direction change, and the blocked admission statuses below remain.

```text
ContractReview = AcceptedDocumentaryBootstrapCandidateContractOnly
NativeImplementationAdmission = BlockedPendingConcreteGaps
TokenHandoffAdmission = BlockedPreExposureServerBinding
HostDeployment = NotPerformed
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
```

No service, pipe, Job, token or security descriptor was created/changed to prepare
this document. No helper/backend was compiled or executed. Existing schemas,
historical negative results, planner flags and source code remain unchanged.

## 1. Identities and ownership, not interchangeable names

Use these symbolic principals, derived from protected installation policy or
Windows observations, never from client JSON:

- `S`: the exact SecApp service SID; not LocalService or All Services.
- `U`: an explicitly permitted installation-requester user SID.
- `L`: the requesting token's logon SID; not its user SID or session number.
- `I`: retained process handle plus creation identity, observed user/logon/session
  and protected image/generation. A PID in a frame is not an `I`.

Candidate initial installation policy permits one explicitly displayed requester
`U`, including when a different administrator performs installation. It does not
auto-enroll whoever connects first or all local users. This is a proposed field
of the future confirmed installation manifest, not approval to enroll an account
now. Missing/mismatched policy blocks discovery. A later multi-user product needs
separate policy review; no runtime AddUser endpoint belongs to the broker.

LocalService remains the account candidate. For this proposal select
SERVICE_SID_TYPE_UNRESTRICTED to include `S`; the name does not grant arbitrary
service rights. Do not silently select RESTRICTED as a stronger equivalent: it
changes restricting SIDs and token-object grants.
[SERVICE_SID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).
The four previously justified privileges remain the maximum; no SeDebug, SeTcb,
SeRestore or service-account change is added.

For new broker-owned ephemeral objects, propose owner `S`, a protected explicit
DACL, no broad LocalService/Everyone/Users/Authenticated Users/All Services grant,
and no inherited ACEs/handles. Validate that `S` is an enabled owner-capable token
group before using it. Explicit OWNER RIGHTS read-control-only ACEs must suppress
implicit owner WRITE_DAC where shared/user ownership would otherwise bypass the
matrix. OWNER RIGHTS does not revoke direct grants, privileged bypass or existing
handles. [Owner Rights](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).
Do not add a blanket deny ACE for LocalService: it would also match the broker.

The SCM-created broker process, threads and primary token already exist before
its entrypoint. Their initial descriptors and any self-hardening/bootstrap window
remain a separate gap: changing a DACL afterward is not creation-time isolation
and cannot revoke a handle already opened. No listener, user token acquisition,
consent admission or child creation may precede accepted bootstrap checks.
This proposal does not claim isolation from every other LocalService process.

## 2. Candidate access matrix

Rights below are requested capabilities, not a claim that every API will permit
them. SYSTEM remains a trusted OS principal. Installation-owned files/SCM entries
retain their separate manifest/ownership review; this is not a global ACL rewrite.

| Object / holder | Candidate access | Never inferred or granted for convenience |
|---|---|---|
| Service entry / permitted `U` | SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START | STOP, CHANGE_CONFIG, DELETE, WRITE_DAC, WRITE_OWNER; start is not run consent |
| Broker process / UI | PROCESS_QUERY_LIMITED_INFORMATION and SYNCHRONIZE (`0x00101000`) for retained instance/path/liveness | PROCESS_DUP_HANDLE, VM access, create-thread, terminate, suspend, DACL/owner writes |
| UI process / broker | The same query/wait pair, through reviewed explicit access on the owned UI process | SeDebug fallback, arbitrary process inspection or handle-copy proxy |
| Broker service token / UI | No token handle exported; cross-account TOKEN_QUERY is not a prerequisite silently assumed to work | TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_ASSIGN_PRIMARY or adjustments |
| Bound client token / acquisition thread | Identification path: TOKEN_QUERY only. Separately admitted impersonation path: TOKEN_QUERY and TOKEN_DUPLICATE | Identification token promoted into execution authority, delegation or caller-supplied handle |
| Duplicated primary token / broker | TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_ASSIGN_PRIMARY (`0x000B`) for the one bound supervisor creation | Session rewrite, privilege/group expansion, transfer to UI/backend |
| Supervisor own primary token / supervisor | At least QUERY, DUPLICATE, IMPERSONATE required by the proposed own-token route; exact descriptor still subject to review | Removing self-access until CreateProcessAsUser fails, then broadening rights automatically |
| Returned child process/thread / creator | Retain exact creation-returned handles through pre-resume validation/cleanup; never export them | Reopening by untrusted PID as ownership, unrelated-process stop |
| Outer user-session Job / broker | Sole noninheritable lifetime ownership; required query/set/assign/terminate rights | Any UI/supervisor/worker duplicate, a named globally discoverable Job or breakaway |

[Process rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
warn that PROCESS_DUP_HANDLE can enable greater access; it is not a harmless
transport permission. Process-query access and token-query access are different
checks. [Token rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects)
do not include SYNCHRONIZE. The
[OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
documentation also states different-account restrictions; a TOKEN_QUERY ACE alone
is not evidence that Standard UI-to-LocalService inspection works. Exact required
identity observations/access routes remain an implementation blocker, not a
reason to grant SeDebug or trust a server's self-reported token fields.

### Pipe rights and logon separation

Use local byte-mode duplex pipes, explicit descriptors, noninheritable handles,
overlapped I/O, PIPE_REJECT_REMOTE_CLIENTS and first-instance creation for each
new name. Private per-action names are broker-generated routing identifiers, not
bearer secrets. Collision rejects; no attaching to an existing server or retry
with weakened flags. First-instance flags cannot be applied blindly to later
server instances of an intentionally multi-instance discovery pipe.

Candidate client mask is FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES |
READ_CONTROL | SYNCHRONIZE = `0x00120083`. It deliberately excludes bit `0x4`
(FILE_APPEND_DATA / FILE_CREATE_PIPE_INSTANCE), write attributes, WRITE_DAC and
WRITE_OWNER. Use these individual rights, not GENERIC_WRITE; do not change read
mode after opening. Server rights are held only by `S` and trusted SYSTEM.
[Named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
The implementation must verify the actual rights its chosen pipe library requests;
a library that expands the mask to GENERIC_WRITE cannot use this policy unchanged.

Discovery may grant that client mask to protected-policy `U` only. After observed
identity binding, private control/token/supervisor endpoints grant it to `L`, not
to both `L` and `U`: allow ACEs combine as alternatives, not an AND condition.
Adding `U` would re-enable the same account's other logons. Independently check
user SID, logon SID, authentication ID, session ID and process instance anyway.
The supervisor shares the requesting logon, so its endpoint also needs exact
retained-child matching; a logon ACE alone cannot distinguish it from the UI.

Propose Medium mandatory label with no-write-up/no-read-up on private user-facing
pipes; reject Low clients. DACL access is insufficient if mandatory integrity
policy denies it. Creation of the exact descriptors under LocalService, without
new privileges or host-policy changes, is still NotTested.
[Mandatory integrity](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).
No paste-ready SDDL is accepted until owner/group, mandatory label, token access
and API-specific rights pass the separate descriptor review.

## 3. Pairing and the unresolved token-channel boundary

All initial discovery/control opens explicitly request SECURITY_SQOS_PRESENT |
SECURITY_IDENTIFICATION. Never rely on the default SQOS; no automatic upgrade.
Each endpoint must be paired before sending private scope or accepting commands:

1. UI reads the protected installed service identity/configuration; SCM must
   report its own-process service RUNNING. Retain the observed process with
   query-limited/wait access, then compare pipe server PID against that retained
   instance and recheck SCM/liveness. START_PENDING/STOP_PENDING/PID-only state
   does not qualify. Protected image/loader/installed-generation validation is
   still required; name, PID, path or signer alone is not sufficient.
2. Broker binds the pipe client's OS PID to a live retained UI instance, observed
   identity/logon/session and installed controller code. Its bounded identity
   thread reads the current handshake before identification-only inspection and
   always checks reversion. Failure closes the connection; reversion failure
   terminates the broker. No general filesystem/registry/network work is done
   while impersonating.
3. Exchange protocol/domain, fresh 32-byte challenges, channel/broker instance,
   generation/policy and strict per-direction sequence. Bind the transcript to
   observed identities and later frozen offer. JSON digests and challenges are
   anti-mixup/replay inputs after peer binding, not server authentication.
4. Private action endpoints must repeat actual peer-instance checks and match the
   original transcript. An endpoint name, echoed nonce or session number cannot
   reconnect/take over an action. Restart/disconnect invalidates it.

SCM status can lag and PIDs are valid only in specific states;
[QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
is an input, not an atomic identity certificate. Native acceptance must validate
the exact server/client handle directions for
[server PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid)
and [client PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)
queries and retained-handle binding. No name/process enumeration fallback.

**Token-channel blocker:** checking a new pipe's server PID only after opening
it with SECURITY_IMPERSONATION is too late to establish a pre-exposure guarantee.
A successful earlier identification connection does not by itself authenticate
a later open. No silent SQOS switch, token-in-JSON, cross-account handle-transfer
shortcut or SeDebug fallback is selected. Reservation/same-name multi-instance
ideas still need proof of endpoint lifetime and server death/recreation behavior;
they are not an accepted recipe in this contract. The stronger channel stays
unimplemented until a documented binding mechanism is independently accepted.

Only after that gap is closed may the dedicated token thread read the exact
exchange, validate impersonation level and effective Standard context, duplicate
the primary token and revert before creation. Identity/elevation/session mismatch,
missing self-access or failed cleanup blocks. The broker never accepts a caller
`ready`, token handle, arbitrary argv/path or precomputed trust verdict.

## 4. Bounded framing and authority sequence

Propose a 4-byte unsigned little-endian byte length followed by 1..16384 bytes of
strict UTF-8 JSON. Length is checked before payload allocation; reject zero,
overflow, truncation, BOM, invalid UTF-8, duplicate keys/fields, unknown version,
message/field and mismatched direction/state. Maximum nesting 8, IDs 64 ASCII
bytes and strings 1024 UTF-8 bytes. No compression, general object deserialization
or user-supplied display text. This is a future wire proposal, not a schema added
to the published contracts.

Sequences start at 1 separately per direction; duplicates/skips/wrap reject.
Fixed messages cover pairing, one proposal, frozen offer, exact Standard intent,
bounded status/cancel and terminal result. Supervisor bootstrap has a disjoint
message domain and cannot confirm human intent. In this **supervisor-only**
slice there is no worker-create/execute message, backend path, VQL or collection.
No arbitrary test executable can substitute for the absent backend entrypoint.

Before any future child creation: validated installation/peers -> displayed
frozen scope -> exact single-use intent -> durable consumed admission/lease ->
create-time Job assignment and suspended supervisor -> pre-resume checks ->
bounded authenticated bootstrap -> stop/reap -> terminal status. This sequence
is required, not implemented here. A bootstrap test would need its own explicitly
reviewed operation/consent; it cannot borrow Version/Help or installation intent.
Disconnect/cancel/expiry never refreshes authority. A lost reply permits bounded
status inspection on the still-bound channel, not another creation.

## 5. Proposed supervisor-only resource ceilings

The following are conservative engineering starting values, not measured fit or
a promise of imperceptible load on other projects. No test ran to obtain them.
They must be enforced, checked and independently reviewed before execution;
unsupported controls reject rather than silently raise/omit a ceiling.

| Resource | Proposed ceiling / enforcement |
|---|---|
| Admission | One global action, no execution queue; at most four pending discovery/control handshakes, each 5 seconds |
| Control data | 16 KiB payload per frame; 64 frames and 1 MiB including framing **combined across both directions and action channels** per action; 2 MiB aggregate explicit control buffers across connections |
| Pending/idle data | Before action binding, at most 8 frames / 64 KiB including framing per handshake; fixed 5-second deadline is never refreshed; a started frame has at most 2 seconds, bounded by the earlier overall deadline |
| Connection allocation | At most 8 server pipe instances including listeners and active/pending endpoints; requested pipe buffers 8 KiB each way; no automatic unbounded instance spawning |
| Cancellation reserve | Reserve 64 KiB within the 2 MiB pool and an active-action I/O slot for cancel/status; pending clients cannot consume them; validate/account before allocation, including rejection handling |
| I/O buffers | Fixed bounded reads/writes; cancellation waits for overlapped completion before freeing memory; never FlushFileBuffers on an unresponsive client |
| Supervisor-only processes | ActiveProcessLimit=1 with JOB_OBJECT_LIMIT_ACTIVE_PROCESS; kill-on-close; no breakaway and no children; later backend integration requires a new reviewed profile |
| Supervisor commit | ProcessMemoryLimit=134217728 and JobMemoryLimit=134217728 bytes, both flags set before creation |
| Supervisor CPU rate | ENABLE plus HARD_CAP, CpuRate=1000 (10%); no minimum reservation, affinity change or global priority policy |
| Wall clock | 10 seconds from immediately before supervisor creation, covering suspended checks and bootstrap; no timer reset on messages or progress |
| Cleanup | Separate 5-second target; uncertainty remains failure and blocks subsequent action/maintenance, not guaranteed instantaneous termination |

Before creation, the existing 30-second offer lifetime is unchanged. Quiescent
idle connections/service close after at most 60 seconds; an action or unresolved
ownership is not quiescence. Preserve control cancellation independently of a
slow token/handshake thread. All pre-action and active buffers count toward the
same fixed pool. Requested pipe sizes are not a total kernel-memory bound:
Windows pipe allocation also consumes nonpaged pool.
[CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew).

[Job memory](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)
limits committed virtual memory, not all resident RAM/kernel buffers/file cache.
[Job limit behavior](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information)
does not replace explicit allocation/error handling; memory-limit notifications
are not a substitute for enforcement. Never sum this table into a claim about
total machine memory or include the broker/UI in the user-session Job.

[CPU rate](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information)
is relative to an enclosing CPU-limited Job when present, otherwise the system;
it is not 10% of one core or a wall-time guarantee. RDS/DFSS can make it unavailable.
Unknown/incompatible nesting rejects. All Job limits must be configured and read
back before atomic creation-time association; no run-first/limit-later fallback.
The broker's own total process CPU/memory bounds are not supplied by this Job:
their safe enforcement and pre-listener bootstrap remain open. Only explicit
protocol allocations are bounded here; no whole-broker resource claim is made.

## 6. Exit criteria and honest next step

Outstanding before admitting native bootstrap implementation: initial broker
process/thread/token ownership and exact constructible descriptors; required
cross-account observation access without new rights; pre-exposure token-server
binding; fixed usable desktop/profile; broker-wide resource bounds; concrete
durable run/lease recovery and maintenance exclusion. The supervisor-only ceiling
does not resolve future worker quotas, offline confinement, private evidence,
startup effects or the actual highestAvailable backend manifest.

Required checks are Planned / NotRun: correct permitted user/logon and rejected
foreign logon/user; discovery versus private-pipe grants; denied instance creation
and privileged-handle access; shared LocalService owner bypass; wrong/dead/reused
peer and restart between channels; token exposure to substituted server; malformed
length/JSON/sequence; control floods; unavailable quota controls; creation crash,
timeout/disconnect and retained-Job-handle cleanup failure. Each rejection needs
a legitimate positive control; document review is not native evidence.

This pass adds no new synthetic readiness model merely to restate these gaps.
The mechanism investigation in section 7 narrows the pre-exposure token-channel
and bootstrap-owner gaps. D-061 in section 8 resolves the account/authority
choice for further design, not those technical gaps. Next establish the concrete
virtual-account binding/object-security recipe before a supervisor-only
source/build plan. Full backend/runtime admission is still blocked.

Independent review: AcceptedDocumentaryBootstrapCandidateContractOnly on
2026-11-06, after correction of the primary-token access mask and verification
against the installed SDK definitions. The read-only reviewer checked this
document and both cross-document links; no blocking documentary findings remain.
No native/backend execution, implementation, installation or runtime acceptance
is implied. The concrete technical gaps listed above remain open.

## 7. Mechanism investigation: no automatic transport/account switch

Date: 2026-11-06. Official API-contract research, not host observations.
The following narrows the two blockers; it does not change the account candidate,
grant budget, transport contract or admission statuses above.

### Pre-exposure authentication: local RPC is a candidate, not a proven fix

Microsoft documents mutual authentication for `ncalrpc` with explicit security
QoS and RPC_C_AUTHN_WINNT. This is a concrete alternative to opening an
impersonation-capable pipe and authenticating it afterward.
[RpcBindingSetAuthInfoExW](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingsetauthinfoexw).
It does not follow that choosing `ncalrpc` alone authenticates the server:
[RPC security defaults](https://learn.microsoft.com/en-us/windows/win32/rpc/security)
must not become the application policy.

QoS supports a target SID and, in V5, a server security descriptor. The reviewed
description does not establish an exact recipe that discriminates service group
SID `S` from another process under the shared LocalService account before client
impersonation authority becomes available. Nor does account authentication by
itself bind a retained process instance or installed generation.
LOCAL_MA_HINT only applies with dynamic endpoints and mutual authentication; it
is not a general static-endpoint fix. The V5 descriptor is documented as required
for mutual authentication; a community example omitting it is not normative
evidence. Explicit static client identity tracking (not server-instance pinning),
effective-only behavior and impersonation level would also need review, with no
delegation or silent fallback. General mutual-authentication flags are not a
substitute for a reviewed provider/protocol-specific recipe.
[RPC_SECURITY_QOS_V5_W](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos_v5_w).

A transport change also invalidates assumptions about the old pipe budgets:
`RpcServerRegisterIf3.MaxRpcSize` does not limit `ncalrpc`, and `MaxCalls` is not
a hard concurrency ceiling. Its default interface descriptor admits normal
Low-integrity clients. Any RPC proposal therefore needs explicit endpoint and
interface access policy, bounded IDL/NDR shapes and allocation review, independent
admission/cancellation budgets and before-authority peer checks. Application
validation after unmarshalling is not a pre-allocation limit.
[RpcServerRegisterIf3](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3).
No RPC endpoint, IDL, generated stub or test helper is added here.

### Initial ownership: the public SCM contracts do not close the gap

The reviewed signatures of
[CreateServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew),
[StartServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)
and the documented levels of
[ChangeServiceConfig2W](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)
provide no identified parameter for setting the initial process/thread/token
security descriptors before the service entrypoint.
[SetServiceObjectSecurity](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setserviceobjectsecurity)
changes the SCM service object, not those runtime objects. No supported mechanism
was identified in these reviewed public APIs; this is not proof that Windows
isolation is impossible.

SERVICE_SID_TYPE_UNRESTRICTED makes `S` owner-capable; it does not document that
`S` becomes the selected default owner or every initial object's owner/DACL.
[SERVICE_SID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).
[TokenOwner](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner),
[TokenDefaultDacl](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_default_dacl)
and the token object's own descriptor are distinct. Do not mark the initial
window resolved by changing any of them after entrypoint.

### Alternative requiring a separate account/effects decision

A virtual account `NT SERVICE\<ServiceName>` is a supported distinct configured
service identity with a NULL password, not merely an extra group on LocalService.
[CreateServiceW virtual accounts](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew).
This may simplify expected-account authentication and avoid the shared account
identity, but initial object descriptors and exact instance binding still need
evidence. It is an unselected alternative, not a claimed isolation solution.

LocalService has documented assign-primary-token and increase-quota privileges.
No corresponding unconditional guarantee for an arbitrary virtual account was
established. Required-privilege configuration removes unused privileges; it does
not authorize granting missing ones.
[LocalService privileges](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account),
[SERVICE_REQUIRED_PRIVILEGES_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow).
For comparison, Microsoft's SQL Server documentation explicitly describes these
as installer-granted per-service rights, not automatic SCM defaults. Its broader
permission list is not a SecApp installation recipe.
[SQL Server installation rights](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17).

Virtual accounts can use computer-account network credentials, whereas
LocalService presents anonymous credentials. Neither means network denial;
changing accounts is not network-neutral and cannot waive offline confinement.
[Virtual-account network identity](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts),
[LocalService network identity](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account).

Research-stage boundary, before D-061: retain LocalService and keep token
handoff/native admission blocked. Adopting a replacement that depends on
installer-assigned user rights requires an explicit revision of D-058's no-grant
envelope; it cannot be inferred
from permission to continue research. If chosen for further design, enumerate
each needed right and its holder, justify it, preserve the existing maximum
privilege budget, and review ownership, network effects and removal semantics.
Do not grant rights to the UI/backend or broaden a shared account/group. A future
exact installation manifest and separate confirmation remain necessary; no
rights assignment, service installation or system-setting change is authorized
by this research. User approval of a direction would not itself close either
technical blocker.

Independent research review: AcceptedDocumentaryBindingResearchOnly on
2026-11-06. The read-only reviewer checked section 7 and the section 6 next-step
delta; no blocking documentary findings remain. Native verification: NotRun.
The earlier accepted documentary contract remains historical; this addition
does not promote it into accepted native implementation.

## 8. D-061: scoped service-account rights proposal

Date: 2026-11-06. The user approved considering targeted rights for the separate
SecApp service in a future installation, with the exact rights and installation
confirmed separately. This resolves the permission choice in section 7, not its
technical blockers. Sections 1-7 retain the earlier LocalService/no-grant research;
this section is the current account proposal. No host account or policy was read
or changed for this proposal.

### Candidate account and entitlement table

Propose an own-process, demand-start broker configured explicitly as
`NT SERVICE\<ServiceName>`, with NULL password; service name/SID and installation
generation must be fixed by the future protected manifest. Do not leave the
account blank, create a normal password-managed account or use a shared account.
This is a virtual-account candidate for further review, not an installed identity.
[CreateServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew).

Only the exact service principal `S` may be a future grant recipient. Keep
SERVICE_SID_TYPE_UNRESTRICTED as the descriptor-review starting point, not a proof
of initial ownership or a reason to copy all earlier LocalService assumptions.
The effective TokenUser, groups, owner, token-object security and initial
process/thread security need explicit verification for this different account.

| Proposed entitlement | Purpose | Installation/runtime boundary |
|---|---|---|
| SeServiceLogonRight | Permit SCM's service-logon type | Separate logon right, not a TokenPrivileges entry or required-privilege-filter item. Propose a direct grant only if the approved supported configuration needs it; account/group deny remains a blocker. |
| SeImpersonatePrivilege | Obtain the authenticated requesting user's impersonation context | Only the fixed, separately accepted token handoff; no general impersonation endpoint, delegation, arbitrary I/O or work under service identity after impersonation failure. |
| SeAssignPrimaryTokenPrivilege | Support broker creation with a different user's primary token where required | Retained in the candidate ceiling until the exact route proves it unnecessary. The restricted-own-token exception is not applied to an unrelated client token. |
| SeIncreaseQuotaPrivilege | Satisfy CreateProcessAsUser resource requirements | Broker-only creation path; never transferred to the Standard supervisor or worker and never repaired at runtime. |
| SeChangeNotifyPrivilege | Account for Windows' service-filter compatibility residual | Included in the total privilege ceiling, not a new grant requested by this proposal. Its presence, if observed, is not proof of other rights. |

The three launch privileges are a justified candidate budget, not proof that each
must be newly granted on this host. Inventory existing direct assignments and
effective/group-derived eligibility separately; propose only a justified missing
delta, never the whole table as unconditional installation commands.
[Account/logon rights and deny precedence](https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants).
In particular, SCM's SERVICE group can already supply SeImpersonatePrivilege;
do not add a redundant direct grant just because the direct LSA list is empty.
[SCM impersonation policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication).
For RPC, a successful impersonation call can still produce only Identify level
without the required capability; check actual level and identity, not status alone.
[RpcImpersonateClient](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcimpersonateclient).
CreateProcessAsUser can enable already-held required privileges for its call;
disabled is not absent. No credential-prompt, different API/account, service-token
child or elevated retry is an automatic fallback.
[CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).

Configure a removal-only required-privilege list for the three launch privileges;
account explicitly for SeChangeNotifyPrivilege, which SCM does not remove.
Missing prerequisites or unexpected surviving privileges block startup before
listeners or token acquisition. Disabled unexpected privileges still count.
The exact creation-time owner/handle window remains unresolved; a startup check
is not a claim to have protected it retrospectively.
[SERVICE_REQUIRED_PRIVILEGES_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow).

No new grant is proposed for the UI, supervisor, backend, installation requester,
LocalService, All Services, Users, Authenticated Users or Administrators. No group
membership edits, interactive/batch/remote logon rights, SeTcb, SeDebug,
backup/restore, take-ownership or driver privileges belong to this plan.
A broker vulnerability would still be serious: these capabilities are not
restricted by Windows to SecApp's intended commands. The narrow authenticated
protocol and protected code are necessary controls, not optional hardening.

### Future installation is a separate authority, not a broker endpoint

The exact manifest must display the service/account SID, package and generation,
owned paths/objects, proposed direct-right additions, existing assignments to
preserve, privilege filter, rationale, network implications and removal policy.
Protect and bind this plan to the installation requester/operation; no client
supplies an arbitrary SID or privilege name. UAC alone is not that authorization.
Account names are display aids; validate the exact SID and protected service
ownership. Existing service/LSA state or a reused name with unknown provenance
must not be adopted merely because spelling matches.

Candidate installation sequence, not executable code:

1. Establish package/owned-object trust and quiescence, then perform read-only
   inventory of account-specific assignments and relevant effective/group/deny
   policy. An account-right enumeration is not a complete effective-token/group-
   policy audit; missing direct entries do not alone prove a grant is needed.
   Distinguish the documented no-rights/not-found result from access denied or
   other errors; unknown results block rather than becoming an empty baseline.
2. Derive and display the exact SID-bound delta from that inventory, including
   existing rights to preserve, then obtain separate confirmation of that plan.
   Immediately before mutation, revalidate the same baseline, identity and plan.
   Any drift, newly missing right or SID/plan change blocks: derive and display
   a new plan and obtain fresh confirmation, never silently recalculate grants
   under the old consent.
3. Before any authorized mutation, durably record the exact pre-state, confirmed
   additions and owned installation identity. Use only reviewed LSA APIs on the
   local policy and exact `S`; no registry editing, policy import/export or
   broad security-template replacement. Apply only the confirmed delta and read
   back afterward; revalidation is not atomicity or absence-of-race proof.
   Leave the service unstarted if results or ownership are uncertain. Never
   start a partly configured service or auto-start collection as validation.
4. Preserve all unrelated rights. Do not remove a deny or edit local/domain policy
   to force success; managed-policy conflicts block without repair. No daemon,
   installer retry loop or runtime endpoint restores rights after policy changes.

[LsaEnumerateAccountRights](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountrights)
requires POLICY_LOOKUP_NAMES and can return a no-rights result as failure status.
[LsaAddAccountRights](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights)
can create an LSA policy account entry and ignores already-held rights. Its policy
handle needs POLICY_LOOKUP_NAMES and, if that entry is absent,
POLICY_CREATE_ACCOUNT; these are installer handle accesses, not broker token
privileges or permission to create unrelated Windows user accounts. No
POLICY_ALL_ACCESS is a default. Add success cannot prove who originally granted
an already-present right or turn it into installer-owned rollback authority.
No installer LSA/SCM policy handle may be inherited or transferred to the broker,
UI, supervisor or backend; the runtime has no rights-management API.

### Removal, crash and policy-change boundaries

Propose selective removal only of this installation's demonstrably added direct
rights on its still-owned exact `S`, after confirmed run quiescence. Never remove
pre-existing/group rights, restore a whole policy snapshot, or use
`LsaRemoveAccountRights(AllRights=TRUE)`. The explicit FALSE/list form narrows
the mutation but does not establish ownership by itself.
[LsaRemoveAccountRights](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaremoveaccountrights).

The reviewed add/remove APIs supply no per-right ownership marker or atomic
compare-and-set contract. A SecApp journal alone cannot prove no administrator
or policy engine changed/re-added the same right meanwhile. Crash, conflicting
state or ambiguous ownership must be reported as incomplete cleanup requiring
review, not silently revoked, repaired or reported as clean uninstall.
Removing a policy assignment is also not accepted here as revocation of a live
token/handle; stop/reap and retained-handle lifetime remain independent gates.
User-right changes take effect at the next logon, not by stripping an existing
process token. Deleting a service registration is also not a substitute for
selective LSA cleanup or stopping and reaping its processes.
[Policy/token lifecycle](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication),
[DeleteService lifecycle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice).
Exact supported concurrency/GPO and rollback semantics must be reviewed before
installer implementation; no fault injection on the user's main host is implied.

Virtual-account computer credentials do not satisfy offline confinement.
The broker and worker still need an accepted preventive offline boundary; no
firewall, domain-policy or deny-logon changes are authorized as a shortcut.
[Virtual-account network behavior](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts).

### Next evidence, not another permission loop

Proceed to the concrete virtual-account/RPC binding and initial-object-security
design under this ceiling. Before native implementation, independently accept
that recipe, cross-account observation, session/desktop/profile, broker resource
bounds and durable run/lease behavior. Before any installation, present the exact
owned-object/right-delta manifest and obtain separate confirmation. Do not ask
again for this already-approved general direction; ask only for a material new
scope or the concrete effects when ready.

Required future positive/negative cases: legitimate Standard requester; wrong
service/account/instance rejected before token exposure; missing/extra privilege;
Identify-only result; direct-versus-group right; applicable deny; policy refresh;
foreign/reused service SID; pre-existing right preservation; interrupted or
ambiguous grant/removal; and no new privilege in supervisor/backend. All are
Planned / NotRun, not native or installer acceptance.

Independent account-grant proposal review:
AcceptedDocumentaryServiceAccountRightsProposalOnly on 2026-11-06. All seven
documentation changes were checked; no blocking documentary findings remain.
This does not accept an installation manifest, RPC recipe or native mechanism.
HostDeployment = NotPerformed; ProductionLauncher = NotImplemented;
AutomaticBackendExecution = Disabled. No runtime code, schema, native helper,
Windows mutation or backend execution is introduced by this section.

## 9. Concrete local-RPC candidate and creation-evidence boundary

Date: 2026-11-06. This follows D-061 without new permissions. It proposes API
settings and a bounded exchange for independent review, not executable RPC/IDL,
an accepted replacement for the pipe contract, an installation or a native test.
The prior token-handoff and native-admission statuses remain blocked.

### Client binding: select a documented version, not implicit defaults

Propose `RpcBindingSetAuthInfoExW` with the following settings before any call,
including discovery or management queries. The expected account comes from
protected installation policy, never from the contacted endpoint.

| Setting | Candidate value / boundary |
|---|---|
| Transport | `ncalrpc` only, no network address, fixed locally configured endpoint; no endpoint-mapper lookup or network fallback |
| Authentication | `RPC_C_AUTHN_WINNT`, `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`, `RPC_C_AUTHZ_NONE` |
| QoS structure | `RPC_SECURITY_QOS_V4_W`, Version=4; explicitly zero other fields |
| Expected principal | Sid=`S`, ServerPrincName=NULL; `S` is now the virtual account identity, not just a group added to LocalService |
| Capabilities | `RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH`; no LOCAL_MA_HINT for this static endpoint or ignore-delegation-failure flag |
| Client context | `RPC_C_QOS_IDENTITY_STATIC`, AuthIdentity=NULL on the verified Standard UI context; no impersonating caller thread |
| EffectiveOnly | TRUE; this limits visible enabled privileges, not token groups, elevation, session or linked-token metadata |
| Control binding | `RPC_C_IMP_LEVEL_IDENTIFY`; matching transport security options `Security=identification static true` |
| Separate token binding | `RPC_C_IMP_LEVEL_IMPERSONATE`; matching `Security=impersonation static true`, only after the stronger-channel prerequisites below |
| Extra security data | AdditionalSecurityInfoType=0, union pointer NULL; no HTTP credentials, delegation or credential prompt |

The supported V4 structure already has Sid and EffectiveOnly. Choose it deliberately
at design time, not as a runtime retry after V5 fails. This does not reinterpret
V5's ServerSecurityDescriptor requirement or invent its access-mask semantics.
STATIC tracks the client identity, not a server process instance. Provider
warnings about IDENTIFY and mutual authentication still require exact protocol
qualification; a configured flag is not proof.
[QoS V4](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos_v4_w).
The specific API documents local mutual authentication with WINNT; do not
generalize that to NTLM over network transports.
[RpcBindingSetAuthInfoExW](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingsetauthinfoexw).
Transport security must not silently request more authority than the QoS level.
[String-binding security options](https://learn.microsoft.com/en-us/windows/win32/rpc/string-binding),
[QoS security cautions](https://learn.microsoft.com/en-us/windows/win32/rpc/choosing-security-qos-options).
STATIC transport tracking captures context on the first RPC for that binding,
not merely when its object is created. Verify Standard identity and absence of
thread impersonation on the actual issuing thread at that first call for each
binding, as well as at setup. A setup-time check alone is insufficient.

Use separate binding objects for control and token operations; never mutate
authentication on an in-flight call or upgrade control implicitly. Do not assume
separate binding objects guarantee separate underlying RPC associations. Binding
setup/readback success is not a successful peer-authentication test. Any failed
setting/call, unexpected actual level or reconnect invalidates the pending offer;
no downgrade, alternate transport or target-SID substitution.

### Server checks: each interface and each call

After accepted startup/object checks, propose explicit endpoint and interface
descriptors plus `RpcServerRegisterIf3` with ALLOW_LOCAL_ONLY, ALLOW_SECURE_ONLY
and SEC_NO_CACHE. Do not use AUTOLISTEN while setup is incomplete. Exact descriptor
masks/constructibility still need review; no NULL/default DACL recipe is accepted.
Before listening, explicitly register WINNT authentication once using
`RpcServerRegisterAuthInfoW`, with NULL GetKeyFn/Arg; do not assume ambient
registration. Pin/review its provider-specific ServerPrincName semantics in the
source/build plan, without treating a returned name as client-side trust.
[Server authentication registration](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterauthinfow).

The flags alone are insufficient: SECURE_ONLY admits null sessions, LOCAL_ONLY
does not mean only LRPC, and endpoints do not privately own interfaces. Registering
one local endpoint does not prevent another component's endpoint from exposing
the same interface. The callback must independently reject the wrong protocol,
interface/domain or operation on every call.
[Registration flags](https://learn.microsoft.com/en-us/windows/win32/rpc/interface-registration-flags),
[Cross-endpoint exposure](https://learn.microsoft.com/en-us/windows/win32/rpc/be-wary-of-other-rpc-endpoints-running-in-the-same-process).

Use zero-initialized V2 call attributes with Version=2 and explicit
RPC_QUERY_CLIENT_PID | RPC_QUERY_IS_CLIENT_LOCAL to require LRPC, local caller,
WINNT, packet privacy, a non-null authenticated session and the exact
interface/allowed OpNum. These query flags were cross-checked as definitions
only in SDK 10.0.26100.0; no runtime query was performed. Bind the returned client
PID to a retained live process with the already reviewed query/wait-only access.
ClientPID is a PID in a HANDLE-typed field,
not a granted process handle to close or duplicate. Unknown/unsupported
observations reject; do not trust PID, SID, session or image claims in payloads.
[RPC_CALL_ATTRIBUTES_V2_W](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/ns-rpcasync-rpc_call_attributes_v2_w).
Client exit followed by PID reuse can race an open-after-query operation. The
retained handle stabilizes the process that was opened, but does not alone prove
it originated this call. Call-to-process-instance association across that race
remains a qualification gate, not a property inferred from matching PIDs.

Separately verify permitted `U`, exact `L`, authentication ID, session, Standard
effective rights and the retained controller identity from the actual call/token.
Check impersonation return and actual level; duplicate only on the dedicated
token route, then revert and check reversion before any ordinary work. Never
execute a rejected request under the service token. The cross-account process
observation route still needs demonstrated constructibility without SeDebug.
No callback parses arbitrary audit data, performs general I/O or starts a child.

### Authority sequence and the unresolved instance link

1. The protected installation policy fixes account `S`, code/generation and
   permitted requester `U`. UI retains the SCM-observed RUNNING instance; this
   observation alone does not authenticate an RPC association.
2. Identification-only control negotiates fixed protocol/domain and fresh
   32-byte challenges, validates peers and prepares one immutable bounded offer.
   Before private scope is exchanged, establish the required instance/generation
   link; an echoed PID, nonce or self-reported principal cannot supply it.
3. Display the exact Standard operation and obtain the existing single-use intent.
   Before opening the impersonation-capable binding, require the accepted
   pre-exposure server binding and instance link. Account-SID targeting is a
   concrete candidate for the former, not proof of the latter.
4. The disjoint token operation must match that offer, actual requester,
   generation, challenges, sequence and deadline. Duplicate the validated token
   and revert; durable consumed admission/lease and pre-creation checks still
   precede supervisor creation. No worker/backend command exists in this slice.
5. Restart, reconnect, cancellation, expiry or ambiguous reply invalidates pending
   authority. Inspect bounded status if still legitimately bound; never repeat
   a create/admit operation merely because its reply was lost.

RPC account authentication is not retained-process-handle authentication.
The reviewed API fields do not yet supply an accepted client-side proof that the
stronger association terminates in the exact retained SCM process/generation.
A second connection to the same name/account, a nonce, or STATIC client tracking
does not close that gap. Same-account stale-instance/restart behavior and any
association-sharing behavior require explicit evidence. No context-handle
cross-binding portability or private runtime API is assumed as a shortcut.
The candidate therefore remains non-executable even though its account/QoS
parameters are now concrete.
In particular, qualification must establish ordering: expected-account rejection
must precede availability of transport-level impersonation when the transport
options request impersonation. Matching transport/QoS levels or observing a
later failed manager call does not establish this pre-exposure property. This
is a required evidence boundary, not a claim that Windows violates it.

### Wire size, deadlines and cancellation are separate controls

Propose fixed-shape request/reply records, each at most 4096 logical bytes, with
fixed arrays and bounded scalar fields. No conformant/unbounded strings, pointer
graphs, compression, generic deserializer, raw paths/argv or caller token handles.
Keep distinct control/token/supervisor domains and reject unsupported enums,
nonzero reserved bytes, bad lengths/sequences and mismatched direction/state.
Future generated stubs require explicit MIDL /robust and inspection of generated
bounds; application checks after unmarshalling are not an allocation boundary.
[Range checking and /robust](https://learn.microsoft.com/en-us/windows/win32/midl/range).

Retain the earlier one-action/four-pending admission and application data budgets;
account for both request and reply buffers and reserve cancel capacity before
accepting work. They are not RPC-runtime or kernel-memory ceilings. MaxRpcSize
does not apply to LRPC and MaxCalls is best-effort, so bounded logical records
alone cannot close broker-wide resource/flood protection.
[RpcServerRegisterIf3](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3).

RPC_C_OPT_CALL_TIMEOUT is ignored for local/async calls. A synchronous call with
that option cannot enforce the proposed 5-second handshake or 10-second action
deadline. These deadlines must be monotonic application deadlines, never reset
by traffic, and must also be enforced independently by the broker.
[RpcBindingSetOption](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingsetoption).

Propose asynchronous calls with owned completion state and explicit cancellation,
not a blocked UI thread or unsafe thread termination. Synchronize issuing and
cancelling: asynchronous cancellation is only issued after successful call
initiation; synchronous initiation failure takes its own cleanup path.
Cancellation success is not server non-execution. Retain buffers/state until
completion is observed and finalized exactly once; pending completion is not
permission to free/reuse memory. Read output parameters only after successful
completion. No automatic action retry or new action while cleanup is uncertain.
[RpcAsyncCancelCall](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcasynccancelcall),
[RpcAsyncCompleteCall](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcasynccompletecall).
Async/cancel are a candidate lifecycle, not a demonstrated bound on initial
binding/authentication, total runtime allocation, server work or cleanup time.

### Creation-time object evidence: defaults are conditional

Missing explicit SECURITY_ATTRIBUTES is not a NULL DACL. Microsoft describes
ordinary token default DACLs as limited to the token user; this supports studying
a distinct virtual account rather than assuming all defaults are public.
[SECURITY_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes).
But the creation API matters: modern CreateProcessW and CreateThread describe
defaults from the creator's primary token, whereas CreateProcessAsUser describes
defaults from its hToken user.
[CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread),
[CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
SCM documents service-account logon and attachment of the resulting token, not
the precise internal creation API/descriptor arguments for this configuration.
[Service User Accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts).
Do not transfer one creation API's defaults to SCM without evidence.

The required evidence is an exact owner/group/DACL/control-flags and effective-
access matrix for the initial process, initial thread and primary-token object
under the supported OS/configuration. Include owner WRITE_DAC implications,
PROCESS_DUP_HANDLE, process memory/thread creation, thread impersonation/token
setting, token duplication/assignment/adjustment, and inherited/already-open
handles. TokenUser, TokenOwner, TokenDefaultDacl and token-object SD remain distinct.
No broad foreign-user/group grant or shared-owner bypass may be hidden by a
later tightening operation. SYSTEM remains a trusted platform principal; this
does not promise resistance to administrator/kernel compromise.

An early fail-closed self-check before listening is useful but observes a
post-creation state. It is not proof of a safe pre-entrypoint interval and cannot
revoke an already-open handle. No DACL repair, startup race/probe, host token
inspection or service installation was performed for this design.

### Narrow next evidence step

Prepare a source/build and qualification plan that separately answers:
(a) exact V4/ncalrpc expected-account rejection before authority exposure;
(b) same-account instance/generation correlation across the two bindings;
(c) actual SCM initial descriptor provenance and allowed access;
(d) bounded initiation/cancellation and pre-unmarshal/runtime resource behavior.
Include legitimate controls and wrong-account/relay/restart/Identify-only,
timeout-with-late-reply and pre-existing-handle negatives. These remain Planned /
NotRun. A document or later compile-only result cannot turn them into Passed.

Do not require another approval for D-061's general direction. Native qualification
would need its own reviewed effects/environment and explicit permission where
required; implementation and installation retain their existing admission gates.
There is still no native/helper/backend invocation authorized by this section.

Independent review: AcceptedDocumentaryRpcAndCreationEvidenceCandidateOnly on
2026-11-06. The read-only reviewer checked section 9 and its cross-document link;
no blocking documentary findings remain after clarifying first-call context,
PID-reuse races and transport-authentication ordering. This does not accept
native implementation, token handoff, installation or backend execution.

## 10. Narrow qualification plan and WIP checkpoint

Date: 2026-11-06. The user requested the next bounded plan followed by a Git
commit/push. Git publication is a WIP checkpoint, not approval to run this plan
or acceptance of the launcher. D-061 permits the proposed future service-right
direction; every exact installation, native test and technical admission boundary
remains separate. No native helper, IDL, installer or runtime code is added here.

### Ordered admission and source/build scope

| Phase | Deliverable / boundary | Evidence it cannot replace |
|---|---|---|
| QP-0: source/design review | Resolve the section 9 instance-binding mechanism, pre-exposure ordering, exact descriptors and bounded cancellation/resource design; review intended source/API and test effects | No test plan or documentary review substitutes for a missing mechanism |
| QP-1: compile-only candidate | Only after its own source/build review and authorization: pinned reviewed sources, IDL/ACF and generated stubs, exact installed compiler/SDK, warnings/imports/manifest and output hashes; never invoke any produced binary | Compilation cannot prove token identity, authentication order, initial ownership or resource enforcement |
| QP-2: bounded local protocol characterization | Separately approved non-collecting fixture checks of fixed messages, actual levels, completion and cancellation in an agreed environment | Same-user endpoints or a deliberately wrong expected SID do not prove virtual-account/cross-account isolation |
| QP-3: exact service configuration | Separately confirmed installation manifest, exact virtual account/right delta and protected code; minimal no-listener startup observation before any custom descriptor change, then only admitted IPC tests | An entrypoint observation cannot prove the pre-entrypoint interval was safe |
| QP-4: composed evidence review | Bind positive and negative results to exact sources/build/configuration; independently review identity, lifetime, resources and cleanup limitations | No case count, exit zero or compile result enables supervisor/backend creation automatically |

These are gated deliverables, not commands or a runnable schedule. A later phase
cannot be used as a way to bypass an unmet earlier implementation/authority gate.
In particular, native characterization may investigate an unresolved platform
property only under a separately reviewed experimental scope; it is not the
production mechanism admitted early under a different name.

Prospective source roles, without creating them now:

- **Qualification client:** fixed control/token-interface calls only; no arbitrary
  endpoint/SID/argv input, shell, collector or backend path. Uses the agreed
  throwaway test identity, never a real user's sensitive audit context.
- **Qualification service:** exact installed virtual identity; fixed registration
  and allowlisted cases, bounded state, checked impersonation/reversion and owned
  cleanup. No general process launcher, maintenance API or evidence parser.
- **Adversarial endpoint fixture:** only specifically approved wrong-account,
  restart/relay and level-observation cases in the disposable environment. No
  impersonation of existing privileged services, credential harvesting or
  access to real user data.
- **Pure result validator:** strict normalized case set and source/configuration
  bindings; cannot start helpers, repair policy or turn Unknown into Passed.

Do not reuse the historical TrustLaunchProbe or native-synthetic/boundary runners
as a production broker or implicitly rerun them. No test fixture can select a
real Velociraptor image. Compiler/generated outputs stay outside Git. A future
build plan must name existing tools and flags, review /robust-generated bounds
and embed the intended execution-level manifest; missing tools trigger a separate
tool-list decision, not installation or PATH mutation now.

### Environment and exact effects admission

Only the user's main computer is currently available. No disposable Windows
environment or multi-identity fixture setup has been approved or verified.
Therefore QP-2/3 adversarial/service cases are NotRun and not authorized on this
host. Do not create a VM, account, service, right assignment or test endpoint to
work around this limitation. Continue read-only analysis and pure tests where
they can genuinely answer a question, without treating them as native evidence.

Before any native execution, a separate test manifest must list:

- Exact source/build/image digests and supported OS/SDK/configuration; every
  participating identity, process and retained ownership relationship.
- Exact owned service/account/SID, rights and descriptor effects, if any; use
  D-061 inventory -> displayed delta -> confirmation -> same-baseline revalidation.
  Never borrow LocalSystem/SeDebug, another service identity or a live credential.
- Exact test case IDs, fixed parameters, local-only endpoint names, allowed token
  observations/duplication, and whether any child creation is included. Default
  for this qualification slice: no supervisor, backend or arbitrary child.
- Per-case elapsed-time, process, commit/CPU, message/buffer and output limits;
  independent deadline/cancel handling and demonstrated enforcement before use.
  The earlier 5-second handshake, 10-second action and 5-second cleanup targets
  are design inputs, not proven broker/fixture ceilings.
- Private temporary locations, normalized output fields, retained-handle cleanup,
  ownership-preserving removal and incomplete-cleanup reporting. No global
  process kill, process-name enumeration, log deletion or unrelated file cleanup.
- Disclosed Windows/service/profile/event-log effects and network restrictions;
  no audited security-setting change, firewall/GPO repair or automatic reboot.

An approved case may operate only on its own retained objects and exact identities.
Unknown ownership, failed reversion, unexpected privilege, resource-limit failure,
scope drift, ambiguous completion or incomplete cleanup stops the sequence and
blocks the next case. Do not automatically retry, raise limits, change accounts,
expand grants or run a production diagnostic to obtain more evidence.

### Case matrix: positive control plus targeted rejection

All rows are Planned / NotRun. This is an evidence specification, not a newly
invented readiness schema or synthetic execution result.

| ID | Positive control | Targeted negative / required distinction |
|---|---|---|
| BQ-001 | Expected virtual account, exact reviewed local binding and actual intended level | Wrong account/relay must be rejected before transport impersonation authority is available; no manager entry or failed reply alone does not prove this ordering |
| BQ-002 | Standard issuing thread verified on the first RPC for each binding | Changed first-call identity, Identify-only token on stronger route, unexpected stronger control level, missing privilege or failed reversion must reject |
| BQ-003 | Exact retained server instance and installed generation linked by the resolved mechanism | Same-account stale instance, restart between bindings, association reuse and replay must not acquire authority; names/nonces/PIDs are not the proof |
| BQ-004 | Call-to-client-instance association with supported observation access | Exit/PID reuse and wrong process/logon/session must reject; retaining a newly opened process cannot retroactively authenticate the originating call |
| BQ-005 | Initial process/thread/token ownership and effective rights match an accepted creation-path model | Broad dangerous grants, owner WRITE_DAC bypass and inherited/already-open handles must be detected/accounted for; post-start repair or self-check is not historical isolation proof |
| BQ-006 | Exact allowed interface/operation, fixed bounded input and callback on every call | Wrong protocol/domain, null session, Low/foreign caller, malformed lengths/enums/reserved fields and callback-cache substitution reject |
| BQ-007 | Bounded call initiation, successful completion and independently available cancel | Hung initialization, deadline, disconnect, late success after cancel and double completion must not cause freed-buffer access, duplicate admission or false non-execution |
| BQ-008 | Demonstrated broker/fixture resource budgets and owned cleanup | Pre-unmarshal/runtime pressure, exhausted cancel reserve, unsupported limits and uncertain cleanup stop; application payload bounds are not total RPC/kernel bounds |

A case that cannot observe the required security ordering or creation interval
is NotDemonstrated, not Passed. A negative case needs a legitimate positive control
under the same reviewed configuration. A test cannot prove universal absence of
a race merely by failing to reproduce it. Missing platform guarantees or an
unresolved instance-binding algorithm remain design blockers even after bounded
experiments. Avoid destructive fault injection on the main computer.

### Evidence and publication boundary

For each future case retain exact source/configuration provenance, expected versus
observed outcome, coverage limitations and cleanup disposition. Private raw
records must remain outside Git and must not capture credentials, reusable tokens,
sensitive audit data or unrelated machine state. A publishable summary uses only
reviewed synthetic identities/placeholders and bounded enums/digests, with no real
SID, PID, username, absolute user path, raw descriptor, stdout/stderr or dump.
Do not fabricate a normalized result file for these unrun cases.

This checkpoint may preserve existing reviewed source and normalized synthetic
history. It does not rerun historical experiments, reclassify their negatives,
close any production gate or release a working Windows launcher. Automatic
backend execution remains disabled and no production service is installed.

Independent plan review: AcceptedDocumentaryQualificationPlanOnly on 2026-11-06.
The read-only reviewer checked section 10; no blocking documentary findings
remain. This accepts neither compilation/native execution nor installation and
does not close any runtime gate.

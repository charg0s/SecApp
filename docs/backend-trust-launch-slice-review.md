# BACKEND-TRUST-LAUNCH-SLICE1

Date: 2026-11-06. Continuation of D-058/D-059: offline verification of already
acquired public bytes, official advisory review and a concrete service-account
proposal. A subsequent, explicitly authorized one-image WinVerifyTrust helper was
compiled in memory and run cache-only, as recorded below. No backend execution,
service installation, token/Job/loader probe or change to Windows settings occurred.

Account update after D-061: [the current bootstrap proposal](broker-bootstrap-contract.md#8-d-061-scoped-service-account-rights-proposal)
uses a per-service virtual account for further design, allowing targeted service
rights only in a future exact, separately confirmed installation. The LocalService
proposal in section 3 is retained research history; no native/ownership/binding
gap is closed by the new permission. Trust findings and admission remain unchanged.

```text
GnuPgCrossCheck = PassedForFreshlyRetrievedKey
FreshKeyRetrieval = CompletedWithExplicitUserPermission
RevocationEvidence = NoneObservedInRetrievedKey
GlobalNonRevocationGuarantee = NotEstablished
PeManifest = highestAvailable
AuthenticodePeDigestBinding = MatchedSignedDigest
LegacyTimestampCryptography = BoundByCms
WindowsAuthenticodeCacheOnly = PassedForPinnedImage
FreshOnlineRevocation = NotChecked
AuthenticodeAcceptance = Pending
AdvisoryReview = PartialWithDependencyFollowup
HistoricalBrokerAccountCandidate = LocalService
ServiceToSupervisorRoute = DocumentedCandidate
SupervisorToBackendRoute = PendingFeasibility
StartupEventSourcePath = SourceReviewedRuntimeGuardPending
BrokerBootstrapContract = ProposedNotImplemented
NativeImplementationAdmission = BlockedPendingSliceReview
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
```

## 1. Additional byte-only verification

The input is the exact Windows AMD64 EXE from
[BACKEND-ACQUISITION-VERIFY1](backend-acquisition-verification.md), SHA-256
`3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32`.
The EXE was never invoked, including Version/Help. All private acquisition and
verification files remain outside Git.

Already installed GnuPG 2.4.9 was used with a new isolated home, no user options,
no agent autostart, no automatic key retrieval/import and cleared auto-key locate.
Only the previously acquired public key was imported into that disposable local
keybox; no personal keyring or system trust store was accessed/imported into.
No tool installation or PATH change was needed. The sandbox initially blocked
MSYS startup; its narrowly approved execution exception was not Windows elevation.

| Offline check | Observed result |
|---|---|
| Public-key import and `--check-sigs` | Exit 0; primary UID self-signature and encryption-subkey binding validated (`!`); no expiry field or revocation indicated in this cached material |
| Detached signature over exact EXE | Exit 0; GOODSIG and VALIDSIG, primary fingerprint `0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1` |
| Same signature over gzip instead | Exit 1; BADSIG |

GnuPG also returned TRUST_UNDEFINED. This is not a web-of-trust identity verdict;
publisher binding continues to rely on the separately checked official fingerprint.
The cached key could not establish absence of a later revocation. No keyserver
request occurred in the initial pass above. The subsequently authorized refresh
is recorded separately below; it does not alter the historical observations.

### Authorized fresh-key follow-up

The user explicitly approved the exact keyserver request. At
`2026-11-06T08:45:29.0121643Z`, the bounded HTTPS fetch from
[the fingerprint endpoint](https://keys.openpgp.org/vks/v1/by-fingerprint/0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1)
completed with HTTP 200, redirects disabled and a 4 MiB/40-second limit.
The public-key file was saved create-new outside Git; its 2658 bytes and SHA-256
`71f37f19312f543534f2eaadde63d1afe28ed2140c16fec85885f92597bbbee6`
match the previously acquired key. The
[official downloads page](https://docs.velociraptor.app/downloads/) was re-read
and still publishes fingerprint `0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1`.
EXE and detached-signature hashes were rechecked against the acquisition record.

A second new isolated GnuPG home was used, with the same no-options/no-agent/
no-auto-retrieval controls. The newly retrieved file, not the cached file, was
imported only into that external review keybox. The observed checks were:

- Exactly one primary public key; its recomputed fingerprint matches the pin.
- `--check-sigs`: exit 0, both the UID self-signature and encryption-subkey binding
  verified; no expiry or revoked status indicated in the returned material.
- Exact EXE detached signature: exit 0, GOODSIG and VALIDSIG for that fingerprint.
- Gzip supplied instead of EXE: exit 1, BADSIG, as expected.

TRUST_UNDEFINED remains the GnuPG web-of-trust result; no ownertrust was assigned.
The source of publisher identity is the separately checked official fingerprint,
not keyserver availability or a UID string. Fresh retrieval closes the missing
refresh step, but one server's response cannot prove globally complete revocation
publication, future key validity or absence of publisher/key compromise. The
evidence is **no revocation observed in the material retrieved at this time**,
not an unconditional non-revocation guarantee. Authenticode, dependency review
and launch acceptance are unchanged. No backend execution, system-key import,
UAC, service/ACL/settings change, new tool installation or Git index/commit/push
operation occurred.

Fresh-key follow-up review: AcceptedFreshKeyVerificationRecordOnly on 2026-11-06,
with no blocking findings. The read-only reviewer checked this documentary delta
against the reported observations, without repeating cryptographic verification.
Global non-revocation, Authenticode and runtime acceptance are not implied.

### Static Windows image observations

A one-shot reader inspected the already acquired file, rechecking its exact size
and full EXE hash after reading it, before parsing PE/resource and inline Go build
fields. Subsequent field traversal/string sizes were bounded; the initial whole-
file read was not a pre-allocation size guard. It loaded no PE module and created
no process from the input. These observations concern this exact asset, not an
accepted general/production PE parser, allocation defense or loader policy.

- Format: AMD64, PE32+.
- Manifest resource: type 24, ID 1, language 1033, 1051 bytes; SHA-256
  `f4e3dd0156714140401e30e772b30aef0822420701258b3fbc9f7e026109bc73`.
- The manifest contains `requestedExecutionLevel` = `highestAvailable` and
  `uiAccess` = `false`. This is static tag/attribute extraction from the selected
  resource, not full XML validation, Windows-loader interpretation, an observed
  UAC prompt or an effective-token test.
- Embedded build information: `go1.27.1`, `golang.org/x/net v0.58.0`,
  `GOOS=windows`, `GOARCH=amd64`, VCS revision
  `7d287b0b988b35657e1b401f7b2ffebaf60dbcae`, `vcs.modified=true`, module version
  `v0.77.3-0.20261004095043-7d287b0b988b+dirty`. Build strings are signed-file
  metadata, not a reproducible-build or exact source-correspondence proof.

In the initial CMS-only pass, the embedded signature was decoded with the existing .NET library and
`SignedCms.CheckSignature(true)` succeeded. The embedded signer certificate says
Rapid7 LLC, SHA-256
`8619486cd757c7035cbcaa97885b145f63d955220c5ba3bea25b4475be180df0`,
validity 2023-10-16 through 2026-12-04 (UTC); one legacy countersigner is present.
This checked CMS cryptography only: PE Authenticode digest binding, certificate
chain, timestamp trust and revocation were **not** accepted or checked here.
No WinVerifyTrust shim was compiled in that initial pass, no certificate was
installed and no online certificate retrieval occurred. Its CMS result alone did
not establish Windows-policy acceptance; the later cache-only check is separate.

### Authenticode PE digest and CMS follow-up

A separately reviewed one-shot PowerShell/.NET checker was run only on the
already acquired pinned EXE. Checker SHA-256:
`622887f457a7459fe51f6dcd5dfb719e01c315c5df00ac552616d76e023661ca`.
It loaded existing managed assemblies, not compiled C#/native code. No chain
engine, WinVerifyTrust, PE loading, backend execution, explicit certificate-store
enumeration/import, network request or file-writing API was invoked by the checker.

The same read-only file stream remained open while its exact 73422840-byte size
was checked before allocation, its bytes were read once, and its full SHA-256
was checked before parsing. The checker rejected unsupported layouts and
required nonempty contiguous raw sections, complete header bounds and one
aligned certificate table at EOF, with no section gaps or overlay. This input had
six nonempty raw sections. CMS input
was bounded and preauthenticated by the whole-file hash; post-Decode object-count
checks do not make this a universal hostile-input PE/CMS parser.

Following the [PE hash exclusion rules](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#appendix-a-calculating-authenticode-pe-image-hash),
it hashed the checked headers/ordered raw sections while excluding CheckSum,
the security-directory entry and certificate table. The calculated SHA-256
`b3d89b77d35d0f2a575d11958d82ceadcc74266aaeddc46998a5c35cdacee273`
matched the signed SHA-256 in the strictly parsed SpcIndirectDataContent.
This PE digest is deliberately different from the whole-file acquisition hash;
both checks remain required and neither is a mapped-process-image attestation.

The existing .NET CMS implementation verified the primary signature and one
legacy countersignature. The latter's single signed time is
`2026-10-04T10:08:57.0000000Z`, within the embedded signer/countersigner certificate
validity intervals. Required leaf EKUs for code signing and timestamping were
present. The countersigner certificate says DigiCert SHA256 RSA4096 Timestamp
Responder 2026 1. This is a cryptographically bound signed time, **not** a trusted
timestamp/chain or historical non-revocation determination.

| In-memory negative case | Observed result |
|---|---|
| Flip one byte covered by the PE image hash | Image digest no longer matches |
| Change primary signature bytes in a still-decodable CMS | CMS cryptography rejects |
| Change legacy countersignature bytes in a still-decodable CMS | CMS cryptography rejects |

The checker exited 0 only after positive verification and all three negatives.
Mutations existed only in memory. The buffer was restored, and an independent
post-run disk hash remained the original whole-file SHA-256. No tampered EXE,
signature, private data or raw output was written to Git or the acquisition files.

### Windows policy boundary before the authorized helper

Installed SignTool was located and only its `verify /?` help was run. It exposes
no documented cache-only switch, so it was not used to verify the image. The
existing `inspect-authenticode.ps1` was not run: it compiles a WinTrust shim and
performs additional checks outside this byte-only slice.

The installed .NET reports 10.0.11. The corresponding official
[chain implementation](https://raw.githubusercontent.com/dotnet/runtime/v10.0.11/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/X509Certificates/ChainPal.Windows.BuildChain.cs)
maps disabled downloads to DISABLE_AIA plus DISABLE_AUTH_ROOT_AUTO_UPDATE.
This clarifies root-update behavior but is not the general
[CACHE_ONLY_URL_RETRIEVAL contract](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain)
for all URL/CTL retrieval. No X509Chain.Build was attempted merely on that basis;
custom-root chain building would also not equal full Windows Authenticode policy.

At completion of the byte-only pass, the narrow permission request for a
separately reviewed cache-only WinVerifyTrust helper was still outstanding.
No such helper was compiled or run during that earlier pass. The subsequent
permission and execution are recorded below; neither the byte/CMS results nor
this exception authorize service installation or backend launch.

Byte-check follow-up review: AcceptedPinnedPeDigestAndCmsRecordOnly on 2026-11-06,
with no remaining blocking findings for this record. The read-only reviewer
reviewed the checker before execution and the reported results/documentary delta
afterward, without independently running it. Chain, revocation, Windows policy,
general-parser safety and runtime acceptance are not implied.

### Authorized cache-only WinVerifyTrust follow-up

The user explicitly approved compiling and running the separately reviewed
one-image helper without network retrieval, elevation or backend execution.
This is a narrow exception to the earlier helper-compilation restriction, not
permission for the historical trust-launch matrix or other native probes.

The reviewed PowerShell helper compiled its small C# P/Invoke wrapper in memory
with the existing runtime; no dependency or compiler installation was required.
Its source SHA-256 was
`6288b990c6f3e80e582e7f886ea17393d4535efab552ca25e932509ac01d9720`;
the separate runner SHA-256 was
`8786bf2b95ea0293124280a0dd08ac95421a6e7251ba5ebe40f2896eadb4e17f`.
Both sources, the working directory and child-only TEMP/TMP were outside all Git
repositories. The runner used a separate hidden normal-user PowerShell process
with no profile and a 30-second process-completion wait. That limit is not a
general production supervisor or a bound on arbitrary process creation/output.
The checker completed normally with exit 0; no timeout termination was needed.

The input was pinned to the same exact 73422840-byte EXE and whole-file SHA-256
above. One read-only, read-shared stream stayed open across both evaluations;
its handle was passed in
[WINTRUST_FILE_INFO](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info).
The helper checked the x64 structure sizes and loaded wintrust.dll from System32.
It selected WINTRUST_ACTION_GENERIC_VERIFY_V2 with WTD_UI_NONE and an invalid
window handle. Each VERIFY had a matching CLOSE; success was tested only as the
exact zero LONG required by
[WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust).

Both predeclared policies used WTD_CACHE_ONLY_URL_RETRIEVAL and
WTD_DISABLE_MD2_MD4. The revocation modes were selected explicitly through
dwProvFlags, following
[WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).
They were independent observations, not an error-triggered fallback:

| Policy | Provider flags | VERIFY | CLOSE |
|---|---|---|---|
| Revocation checking for the chain except its root, cache-only | `0x00003080` | `0x00000000` | `0x00000000` |
| No-revocation diagnostic, also cache-only | `0x00003010` | `0x00000000` | `0x00000000` |

The strict cache-only policy succeeded. The diagnostic row would not replace a
failure of that policy. Exit 0/Completed describes successful invocation of both
observations; their individual VERIFY codes determine their policy verdicts.
The same open stream's size/hash matched again after the calls, as did an
independent post-process disk hash. The 207-file repository fingerprint was
unchanged by execution, and the Git index remained empty.

This establishes Windows Authenticode acceptance for this pinned image under
these policies in the local trust/cache context at review time. It does not
establish fresh online or globally complete revocation knowledge, separately
audited per-certificate/timestamp-chain details, reproducible builds, absence of
vulnerabilities, SmartScreen/WDAC/AppLocker acceptance, safe startup effects or
binding to a mapped process image. No certificate import, trust-store repair,
network retry, backend invocation, UAC or system-settings change was performed.
No raw output, binary, signature, key or machine evidence is included in Git.

Pre-execution independent review: AcceptedCacheOnlyWinTrustExecutionForPinnedImageOnly
on 2026-11-06, with no blocking findings. The read-only reviewer checked both exact
source hashes without compiling or running them. Post-execution review:
AcceptedCacheOnlyWinTrustRecordForPinnedImageOnly on 2026-11-06, with no blocking
findings. This was a documentary check of the normalized delta against reported
results, not an independent repeat of execution. Overall Authenticode release
policy and runtime admission remain Pending and Blocked respectively; this result
does not implement or admit the launcher.

## 2. Advisory review: useful findings, no blanket safe-release verdict

The [publisher's advisory index](https://docs.velociraptor.app/announcements/advisories/)
and [release security summary](https://docs.velociraptor.app/announcements/advisories/v0-77-2/)
identify fixes in 0.77.3, including CVE-2026-78411/78412/78413. The summary also
contains older 0.77.2 text; its title is not a complete current dependency audit.
The [Prefetch advisory](https://docs.velociraptor.app/announcements/advisories/cve-2026-77797/)
lists affected Windows versions before 0.77.3. That narrow version statement is
not proof that all Windows parsers or all later dependency issues are safe.

[GHSA-9qq5-422f-33c2](https://github.com/Velocidex/velociraptor/security/advisories/GHSA-9qq5-422f-33c2)
describes server-side SQL permission bypass for versions through 0.77.1; its
patched-version field is None. Do not infer a patch solely from that record.
The proposed Version/Help slice does not expose a server/API/notebook, but
unreviewed initialization is not automatically exempted by the command name.

[Upstream issue 5070](https://github.com/Velocidex/velociraptor/issues/5070), opened
2026-10-10, reports Go/x/net dependency findings for a Linux/container 0.77.3
asset (CVE-2026-78667/78669/97031) and discusses dirty build metadata. Its author
explicitly leaves vulnerable-path reachability untested; the maintainer response
discusses build version stamping, not closure of every dependency finding.
Our Windows asset actually embeds Go 1.27.1, not the issue's Linux Go 1.26.8;
its x/net version is also 0.58.0. These are follow-up inputs, not a demonstrated
Windows exploit or proof of infection. Exact affected ranges, current upstream
fixes and reachability for the chosen operations remain PendingReview.

The [support policy](https://docs.velociraptor.app/docs/overview/support/) does
not guarantee unusual deployment configurations. SecApp's service/sandbox route
therefore needs its own evidence. No newer asset was selected or downloaded,
and no dependency was upgraded, vendored or rebuilt in this pass.

## 3. Concrete broker-account proposal, not installation approval

For the next narrow technical design, propose **NT AUTHORITY\LocalService** in
an own-process, demand-start service with a per-service SID. This explicitly
replaces the earlier virtual-account preference as the current **candidate**;
it is not an account fallback or an accepted deployment change. The service
direction and separate Standard user-session supervisor remain unchanged.

[LocalService](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account)
has documented impersonation, assign-primary-token and increase-quota privileges
(the latter two initially disabled), plus change-notify. Thus the candidate need
not depend on granting new user-rights. Its identity is shared with other
LocalService services: a service SID alone does not prove isolation from them.
Anonymous network credentials are not network denial.

Proposed removal-only required list: SeImpersonatePrivilege,
SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege and SeChangeNotifyPrivilege.
[Service privilege filtering](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow)
does not grant absent rights. Verify actual effective capabilities in the future
implementation; unexpected/missing rights block admission, with no runtime policy
repair, LocalSystem fallback, SeTcb/SeDebug/backup/restore or privilege transfer
to the supervisor/backend. Exact descriptors and effective-rights review remain.

The proposed token channel remains locally authenticated and separate from
identification-only control. Impersonate the bound caller only on the bounded
token thread; duplicate to a primary token; validate user/logon/session and
effective Standard rights; revert before ordinary broker work. Do not accept a
UI token handle, select another session, capture a password or rewrite session
IDs. Failure rejects; revert failure terminates the broker. D-058's exact
trusted-host confirmation and one-use binding still apply, not a caller ready flag.

[CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
is the candidate for broker-to-supervisor creation in the token's session,
with fixed protected application/environment/directory, suspended creation and
no inherited cross-session handles. Its privilege enablement does not grant a
missing right. [CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
does not substitute for this topology: it uses the caller's session, not the
token's session. No shell/runas or automatic UAC/shim fallback is proposed.

Require an already logged-on supported user session with a usable profile.
[LoadUserProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew)
would require backup/restore plus admin/LocalSystem and is not an allowed repair.
Do not substitute service HKCU/environment for the user's. Missing context blocks
this slice or yields honest NotTested for an independently allowed operation.

### Concrete bootstrap boundary for the next implementation review

The following narrows the candidate; it does not admit native execution. Use the
D-058 trusted-host assumption and D-056 ordinary exact Standard intent, not the
historical protected-confirmation-desktop prerequisite. Starting the service is
never approval to start a supervisor or backend.

| Boundary | Required construction | Refusal / excluded shortcut |
|---|---|---|
| SCM to broker | One own-process demand-start LocalService instance; protected installed image/policy; service SID; only the four justified privileges listed above | Missing/extra privileges, unknown installation ownership or another account block; no user-right grant, auto-start scan or LocalSystem fallback |
| Requester to broker | Bound local control channel plus separate SecurityImpersonation token exchange; requesting user/logon/session and exact process instance agree | No remote request, caller-provided token handle, session enumeration, password, delegation or identity-only-to-impersonation upgrade |
| Token handling | Dedicated bounded thread; duplicate the bound caller's token; validate effective Standard rights; revert before creation or ordinary broker work | Elevated caller, cross-user/session identity, failed impersonation or failed revert reject; revert failure terminates the broker |
| Broker to supervisor | CreateProcessAsUserW; explicit protected application path, mutable fixed command line, constructed Unicode allowlist environment and fixed working directory; suspended creation with STARTUPINFOEX | No shell/PATH lookup, inherited service environment, arbitrary arguments, profile loading or token-session rewrite |
| Session transport | Supervisor in the caller's existing session; bInheritHandles=false across Session 0; bounded local IPC bound to retained process handles and broker/action/generation | No service stdio handles passed across sessions, privileged handle transfer or numeric-PID-only authority |
| Lifetime ownership | Broker creates an unnamed noninheritable kill-on-close outer Job with reviewed limits before creation; PROC_THREAD_ATTRIBUTE_JOB_LIST assigns the supervisor during creation | No create-then-assign fallback; unsupported attribute, incompatible nesting or assignment failure rejects |
| Bootstrap authorization | Consume the frozen one-use offer with durable run/lease ownership before creation; verify suspended child identity/context before resume; authenticated bounded bootstrap after resume | A Hello/ready message is not consent, an installed-generation verdict or permission to create a worker |
| Supervisor to worker | Separately reviewed constrained own-token CreateProcessAsUser route, same-session exact handle list and fixed operation only | No assumption that the service's quota/assign-token rights transfer; failure cannot switch API/account, elevate or use RunAsInvoker |

The process-creation parameter requirements follow
[CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
The broker retains its returned process/thread handles; a later OpenProcess by
PID is not a substitute for instance ownership. Explicit object descriptors must
allow required supervisor self-token access without granting another user access.
They, exact desktop/window-station access, token-access masks and authenticated
peer-handshake fields still need implementation review; this table is not a
complete SDDL or wire protocol.

[Creation-time Job assignment](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
is the selected candidate instead of a post-create assignment gap. Keep the
broker out of the user-session Job; its first member establishes that Job's
session. The broker alone holds the outer Job handle; no copy goes to UI,
supervisor or worker. The same-session worker must remain in the inherited outer
Job with no breakaway. Supervisor loss triggers broker-owned tree termination;
broker loss closes its sole Job ownership. Completion still needs retained
process/Job accounting and confirmed quiescence, not pipe EOF alone.
[Job semantics](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-createjobobjectw).
Nested-Job compatibility, worker creation races, quotas and crash/durable-state
reconciliation remain Planned / NotRun, not proved by these API contracts.

The one-active-action, control-frame, offer-expiry, diagnostic 10-second timer,
64-KiB-per-stream and five-second cleanup-target rules remain those of the
[broker](service-launch-broker-design.md) and
[diagnostic contract](backend-diagnostic-contract.md). The diagnostic timer starts
before supervisor creation, not at backend resume. Concrete CPU/memory budgets,
effective object ownership, private buffers and preventive offline enforcement
are still required before a real operation; no unlimited placeholder is accepted.

### Transitive event-source and startup-effects disposition

Source scope: Velociraptor commit
`7d287b0b988b35657e1b401f7b2ffebaf60dbcae`.
Its [go.mod](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/go.mod)
selects golang.org/x/sys v0.48.0 without a replacement for that module.
This is source-level tracing, not proof of reproducible correspondence to the
asset's dirty build or a full imported-package initialization audit.

[main.go](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/main.go)
calls logArgv before parsing/dispatch. In
[admin_windows.go](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/admin_windows.go),
any installation error selects `.NET Runtime`, including an already-existing
source, not only access denial. It attempts one local Information event, ID 1000,
whose message contains JSON argv including argv[0]. A log error reaches stdout
before command output and must fail the unchanged strict diagnostic profile.
SecApp must not strip that prefix or retry automatically.
Successful fallback can hide an earlier partial installation: absence of an
error prefix or exit 0 is not evidence that no registry write occurred.

The exact installation branch is in
[x/sys eventlog/install.go](https://github.com/golang/sys/blob/v0.48.0/windows/svc/eventlog/install.go),
with its nonvolatile creation wrapper in
[registry/key.go](https://github.com/golang/sys/blob/v0.48.0/windows/registry/key.go):

| Step | Requested effect / branch |
|---|---|
| Open parent | HKLM `SYSTEM\CurrentControlSet\Services\EventLog\Application` with CREATE_SUB_KEY; failure returns before creation |
| Create/open source | Child `Velociraptor` with SET_VALUE; an existing child returns an error before value writes |
| New child only | Write `CustomSource` DWORD 1, `EventMessageFile` REG_EXPAND_SZ `%SystemRoot%\System32\EventCreate.exe`, then `TypesSupported` DWORD 7 |
| Intermediate failure | Return immediately; previously created key/values are not rolled back by this function |

`EventCreate.exe` is a message-resource reference here, not an executed child.
Pre-registering `Velociraptor` therefore does not fix fallback; SecApp's proposed
installation manifest must not add that registration merely as a workaround.
Do not modify or remove existing `Velociraptor`/`.NET Runtime` registrations.

[eventlog/log.go](https://github.com/golang/sys/blob/v0.48.0/windows/svc/eventlog/log.go)
opens locally through RegisterEventSource with a null server, then calls
ReportEvent with category 0, a null user-SID pointer, one message string and no
binary data. A deferred Close attempts DeregisterEventSource, but its error is
ignored by logArgv; this is not proof of successful close or persistence/flush.
Microsoft distinguishes this
handle operation from source installation: if a source is absent, the event
service can use the Application log without a matching description resource.
[RegisterEventSourceW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registereventsourcew).
An existing source can be routed to its configured log; do not universally
label the fallback as an Application event. Do not infer that every host permits
logging, that the event will be rendered correctly, or that null SID makes the
event anonymous. The same upstream file also defines InstallAuditlogger with
installation/fallback logic; its reachability and other initializers remain
part of the unfinished whole-startup review.

**Proposed runtime guard, not implemented or tested:** before backend creation,
establish that the exact proposed worker context cannot obtain CREATE_SUB_KEY on
that exact native registry parent. Use a separately reviewed read-only descriptor/
effective-access assessment; never invoke Install/CreateKey/SetValue as a probe.
The future check must bind the actual worker identity, restrictions and native
view, use proper registry access mapping, and distinguish API failure from a
successful assessment that denies access. Missing descriptors, unknown/unsupported
security semantics or granted creation access block this candidate, without ACL
repair or an elevated retry. Revalidate immediately before resume and reject a
detected policy/context change. Trusted-host assumptions do not turn an access
label or a stale check into a universal race-proof guarantee.
[AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)
requires an impersonation token and separate AccessStatus handling;
[RegCreateKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)
checks the key's security descriptor, not merely an earlier handle's access mask.
Neither API has been called for this proposal. This is a guard candidate for the
reviewed branch only, not preventive denial of arbitrary startup writes/network.

For a later explicitly confirmed diagnostic, disclose the normal local event-log
attempt and its OS-controlled retention/possible forwarding. Never promise that
private SecApp buffer deletion erases Windows logs or override host forwarding
policy. Keep argv restricted to the fixed Version/Help template and a protected
non-user-specific install path; no secrets, evidence paths, user-supplied values
or collection data. If those conditions cannot be met, block instead of silently
logging more. Collection arguments/effects need a separate review. SecApp must
not clear event logs on cancellation or uninstall. No backend was run and no
event source, registry value or Windows setting was changed to obtain this record.

Effects/bootstrap follow-up independent review:
AcceptedSourceEffectsAndBootstrapCandidateOnly on 2026-11-06, with no blocking
findings for the normalized documentary delta. The read-only reviewer checked
the pinned source chain, API contracts and candidate table without running a
backend/helper or probing the host. The runtime guard, composed launch route,
cleanup and offline/privacy boundary remain unaccepted; this is not native
implementation or installation admission.

## 4. What still prevents a complete launcher

- **Supervisor-to-worker creation:** the Standard supervisor does not have the
  broker's privileges. The [restricted own-token exception](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
  supports investigating CreateProcessAsUser, but it is not a blanket quota,
  manifest, desktop or loader guarantee. The actual `highestAvailable` asset
  must work without elevation, shim or rights expansion, or this route rejects.
- **Creation/lifetime gap:** suspended creation followed by Job assignment still
  has an unowned crash window. Consider creation-time
  [PROC_THREAD_ATTRIBUTE_JOB_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
  for a reviewed Windows 10+ API baseline, not a claim that all Windows 10 builds
  are supported/current. [Job session binding](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-createjobobjectw)
  follows the first assigned process; keep the Session 0 broker out of the
  user-session Job. Effective ownership, no breakaway and crash cleanup need proof.
- **Startup effects:** the event-source branch and partial-write/fallback cases
  are traced above. No pre-registration workaround is selected. Exact-worker
  no-write assessment, full imported initialization, disclosed logging/privacy
  and source-to-asset suitability still need acceptance before Version runs.
- **Offline and privacy:** neither LocalService, a restricted token nor a Job
  proves preventive network denial. No firewall/security-policy change, network
  proxy, plaintext evidence fallback or broadened collection is authorized here.
- **Trust and consent:** key-refresh/revocation policy and applicable Authenticode policy,
  advisory reachability, protected code/IPC and exact separate Version/Help intent
  remain applicable gates. No historical schema or planner flag is relaxed.

[BROKER-BOOTSTRAP-CONTRACT1](broker-bootstrap-contract.md) now details candidate
object/access masks, logon-scoped IPC pairing and supervisor-only resource limits.
It explicitly retains the pre-exposure token-server binding and initial broker
object-ownership gaps; none is closed by a late PID query or a later DACL change.
Next bounded work: resolve those gaps plus desktop, broker-wide resources and
recovery, then independently admit a compile-only bootstrap/control and Standard-
supervisor lifetime slice **without a backend entrypoint**. Neither documentary
review admits that implementation. Do not substitute another generic readiness
model for implementation. Native installation/testing
still needs its exact owned-object manifest, test effects and explicit approval;
none occurs now. Full runtime/release/launcher acceptance remains Blocked.

Independent review: AcceptedPartialTrustAndAccountProposalOnly on 2026-11-06,
with no remaining blocking findings for this record/proposal. The read-only
reviewer checked the data-reader method, related documentation and official
sources against the author's reported observations; verification was not repeated
by the reviewer. This does not accept a general parser, Authenticode, current
revocation, release, native/runtime implementation or installation.

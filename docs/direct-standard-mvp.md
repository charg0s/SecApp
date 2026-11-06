# DIRECT-STANDARD-MVP1

Date: 2026-11-06. D-062 records the user's explicit approval to remove the service
from the first-release critical path. It supersedes D-058/D-061's service direction
for this MVP, not the trusted-host limitation or hostile-input safety.
Service/elevated collection research is deferred, not Passed.

D-063 subsequently permits the pinned backend's scoped event-source registration
and normal startup logging. It does not authorize elevation or changes to audited
security settings. Additional permissions must be explained and requested; prefer
the supported straightforward route over complex workarounds to avoid asking.

D-064 later grants one user-confirmed elevated control run, described below. The
pure Standard route's admission flags stay unchanged; this is a separate scoped
development run, not a grant for general elevated collection.

```text
FirstReleaseTarget = DirectStandardMvp
ScopeDecision = ApprovedByUser
RequirementsReview = AcceptedRequirementsDirectMvpOnly
ServiceForMvp = Deferred
ElevatedCollectionForMvp = Deferred
PureAdapterAdmission = AcceptedPureDefenderAdapterPreviewSliceForImplementation
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
```

## Fixed finish line

One manually selected useful read-only Defender real-time status check on a
trusted Windows/session: display scope -> confirm -> run as the ordinary user ->
bounded result -> private report. Denied/unsupported data is NotTested; a report
containing only NotTested is not useful MVP completion. No protection-setting
change, service, UAC, account grant or elevated fallback belongs to this route.

Only three delivery slices are needed; service/RPC qualification is not one:

1. **Output to report:** bounded two-field adapter and private supplied-file
   preview. This pass implements that code, not a collector or fake success record.
2. **Direct process boundary:** authenticated fixed EXE/operation, actual Standard
   parent/child, bounded output/time/resources and owned cancellation/cleanup.
   Check manifest, startup effects and offline behavior without service-specific gates.
3. **One end-to-end acceptance:** explicit confirmation, useful supported live
   data, private report/minimal UI and targeted failure/cancel cases. No full audit,
   remediation or elevated coverage is implied.

Routine implementation and pure tests need no repeated general continuation
approval. Effects outside this scope still require exact agreement. Old native
runners, published schemas and planner flags are not the new admission authority.

## First code slice: supplied Defender output

The candidate fixed query selects only `AMRunningMode` and
`RealTimeProtectionEnabled` from `MSFT_MpComputerStatus` in local
`root/Microsoft/Windows/Defender`, with `LIMIT 2` to detect excess rows. No user
query, remote host, artifact name, config or arbitrary arguments are accepted.
It is not a runtime-approved command yet.

Pinned source revision: `7d287b0b988b35657e1b401f7b2ffebaf60dbcae`.
The [WMI implementation](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/vql/windows/wmi/wmi.go)
uses local ConnectServer/ExecQuery, materializes rows synchronously before returning,
and logs provider errors. VQL LIMIT is not a COM memory/time bound; permission
metadata is not a sandbox. The [query command](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/query.go)
supports JSONL but can load API configuration/use a remote route and defaults to
NullACLManager. Ambient config must not select that route. These two source reads
are partial collector-path evidence, not transitive runtime acceptance.

Microsoft documents Normal as active mode. Passive/Passive Mode and SxS Passive
Mode are not active protection for this rule; EDR Block Mode requires additional
context and is Unknown here. Realtime is an actual boolean, not a truthy string.
[Modes](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows),
[passive values](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-passive-mode),
[read-only WMI property](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpcomputerstatus).
Provider/version availability and Standard access are not tested yet.

The adapter accepts at most 4096 bytes before decode, one row of at most 1024 bytes,
bounded depth, strict UTF-8, no BOM, and LF or CRLF termination. Only the two named
fields are allowed. Missing/null/unknown values and zero bytes give NotTested;
wrong types, extra fields/rows, duplicate keys, invalid Unicode, truncated or
non-JSON output and excessive nesting reject. Unknown raw strings never enter
the report. Reuse the existing Defender rule, never fabricate an Observation,
CollectorExecution, accepted import or historical schema verdict.

The report is an internal frozen object rendered to text/HTML, not a new published
JSON contract, AuditRun or ExportManifest. It always states supplied-output preview;
provenance, freshness and successful collection are not established. Normal rows
cannot prove execution success without stderr/exit/cancel evidence. A future live
caller must reject failed/incomplete execution before assessment, not attach a
caller-provided verified flag to this preview.

```text
node tools/preview-defender-check.mjs --input tests/backend/fixtures/defender-normal.synthetic.jsonl
node tools/preview-defender-check.mjs --input tests/backend/fixtures/defender-normal.synthetic.jsonl --format html
node --test tests/backend/test-direct-defender-output.mjs
```

The fixture is synthetic. Preview reads an explicitly selected local regular file
with bounded reads; it rejects UNC/device/alternate-stream syntax and observed
symbolic links in ancestry. It assumes a genuinely local filesystem: drive-letter
syntax alone does not prove absence of mapped drives or hostile redirection.
Already-compromised same-user race resistance is not claimed. It never starts a
child, opens a browser, writes a report, uploads or changes Windows. Output is
SensitiveSecurityData; saving/retention/encryption is not implemented. HTML has
no scripts/external resources and uses a restrictive CSP. Exit 0 means the supplied
row could be assessed (including Concern), 2 means NotTested, 1 means rejection/
read/usage failure. It is not a health exit code.

## Remaining concrete launch work

### Implemented pure operation boundary (not a launcher)

`src/backend/direct-defender-operation.mjs` fixes the acquired candidate's digest
and size, the one query, relative empty config name/bytes, environment-name
allowlist and proposed OS limits. There is no arbitrary command/config argument,
spawn, shell, native call, runtime flag or externally supplied verified override.
The 30-second wall deadline, 3-second cleanup grace, 512 MiB Job committed-memory
limit (not physical memory) and one active backend process are requirements,
not enforcement by this pure module.
External Windows WMI providers are not children owned by that Job; terminating
the query client is not a promise to terminate work inside shared OS providers.

The output gate retains at most 4096 bytes in a fixed buffer, copies chunks,
requires both stream EOFs and zero exit, rejects any stderr, and makes failure
sticky. Timeout/cancel/transport/cleanup failure cannot be hidden by a normal row.
Startup error prefixes are not stripped. The buffer is cleared on completion or
rejection; this is best-effort owned-buffer clearing, not guaranteed process-memory
erasure. Empty supported output remains NotTested. Even a successful synthetic
event sequence returns only the existing SuppliedBackendOutput preview, not
proof of live collection, consent, origin, freshness or actual Job cleanup.

The pinned [loader](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/config/loader.go)
returns the first successfully loaded config; an explicitly selected file is
before Embedded/EnvLiteral/NullLoader in main.go. Therefore the candidate uses
`--config secapp-empty.config.yaml` with exactly `{}\n` and an environment built
from empty, with no API-config variable. This avoids relying on an empty
VELOCIRAPTOR_LITERAL_CONFIG to defeat earlier embedded loading. A future host must
create and hold the exact file in its private bound working directory; no file
is created by this module. Fixed relative config/argv0 avoid placing user paths
in the backend's startup argv event. Absence of a network setting in this config
is not an OS network sandbox or complete startup/network review.

Source-only follow-up also read pinned
[main.go](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/main.go),
[admin_windows.go](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/admin_windows.go),
[embedded.go](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/config/embedded.go)
and [tool startup](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/startup/tool.go).
Tool startup calls org/service and throttling initialization; those transitive
effects are not closed by selecting the WMI plugin. Registry installation is
attempted before command dispatch, regardless of this config choice. No real
backend, native helper or probe is executed in this implementation pass.

Independent static review: AcceptedPureDirectOperationOutputGateImplementationOnly;
no blocking findings for this pure slice. The author ran 97/97 direct tests (45
new) and the complete npm gate: 554 Node tests, no failures/skips, plus the four
validator stages. The reviewer did not run tests. Dependency inventory and
diff whitespace checks passed. No native/runtime acceptance, Git commit or push
is implied by those results.

The acquired v0.77.3 EXE requests highestAvailable; same-user is not proof of
Standard rights. No ShellExecute/runas, RunAsInvoker shim, manifest patch or
automatic elevation is currently authorized. The earlier restricted-own-token
CreateProcessAsUser route remains research, not the selected implementation.
Under D-063, prefer the standard supported launch route and ask for any concrete
additional permission before using it, instead of building a complex workaround
merely to avoid asking. A future permission request must distinguish logging
setup from elevation of the actual collection process.

### D-063 scoped event-source exception

The startup event-source installation attempt occurs before dispatch. The user
now permits that exact pinned attempt and normal startup logging, so proving
registry denial is no longer a launch requirement for this branch. Its allowed
target is `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Velociraptor`,
with new-key values `CustomSource` DWORD 1, `EventMessageFile` REG_EXPAND_SZ
`%SystemRoot%\System32\EventCreate.exe`, and `TypesSupported` DWORD 7. The upstream
source leaves existing registrations unchanged and can fall back to `.NET Runtime`.
This includes normal startup argv logging, not arbitrary logging of collected
data or secrets. Registration and events can persist; OS retention or configured
forwarding is not changed and no logs are erased. Do not imply that private-buffer
cleanup erases Windows events or that SecApp can guarantee host logging stays local.

No standalone registry installer, ACL repair, existing-source overwrite, elevated
retry or broader registry authority is granted. Partial registration on failure
is possible in the upstream path; do not report an unchanged system or silently
repair/roll it back. If extra rights are needed, explain the exact operation,
purpose, persistence and risks and ask first. This removes one permission blocker,
not the remaining startup/config/offline or owned-process lifecycle work. No
backend execution or Windows mutation occurred in this permission-recording pass.
The pure operation metadata reflects the exception but keeps executionAdmission
NotAccepted and does not enforce or mint product consent.

Independent static review: AcceptedScopedEventLogPermissionDeltaOnly, with no
blocking findings. The author ran 98/98 direct adapter/operation tests, including
a regression that logging permission cannot enable elevation, network or runtime
admission. This is not native execution evidence.

Independent admission: AcceptedRequirementsDirectMvpOnly and
AcceptedPureDefenderAdapterPreviewSliceForImplementation. This admits pure code,
file preview and synthetic tests, not a launcher/native test/collection.

Final static code review: AcceptedPureDefenderAdapterPreviewImplementationOnly.
The independent read-only reviewer found one CLI stream-error issue; it was fixed
and covered by two real Node-entrypoint tests. No blocking findings remain for
this preview slice. The author ran 52/52 synthetic/CLI tests with no skips; the
reviewer did not independently execute them. The two child processes in these
tests are only the literal Node preview CLI, never a native helper or backend.
This verdict does not accept the live collector, launcher or private persistence.

## D-064: one elevated control run

Permission: one fixed Defender operation through the normal UAC prompt, accepted
by the user. Only `SecAppDefenderControl.exe` and the pinned backend are elevated;
the PowerShell controller and SecApp result reader remain ordinary processes.
The locally compiled helper is unsigned: UAC may display Unknown publisher.
It is not a service and adds no account right, scheduled task, driver, PATH entry,
trust-store item or security-policy setting. Elevated execution is more powerful
than its fixed read-only purpose; this is explicitly not an OS read-only sandbox.

The new helper source, manifest and explicit controller are under
`tools/backend/defender-control`. They do not call the old native synthetic or
boundary runners. The helper takes only a GUID run ID and the controller's PID/
creation time, never a user-supplied executable, query, config or output path.
It holds the parent's process handle and compares actual SID/session; an elevated
controller, different UAC account/session, stale PID/time or missing parent fails
before backend creation. It does not use a linked/restricted token or grant rights.

Working data is under a new `C:\Dev\SecApp-Control-<run-id>` (D-065), outside Git:
the helper sources/manifest, compiled EXE, verified backend copy and bounded build
receipt; then a
create-new `attempted.once`, exact `secapp-empty.config.yaml` containing `{}\n`,
optional `cancel.request`, and at most 8192-byte `result.json`. The latter contains
SensitiveSecurityData (bounded backend output encoded as base64 is NOT encryption).
No automatic report export/upload occurs. Atomic directory creation supplies a
protected DACL and current-user owner, with exactly three inheritable FullControl
allow entries: current user, SYSTEM and Administrators. A collision fails without
reuse or repair. The directory's rights are checked immediately. Existing ancestor
ACLs are not changed. Nonlocal storage, missing persistent ACL support, reparse or
unexpected final paths fail. No existing file is overwritten. Native handles hold
the ancestor chain and leaf without delete sharing while active; this protects
against rename/delete, not all metadata mutation. Authenticated backend and config handles
deny writes/deletion for the run. Active same-user tampering is outside D-058's
trusted-host guarantee; this is not mapped-image or preventive DLL attestation.

The EXE is a streamed CREATE_NEW private copy of the previously acquired v0.77.3
asset; the original is unchanged and its ACL is not copied. Both are checked for
size 73422840 and SHA-256
`3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32`.
Signature/cache-only Windows verification is historical evidence, not freshly
checked online revocation. The helper rechecks exact bytes while holding the file.
The explicit application path, fixed quoted query, private cwd and empty-constructed
SystemRoot/WINDIR/TEMP/TMP environment avoid inherited config/command arguments.
No output/scoping/profile/trace/dump flags or API config are accepted.

The child starts suspended with Job-list and explicit three-handle stdio list at
creation. The Job is non-inherited, kill-on-close, no breakaway, one active backend
process and 512 MiB committed-memory ceiling. Pipes are alternately drained in
bounded polls; any stderr, >4096-byte stdout, nonzero exit, incomplete streams,
identity error, timeout or cancellation fails. The helper's 30-second monotonic
deadline includes preflight; a separate 40-second watchdog requests self-only
TerminateProcess if the main thread stalls, closing its Job without DLL detach.
This is not an absolute deadline guarantee under stalled kernel I/O. Cleanup has
at most 3 seconds and
must observe root exit/empty Job to count as complete. Parent death or an owned
cancel marker requests stop. An ordinary controller cannot assume permission to
kill an elevated helper, so it uses this cooperative channel/watchdog instead.
These limits do not govern shared external WMI providers or OS log retention.

Compile-only uses the existing Framework64 compiler with explicit references,
no restore/download, bounded compiler output and no helper/backend execution.
Before that compiler, an in-memory Reflection.Emit bridge defines only filesystem
Win32 imports; it does not run a disk-backed Add-Type/CodeDOM bootstrap compiler.
All actual helper compiler output/TEMP/TMP is in the newly private workspace.
RunPrepared accepts only a previously reviewed GUID/helper hash, locks that helper,
rejects a changed source/manifest and marks the attempt before invoking UAC.
No automatic retry occurs on cancellation/failure. Temporary files are removed
by exact owned-name cleanup only after confirmed helper exit and result handling;
unknown lifetime is a failure, not a reason to delete active files or kill by PID.

The bounded result reader uses strict JSON, exact keys/run ID, canonical base64,
complete lifecycle fields and the existing two-field parser. It labels the result
HelperReportedNotAttested; a supplied file cannot prove actual execution or mint
accepted Observation/AuditRun/provenance. The controller/run record is separate
evidence. Empty/unsupported data remains NotTested, never useful MVP completion.

Source follow-up review: AcceptedPinnedEmptyConfigQueryStartupSourceSliceOnly.
The reviewer traced explicit-file config selection, nil Datastore/API/front-end
paths, generic tool/org services, dummy inventory (HTTP client construction does
not issue a request; AddTool only changes memory), and local WMI. No additional
reachable registry/file write or network request was found in that selected startup
chain beyond allowed EventLog. This is not all-package-initializer analysis or
preventive network enforcement. See pinned
[org services](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/services/orgs/services.go),
[repository](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/services/repository/repository.go),
[dummy inventory](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/services/inventory/dummy.go).

The exact compile-only command received AcceptedDefenderControlCompileOnlyCommand.
Its first invocation refused the existing directory access policy with PRIVATE_ACCESS
before calling the compiler. No helper/backend was executed and no ACL was changed.
This was an authorization issue for creating a private owned workspace, not a reason
to accept broader file access or alter existing directories silently. D-065 now
authorizes only the new private workspace described above; the previous refusal
does not count as a build or run. A run-review watchdog finding was corrected from ExitProcess to a
self-only TerminateProcess; this correction is not runtime proof.

AppData workspace creation subsequently hit a normalized-path mismatch: the OS
redirected the new leaf into the desktop host's per-package LocalCache. Preparation
stopped before compilation, leaving only empty new directories. The fixed `C:\Dev`
development root avoids that AppData projection without disabling virtualization
or changing existing ACLs. The acquisition source is read-locked and byte-pinned,
not used as an execution directory; only the destination namespace must match its
literal execution path. See Microsoft's
[packaged desktop filesystem behavior](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-behind-the-scenes).

Historical pre-D-065 source review: AcceptedDefenderControlSourceReviewOnly after the watchdog
fix. The previous RunAdmission was BlockedPrivateWorkspace. The author ran 122/122 targeted Node
tests (24 new) and the full npm gate: 579 Node tests with no failures/skips plus
the validator stages. PowerShell parsing and diff whitespace checks passed. The
reviewer did not run tests. No compiler/helper/backend execution or UAC occurred.
The new ACL/path design received AcceptedNewPrivateWorkspaceDesignScopeOnly;
the concrete delta and eventual build/hash still need review before execution.
Do not infer a performed collection
from permission, source review or pure tests.

## D-064/D-065 observed control checkpoint (2026-11-06)

AcceptedFixedDevWorkspaceCompileOnlyCommand was followed by a successful
compile-only build in the new fixed development workspace. The original backend
remained unchanged; the new private copy passed exact size/hash verification.
The reviewer independently checked build receipt/hashes, six prepared files and
the protected three-entry DACL before AcceptedSingleD064DefenderControlRunCommand.

Exactly one RunPrepared attempt was then made through user-confirmed UAC. The
controller returned success and confirmed helper exit. The bounded helper receipt
reported Completed/NONE, backend creation/resume, exit code 0, root exit, empty Job
and closed pipes. The ordinary SecApp reader accepted the receipt and produced a
useful two-field result, not NotTested. The actual field values, raw transport,
working-path identifiers and machine evidence are deliberately not stored here.

After result handling and confirmed helper exit, exact owned-file cleanup removed
the temporary build/backend copy/config/result and new workspace. The empty
AppData-attempt directories created in this pass were also removed without
recursive deletion. The original acquired backend's SHA-256 was rechecked unchanged.
Existing folders/ACLs, other projects and Windows protection settings were not
modified by the implementation. D-063 EventLog registration/logging remained an
allowed backend side effect; no log erasure or retention change was performed.

Verification: 580/580 Node tests, zero failures/skips, all npm validation stages,
Windows PowerShell 5.1 parsing and whitespace checks passed. This is one successful
live development check, not production launcher acceptance, origin attestation by
the result-file parser, a compromised-host guarantee, or native timeout/cancellation
failure-path qualification. No automatic retry or later run is authorized by this
record. The following D-066 wrapper is a later source/synthetic-tested slice.

## D-066 interactive development command

Entry: `npm run check:defender` from this checkout in an ordinary interactive
Windows terminal; `-- --help` performs no preparation or collection. No dependencies,
downloads or installer are added. This development layout supports `C:\Windows`
and `C:\Dev`, with the previously acquired pinned backend at the existing acquisition
path. Another Windows root is rejected rather than choosing an executable from
an environment override. Ordinary controller enforcement remains in PowerShell.

The Node layer validates TTY/arguments before effects, verifies the pinned controller
and three native build inputs, and invokes only the fixed PowerShell/script with
`shell:false`. Prepare, run and discard have bounded private output and deadlines;
stdout/stderr errors, overflow, abort or unknown child close fail. Termination
requests target only the owned ordinary controller, never process names/trees;
they do not prove helper or compiler termination. Unknown lifetime retains data.

After a successful closed preparation process, strict JSON decoding requires the
exact build keys, nonce, hashes and `executed=false`. The immutable offer contains
the two fields, helper digest, scope, elevation power, D-063 effects and retention.
The typed one-use phrase confirms collection, not merely elevation; a separate
normal UAC prompt follows. The keyboard reader caps a chunk at 256 bytes and the
answer at 64 characters, rejects control input, restores raw mode and cancels on
EOF, terminal failure or timeout. Redirected input and `--yes` cannot confirm.

Each new prepared folder contains the historical six payload/build files plus an
empty `controller.lock`. The lock is held exclusively through prepare/run/discard.
DiscardPrepared only accepts that fresh seven-file set, a matching source/build/
backend pin and no attempted.once. RunPrepared remains single-attempt. C# sources
and the manifest are unchanged; the helper's existing lifetime rules still apply.

With CleanupOnSuccess the controller emits SecAppDefenderRunEnvelopeV1: exact run
ID, observed helper exit confirmation and actual exit code, data-files-removed flag,
`workspace_removed=false`, and the unmodified bounded inner result JSON as a string.
The Node decoder requires actual helper exit 0 AND a valid complete inner lifecycle;
controller exit 1 can represent only a cleanup failure, never a successful nonzero
helper exit. Missing coverage is still NotTested. Supplied transport alone remains
HelperReportedNotAttested, not cryptographic runtime provenance or an AuditRun.

Before data-file removal, the controller requires observed helper exit 0 plus an
anchored exact wire grammar, bound run ID, complete flags, elapsed bound and canonical
base64. Duplicate keys, extra fields and trailing data reject. Payload file handles
are released, but directory namespace handles and the operation lock stay held.
Only the exact checked file-name set is deleted; unknown entries cause refusal.
The private directory/zero-byte lock remain and are reported, not silently called
a fully removed workspace. Cleanup errors are visible; partial/failed deletion
is not retried automatically. No Windows log retention/erasure changes occur.

Tests for the Node flow use fake executors. Real CLI tests invoke only Node for
help, invalid arguments and non-TTY refusal; `npm test` never invokes PowerShell,
a compiler, UAC or Velociraptor. The separate Test-DefenderControlReceipt.ps1 extracts
only the pure regex/base64 function and exercises synthetic strings; it does not
execute controller top-level/filesystem/native code. Source/synthetic acceptance
does not prove this new wrapper's live UAC, cleanup, timeout or cancellation paths.
Its end-to-end operator acceptance required the fresh explicit D-067 run decision
recorded below; source/synthetic results alone did not grant it.

Independent source recheck accepted the implementation slice as
AcceptedInteractiveDefenderCliSourceAndSyntheticTestImplementationOnly. Both concrete
findings (environment-selected interpreter and missing actual helper exit code)
were fixed with negative coverage. Author verification passed 656/656 Node tests
(76 new), all npm validators, 26 pure PowerShell receipt vectors, UTF-8/LF and
whitespace checks. No native compilation, helper/backend execution or UAC was
performed for D-066; the reviewer did not execute tests. Dependency versions,
lockfile, published schemas, native C# sources and manifest are unchanged.

## D-067 observed interactive acceptance (2026-11-06)

The user separately authorized one real acceptance of the new command and retained
personal control of UAC. Repository/source-pin preflight passed. The exact existing
Velociraptor EventLog source and its three expected values were read before the run;
registration was already present, so no new source registration was required.
No protection setting, existing ACL, service or other project was changed.

One visible ordinary terminal invoked `npm.cmd run check:defender`. The operator
entered the displayed one-use collection phrase and confirmed UAC manually. The
agent neither typed confirmation nor controlled the security/terminal UI. The
outer terminal process propagated CLI exit 0 and its exit was observed. According
to the pinned implementation this means the actual helper exit/lifecycle, useful
two-field result and data-file removal checks all passed, rather than a cancellation,
NotTested outcome, unknown lifetime or cleanup warning.

Read-only postcondition checks found exactly one zero-byte controller.lock in the
new directory, with its private protected DACL intact. The source backend SHA-256
and the three inspected EventLog values were unchanged. The directory/coordination
file remain deliberately; workspace removal is not claimed. Log-event contents
and unrelated machine state were not collected or audited.

Evidence is the observed command exit plus filesystem/configuration postconditions,
not captured terminal text or independent visual acceptance. Actual security field
values and raw reports are not retained in Git. This single successful end-to-end
acceptance does not exercise native cancellation, timeout, UAC refusal, partial
cleanup or compromised-host cases, and does not authorize an automatic repeat.
No implementation change, dependency change, commit or push accompanied this run.

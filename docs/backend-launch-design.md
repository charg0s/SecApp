# Direct launch from SecApp: design reopened

Stages: `BACKEND-LAUNCH-PLAN1`, `BACKEND-NATIVE-SYNTHETIC1`,
`BACKEND-IMAGE-TRUST-DESIGN1`, then `PROTECTED-INSTALLER-DESIGN1`.
Status: planning boundary and isolated synthetic native experiment implemented;
production native execution not implemented.

Current first-release overlay: [D-058 / TRUSTED-HOST-MVP1](trusted-host-mvp.md)
defines the broader trusted-host assumption, development/install permissions and
the exact TL/LS/MMR applicability mapping. It supersedes D-056's confirmation-
only exception and the stronger-profile requirements below where explicitly
mapped. The existing planner remains a non-executing strict-profile diagnostic;
no old result/schema is promoted to MVP runtime authority. Basic safe launch,
binary trust, effects, data protection and cleanup still require acceptance.

[BACKEND-DIAGNOSTIC-CONTRACT1](backend-diagnostic-contract.md) refines the first
Version/Help operation, output matching and required current release review.
It does not enable the planner or waive the pre-execution gates below.

The user explicitly lifted the restriction on developing direct Velociraptor
launch from SecApp. This is the current decision, superseding the historical
work deferral in D-028. Development permission and technical readiness are
separate: no failed/unknown invariant is accepted merely because work resumed.

```text
TrustLaunchStatus = DesignReopened
BackendLaunchDevelopment = Authorized
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
VelociraptorInvocationFromSecApp = BlockedPendingTechnicalGates
ProductPaths = ImportOnlyAndDirectLaunchDevelopment
```

The target product also preserves an optional explicitly consented Elevated
pass (D-033). Non-elevated launch is the default path, not a permanent ban on
administrative checks. The current planner remains diagnostic-only and does
not implement either native launch mode.

The planning pass performed repository work and synthetic Node tests only. It did not
launch Velociraptor, compile/run the C#/PowerShell helper, run native probes,
download anything, collect host data, request UAC, alter Windows settings,
install dependencies, or commit/push. The old prototype source and normalized
contract are retained as historical evidence, not wired into the product.

The later, separately authorized native-synthetic stage compiles a new
self-launch-only helper outside the repository. Ten bounded cases passed in
three runs of the final source. No Velociraptor, old TrustLaunchProbe matrix,
UAC, DLL/module/reparse probe, installation, network or Windows modification
was used. The [experiment record and limits](../tests/backend/native-synthetic/README.md)
are development evidence, not production readiness or permission for a backend
handshake. Only pure normalized-record validation joins npm test.

The following [image/root trust design](backend-image-trust-design.md) reviews
official API guarantees and specifies sixteen future acceptance vectors,
all NotRun. Protected versioned installation is now the user-approved design
direction under DEPLOY-001, not a complete isolation proof. The
[installer design](protected-installation-design.md) specifies maintenance scope,
permissions and update/recovery requirements, with 22 Planned/NotRun cases.
The subsequent [maintenance protocol design](maintenance-protocol-design.md)
proposes helper-owned confirmation and protected replay/recovery state. Its
28 protocol cases are Planned/NotRun. It is not the collector/supervisor IPC
protocol and cannot authorize a Standard or Elevated backend invocation.
No installer, administrative action, native test or runtime authority is added.
File placement, loader prevention, process/IPC trust and mapped-byte evidence
are distinct obligations. The current nine gates and planner remain unchanged.

The later D-052 decision approves the separate-identity SCM broker for design
only. [SERVICE-LAUNCH-BROKER-DESIGN1](service-launch-broker-design.md) refines the
Standard supervisor/session boundary without authorizing implementation,
installation or a real backend launch. The no-service wording of the initial
stage is superseded only for this component; technical acceptance remains open.

## Implemented planning boundary

`src/backend/launch-plan.mjs` produces a strict public diagnostic plan from
only an operation enum and optional lowering-only resource limits. Version and
Help map to the exact argument arrays retained by the compatibility experiment.
No binary is located, opened, verified, or executed. Its v0.77.1 identity is a
historical compatibility pin, not a claim about the current release or any
installed executable. An independent current suitability/trust review remains
mandatory before a real launch.

The planner has no executable path, raw argument/VQL/config/artifact input,
environment override, readiness callback, or force flag. It rejects unknown
fields, inherited/non-data properties, proxies, duplicate CLI options, and
invalid/increased limits. Limits are at most 10 seconds and 64 KiB per output
stream; these are proposed diagnostic ceilings, not a claim of enforced native
resource limits. Every valid plan currently says Blocked and execution_enabled
false, lists all nine blockers, and records binary_verification NotPerformed.

`schemas/backend/launch-plan.schema.json` defines the Draft 2020-12 contract.
The deterministic JCS SHA-256 excludes only `plan_digest`. This detects plan
changes relative to its digest; it is not a signature, trust anchor, or launch
capability. A modified plan must never be accepted by a future native boundary
as evidence that runtime checks succeeded. Freezing objects prevents accidental
mutation in this API, not malicious modification of SecApp itself.

```text
node tools/plan-backend-launch.mjs --operation Version --json
node tools/plan-backend-launch.mjs --operation Help --timeout-ms 5000
npm run test:backend-plan
```

Exit codes: 0 for help, 2 for a valid but technically blocked plan, 64 for
invalid arguments, 1 for an internal failure. Error output excludes request
values. The planner writes stdout only and supplies no authorization to execute
the emitted argv elsewhere. Ordinary import/assessment stays independent.

`command_template.elevation: Forbidden` is scoped to the registered Version
and Help diagnostics. It is not a global product policy and must not be widened
to implement elevation by changing one flag. A future elevated collection path
needs its own reviewed request/consent contract and runtime boundary.

## Standard and explicitly consented Elevated passes

This design follows the existing AuditPass and ConsentReceipt model in
[architecture.md](architecture.md), without changing the immutable core schemas:

- Standard is first and uses only StandardUser CollectorExecutions. It never
  silently retries a denied read with administrative rights.
- Elevated is optional and separately selected. It contains only approved
  Elevated CollectorExecutions, after the required Standard prerequisite.
- The user is shown the exact checks, why each needs additional rights, what
  data will be read, and the operational limits before confirming. A batch UI
  may approve a displayed set, but each action needs its own correctly bound
  single-use authority; there is no reusable "allow everything" receipt.
- Administrative ConsentReceipt uses CollectPrivilegedReadOnly and the existing
  run/pass/action/host/collector/digest/expiry/nonce bindings. Application-level
  validation must enforce those bindings in addition to local schema checks.
- The application confirmation and the Windows elevation mechanism are distinct
  gates. A UAC approval alone does not describe approved collector scope; an
  already-elevated parent is not a substitute for fresh scoped user consent.
- The UI, import/parser, and report renderer remain unprivileged. A reviewed,
  narrow, short-lived elevated helper owns only the approved work, enforces
  fixed commands, revalidates identity and scope, and terminates with its owned
  process tree. This does not authorize an elevated service or blanket elevated
  application. The later D-052 Standard launch-broker design is separate and
  cannot consume this Elevated authority or replace its explicit consent.
- Decline, cancelled/failed elevation, insufficient rights, scope mismatch, or
  expired consent must not trigger another method or an automatic prompt loop.
  Record the applicable skipped/cancelled/failed execution state; unperformed
  checks remain NotTested. Retain valid Standard observations and report the
  coverage gap, not a clean result. Any retry requires a new explicit action.
- Administrative consent does not authorize NetworkAccess, DefenderScan,
  DefenderOffline, MemoryAcquisition, SensitiveDataCollection, Reboot,
  Remediation, or Export. Each required additional authority stays separate.
  The initial Elevated collection pass remains read-only and offline.
- "All necessary rights" means the minimum reviewed rights required by the
  selected check, not implicit SYSTEM/TrustedInstaller authority, driver
  installation, disabling security controls, or bypassing protected resources.
  Any such additional mechanism would need its own separate design and approval.
  Missing access remains
  a coverage limitation, even after an administrative pass.

The elevated boundary must apply its own stronger process/image/root/IPC trust
requirements; user confirmation does not waive DLL, reparse, image-binding,
handle, resource, or cleanup checks. The elevated helper must not accept paths,
commands, or capabilities solely because an unprivileged caller supplied them.
The exact Windows elevation API, helper trust/installation model, authenticated
IPC, cancellation semantics, and replay store are still to be selected and
independently reviewed. No UAC request or elevated operation is authorized by
this documentation update or by the user's approval of the future feature.

Required future acceptance cases include successful scoped elevation, decline,
UAC cancellation/failure, already-elevated parent without scoped consent,
cross-run/pass/collector/digest substitution, expired/replayed receipts,
foreign consent-type substitution, rights mismatch, helper crash/timeout,
cleanup failure, and Standard-result preservation. A wider scope always
requires a new user decision; unavailable checks never become safe results.

## Intended execution architecture (not yet implemented)

Keep the user-facing orchestration and untrusted-output parsing in SecApp.
Introduce a narrowly scoped native process supervisor to own the Windows
process, thread, token, Job, image/root locks, and explicit pipe handles for
one operation. This is a responsibility boundary, not an approved Windows
launch API or token-selection mechanism. Those decisions remain open.

The supervisor must independently enforce registered commands, binary identity,
privilege, allowed environment, working-directory policy, limits, cancellation,
and cleanup. A client-provided boolean such as verified/ready/approved, the
existing JSON contract, or a passed diagnostic test cannot replace its checks.
Requests and results need a reviewed bounded protocol with exact run/action
binding and replay handling before implementation; arbitrary paths/commands
must not cross that boundary. D-052 now approves the narrow SCM launch broker
for design, superseding this document's original no-service direction only for
that component. See [its roles, token/session and protocol boundaries](service-launch-broker-design.md).
No remote server, gRPC credentials, automatic startup scan, scheduled/background
collection agent or elevated fallback is selected. Service implementation and
host installation remain unauthorized. This does not remove the separate
user-selected Elevated path specified above.

Do not wire `Invoke-TrustLaunchPrototype.ps1` into a launch button: it discovers
a compiler and runs a diagnostic suite, not a single product operation. Do not
promote its `RunAsInvoker` compatibility observation into a production mechanism.
D-056 explicitly narrows only the Standard confirmation claim for the trusted
local MVP, as specified in its scope overlay. Do not drop other same-user/file/
process threats or weaken loader, token, maintenance or Elevated requirements
by implication. Any further reduction needs an explicit reviewed decision;
administrative rights are not a fallback.

## Required lifecycle

The following are requirements, not implemented state-machine claims:

| State | Required condition before advancing |
|---|---|
| Requested | Explicit registered operation, bounded parameters, exact action authority; never an implicit startup action |
| Prepared | Reviewed private root/temp/output lifecycle; stable owned handles; no unexpected reparse/adjacent content; reviewed offline enforcement |
| Verified | Exact current source/copy identity and bytes authenticated under the reviewed release/signature policy; locks retained |
| Suspended | Child created without unintended elevation and with required Job/handle/loader constraints applied before workload |
| PreResumeChecked | Required token, Job, handle, image identity, initial inventory, and preventive loader policy checks pass; no Unknown accepted |
| Running | Explicit resume; bounded stream draining and deadline/cancellation enforcement; runtime observation is supplemental |
| Stopping | Timeout, cancellation, output/identity/policy violation, or normal exit initiates bounded whole-tree cleanup |
| Reaped | Confirm no live descendants, close owned handles, apply reviewed private-output lifecycle; cleanup failure cannot report success |
| Parsed | Bounded strict parser verifies command-specific output and expected identity; process exit zero alone is insufficient |

Every failure before resume must terminate/reap a created suspended child.
Every post-create failure must follow a bounded cleanup path, including pipes
held open by descendants. No branch may fall back to an unrestricted process,
shell, elevated token, shim, or weaker policy. Runtime module observation cannot
undo code that already loaded. Reopening an image path and matching a file ID
is not accepted as proof that those verified bytes are the mapped image.

## Historical blockers and required closure evidence

All nine remain open. The new synthetic stage checks a narrower effective-rights
predicate and bounded process-tree lifecycle; it does not re-run the old trust
matrix or close any listed production gate. In particular, linked-token metadata
remained Present even though the synthetic child was not effectively elevated.

| Planner gate | Closure evidence required |
|---|---|
| TL-ADJACENT-DLL | Demonstrated execution-root/loader policy against placement by the in-scope concurrent adversary |
| TL-LINKED-TOKEN | Reviewed token criteria and child-token evidence meeting them, not merely an elevation label |
| TL-NON-ELEVATED-MECHANISM | Selected mechanism with standard-user/admin-capable-parent behavior, no UAC or compatibility fallback |
| TL-REPARSE-REPLACEMENT | Handle/root lifetime design plus replacement-race negatives; path-string checks are insufficient |
| TL-INITIAL-INVENTORY | Initial inventory at the required pre-resume boundary, with failure handled before workload |
| TL-PREVENTIVE-LOAD-POLICY | Preventive policy for future image loads; monitoring alone does not close this gate |
| TL-UNKNOWN-MODULES | Explain/classify the four historical Unknown modules under a reviewed allow policy; never allow Unknown generically |
| TL-IMAGE-BYTE-BINDING | Reviewed binding from authenticated bytes to the created process image, including concurrent substitution negatives |
| TL-PRODUCTION-LOAD-CONTEXT | Composed production-safe directory/environment/image-load design and negative evidence |

Static inspection found that `RunModuleObservation`'s diagnostic result
logic can label an inventory Pass while retaining Unknown modules (see the
`INITIAL_MODULES_CLASSIFIED_WITH_UNKNOWN_MAIN_FILE_ID_REOPENED` and
`RUNTIME_MODULES_CLASSIFIED_WITH_UNKNOWN` result codes in TrustLaunchProbe.cs).
That historical diagnostic behavior is not production readiness. The new plan
keeps the Unknown gate open and does not consume these Pass labels.

Additional launch prerequisites remain: a reviewed supervisor implementation,
current binary trust verification, private run-storage policy, offline
enforcement, bounded output/tree cleanup, exact action authorization, and
independent launch review. Prior successful Job/cleanup observations remain
useful but do not prove the new composed implementation.

## Implementation sequence and acceptance

1. Planning boundary (this stage): fixed diagnostic operations, immutable pins,
   lowering-only limits, exact blockers, strict schema, no execution. Synthetic
   tests must reject override, command/pin substitution, and readiness promotion.
2. Native boundary design: select the token/launch and preventive loader/root
   strategy against the explicitly scoped threat model; resolve feasibility with pinned
   authoritative API documentation before choosing implementation calls. No
   low-level mechanism is declared approved by this document. The image-trust
   design now records API facts, rejected shortcuts and the user-approved
   protected-installation direction. Installer lifecycle design follows; neither
   design authorizes deployment or weakens the gates.
3. Supervisor implementation and controlled evidence: separately scoped native
   compile/tests, resource/cleanup negatives, and closure of all applicable
   launch gates. Keep binary-backed material outside Git; preserve only
   normalized non-sensitive results. BACKEND-NATIVE-SYNTHETIC1 now provides a
   narrow self-launch experiment, not the production supervisor. Independent
   review and the unresolved trust design still precede readiness.
4. First real backend handshake: separately authorized Version, then Help,
   checking exact observed identity and bounded output. No machine collectors.
5. Synthetic collection: separately reviewed constant artifact and result
   framing/normalization; silent success or missing rows must fail closed.
6. Read-only protection collection: reviewed source/capability graph and exact
   parameters for each chosen collector, supported-platform matrix, privacy
   policy, and mapping into existing Observation payloads. Defender, Firewall,
   BitLocker, and Secure Boot rules alone do not provide these collectors.
7. Optional Elevated collection: design the consent UI and narrow elevated
   helper alongside the standard path; enable the additional pass only after
   its own IPC/trust/authorization/cleanup review and positive/negative evidence.
   Preserve Standard results and explicit NotTested coverage on refusal or
   failure. Do not make elevation a hidden retry of step 6.

This ordering reopens direct-launch work while keeping the current importer
usable. Completing planning is not completing the launcher. No real-host result,
production readiness, or closed native security blocker is claimed here.

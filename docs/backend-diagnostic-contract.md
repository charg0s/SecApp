# BACKEND-DIAGNOSTIC-CONTRACT1

Current precedence: [D-058 / TRUSTED-HOST-MVP1](trusted-host-mvp.md) supersedes
this contract's blanket permission restrictions and strict TL/LS/MMR gate
applicability. Keep its fixed operations, per-operation output/consent profiles,
limits, trust-before-execution, privacy and cleanup semantics. Its prior review
does not cover the later scope revision, and no executable contract is added.

Date: 2026-11-06. Scope: the first real-operation contract after D-056's
[trusted-local MVP decision](trusted-local-mvp.md). This is a design contract,
not a launcher, installed policy, executable request schema or new native result.
It does not accept the complete service architecture or close any launch gate.

```text
ContractStatus = AcceptedDocumentaryDiagnosticContractOnly
FirstOperation = Version
SecondOperation = HelpWithSeparateConfirmation
RuntimeReleaseSelection = PendingCurrentReview
RuntimeAcceptance = BlockedPendingRemainingGates
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
HostDeployment = NotAuthorized
```

## 1. One diagnostic action, not an audit

The first integration must prove a bounded round trip for one registered
diagnostic, without registering a collector or querying Windows protection data.
Version and Help have disjoint exact action bindings. Completing Version cannot
automatically start Help, unlock collection, mark a host safe or enable later
execution. Installation, startup, opening a report and GetCapabilities cannot
start either operation. There is no retry with another binary, API or privilege.

Use the D-052 service/supervisor direction with the D-056 ordinary Standard
exact-intent confirmation assumption. All other launch, privacy and lifecycle
requirements stay in force. A successful command cannot prove the mechanisms
needed to launch that very command safely; those checks precede it.

The user-facing purpose is "check the approved backend's reported build" or
"check the approved backend's command-line help format", not "scan this PC".
No Defender scan, reboot, network, memory acquisition, remediation, export or
Elevated authority belongs to these actions. No AuditPass/CollectorExecution,
Observation or ConsentReceipt is fabricated to represent a diagnostic.

## 2. Fixed invocation and scope

The following arrays are already retained in the non-executing
[planner](../src/backend/launch-plan.mjs) and
[historical compatibility contract](../tests/compatibility/expected/compatibility-contract.json).
They are proposed templates for the first reviewed runtime release, not a claim
that any other release implements them identically.

| Operation | Exact argument array | Required successful stream shape |
|---|---|---|
| Version | `["--nobanner", "--nocolor", "version"]` | Exit 0; stdout matches the selected release's exact Version profile; stderr empty |
| Help | `["--nobanner", "--nocolor", "--help"]` | Exit 0; stdout empty; stderr matches the selected release's exact Help profile |

No shell, command-line concatenation from caller data, stdin, arbitrary subcommand,
path, config, VQL, artifact, output destination or environment override. The
supervisor derives the explicit application path from its protected installed
generation; command-line serialization still needs review for that native API.
The UI chooses only the operation and existing lowering-only limits. Broker-owned
run/action bindings and the exact frozen offer follow the MVP protocol.

Help is available only after an accepted Version result for the same authenticated
generation, release/asset and policy. It still requires a new offer, confirmation,
admission and current launch checks. A changed generation/policy invalidates that
compatibility prerequisite. A saved JSON result or copied digest cannot satisfy it.
The initial slice retains that prerequisite only within the current bound broker/
UI session; restart or disconnect requires a fresh explicit Version action.

Do not copy the historical harness environment into production. In particular,
`__COMPAT_LAYER=RunAsInvoker` is not the selected launch mechanism. The reviewed
allowlist must exclude inherited configuration/secrets and define every required
profile/temp/locale value; a broker must not expose its service profile as the
requester's profile. No PATH search or user-writable code/config lookup is allowed.

Even `version`/`--help` pass through program startup. Before runtime admission,
review the selected release's manifest, global initialization and both command
handlers, including transitive configuration discovery, plugins, file writes,
update/telemetry/network behavior and child creation. "No collector requested"
does not prove no side effects. If the unchanged backend cannot meet the reviewed
scope, reject it; do not add a shim, config flag or patch to make the test pass.

## 3. Three distinct identity checks

1. **Source/release suitability:** select a currently reviewed official release,
   resolve its tag to an exact source revision, and review the diagnostic startup
   path and supported Windows/architecture matrix. This pass selects no release
   and performs no upstream retrieval. Historical v0.77.1 is not current approval.
2. **Pre-execution asset trust:** independently authenticate the official asset,
   whole-file bytes, allowed signer/key identity and protected release policy,
   including rollback floor, expiry and offline trust/revocation limitations.
   Source identity, Authenticode identity and detached-signature identity are
   different evidence. An old cache/signature result is not a current verdict.
3. **Post-execution compatibility:** compare bounded reported build/help data
   against that already-authenticated release's fixed output profiles. These
   strings are claims made by the program, not proof of signer, provenance or
   authenticated-bytes-to-mapped-image binding.

Steps 1-2 and the existing image/loader gates must pass before executing step 3.
Do not run Version first to decide which executable should have been trusted.
No network fallback during launch, no fetched trust material from the worker,
and no UI-supplied `ready`, `verified`, digest or release selector may bypass this.
The offline trust-update/acquisition workflow remains a separate reviewed scope.

## 4. Bounded output and release-specific parsing

Existing proposed ceilings remain 10,000 ms and 65,536 bytes per stream, with
caller reductions only. Count raw bytes before decoding/allocation; stdout and
stderr are independently bounded and drained concurrently. A merged stream,
replacement-character decoding or truncation-as-success is forbidden.

For this proposed implementation, the operation timer starts immediately before
the first per-action supervisor creation and covers bootstrap, suspended-child
checks, workload and normal draining. Within one action it is not reset at resume
or on output. A separately admitted Help action has its own bound timer; it cannot
extend or reuse Version's authority. Stop/cleanup has the broker design's separate
five-second target; inability to prove quiescence stays blocked, not a promise that all processes can always
be killed within that time. Offer expiry remains its separate 30-second limit.

Before implementation, fix and review memory/CPU/process-allocation budgets and
their actual enforcement in the composed boundary. No additional backend child
is required or permitted by these diagnostic templates. Any required exception
needs its own review. Missing enforceable budgets are a blocking prerequisite,
not permission for unbounded resources or a silently enlarged limit.

All output is untrusted private transient data until validation. Do not label it
Public because the intended command reports a build: an error could include
private paths or other unexpected data. Keep raw bytes out of privileged parsers,
normal logs, reports, telemetry, Git and persistent plaintext files. Redacted
codes/byte counts are the normal result; discard raw buffers after terminal
processing under the reviewed storage policy. No secure-memory-erasure, paging
or crash-dump guarantee is implied. Required private storage/key/crash handling
still blocks runtime; this document does not exempt diagnostics from it.

Each operation needs its own independently reviewed, immutable output profile
in protected policy before its launch offer can be produced. A missing/unsupported
Help profile blocks Help, not an otherwise eligible Version action; no automatic
Help probe may be used to obtain that missing profile:

- **Version profile:** exact ordered field names, scalar values, separators,
  quoting, line endings and final-newline rule for that asset. Use a bounded
  seven-scalar recognizer if the historical form is retained; do not load general
  YAML, allow tags/aliases/nesting, infer types, ignore unknown fields or accept
  duplicate fields. Match complete input, not a version substring. Strict UTF-8,
  no BOM/NUL/escape controls; normalization is only what the profile explicitly
  permits. No implicit trimming, Unicode normalization or prefix matching.
- **Help profile:** expected stream, exit code, exact length and SHA-256 over the
  complete raw bytes for a fixed reviewed locale/environment. A protected exact
  digest is a compatibility check, not an authenticity anchor by itself. No
  command discovery, hyperlinks, HTML/terminal rendering or dynamic registration
  from help text. If the release cannot provide a stable bounded profile, keep
  Help unsupported pending a separately reviewed parser, not "any nonempty text".

The [historical observation](velociraptor-adapter-compatibility.md#4-release-source-and-runtime-identity)
reported `velociraptor`, `0.77.1`, commit `3137c7f71`, build time
`2026-06-22T15:35:00Z`, compiler `go1.25.3`, `windows`, `amd64` in that order.
Its Version stdout was 143 bytes; its Help stderr was 3,624 bytes, with the other
stream empty and exit 0 in both cases. Those counts and the documented values
are historical observations, not complete accepted output profiles. The retained
record does not establish a Help byte digest or a fully specified Version byte
grammar; do not reconstruct production acceptance by guessing omitted bytes.

After matching, expose only the expected bounded registry values plus match
status, operation/action binding and lifecycle/error metadata. Help success
means "expected diagnostic format matched", not "all advertised commands allowed".
Never display raw failures or substitute attacker text into the confirmation UI.

## 5. Admission, completion and result meaning

One confirmation authorizes one invocation, once. It binds authenticated material,
operation, exact limits, policy/generation, expected output-profile digest, data/
storage/effect scope and the requesting session. Present the exclusions and
trusted-session limitation before confirmation. Changes invalidate the offer.
Foreign collection, SensitiveDataCollection, maintenance or Administrative receipts
cannot substitute for this diagnostic intent; diagnostic intent grants none of them.

Use the existing broker-owned consume-before-create admission, deployment lease,
suspended creation, pre-resume gates, bounded draining, whole-tree cleanup and
restart reconciliation. No fallback to a direct UI child, detached execution,
automatic retry, cached approval or service-account backend. Cancellation and
UI/broker/supervisor disconnect/crash handling remain mandatory.

The following are semantic outcomes for a future contract, **not new values in
an existing schema**. Terminal reporting keeps operation outcome and cleanup
certainty separate; cleanup failure/uncertainty always prevents success and
further admission, even after exit 0 and valid text. Retain the original cause
as a redacted reason; later cleanup trouble must not erase a timeout or cancel.

| Condition | Required meaning; no automatic recovery action |
|---|---|
| Absent/failed release, launch, storage, consent or policy prerequisite that must be checked before creation | Blocked; no backend creation, explain the failed gate without sensitive values |
| Decline/expiry before admission | NotStarted; no execution or consumed reusable permission |
| Create/bootstrap/pre-resume failure | Failed; reap any created tree; never resume to obtain missing evidence |
| Timeout, cancellation, stream overflow, peer loss or policy violation after admission | Stop/reap; no successful/partial diagnostic claim or automatic retry |
| Exit nonzero | Failed even if a version-looking prefix is present |
| Exit 0 with wrong stream, empty/truncated/malformed/mismatched output | Failed compatibility check; never BackendVerified or safe finding |
| Exit 0, exact profile match, all retained gates satisfied, confirmed reap and reviewed buffer disposition | DiagnosticSucceeded for this one action only; audit coverage unchanged |
| Cleanup or durable ownership unresolved | RecoveryUncertain plus original cause; block launch and affected maintenance publication |

These diagnostics create no findings and do not change protection coverage from
NotTested. The current public launch plan remains Blocked with execution_enabled
false. No persisted diagnostic record is an execution capability; trust and
consent are always re-evaluated by the runtime authority.

## 6. Evidence required before implementation or a real handshake

All nine TL records remain Open. LS/MMR obligations are neither deleted nor
replaced by this table. It groups the existing requirements by the concrete
decision needed for this operation; it does not invent another synthetic model.

| Required item | What is missing now |
|---|---|
| Current release/output policy | Current official release suitability; exact source/asset/trust association; startup side-effect review; the immutable output profile for each enabled operation |
| Service/token/session boundary | Accepted account/privilege and authenticated token handoff; safe supervisor bootstrap; complete process/thread/token/handle ownership and linked-token criterion |
| Image/root/load context | Protected ancestry and reparse/replacement proof; authenticated bytes bound to the mapped image; initial inventory and preventive future-load policy with no Unknown |
| Offline/storage/resource boundary | Preventive offline confinement without broker proxy; reviewed private buffers/temp/crash lifecycle; enforced allocation/process budgets |
| Composed authority/lifecycle | Exact Standard diagnostic offer, one-use admission/lease, timeout/cancel/crash cleanup and recovery/maintenance exclusion under the real boundary |
| Independent acceptance/authorization | Review of the concrete implementation and evidence plan; separately scoped native execution/deployment permission before any applicable operation |

Required future acceptance vectors are **Planned / NotRun**, not this pass's
test results: correct Version and separately confirmed Help; wrong asset/signer/
release; writable/replaced image or unknown initial/later module; elevated or
foreign-session token; arbitrary argv/config/env/readiness substitution; empty,
swapped, malformed, duplicate-field, invalid-UTF-8/BOM/control or mismatched output;
per-stream limit and flooding during timeout; Version-to-Help consent replay;
cancel/decline/expiry; crash/disconnect at each admission boundary; lingering
descendant/pipe; cleanup failure; changed generation or uncertain maintenance;
and attempted raw-output-to-UI/launch injection. Each applicable success predicate
needs a positive control and an isolated rejection case under the selected release.

The next prerequisite is a current release/startup/output-policy review, alongside
the unresolved service/image/offline mechanism decisions. On 2026-11-06 the user
separately authorized reading official Velociraptor documentation, release
metadata and official repository source. That permission excludes binary,
signature and key downloads, program execution and Windows changes. Native
compilation and service installation also remain separate. A new document or
successful pure planner test cannot replace technical decisions or expand that
permission.

Review status: AcceptedDocumentaryDiagnosticContractOnly on 2026-11-06. The
independent read-only reviewer checked this document and five cross-document
changes, including per-operation profiles, deadlines, consent and retained gates,
with no remaining blocking findings. This is not acceptance of a runtime,
native mechanism, concrete release or output profile. No runtime, schema,
dependency, old compatibility fixture or execution flag is changed.

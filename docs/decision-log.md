# SecApp Decision Log

Status: architecture baseline accepted by ARCH-REVIEW6; direct-launch development reopened by user authorization, technical launch gates unresolved; import-only core implemented pending independent review

An accepted design decision does not authorize runtime code, binary acquisition, elevation, dependency installation, deployment, commit, or push.

ARCH-REVIEW6 accepted baseline `283da2e85dbdd7802308632aae29e4c2eea45400` with no blockers or high-priority corrections and authorized only the separate VELOCIRAPTOR-ADAPTER-COMPAT1 experiment. Full runtime implementation remains unauthorized.

## Accepted design decisions

### D-001: Keep Velociraptor external and unmodified

SecApp does not fork, vendor, embed, modify, or add Velociraptor as a submodule. An externally supplied official binary is a forensic backend behind a SecApp adapter. Gaps are addressed with reviewed custom artifacts and normalization unless a reproducible fork criterion is met.

### D-002: Prefer a separate local CLI process

The proposed combination is a bounded process, structured CLI command contract, result import, and built-in/custom artifacts without a persistent server. Instant mode, frontend/client, gRPC, and offline collectors remain fallbacks requiring separate review.

### D-003: Pin capability research to release v0.77.1

The release tag resolves to source commit [3137c7f714ab344dd37d0df1d5393573e41b30a5](https://github.com/Velocidex/velociraptor/tree/3137c7f714ab344dd37d0df1d5393573e41b30a5). This source pin supports architecture claims only. A runtime pin separately requires a verified binary version, digest, signer/trust decision, acquisition metadata, and rollback floor.

### D-004: Treat artifact permissions as non-enforcing metadata

Required/implied permissions do not sandbox client-side VQL. Acceptance uses transitive source, import, artifact-call, plugin/function, optional branch, and pinned-parameter analysis. Any unclassified capability is PolicyRejected.

### D-005: Exclude UnsafeForDefault user-related built-ins

Windows.Sys.Users declares FILESYSTEM_WRITE. Generic.Client.Info calls it from the Users source. Windows.Registry.RDP reaches it through Windows.Registry.NTUser. Windows.System.LocalAdmins requires EXECVE and invokes PowerShell. None is accepted as a whole in the default profile. Safe VQL-native custom replacements require a compatibility experiment.

### D-006: Use immutable strict contracts

Current schemas use Draft 2020-12, schema_version 1.0.0, and immutable IDs under https://schemas.secapp.dev/v1/. Root unknown properties and unknown major versions fail closed. Compatibility and migration follow [schema-compatibility.md](schema-compatibility.md).

### D-007: Use a bounded flat rule graph

RuleDefinition uses a non-recursive predicate table with references: at most 64 nodes, depth 8, and 16 children per All/Any. Missing, null, type mismatch, and evaluation order are explicit. Duplicate IDs, missing references, unreachable nodes, and cycles are application-level rejections.

### D-008: Separate lifecycle and coverage

CollectorExecution separates pre-execution, Running, and terminal states. AuditRun contains independent standard, elevated, reboot-continuation, and post-reboot passes. Coverage findings for NotTested, BackendNotFound, ConsentDenied, and PolicyRejected are distinct from security findings and need no ordinary Observation.

### D-009: Use strict ConsentReceipt

Consent is single-use and bound to run, pass, collector, definition digest, purpose, capabilities, classes, host digest, expiry, user presence, application/text versions, and nonce. Scope comparison, expiry, revocation, conflict, and replay are application-level checks.

### D-010: Use model-level append-only ActionLog

ActionLog entries have a monotonic sequence and previous-entry digest chain. The log and digest are manifest members. This detects chain modification relative to a trusted anchor but cannot prevent a compromised administrator from rewriting all local state.

### D-011: Standardize digest and path semantics

Content, file, object, manifest, and profile digests have separate logical content and canonicalization. Object-like JSON uses RFC 8785 JCS; files use raw bytes. Self-digest fields are excluded exactly. Logical paths are strict relative ASCII identifiers. [integrity-model.md](integrity-model.md) is normative.

### D-012: Make public redaction fail closed

Public exports never Include personal, network, sensitive-security, secret, or memory classes. Hash requires a key ID. Unknown/duplicate field paths, class-policy weakening, and unassessed composition reject export. ExportManifest pins the exact source, profile, and composition digests.

### D-013: Require authenticated single-use reboot state

Reboot state binds run, host, build, executable, next stage, expiry, sequence, and nonce. HMAC-SHA256 and Ed25519 have exact tag lengths. Replay, rollback, stale state, or verification uncertainty causes fail-closed startup. No secret key, command, or local path is stored.

### D-014: Adopt initial safety limits

The structural and byte/archive limits in [integrity-model.md](integrity-model.md) are conservative starting points. Raising them is a reviewed compatibility/security change with resource-exhaustion tests.

### D-015: Block runtime on privacy/storage decisions

Retention, temporary files, ACLs, encryption, key lifecycle, backups, crash/paging/indexer exposure, SSD deletion limitations, local-only semantics, composition risk, export deletion, compromised-host limitations, and corroboration must be resolved before runtime.

### D-016: Make AuditPass standalone and AuditRun an index

The retained `passes/<pass-id>.json` layout requires an immutable standalone AuditPass schema and an AuditPass manifest role. AuditRun holds only bounded references/summaries, with a 4 MiB serialized limit, 2 GiB decompressed-run budget, and 4 GiB package budget.

### D-017: Separate every consent authority

Administrative, NetworkAccess, Reboot, DefenderScan, DefenderOffline, MemoryAcquisition, Remediation, SensitiveDataCollection, and Export map to disjoint exact operation codes. A receipt is bound to one run, pass, action, target, and single use; possession of one type never implies another.

### D-018: Normalize each manifest type independently

AuditManifest sorts members by logical path and member ID. ExportManifest separately sorts export entries, omissions, and warnings by their own declared keys. Both reject duplicates before RFC 8785 JCS and SHA-256 LowerHex. ExportManifest does not acquire fields from RedactionProfile.

### D-019: Make action effects mutually exclusive

Every ActionLog action type owns exactly one authorization/effect shape, while routine actions own none. A complete required structure does not excuse a second foreign structure; the entry is rejected with `ACTION_EFFECT_CONFLICT`.

### D-020: Split pass failures by responsibility

`PASS-004` reports only execution/pass privilege mismatch, `PASS-005` reports exact consent and binding failures, and `PASS-006` reports prerequisite or reboot-chain failures. Pass application vectors first validate as complete schema objects and isolate one named rule.

### D-021: Use discriminator-specific consent bindings

Collector operations, export, remediation, and reboot carry disjoint binding variants. Export has no collector/pass binding; remediation binds an action and exact target; reboot binds workflow and stage. Optional related collectors are role-limited and cannot turn one authority into another.

### D-022: Make package limits self-describing and overflow-safe

AuditRun carries one immutable normative `package_limits` object. All counters use checked unsigned safe-integer arithmetic, and each exhausted reference, byte, ZIP, ratio, stream, nesting, decompression, and package budget has a deterministic error code.

### D-023: Require the full validator through SCHEMA-VALIDATION1

ARCH-FIX3 performed only dependency-free local structural and contract checks. SCHEMA-VALIDATION1 subsequently supplied the exact-version development dependency, reviewed lock, strict offline Draft 2020-12 registry, deterministic commands, and no runtime dependency. CI integration and independent recheck remain separate decisions.

### D-024: Make XOBJ coverage executable and complete

XOBJ-001 through XOBJ-018 use one bounded test-only materialized graph model and separate deterministic rule functions. Constituent objects pass their production schemas; the wrapper accepts only bounded data mutations and is frozen before evaluation. Duplicate IDs remain visible until XOBJ-002 rejects them. The application gate fails for missing inputs, unknown rules, missing dispatch implementations, absent positive/negative coverage, unexecuted or skipped vectors, or any mismatch among registered, executable, and covered rule sets. This is reference validation, not runtime implementation or provenance proof.

### D-025: Supersede D-023 gate sufficiency with strict digest conformance

D-023 remains the historical dependency and full-schema-validator decision, but its original digest sub-gate was not sufficient: the reported 9/9 result did not exercise nonempty ProfileDigest ordering or byte-backed digests and allowed malformed direct JCS values to be accepted or to crash with raw exceptions. JCS-DIGEST1 supersedes that sufficiency boundary with official RFC 8785 serialization/property-order vectors, ECMAScript number cases, strict Unicode and direct-API fail-closed behavior, exact `field` ProfileDigest normalization, raw-byte FileDigest vectors, and normative ContentDigest text canonicalization. Passing remains a local design-contract gate, not provenance, runtime conformance, or a trust anchor.

## Superseding decision accepted by ARCH-REVIEW6

### D-026: Supersede count-only and universal consent gate sufficiency

ARCH-REVIEW5 reproduced two blockers against checkpoint `04351799ad780602bf73324336f40ab300c80323`. First, XOBJ-011 applied CollectorExecution/pass binding to every receipt and rejected schema-valid Export, Remediation, and Reboot graphs. Second, digest completeness compared only category counts, so deleting `JCS_RFC8785_SERIALIZATION_SAMPLE` and replacing it with a duplicate preserved exit 0. The count-only result was a false positive.

ARCH-FIX4 makes XOBJ-011 discriminator-aware with four immutable models: `CollectorExecution`, `Export`, `Remediation`, and `Reboot`. All nine consent types remain in fail-closed dispatch. DefenderOffline retains the already documented collector-scoped model; no new reboot-scoped authority is introduced. Exact required variant sets, required positive/negative/substitution vector IDs, execution state, and skipped state now gate exit 0.

Digest completeness now uses immutable exact required-ID sets for catalog digest, JCS conformance/direct API, ProfileDigest, FileDigest, ContentDigest, permanent schema guards, and checked arithmetic. Missing, duplicate, wrong-category, skipped, or unexecuted IDs fail with stable controlled codes, and six in-memory mutations run for every required ID. The RFC claim is limited to a covered conformance set with `full_corpus_claimed: false`.

D-026 supersedes only the sufficiency claims of D-021/D-024/D-025; it does not erase their historical text or change D-025 ContentDigest semantics. ARCH-REVIEW6 accepted this architecture baseline at `283da2e85dbdd7802308632aae29e4c2eea45400`. That acceptance does not prove runtime authorization, provenance, Velociraptor compatibility, production readiness, or production-ready schemas.

### D-027: Keep the v0.77.1 CLI contract review-gated

VELOCIRAPTOR-ADAPTER-COMPAT1 authenticated and exercised the exact official v0.77.1 Windows AMD64 asset. Direct JSON, custom `--definitions`, bounded ZIP import, external timeout/cancellation, and literal argument transport are reproducible for the tested pin. Production implementation remains blocked by the `highestAvailable` launch boundary, the `--hard_memory_limit` panic, unproven Windows Job Object descendant containment, and silent-success cases that require strict preflight/postconditions. [velociraptor-adapter-compatibility.md](velociraptor-adapter-compatibility.md) is the normative experiment record. The decision authorizes only VELOCIRAPTOR-ADAPTER-COMPAT-REVIEW1, not adapter runtime work.

### D-028: Defer trust-launch and select import-only as the next product path

`TRUST-LAUNCH-DEFER-CHECKPOINT1` preserves the trust-launch sources and
normalized result contract above baseline
`942d2a15b7145f9ed1e5be46507c06fdcbe1544d` as a WIP compatibility
checkpoint. Prior compile-only and synthetic prototype observations remain
development evidence only. Velociraptor was not invoked through this
prototype, and this decision authorizes neither a production launcher nor a
SecApp runtime adapter.

The product policy is fail closed and normative:

```text
TrustLaunchStatus = Deferred
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
VelociraptorInvocationFromSecApp = ForbiddenByDefault
NextProductPath = ImportOnly
```

The unresolved adjacent-DLL, linked-token, non-elevated-launch, reparse,
pre-resume module-inventory, preventive loader-policy, unknown-module,
verified-bytes-to-mapped-image, and production-safe image-load-context
blockers remain open. The detailed checkpoint is recorded in
[velociraptor-adapter-compatibility.md](velociraptor-adapter-compatibility.md)
and [the trust-launch fixture README](../tests/compatibility/trust-launch/README.md).
Import-only development required the separate `AUDIT-PACKAGE-IMPORT1` stage;
that stage is now implemented as a bounded local importer and does not start or
authorize a backend launcher.

### D-029: Use a bounded reference import core

`AUDIT-PACKAGE-IMPORT1` adopts dependency boundary Variant A. The
production-neutral `src/import/` core uses only Node standard-library APIs and
the existing side-effect-free strict JSON/JCS primitives. It performs bounded
stable-file reads, strict JSON/JSONL parsing, a restricted in-memory ZIP
profile, exact manifest membership, FileDigest/object/manifest digest checks,
cross-object import references, normalization, and privacy-safe results. It
does not extract archives to disk, invoke a process, use the network, elevate,
collect, remediate, or import a development command entrypoint.

Full Draft 2020-12 validation remains an explicit reference callback boundary.
The original lockfile-pinned Ajv connection was test-only; missing reference validation
fails closed and Ajv is not promoted to a production dependency. The ZIP
profile is single-disk, non-ZIP64, non-encrypted, regular-file-only, and rejects
prefix/self-extracting data, nested archives, executable content, symlinks,
path ambiguity, unsupported methods/features, CRC mismatch, undeclared
membership, and resource-limit violations.

An accepted import asserts modification detection relative to the imported
bytes and manifest only. It always records that provenance and host truth are
not established. The committed fixtures are synthetic JSON/JSONL; ZIP cases
are generated in memory during the automated suite and removed afterward.
This implementation checkpoint does not authorize automatic backend execution
or make the schemas, source host, package producer, or SecApp runtime
production-ready.

### D-030: Expose the bounded importer through a reference CLI

The local import command reuses one pinned, offline Draft 2020-12 adapter for
both CLI and synthetic tests. This extends D-029's test-only adapter placement
to development/reference tooling without promoting Ajv to a production
dependency. The dependency-free importer still fails closed without the
explicit validation callback.

The CLI requires a selected local file, never loads schemas from input or the
network, and emits summary-only output with controlled exit codes. Every
result labels assessment as not performed and validation as import-contract
checks. It does not authorize imported actions or make imported findings
trusted. Complete application validation, domain evaluation, storage, UI,
release packaging, and independent review remain open.

The import hardening rejects excessive depth before recursive parsing,
non-I-JSON values, over-limit JSONL records during framing, ZIP filename BOM
normalization, and bytes after a DEFLATE stream. Windows source-path syntax
also rejects UNC variants, device aliases, and alternate streams. This is not
a proof of native filesystem race or reparse protection.

### D-031: Evaluate an explicit imported snapshot with a private reference report

An explicit `--assess windows-protection-v1` extends the D-030 CLI with four
strict versioned Observation payloads, six deterministic checks, and private
text/JSON/standalone-HTML output. Plain import retains its summary-only,
assessment-not-performed behavior. The assessment uses the existing pinned
development-only validator; no dependency or existing core schema changes.

The profile binds payload schema, area, subject, and SensitiveSecurityData
classification; rejects duplicate domains and mixed runs; and preserves
missing, unsupported, or failed inputs as NotTested. Expected reported values
mean only NoConcernReported, not host safety. Confidence, severity, and status
remain independent. The profile's chosen severity levels are provisional
SecApp review priorities, not externally validated risk ratings.

The report records source, profile, schema, observation, and report digests
for reproducibility, without claiming a protected trust anchor, provenance,
or freshness. Its validation scope is ImportedObservationProfile, not full
application/XOBJ/consent validation. It is not an AuditRun or an ExportManifest.
All output is SensitiveSecurityData and stdout-only; app-managed persistent
storage and public export are still blocked on their own policies. The HTML
renderer escapes text, uses a restrictive CSP, and has no scripts or external
assets. See [the profile contract](windows-protection-import.md).

Independent rule/security review, browser regression coverage, supported
external producers/converters, real-host end-to-end testing, and release
packaging remain open. Nothing here authorizes collection or backend launch.

### D-032: Reopen direct-launch development without promoting WIP evidence

The user explicitly lifted the earlier development restriction and requested
work on launching Velociraptor from SecApp. This supersedes D-028's deferral as
a work restriction. It does not turn its nine unresolved blockers into passes,
approve an elevated/networked collector, or authorize unrelated system changes.
Automatic/background execution remains disabled; a future launch must be an
explicitly selected operation, bounded by its own policy and technical gates.

`BACKEND-LAUNCH-PLAN1` implements a pure, non-executable planner for fixed
Version/Help operations, immutable historical identity pinning, lowering-only
time/output limits, a deterministic plan digest, and exact unresolved-gate
reporting. It has no executable path, force flag, arbitrary argv/VQL/config,
process API, native helper, readiness callback, or cached authorization token.
It cannot verify an installed binary or grant launch authority. Its tests are
synthetic and do not run the trust-launch matrix or Velociraptor.

The intended implementation boundary is a narrow native process supervisor,
not the diagnostic PowerShell wrapper or unrestricted Node process creation.
This selects responsibility boundaries only: an acceptable non-elevated launch
mechanism and preventive image-load policy are still not selected or proven.
The unchanged threat model includes concurrent same-user interference.
Weakening that model, treating Unknown as allowed, or using observation in
place of prevention would require an explicit reviewed decision, not a fallback.

Current status is DesignReopened / development Authorized / production launcher
NotImplemented / invocation BlockedPendingTechnicalGates. The first proposed
real workload is version identity verification, then help, then a reviewed
constant synthetic artifact. Machine collection and its Observation mapping
come later. The version step is not permission to collect or evidence that a
backend is trusted. See [backend-launch-design.md](backend-launch-design.md).

### D-033: Preserve optional, explicitly consented elevated auditing

The user clarified that future SecApp must support checks with the necessary
administrative rights after user confirmation. Standard-user launch remains
the default; it is not a product-wide prohibition on elevation. This reaffirms
the existing Standard / optional Elevated AuditPass model rather than changing
core contract schemas or authorizing an administrative action now.

An elevated pass requires a displayed exact check/data/privilege scope,
Administrative consent bound to each action under the existing single-use
ConsentReceipt model, and a reviewed Windows elevation path. UAC approval or
an already-elevated parent alone is not SecApp scope authorization. Keep the UI
and untrusted-data parsing unprivileged; use a narrow, temporary elevated helper
only for approved read-only work. No automatic fallback, prompt retry loop,
persistent service, or blanket "always administrator" mode is selected.

Administrative consent does not imply network, scans, memory, sensitive data,
reboot, remediation, or export consent. Scope expansion needs a separate user
decision and matching authorities. Declined, cancelled, failed, or insufficient
elevation preserves valid Standard results and NotTested coverage for checks
not performed. Necessary rights mean least privilege for reviewed checks, not
unbounded authority or a promise of complete visibility.

The Version/Help planner retains elevation Forbidden for those diagnostics;
that field is not the future product policy. Elevated launcher implementation,
UAC/IPC/helper trust, private storage, replay handling, and failure/cleanup tests
remain open. See [the two-pass launch design](backend-launch-design.md).

### D-034: Validate a separate bounded self-launch experiment, not a production launcher

The user approved the proposed narrow native-synthetic stage. The new
BACKEND-NATIVE-SYNTHETIC1 helper compiles locally with an existing compiler
outside the repository and launches only itself in fixed synthetic modes.
It does not use the old TrustLaunchProbe matrix, Velociraptor, UAC, network,
collectors, DLL/module/reparse probes, or Windows configuration changes.

All ten cases passed in three runs of the final source: current/restricted
child control, timeout/cancellation tree cleanup, individual stream limits,
nonzero exit, a root leaving a pipe-holding leaf, pre-create cancellation,
and failure before resume. Atomic Job assignment, bounded draining and cleanup,
and explicit child rights checks are experiment mechanisms, not independently
reviewed product security claims. A count-only tree assertion was replaced by
a synthetic leaf handshake after the independent result checker rejected it.

Only normalized outcomes and source/manifest hashes are retained. No compiled
binary, raw pipe/compiler output, machine identity, path, or token dump is
added. Temporary build removal succeeded. Exact record-ID/lifecycle negatives
run in npm test without compiling or invoking native code. The recorded digest
does not authenticate the compiler or prove verified bytes became a mapped image.

Linked-token metadata remained Present despite effective non-elevated child
rights. This does not waive the historical linked-token criterion or select a
production token mechanism. All nine original gates remain open. Concurrent
same-user image/root interference, preventive loading, genuinely non-admin and
elevated-parent matrices, supervisor-crash/IPC cancellation, private storage,
and independent review remain work. Optional Elevated support from D-033 is
unchanged and not exercised. A real Version/Help invocation is not authorized
by this experiment. See [the recorded scope](../tests/backend/native-synthetic/README.md).

### D-035: Separate image-trust obligations and request a deployment decision

BACKEND-IMAGE-TRUST-DESIGN1 is a design-only continuation. The user separately
permitted reading official Microsoft Learn documentation; no downloads of
software, native execution/probes, UAC, installation or Windows changes occurred.
The review distinguishes verified source bytes, protected file placement,
creation-time loader prevention, initial mapping evidence, later observation
and process/IPC integrity. Passing one does not substitute for another.

The documented APIs do not justify inherited SetDefaultDllDirectories policy,
System32-only enforcement from PreferSystem32Images, arbitrary publisher
allowlisting from signature mitigation flags, a trustworthy empty pre-resume
module list, or mapped-byte proof from a pathname. The linked-token and all
other historical criteria remain unchanged. Facts, inferences and primary
sources are recorded in [the image-trust design](backend-image-trust-design.md).

A protected versioned installation is the preferred candidate for review,
keeping normal Standard checks unelevated and setup/update consent separate
from optional Elevated collection. It is not accepted as a complete isolation
solution, and its deployment choice DEPLOY-001 was pending at this stage
(subsequently approved for design in D-036). Portable
same-user staging is not promoted to production; AppContainer/separate-principal
and managed App Control remain alternatives, not implicit fallbacks. No service
or device policy is selected or authorized by this decision.

Sixteen acceptance vectors are Planned/NotRun, not new pass evidence. No
planner, contract schema, native source, expected trust-launch result or
dependency changes are made. Obtain the deployment-design choice before
implementation; later installer/native-test/backend execution needs its own
specific authorization. Do not solve feasibility by silently weakening the
same-user threat model or declaring Unknown acceptable.

### D-036: Approve protected-installation design, not installation or collection

The user explicitly confirmed DEPLOY-001 for further installer design, while
excluding installation and Windows changes. Its status is ApprovedForDesign.
This resolves the protected versus portable product direction; it does not
approve an installer implementation, native test, UAC request or backend launch.

PROTECTED-INSTALLER-DESIGN1 specifies a signed x64 per-machine MSI authoring
target for SecApp-owned files, separate fixed maintenance consent, protected
code/policy/selector ownership, private staging, exact release admission and
side-by-side generation/recovery requirements. The authoring framework, signing
infrastructure, OS/filesystem matrix and concrete concurrency/durability
mechanisms remain implementation prerequisites, not assumed capabilities.

Velociraptor stays external and unmodified, not bundled into the MSI. Separate
future enrollment must authenticate the exact official asset without running
it. Installation never grants collector authority, launches a backend for a
health check, starts an elevated UI, or reuses Administrative collector consent
for maintenance. Ordinary operation remains Standard; optional Elevated checks
still need their own exact approval. No persistent updater/service is selected.

Recovery must distinguish MSI rollback from selector/enrollment state and must
not restore a revoked or below-floor version. Repair/uninstall are explicit and
bounded to owned objects; user evidence is preserved and security-floor reset
is not an ordinary reinstall feature. Busy, uncertain commit, missing trust or
reboot-required states cannot become ready/success assertions. Runtime storage
and all nine launch gates remain open.

Twenty-two installer acceptance cases are Planned/NotRun. This stage modifies
documents only, with no schema/package/dependency/native-code change. The next
proposed artifact is a pure non-executing deployment-plan/lifecycle contract,
not an executable installer. See [the installer design](protected-installation-design.md).

### D-037: Implement a pure deployment model without maintenance authority

The user accepted DEPLOYMENT-PLAN-CONTRACT1 as the next non-executing step.
Two versioned development-only schemas and a bounded pure state model now
represent Install, Update, EnrollBackend, Repair and Uninstall. They preserve
separate maintenance versus collector scope without changing immutable core
ConsentReceipt/ActionLog contracts. Synthetic confirmations bind exact machine,
operation, complete old/new tuple, manifest/policy digests and generation, with
modeled expiry and declared nonce replay rejection. These checks are not
authentication, a real single-use store or consent for installation.

The model rejects generation overflow and epoch rollback, preserves the floor
across uninstall/reinstall, makes publication uncertainty RecoveryRequired,
and keeps committed selection on cleanup failure. No automatic recovery,
backend health check, elevated UI, host writer or installer invocation exists.
Every projection disables installation and backend execution; a completed model
is not a Ready result. Production disk/journal retention, authentication,
admission/lease primitives and recovery execution remain unresolved.

The exact DP-001 through DP-040 pure vector set joins the existing offline
development gate. It is not native acceptance evidence: the 22 PI cases and
all nine launch gates retain their prior status. The next boundary is review
of protocol trust, durable state and recovery, not implicit MSI/native execution.
See [the contract and limitations](deployment-plan-contract.md).

### D-038: Design maintenance authority at the helper, not in the ordinary UI

The user accepted the next protocol-design step. MAINTENANCE-PROTOCOL-DESIGN1
records a local helper-owned named-pipe candidate, exact peer/offer binding,
helper-owned operation confirmation and protected consume-before-effect
admission. The ordinary UI remains an untrusted requester. A PID, SID, pipe name,
challenge, hash or successful UAC prompt does not prove UI integrity or authorize
the exact maintenance scope. A post-UAC helper dialog is not automatically a
Windows secure-desktop interaction; confirmation integrity remains a gate.

No client Approve/Commit, arbitrary path/command, reusable receipt or shared UI
secret is accepted. Release metadata is independently authenticated before the
offer; bounded byte intake follows durable admission. A lost reply permits only
status inquiry, not execution retry. Counter/floor state survives compaction and
uninstall. Unknown durability, missing state or publication ambiguity blocks
progress; explicit recovery needs fresh scope confirmation and never lowers the
floor or restores an old generation number. MSI and selector rollback remain
separate transaction domains. Alternate-admin credentials do not authorize
profile writes, audit collection or an elevated SecApp UI.

This is a documentation/research proposal, not an accepted native mechanism or
production wire schema. Twenty-eight MP cases are Planned/NotRun, and all PI,
image and launch gates are unchanged. Existing schemas, pure model, runtime
sources and dependencies are unchanged. Next is a separate development-only
message/replay/recovery contract model, followed by independent review before
any native implementation. See [the protocol design](maintenance-protocol-design.md).

### D-039: Implement synthetic maintenance contracts without native authority

The user authorized implementation while retaining the stated execution,
installation, system-change, dependency/network and Git-publication restrictions.
MAINTENANCE-PROTOCOL-CONTRACT1 supplies three versioned development schemas and
a strict in-memory model, not production helper/IPC code. Existing deployment
and core audit/consent schemas remain unchanged; pinned Ajv remains dev-only.

Wire messages cannot perform helper-local confirmation, verification, reserve
or commit actions. Synthetic offers bind the full context, scope and handshake;
confirmation records additionally bind the approver. Modeled durable admission
consumes a counter before intake, uncertain persistence yields RecoveryRequired,
and lost replies permit status inquiry rather than duplicate effects. Recovery
is a disjoint freshly confirmed request and cannot lower the floor or reuse an
old generation. Every projection keeps all host effects disabled.

MPC-001 through MPC-048 are pure reference vectors, with an exact-ID completeness
check. They do not close MP/PI/native launch cases. Payloads are metadata only;
OS peer identity, signatures, user presence, durable storage, stream framing,
power-loss behavior and native phase watchdogs remain unimplemented. The next
boundary is review and selection of those concrete mechanisms, not an implicit
native experiment or launch. See [the contract](maintenance-protocol-contract.md).

### D-040: Narrow maintenance mechanisms without claiming native acceptance

MAINTENANCE-MECHANISM-REVIEW1 is author self-review under the retained restrictions,
not independent security sign-off. Official Microsoft Learn research supports
continuing the protected short-lived helper/local-pipe direction. Stable protected
coordination files and a bounded append-record journal/compact head are selected
as candidates for further modeling, not deployed mechanisms. A free gate handle
does not prove post-crash tree quiescence; UAC does not confirm the exact operation;
flush/replace calls do not alone prove cross-file durability. These remain blockers.

The pure reference model now permits an exact journal-bound null recovery target
with no payload, fresh confirmation/counter and preserved generation/floor rules.
This covers interrupted Uninstall and restoration of a prior uninstalled state;
it does not add data deletion, implicit candidate abandonment or native recovery.
MPC-049..053 extend the original exact-ID tests. Existing schemas, dependencies,
native source and evidence remain unchanged. All host effects stay disabled.

Next is MAINTENANCE-PERSISTENCE-MODEL1, a pure synthetic fault model separating
write, flush, head publication, acknowledgement and crash observations. Native
code, installation/UAC and backend execution still require separate authorization
and prerequisite independent review. See [the review](maintenance-mechanism-review.md).

### D-041: Model persistence uncertainty without implementing a protected store

The user authorized MAINTENANCE-PERSISTENCE-MODEL1 under the retained restrictions.
It adds separate development-only scenario/projection schemas and a pure bounded
fault model; existing protocol/deployment/core schemas and dependencies remain
unchanged. Normal maintenance scope is an upstream hypothesis, not a new receipt
or production authorization format.

Journal and head write, flush, re-read and acknowledgment are separate modeled
events. NotWritten is known absence of effects, while failed/unknown flush or
torn write preserves conservative possible consumption/generation/floor and
blocks selection. Fresh recovery retains original lineage; compaction cannot
retire records before a matching checkpoint/head sequence. Unknown state never
becomes a new installation. DurableHypothesis is not native durability evidence.

MPS-001..040 and exact-ID completeness join npm test. No filesystem writer,
storage bytes/decoder, native APIs, IPC, UAC, installer or backend execution are
added. All MMR, TL, IT, PI and MP blockers remain open. Next is composition review,
not an implicit host experiment. See [the contract](maintenance-persistence-model.md).

### D-042: Compare maintenance models without creating a production authority bridge

MAINTENANCE-COMPOSITION-REVIEW1 is a bounded author self-review with paired
synthetic traces, not independent acceptance or a formal refinement proof.
MCC-001..024 and exact-ID completeness join npm test. No schemas, dependencies,
native source, evidence or system state are changed.

The review reproduced two discrepancies: local protocol work could continue
after a lost reply without querying current status, and a fresh persistence
session labeled unresolved publication Active. The protocol now suspends all
progress except QueryStatus/Interrupt while the reply is lost. Persistence
returns RecoveryRequired for the pending lineage until fresh recovery admission.
Counters, generations, floors and known committed state remain preserved.

The persistence model does not check full maintenance operation scope, and its
digests are not interchangeable with protocol confirmation. Stricter storage
uncertainty must win over an abstract protocol outcome. No combined Ready result,
authorization adapter or native implementation is added. All prior trust gates
remain open. The next bounded slice is MAINTENANCE-STORE-CODEC1, an in-memory
byte-format/codec contract, not a host store. See
[the review and unresolved obligations](maintenance-composition-review.md).

### D-043: Serialize synthetic storage snapshots without implementing persistence

The user authorized MAINTENANCE-STORE-CODEC1 under the retained restrictions.
It adds a separate immutable development document schema and an in-memory
whole-snapshot codec. The fixed versioned frame contains an exact bounded length,
SHA-256 over its prefix/payload, and canonical UTF-8 JSON. Existing schema
documents, models, dependencies, native source and evidence remain unchanged.

Encoding/decoding checks document and component digests, record links, synthetic
machine consistency and declared conservative minima. Explicitly Known snapshots
without an incomplete checkpoint must also pass the existing pure replay check.
Unknown/checkpoint hypotheses are preserved, not repaired or promoted. A digest
is not authentication, a serialized minimum is not an external trust anchor,
and a successfully decoded document grants no operation or launch authority.

MSC-001..036 and exact-ID completeness join npm test. There is no file writer,
append-record persistence implementation, session resume, native API, installer,
IPC, UAC or backend execution. All prior launch/maintenance blockers remain open.
Next design work must address explicit retirement, capacity and interrupted
checkpoint policies; native work still requires independent prerequisite review
and separate authorization. See [the format and limitations](maintenance-store-codec.md).

### D-044: Define explicit retirement, capacity and checkpoint recovery policy

MAINTENANCE-RECOVERY-POLICY1 is documentation-only policy for the next versioned
synthetic model, not a runtime implementation or independent acceptance. It
defines fresh, disjoint confirmation for logical retirement of an ordinary
Admitted unpublished candidate, terminal metadata compaction and checkpoint
reconciliation. Consumed counters and prior selection/generation/floor remain
preserved; metadata authority does not delete payloads or user data.

Future admission must reserve its complete logical record/byte budget plus
metadata-maintenance capacity, rather than discovering exhaustion after admission.
The selected nominal budgets are six records for ordinary/publication work,
four for cleanup-only/retirement and two for explicit metadata compaction or
checkpoint reconciliation. A full legacy journal without that space remains
blocked; no truncate/reset/emergency-store workaround is selected. Repeated
failures can still exhaust the bounded reserve.

Checkpoint eligibility requires exact agreement of the reconstructed terminal
old state, candidate and either permitted head, not checksum agreement alone.
Reconciliation still needs a newly consumed counter and newly bound checkpoint;
unknown evidence never becomes Known through classification. RP-001..030 are
Planned/NotRun requirements, not added executable-test evidence.

No code, schemas, package metadata, dependencies, native files or evidence change
in this stage. Next is MAINTENANCE-RECOVERY-MODEL2 with separate major-family
development contracts and pure tests; no in-place v1 schema change, migration or
host adapter. MMR-004/MMR-006 and all other native/launch gates remain open. See
[the policy](maintenance-recovery-policy.md).

### D-045: Implement synthetic recovery v2 without enabling native effects

The user authorized continuation and separately permitted read-only Velociraptor
execution, expressly excluding creation, deletion or changes to system settings.
This does not authorize installation, services, registry/ACL/PATH changes, UAC,
network, remediation or arbitrary collectors, nor waive any trust prerequisite.

MAINTENANCE-RECOVERY-MODEL2 implements D-044 in a separate major-family development
schema, pure model and SA_MSC02 snapshot codec. v1 schemas/models/codecs/tests are
byte-identical. Fresh metadata authority retires only an unpublished ordinary
candidate, compacts terminal state, or reconciles exact eligible checkpoint
representations. Counters/lineage and conservative minima survive interruption;
metadata operations preserve selection/generation/floor and never delete payloads.

Admission reserves nominal 6/4/2 record budgets and bounded bytes before any
consumption. Reconciliation records fresh authority before deriving its new
checkpoint and retains the old chain/candidate until verified retirement. Unknown
or exhausted control states block; no availability guarantee or emergency store
is invented. RP-001..030 plus exact-ID completeness are executable synthetic
tests, including all durable-step interruptions and v1/v2 reader rejection.

This is author-reviewed development evidence, not an independent acceptance or
host durability proof. No physical writer, native API, installation, backend
execution, migration, commit or push is part of this stage. All MMR/TL blockers
remain Open. Next is independent recovery/composition and trust-boundary review;
see [the implementation and limits](maintenance-recovery-model-v2.md).

### D-046: Correct recovery-model review findings without widening authority

The user authorized correcting the four reproduced author-review findings.
MAINTENANCE-RECOVERY-FIX1 tightens candidate epoch checks to include the currently
selected epoch, preserves conservative minima from every verified replay prefix,
rejects unexplained terminal-anchor generation gaps, and makes expiry exclusive
at preparation and admission. Newly generated default offers expire five minutes
after simulated_at; existing input authority is never renewed or rewritten.

MRF-001..012 plus exact-ID completeness cover positive and negative cases,
including independently framed codec inputs and paired protocol/v2 expiry
boundaries. The first run against the unchanged implementation reproduced the
defects; after correction the new suite and unchanged RP suite pass. All schemas,
v1 code/tests, original v2 tests/codec/fixtures, lockfile, dependencies and native
source remain unchanged. These are WIP implementation corrections to existing
invariants, not a format migration or native acceptance.

The original corrupt journal is retained even when its strongest known prefix
minima are preserved; no truncate/reset/repair or implicit recovery is introduced.
All MMR/TL blockers stay Open. Independent recheck and composed-boundary review
are still required. No native/backend invocation, system mutation, installation,
UAC, network, commit or push occurs. See [the fixes and evidence](maintenance-recovery-fixes.md).

### D-047: Correct independent recovery findings without promoting model authority

The user authorized fixing the separate review's three reproduced findings and
rechecking them. MAINTENANCE-RECOVERY-FIX2 validates supported finite canonical
timestamps in every current/historical offer container, rejects terminal anchor
operation/outcome pairs that no valid transition can produce, and limits
publication-related transaction status to the queried unresolved lineage.
Historical expiry is not reapplied against current time; a retired query does not
clear current reply loss or turn global recovery uncertainty into known selection.

MRR-001..010 plus exact-ID completeness first reproduced five failing cases
against unchanged FIX1 code (with five passing controls), then passed after the
corrections. A separate strict schema gate proves schema-valid semantic negatives.
The suite joins the existing command without changing dependencies, schemas,
wire fields, digest domains, the codec, v1, RP/MRF or native sources. No migration
or physical persistence mechanism is introduced.

See [the findings, corrections and recheck record](maintenance-recovery-recheck.md)
for the bounded independent disposition. All MMR/TL blockers remain Open; no
native/backend execution, system mutation, installation, UAC, network, commit or
push is authorized by this model correction or its test results.

### D-048: Compare original synthetic models without creating a production bridge

The user authorized COMPOSED-BOUNDARY-CONTRACT1 after the composed review found
that recovery v2's opaque digest/epoch does not itself enforce deployment's full
operation scope. A private test-only checker now recomputes deployment, protocol
v1 and recovery v2 from their original scenarios, requires explicit full-tuple,
operation, counter/origin, generation/floor, context and clock correspondence,
and compares every supplied output claim against recomputation.

Only four complete boundaries of five ordinary operations from a declared fresh
stable anchor are covered. Recovery/metadata operations and historical terminal
mapping have no implicit analogue. v2's conservative Unknown selection at Commit
is retained even where other models expose a selected tuple. Every successful
comparison is non-authority with execution disabled and launch blocked.

CBC-001..030 plus completeness join npm test without changing models, codecs,
schemas, dependencies or native code. No production bridge, migration, launcher,
host writer, native probe, UAC or system change is introduced. All MMR/TL blockers
remain Open. See [the bounded contract and review disposition](composed-boundary-contract.md).

### D-049: Bind recovery to complete synthetic history without promoting snapshots

The user authorized the recovery/historical follow-up to D-048 and independent
recheck. COMPOSED-RECOVERY-CONTRACT1 adds a private test-only checker that replays
one ordinary origin and up to three fresh recovery attempts. Deployment remains
the original scope witness; finalization, permitted restoration and cleanup must
each pass their own protocol/v2 admission. Whole restart stores, historical
lineage, tuple mappings, counters, generations, floors, contexts and clocks must
correspond; no standalone Known snapshot or rehashed claim replaces history.

Status observations remain read-only and cannot grant new authority. The v2
metadata-only operations have no implicit protocol/deployment analogue. Unknown
selection and the committed status asymmetry remain conservative. No production
bridge, schema/model change, physical persistence or native operation is added.
CRH-001..025 plus completeness join npm test; existing suites and all MMR/TL
blockers remain unchanged. See [the exact scope and review](composed-recovery-contract.md).

The independent review's challenge-role freshness finding was reproduced by
CRH-025, corrected with a common challenge-label set, and closed by focused
recheck. The combined CBC/CRH scope received bounded PASS, not native acceptance.

### D-050: Keep authorized native observations separate from production acceptance

The user explicitly authorized compiling and running a separate synthetic native
harness on the primary computer for DLL/image, IPC and abrupt test-process exit
checks. This does not authorize Velociraptor in this experiment, UAC, installation,
dependencies or changes to ACLs, registry, PATH, services or system settings.

NATIVE-BOUNDARY-EXPERIMENT1 records seven observations from three final-source
runs. PreferSystem32 did not prevent an explicit local fixture mapping; a
same-user sibling obtained the requested dangerous process rights without using
them for injection. MicrosoftOnly blocked that inert managed PE after startup;
bounded pipe matching and one abrupt-supervisor cleanup case also completed.
Image pathname/hash agreement remains explicitly weaker than mapped-byte proof.
No startup-loader, authenticated IPC, protected root or lease-atomicity claim is
made. The unchanged historical helper types are reused, not its old test matrix.

Only source and normalized synthetic results are retained. Binaries were built
outside Git and removed. Thirty-three pure record/source-binding tests join npm
test; native execution remains explicit and manual. The planner, native evidence
from earlier stages, schemas and dependencies remain unchanged. All TL/MMR
blockers stay Open. See [the experiment and limits](../tests/backend/native-boundary/README.md).

### D-051: Recommend a separate-identity launch broker without authorizing a service

The user approved the small first-release plan and asked to choose a safe launch
mechanism without system changes. BACKEND-LAUNCH-MECHANISM-SELECTION1 recommends
an SCM-bootstrapped, separate-identity narrow broker plus a constrained Standard
worker as the next candidate for design approval. The observed default same-user
candidate is insufficient; this is not a proof that all service-free alternatives
are impossible. AppContainer is possible additional containment, not by itself
authenticated bootstrap or exact human-action confirmation.

A service would change the prior no-service direction. At this recommendation
checkpoint the product decision was PendingUserApproval (resolved later by
D-052); persistent registration, service code, host installation,
ACL/account changes and UAC remain unauthorized. No account or privilege bundle
is approved by name, and collector identity must not silently change to a service
profile or inherit broker privileges. Loader prevention, mapped-image binding,
consent, offline/storage and composed lifecycle remain separate blocking gates.

The [selection document](backend-launch-mechanism-selection.md) records alternatives
and eight Planned/NotRun acceptance checkpoints. No runtime, schema, model,
dependency, historical result or planner flag changes; all TL/MMR blockers remain
Open. This is an author recommendation, not independent native acceptance.

### D-052: Approve the launch-service direction for design only

On 2026-10-11 the user accepted the service-based direction and explicitly asked
to continue design without installation or system changes. This resolves D-051's
PendingUserApproval and supersedes DEPLOY-001's no-service choice only for one
narrow SCM launch broker. It does not authorize service implementation,
registration, account/privilege/ACL changes, UAC, dependencies or native trials.

[SERVICE-LAUNCH-BROKER-DESIGN1](service-launch-broker-design.md) proposes demand
start, a separate broker identity, one active Standard operation and a protected
supervisor in the requesting user's session. The broker cannot install, update,
repair, run arbitrary commands or lend its own rights to Velociraptor. A
per-service virtual account is the account candidate for review, not an accepted
privilege configuration; LocalSystem is not a fallback. Maintenance and future
explicitly confirmed Elevated collection retain their separate authorities.

Identification-only control IPC is not a launchable user token or proof of human
intent. A separate authenticated token-acquisition route, exact confirmation,
process/thread/token ownership and same-session stream handling require review
together. No cross-session handle inheritance or automatic token/session
substitution is assumed. Proposed limits and messages are design requirements,
not a wire implementation or new schema. All TL/MMR gates remain Open; LS-001
has product approval only, not technical acceptance. The current planner,
historical records, source code, schemas and dependencies remain unchanged.

### D-053: Bind exact displayed scope to broker-internal one-use launch admission

On 2026-10-11 the user requested further design of protected launch confirmation,
without installation or system changes. [LAUNCH-CONFIRMATION-DESIGN1](launch-confirmation-design.md)
separates the ordinary UI, a proposed per-action confirmation component (CC)
and the authority-owning broker. The broker independently freezes the operation,
checks, data/effect scope, identities, policy/material, limits and presentation
resources. CC derives the complete display and returns an exact decision only
over its separate authenticated role channel. Public UI approval is not authority.

The proposed launch permit is a private broker admission record, consumed with
run/deployment ownership before backend creation. It is not a bearer file or
client-signed bypass. Replay, changed scope, decline, expiry, cancellation races,
lost acknowledgement and uncertain crash outcomes must not create a second
execution or restore permission. One offer covers one action/backend invocation;
distinct executions and consent domains cannot be folded into a reusable grant.

This is design, not platform acceptance: authenticated IPC, a DisplayModel digest,
a Hello result/signature or prior UAC does not independently prove exact protected
display and human input. The Windows mechanism remains NotSelected, NativeApproval
Disabled and all TL/MMR gates Open. No keys, new production schemas, native code,
dependencies, installation or host configuration changes are authorized. Existing
ConsentReceipt variants and optional separately confirmed Elevated work remain
unchanged; Standard does not waive sensitive-data or other required consent.

### D-054: Triage confirmation mechanisms without accepting a Windows boundary

On 2026-11-06 the user asked to continue the documentation-only design. The
[mechanism review](launch-confirmation-design.md#61-windows-mechanism-triage-2026-11-06)
compares ordinary UI/UIPI, UAC, Hello, secure Credential UI and a private desktop
against the existing same-user threat model and exact-scope protocol. It records
official Microsoft API constraints and labels SecApp deductions separately.

Ordinary same-integrity UI is not accepted as the sole human-input boundary.
Credential UI offers a documented secure prompt but returns credential material,
not SecApp's exact launch permit; no credential handling or provider installation
is authorized. Prior UAC or a Hello result/signature remains insufficient alone.

The author's next research priority is an explicitly secured private desktop
with a protected in-session CC bootstrap. This is not user selection of that
mechanism or technical acceptance. The review identifies nonexclusive desktop
creation, parent-station/same-user rights, owner/handle authority, session-token
placement and switch/input/recovery as unresolved. In particular, moving a
service token between sessions must not silently add the excluded SeTcb right.
One concrete access/bootstrap sequence must satisfy these constraints or the
route must be rejected for an explicit revised architecture decision.

DisplayInputProtection stays NotSelected, NativeApproval Disabled and all TL/MMR
gates Open. The broker account/privilege budget, schemas, protocol authority,
planner flags and optional separately confirmed Elevated path are unchanged.
No code, native/API probe, input injection, installation, key/credential enrollment,
service/desktop creation or host-setting/ACL modification is authorized here.

### D-055: Do not advance the private-desktop candidate to implementation

On 2026-11-06 the user asked to begin the minimum working-release plan. The
next agreed task was to resolve launch feasibility without assuming installation
or system-change permission. The [bounded bootstrap review](launch-confirmation-design.md#64-concrete-bootstrap-review-no-implementation-go-ahead)
records NotAccepted / no implementation go-ahead under current evidence.

Session 0 switching and the service-token session rewrite do not fit the chosen
topology/privilege budget. Ordinary grants to the requesting user's shared SID
do not distinguish CC from an in-scope hostile peer. Restricted tokens alone
do not repair that distinction. OWNER RIGHTS can constrain implicit owner rights,
so the review does not claim that every secured same-user construction is
impossible. The retained-handle bootstrap alternative remains unproved at
creation/attachment, genuine interaction and restoration after CC death.
IMO_HARDWARE can also represent UIAccess-injected input; it is not by itself
proof of a physical or informed user decision.

The review is author analysis of official API contracts, not independent/native
acceptance. It ends the current paper-only pass and requests a separate user
decision on isolated, explicitly authorized native research versus a revised
first-release assurance scope. No option is selected automatically, the same-user
threat model is unchanged and D-052's service direction is not revoked.

No service/CC implementation, host installation, VM/hypervisor setup, ACL/account/
privilege change, UAC, key enrollment or backend/native execution is authorized
by this disposition. DisplayInputProtection remains NotSelected, NativeApproval
Disabled and all TL/MMR gates Open; source, schemas, dependencies, historical
results and planner execution flags are unchanged.

### D-056: Select a trusted-local MVP with a narrower Standard confirmation claim

On 2026-11-06 the user chose the second path from D-055: a limited first working
release for a trusted local session, without claiming same-user-malware-resistant
confirmation. [TRUSTED-LOCAL-MVP1](trusted-local-mvp.md) records the exact scope,
cost, proposed Standard intent protocol delta and retained safeguards.

This permits an ordinary trusted-session UI to report one exact Standard intent
to the broker, instead of requiring a separately protected CC/private desktop.
The broker still owns scope derivation, prerequisite checks and single-use run
admission; the UI cannot override readiness, verification or consent domains.
The exception is to the human-intent guarantee under pre-existing session
compromise, not to hostile input handling or compromises caused by SecApp itself.
The target protection profile remains SensitiveSecurityData and needs the
corresponding exact consent flow before collection.

D-052's service direction stays selected for design. No portable/no-service
architecture, privilege reduction criterion, weaker loader policy, plaintext
storage fallback, installer or backend invocation is implicitly approved.
Maintenance and the future optional Elevated path retain their stronger separate
authorities. All nine TL records/planner gates and other MMR obligations remain
Open; immutable schemas, source and historical results are not rewritten.

The user separately authorized a read-only independent reviewer for this scoped
revision. The reviewer accepted the documentation delta as AcceptedScopedDeltaOnly
with no blocking findings, including the separately bound Standard sensitive-data
consent distinction. This is not acceptance of the future collection flow or
full runtime/native acceptance. Host changes, dependencies, keys,
native compilation/tests, service installation, commits and pushes are not part
of this pass. The current diagnostic planner stays non-executing.

### D-057: Define the first diagnostic action without promoting launch readiness

On 2026-11-06 the user authorized continuing to the Version/Help operation
contract after D-056. [BACKEND-DIAGNOSTIC-CONTRACT1](backend-diagnostic-contract.md)
specifies Version first, then Help only with a separate exact confirmation and
current checks. Neither action is a collector or grants authority to collect.

The contract separates current release/source review, pre-execution asset/image
trust and post-execution reported-build compatibility. It retains exact argv and
10-second/64-KiB-per-stream ceilings, requires release-specific output profiles,
and accounts for the historical Help-on-stderr result. Counts/exit zero and
version strings are not authentication or sufficient compatibility evidence.
Startup/configuration side effects, private buffers and composed cleanup still
need review even for these short diagnostic commands.

This is a design proposal, not approval of a concrete runtime release or service
implementation. Current release selection, all nine TL gates and remaining LS/MMR,
offline/storage/consent requirements stay unresolved. No source/schema/dependency,
historical fixture or execution flag changes. No upstream retrieval, asset
download, native compilation/probe, installation, backend execution or Git
mutation is authorized by this contract. Independent review accepted only this
documentation as AcceptedDocumentaryDiagnosticContractOnly, with no remaining
blocking findings; runtime/release/output-profile acceptance is still pending.

The user subsequently authorized official Velociraptor documentation, release
metadata and source reads only. [BACKEND-RELEASE-REVIEW1](backend-release-review.md)
records the v0.77.3 candidate and exact source revision, compressed-asset metadata,
and a pre-dispatch Windows event-source installation/logging call. Candidate
admission remains Blocked; this is partial static review, not release selection,
asset verification, a native test or permission to change Windows.

### D-058: Rebaseline the first release for a trusted host and scoped installation

On 2026-11-06 the user agreed to the proposed minimum permission envelope and
broader trusted-local-environment MVP, rather than only relaxing confirmation.
[TRUSTED-HOST-MVP1](trusted-host-mvp.md) is authoritative for current permissions,
assumptions, exact TL/LS/MMR applicability and retained minimum acceptance gates.

Ordinary implementation/builds, reviewed official backend/signature/key acquisition
outside Git and bounded diagnostic/read-only integration are authorized subject
to the applicable technical review and exact test/operation scope. Initial
installation is allowed in principle only after a concrete owned-object mutation
manifest is reviewed, displayed and explicitly confirmed; UAC is not requested
in this pass. Missing tools still need a concrete agreed list. No dependency,
service privilege, registry/ACL/PATH/security-policy or Git change is implied.

The first release assumes a trusted Windows/session and does not claim resistance
to pre-existing same-user malware across confirmation, processes/files/loading or
local evidence. Initial-install confirmation has the same host-trust limitation
while retaining package trust, exact scope and UAC. This does not excuse SecApp-
introduced compromise, unsafe parsing/paths, other-user access, weak asset trust,
elevation/consent confusion, unbounded execution, leaks or false success.

The service direction remains. Stronger initial/future-module and mapped-image
attestation, active same-user interference proofs and absent generic maintenance
features are deferred, not marked Passed. Basic protected installation, effective
Standard rights, fixed commands, safe working context, exact consent, offline/
private storage and crash/cleanup/maintenance exclusion still need implementation
and independent acceptance. Future Elevated collection remains separate.

Replace "no Windows changes anywhere" with "do not alter audited security
settings; permit only exact approved installation, owned working data and normal
logging effects". The v0.77.3 event-source call is still a source finding and
requires concrete effects review, not an elevated or unrestricted launch shortcut.

Historical results, planner/schema contracts and pure tests remain unchanged.
No runtime flags are enabled, assets acquired, code compiled, native probes run
or Windows settings changed by this documentation pass. Independent review accepted
the requirements delta as AcceptedRequirementsRebaselineOnly, with no remaining
blocking findings. Retained technical gates and runtime remain unaccepted.

### D-059: Record authenticated candidate bytes without runtime admission

On 2026-11-06, [BACKEND-ACQUISITION-VERIFY1](backend-acquisition-verification.md)
used D-058's reviewed acquisition permission to obtain the official v0.77.3
Windows AMD64 gzip and detached signature outside Git. The measured compressed
hash matches GitHub metadata; the extracted EXE hash matches the official
downloads table. Detached RSA/SHA-512 verification succeeded under the currently
published primary-key fingerprint, using an existing external public-key file.
Wrong fingerprint/hash and wrong signed byte-domain checks were rejected.

This is byte authentication only, not fresh-key/revocation or Authenticode
acceptance, a safe-release conclusion, a protected installation, mapped-image
proof or runtime pin change. Backend execution, Windows changes and installation
did not occur. The source startup-effects finding and applicable MVP gates remain
unresolved; no execution flag or historical contract is changed. The acquisition
record states its remaining trust/release/launch review obligations explicitly.

### D-060: Narrow the trust review and propose LocalService broker bootstrap

On 2026-11-06, [BACKEND-TRUST-LAUNCH-SLICE1](backend-trust-launch-slice-review.md)
cross-checked the acquired EXE with existing GnuPG in an isolated external home,
using the previously acquired key. Static byte inspection established the actual
highestAvailable manifest and Windows build dependency versions. CMS cryptography
was checked without a Windows trust verdict. Current key revocation, full
Authenticode, dependency reachability and runtime acceptance remain pending.

The current technical proposal is LocalService, own-process/demand-start, with
service-SID protection and removal-only privileges, replacing the earlier virtual-
account preference as a candidate only. Its documented rights support studying
CreateProcessAsUser for the user-session supervisor without adding user-rights,
LocalSystem or SeTcb. This does not resolve the separate Standard supervisor's
worker-creation path or preventive offline/effects boundary. No privilege/account
change, installation, native probe, backend execution, runtime-code/schema change
or Git mutation occurred. The record defines concrete remaining checks before a
compile-only bootstrap slice; it does not issue an implementation-ready flag.

### D-061: Permit scoped service-account rights in a future reviewed installation

On 2026-11-06 the user explicitly agreed to allow necessary rights to be assigned
only to the separate SecApp service in the design of a future installation.
The exact rights list and installation itself must be reviewed and separately
confirmed. This narrows D-058's no-service-grant restriction; it does not grant
permission to assign rights or install anything now.

For further account design, use a per-service virtual account rather than the
shared LocalService candidate from D-060. The concrete candidate entitlement
table and installation/removal boundaries are in
[BROKER-BOOTSTRAP-CONTRACT1 section 8](broker-bootstrap-contract.md#8-d-061-scoped-service-account-rights-proposal).
They remain a proposal, not an accepted installation manifest, proven token
configuration or ready native implementation. Permission for this direction is
not confirmation of each proposed right.

Any future grant must target the exact owned service SID, never the requester,
UI, supervisor/backend, LocalService, All Services or a broad local/domain group.
No Administrator membership, LocalSystem fallback, SeTcb, SeDebug or expansion
of the four-privilege candidate ceiling is authorized. Service logon eligibility
is accounted for separately from token privileges. The runtime cannot grant,
repair or broaden its rights.

All retained gates still apply: initial object security, authenticated token
handoff, exact Standard context, protected code, bounded lifetime, offline and
private data handling. A distinct account does not prove these automatically.
The account's machine-credential network behavior must remain in effects review.
No Windows/LSA/registry/ACL/service/UAC action, native compilation/probe, backend
execution, schema/code/dependency or Git-index change occurs in this pass.

Independent review of this documentary permission/account delta:
AcceptedDocumentaryServiceAccountRightsProposalOnly on 2026-11-06, after review
of all seven documentation changes and correction of inventory/consent ordering.
No blocking documentary findings remain. This is not runtime or installation
acceptance.

### D-062: Deliver the first version without a service or elevated collection

On 2026-11-06 the user explicitly accepted the proposed direct Standard MVP:
ordinary same-user execution on a trusted Windows/session, one fixed read-only
check after confirmation, authenticated executable, bounded lifecycle and private
report. Service and elevated checks move to a later version, not permanent removal.
This supersedes D-058/D-061's retained-service direction for the first release.

The finite path is [DIRECT-STANDARD-MVP1](direct-standard-mvp.md). Service/RPC
handoff and SCM creation-time proof are no longer gates for this route. Historical
failures remain unchanged. Actual Standard rights, wrong-image prevention,
command/startup effects, offline behavior, output/tree cleanup, honest coverage
and hostile-input safety remain. No UAC, service, grant, audited-setting mutation,
new dependency or Git operation is authorized by this decision. The old planner
and published contracts are unchanged; no generic readiness override is added.

Independent admission: AcceptedRequirementsDirectMvpOnly and
AcceptedPureDefenderAdapterPreviewSliceForImplementation. The first code slice
is a bounded decoder, separate report and explicit-file preview with synthetic
tests. It does not fabricate import/Observation/CollectorExecution acceptance or
prove real collection. Native launcher implementation/execution retains its
concrete source/effects review, not the deferred service requirements.

### D-063: Allow scoped backend event logging; ask instead of complex workarounds

On 2026-11-06 the user explicitly permitted the described Velociraptor event-source
registration and normal startup logging. The user also directed that additional
permissions be requested with an explanation of what they allow and why they are
needed, rather than pursuing complex workarounds to avoid asking.

For the pinned v0.77.3 startup path, this permits creating the `Velociraptor`
source under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application` and
the upstream values `CustomSource` DWORD 1, `EventMessageFile` REG_EXPAND_SZ
`%SystemRoot%\System32\EventCreate.exe`, and `TypesSupported` DWORD 7. It also
permits the normal startup argv event, including the existing `.NET Runtime`
fallback. The setting/event may persist. No secrets or collected data belong
in argv; local paths can identify the user and should be avoided where possible.
Existing OS retention/forwarding is not changed, and no logs are erased.

This replaces the requirement to preventively deny that exact source-registration
attempt in the direct MVP. It does not accept arbitrary registry writes, ACL
changes, modification/repair of existing source registrations, UAC/elevation,
services, protection-setting changes, network collection, or remediation. An
access-denied outcome is not permission to escalate or repair. Any extra right
must be requested for a concrete operation with its purpose, scope, persistence
and risks before use; permission to register logging is not permission to run
the whole check as Administrator. Prefer the standard supported launch route;
if it needs an additional permission, ask instead of inventing a complex bypass.

This is development/operator scope, not a reusable product consent token or
runtime acceptance. The remaining launch, config/offline, lifecycle and output
checks still apply. No backend was executed, Windows setting changed, or Git
commit/push performed when recording this decision.

### D-064: Permit one fixed elevated control run through user-confirmed UAC

On 2026-11-06 the user approved preparing and performing one control run through
normal Windows UAC, after preparation/review. Elevation applies only to the
small SecApp helper and the unmodified pinned Velociraptor backend, never the
ordinary controller/UI or a persistent service. The exact operation reads
`AMRunningMode` and `RealTimeProtectionEnabled` from the local Defender WMI
provider. No other query, remote host, artifact, command or automatic retry is
authorized. The user personally confirms UAC; the agent does not click it.

The user was explicitly told that administrative rights technically permit more
than reading: a fixed command is not a read-only sandbox. This narrowly supersedes
the Standard-only/no-UAC condition for this one control run, not the ordinary
default or the separate consent requirement for later elevated operations.
It does not permit services, audited security-setting changes, network collection,
remediation, reboot, credential use, ACL repair or broader registry changes.
D-063's exact event-source registration and normal event logging remain allowed.

The implementation and concrete working-data/lifetime contract are recorded in
[DIRECT-STANDARD-MVP1](direct-standard-mvp.md#d-064-one-elevated-control-run).
Compile outputs, empty config and bounded private transport stay outside Git in
an owned GUID run directory. Existing permissions are inspected, not changed.
The original backend is not modified; its pinned bytes are locked and rehashed.
The later D-065 workspace decision permits a verified private copy.
Each prepared directory permits only one UAC attempt, not an automatic retry.
No current schema, old planner or Standard operation admission is changed.
Authorization is not proof that the helper/build/runtime or resulting data pass.

### D-065: Create new private SecApp workspaces without changing existing ACLs

On 2026-11-06 the user explicitly authorized new SecApp working directories with
the explained private rights, while prohibiting changes to existing directories
and other projects. This addresses the previous compile-only PRIVATE_ACCESS
refusal; it does not relax the private-data policy or authorize ACL repair.

Each attempt creates a new `C:\Dev\SecApp-Control-<run-id>` directory outside Git.
Creation supplies a protected DACL, current-user owner, and exactly three normal
inheritable FullControl allow entries: current user, SYSTEM and Administrators.
The GUID name must not already exist. Existing ancestors are opened/checked, not
given new permissions. The volume must support persistent ACLs. Namespace handles
exclude delete sharing and verify directory type, absence of reparse points and
final path; this is not a guarantee against every metadata change or same-user
tampering on an untrusted host.

Source, manifest, build output and a streamed CREATE_NEW copy of the already pinned
backend inherit the new directory's rights. Source ACLs are not transferred. The
original backend remains unchanged, and both source/copy bytes are hash-checked.
The controller defines a small in-memory Win32 filesystem bridge without disk
bootstrap compilation; the actual helper compiler uses only the new workspace
for output/TEMP/TMP. No new download, installation, service, registry change beyond
D-063, or general elevated collection is authorized. D-064's one UAC attempt,
fixed operation and manual confirmation still apply. Authorization and source
review are not evidence of a completed build or successful collection.

The first AppData-location attempts stopped after creating empty directories but
before the compiler: the normalized leaf path was redirected into the desktop
host's per-package LocalCache. No mismatched path was accepted. The fixed `C:\Dev`
development location avoids this AppData projection without changing Windows or
the host package's virtualization settings. Existing parent directories retain
their permissions. The original acquisition file may still be virtualized: only
its read-locked, length/hash-verified bytes are streamed into the new private
destination; it is never executed in place. Destination namespace checks remain
strict. This is a local development layout, not a portable installation contract.

Observed follow-through: compile-only succeeded; after independent exact-build
review the one D-064 UAC control attempt completed and its bounded result was
accepted by the SecApp reader. The helper reported backend exit 0, root exit,
empty Job and closed streams; controller exit confirmed helper completion. Exact
owned cleanup removed temporary files/new directories; the original backend hash
remained unchanged. Only normalized development outcomes are recorded here, never
actual security values or raw evidence. This does not authorize repeated runs or
promote the Standard route, general runtime or native failure-path coverage.

### D-066: Implement an interactive fixed Defender check, without another live run

The user agreed to turn the working control slice into a launch/confirmation/result
workflow. This pass implements that command and checks source plus synthetic data;
it does not renew D-064's consumed one-off execution authority. No helper build,
backend execution or UAC is performed as part of this implementation pass.

`npm run check:defender` accepts only an ordinary Windows terminal and no operation
flags. Before preparation it describes the new private directory/build/copy.
Before collection it shows the fixed two WMI fields, elevated helper/backend,
helper digest, EventLog effect, limits, data handling and narrow coverage. A typed
phrase is bound to the immutable prepared run/digest; UAC is a separate elevation
confirmation. EOF, timeout, wrong text, redirected input or unknown arguments do
not authorize collection. No unattended mode, arbitrary query or retry is added.

The existing C# helper/Workspace sources and manifest remain pinned and unchanged.
The wrapper pins its controller too and uses the fixed supported Windows PowerShell
path, not an inherited variable as executable authority. The controller now uses
an exclusive zero-byte `controller.lock` to serialize preparation/run/discard for
one GUID. An unstarted prepared discard requires the exact fresh file set and pins.
Success cleanup requires an observed helper exit 0 and a strict run-bound complete
lifecycle receipt; a JSON claim or kill request alone cannot authorize cleanup.

Cleanup removes only known data files under retained directory handles. It keeps
the private leaf and empty lock file, reporting `workspace_removed=false`; no
recursive/delete-after-unlock path or existing ACL change is introduced. Failed or
unknown lifetime/cleanup remains an explicit operator follow-up, not an automatic
retry. A versioned internal envelope distinguishes actual helper exit, bounded
result bytes and data cleanup; the original raw helper JSON mode is preserved.
These private development transports are not published AuditRun/schema revisions.

Independent recheck: AcceptedInteractiveDefenderCliSourceAndSyntheticTestImplementationOnly.
The interpreter-override and actual-helper-exit findings were fixed and covered by
negative tests. The author ran 656/656 Node tests (76 new), all npm validators and
26 separate pure PowerShell receipt vectors; zero failures/skips. The reviewer did
not execute tests. No new native build, backend run, UAC, system-setting change or
Git publication occurred in D-066. Its subsequent live acceptance is D-067 below.

### D-067: One operator-confirmed acceptance of the interactive Defender command

The user explicitly authorized one acceptance run of the new command, with UAC
confirmed personally and no system-settings changes. Preflight matched the pinned
sources and found the exact EventLog source already registered with the expected
three values; no new registration was needed. Existing permissions/settings were
not repaired or changed. The operator received a visible ordinary terminal and
entered the collection confirmation and UAC themselves; no automated input was used.

The terminal process exited with the command's propagated exit code 0. Under the
checked command's success contract this requires a closed controller, actual helper
exit 0, complete bound lifecycle, useful decoded data (not NotTested), and confirmed
payload-file cleanup. Post-run inspection independently found only a zero-byte
controller.lock in the new private workspace. Its protected three-entry DACL, the
original backend digest, and the same EventLog values passed read-only checks.

No raw terminal output, field values, screenshots, result transport or run-path
identifiers are stored in the repository. The agent observed the process exit and
filesystem postcondition, not the terminal's visual content. This records one
successful interactive path, not a compromised-host guarantee, a full security
audit, or qualification of native failure/timeout/cancel paths. No automatic
repeat, dependency install, service change, commit or push was performed.

### D-068: Minimal local Defender window and one private report

The user authorized a minimal interface and unified report around the accepted
Defender control check, retaining personally confirmed UAC and no system-settings
changes. `npm start` now opens an ordinary Windows Forms view; merely opening it
does not prepare or collect. A preparation button, exact one-use phrase and then
manual UAC gate the unchanged fixed operation. No service, browser server, network,
new dependency or broader collector is introduced. Existing event-source values
are checked read-only before preparation/confirmation; no repair is attempted.

The CLI and window share a normalized private two-field report. Separate HTML save
uses a chosen new local file, without overwrite, automatic export or raw evidence.
Missing coverage stays NotTested, other areas remain untested, and reported helper
completion is not cryptographic attestation or a compromised-host guarantee.
Source/synthetic tests and non-visible Windows Forms control construction are the
evidence for this slice, not live GUI acceptance. No helper build, Velociraptor run,
UAC interaction, system change, commit or push occurred in this implementation pass.
See [scope and acceptance](defender-desktop-mvp.md). Subsequent manual results are
recorded separately in D-069; the implementation-only claims above are historical.

### D-069: Narrow manual desktop acceptance and source checkpoint

On 2026-11-06 the user requested manual acceptance of the Defender window. The first
opening did not display a window. Removing the UI host's hidden-start flag fixed
the operator-visible opening; a synthetic source assertion preserves that setting.
This did not change the pinned native helper/controller or their launch limits.

The operator exercised preparation-only cancellation and supplied the successful
discard/no-collection message. They then supplied a useful completed report from
the personally confirmed live path, including the cleanup notice. After closing
that window before saving, they requested another opening and provided a saved
HTML report from a later manually confirmed session. Read-only file inspection
confirmed UTF-8, the expected two-field report/limitations, and absence of scripts,
forms and external resources. No automated collection confirmation or UAC action
was used. No audited-setting modification was authorized by this acceptance.

This records narrow manual acceptance, not blanket GUI/native/production acceptance.
Cleanup is recorded as reported by the accepted UI output, not as a new independent
filesystem/ACL audit; saved HTML source inspection is not browser-rendering proof.
Remaining visual, refusal/failure and export-negative cases stay unqualified in
[the acceptance record](defender-desktop-mvp.md#d-069-narrow-manual-acceptance-2026-11-06).

The user explicitly requested documenting these outcomes and committing/pushing
the current implementation. Only source, synthetic tests and normalized documents
are included. The real report, field values, raw output, run IDs, runtime paths,
per-run digests, binaries, acquisition material and caches remain outside Git.
The checkpoint itself does not rerun Velociraptor, compile a helper, request UAC or
change Windows. The development layout is still not portable or an offline scanner.

## Open decisions before runtime

| ID | Decision | Required evidence |
|---|---|---|
| O-001 | Runtime binary acquisition, signer/hash trust, pinning, update, and rollback | Official release metadata study plus tamper/downgrade tests |
| O-002 | CLI stdout versus standardized collection container | Binary-backed v0.77.1 compatibility experiment for sources, logs, errors, partial output, cancellation, and encodings |
| O-003 | Windows elevation boundary | Threat model, typed protocol, consent flow, DLL/path/TOCTOU/replay tests |
| O-004 | Private storage and retention | Exact durations, ACL/encryption format, temp/crash/paging/backup lifecycle, key recovery/erasure, SSD limitations |
| O-005 | Safe platform/users/local-admin/password-policy collectors | Demonstrated read-only VQL-native definitions without transitive write or exec |
| O-006 | Safe WinRE/recovery sources | Read-only sources without command execution, repair, or configuration change |
| O-007 | Area-specific Observation schemas | Field definitions, privacy mapping, byte limits, provenance, and fixtures |
| O-008 | Initial rules and severity rationale | Security review plus deterministic positive/negative examples |
| O-009 | Supported Windows versions/editions | Standard/elevated behavior and unsupported-state test matrix |
| O-010 | HTML renderer, localization, and CSP | Injection corpus and browser regression plan |
| O-011 | Validator CI integration and independent recheck | Reproduce the installed pinned Draft 2020-12, discriminator-aware XOBJ-GRAPH1, and exact-ID JCS-DIGEST1 gates in deterministic CI, then perform ARCH-REVIEW6 |
| O-012 | External integrity trust anchor | Protected stored digest or detached signature design and key lifecycle |
| O-013 | Protected maintenance implementation; DEPLOY-001 approved for design | Independently reviewed helper authority/confirmation and MP cases, signed packaging, tested ownership/ACLs, durable admission, runtime leases, crash recovery and bounded retention |
| O-014 | Narrow launch broker; D-052 approved for design only | LS-001/002/003 account/privilege, authenticated token handoff, object ownership, session/handle and exact-confirmation review; all remaining TL/MMR gates and independent native acceptance |

Direct-launch development is authorized under D-032 alongside the working
import-only path. Automatic/background execution remains disabled, and actual
general production execution remains blocked by unresolved technical gates, not
by D-028's superseded development restriction. The narrowly scoped, completed
D-064/D-065 control run above is not general runtime acceptance.

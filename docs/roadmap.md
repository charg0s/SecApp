# SecApp Roadmap

Status: Stage 0 accepted at `283da2e85dbdd7802308632aae29e4c2eea45400`; direct-launch development reopened with unresolved technical blockers; import-only core implemented pending independent review; no release dates are implied

## Current release target: direct Standard MVP (D-062)

[DIRECT-STANDARD-MVP1](direct-standard-mvp.md) is the user-approved current path:
one fixed read-only Defender check, ordinary rights, explicit confirmation,
bounded execution/cancellation and private reporting on a trusted host.
Service/RPC/elevated work is deferred, not part of this release's critical path.

1. Bounded raw-output adapter and supplied-file report preview: implemented in
   this slice, with synthetic tests; no live collection claim.
2. Direct Standard launcher: next, including backend trust/startup effects, fixed
   operation, resource/output limits and owned cleanup; not implemented yet.
3. Useful live check -> report/minimal UI, plus targeted refusal/cancel acceptance.

No automatic elevation or permission to alter audited settings is added. A
NotTested-only report or synthetic preview is not MVP completion. The QP-0 service
path remains historical/deferred, not a prerequisite for this direct route.

## Historical trusted-host/service target (D-058 / D-061)

The user approved [TRUSTED-HOST-MVP1](trusted-host-mvp.md) on 2026-11-06,
broadening D-056 beyond confirmation alone. The first release assumes trusted
Windows and a trusted session, with no guarantee against pre-existing same-user
malware. Stronger isolation/protected-desktop research is deferred, not Passed.
The service remains selected; actual installation still requires its exact
reviewed mutation manifest and explicit confirmation.

The requirements delta has independent AcceptedRequirementsRebaselineOnly status.
The [acquisition record](backend-acquisition-verification.md) now establishes
the v0.77.3 gzip/EXE byte domains and detached-signature cryptography under the
pinned primary key, without execution. Key lifecycle, Windows image trust and
release/runtime acceptance remain pending.
The [trust/launch follow-up](backend-trust-launch-slice-review.md) adds GnuPG
verification and the actual `highestAvailable` manifest, flags current dependency
review work and records the historical LocalService candidate. D-061 permits
a virtual-account proposal with necessary service-only rights at a future exact,
separately confirmed installation; [the rights table](broker-bootstrap-contract.md#8-d-061-scoped-service-account-rights-proposal)
is a candidate, not an accepted manifest or current grant. The
[QP-0 feasibility review](broker-rpc-feasibility-review.md) finds the current
two-binding RPC candidate NoGoForNativeImplementation: no missing guarantee is
closed by compilation or a test plan. Its explicit-token-handle/typed-context
alternative requires a concrete contract-equivalence review before adoption.
Next resolve that account's pre-exposure RPC binding and initial object security,
then the remaining bounded Standard launcher/effects and release-trust slice;
implement/test only
after its independent acceptance. Version -> separately confirmed Help ->
reviewed read-only protection collection -> private assessment/report -> minimal
UI/package acceptance.
SensitiveDataCollection remains separately authorized. No old planner flag,
schema or historical expected result changes to make this sequence look ready.

[Initial release triage](backend-release-review.md) retains the v0.77.3 startup
event-source finding. D-058 replaces a blanket no-system-change policy with
exact approved installation/working/logging effects, not permission to alter
audited security settings. Release trust and actual launch remain unaccepted.
Full generic maintenance/update and active same-user resistance are not on the
first release's critical path; basic install ownership, recovery refusal and
run quiescence remain mandatory. The stage history below is retained evidence.

## Guiding constraints

- Keep SecApp independent and fully open.
- Prefer an unmodified Velociraptor backend and upstream-compatible artifacts.
- Keep collection, normalization, rules, findings, reporting, orchestration, and UI separate.
- Default to read-only and offline collection.
- Treat elevation, network, reboot, memory acquisition, Defender Offline, and remediation as separate consent scopes.
- Use synthetic fixtures only.
- Do not claim complete threat detection.

## Stage 0: architecture and upstream suitability

Deliverables:

- official-source study of Velociraptor modes and security boundaries;
- integration-option comparison;
- audit parity matrix;
- data-contract schemas;
- assessment, privacy, and threat models;
- AUDIT-FOUNDATION1 definition;
- fork criteria and decision log.

Exit evidence:

- every technical Velociraptor claim links to official documentation or the v0.77.1 release tree resolved to commit 3137c7f714ab344dd37d0df1d5393573e41b30a5;
- source/research pinning is kept separate from the future runtime binary version, signer, and digest;
- schemas, positive examples, negative cases, local references, and application-level invariants pass a full Draft 2020-12 CI gate;
- open blockers are explicit;
- no runtime code or backend binary is present.

ARCH-REVIEW6 accepted baseline `283da2e85dbdd7802308632aae29e4c2eea45400` with no blockers or high-priority corrections and authorized only the separate VELOCIRAPTOR-ADAPTER-COMPAT1 experiment. This acceptance does not make any validator a runtime dependency, provenance proof, production-readiness claim, or declaration that schemas are production-ready.

## Stage 1: contract and backend compatibility experiment

This stage requires separate authorization because it introduces executable development and a user-supplied backend binary.

Questions to answer:

1. What exact official binary acquisition and verification process is acceptable?
2. Which Velociraptor versions are supported?
3. Is local stdout JSON stable and source-identifiable for selected artifacts?
4. Is a standardized collection container required?
5. How do timeout, cancellation, limits, partial output, and exit codes behave?
6. Can custom artifacts load from a digest-checked read-only directory?
7. Can all default collectors avoid network, execve, write, upload, and memory capabilities?
8. Does the reviewed runtime binary correspond to the v0.77.1 source pin, and how is that binding authenticated?
9. Can safe VQL-native platform, users, local-admin, password-policy, and recovery collectors replace UnsafeForDefault built-ins?

Deliverables:

- recorded compatibility results, not product collectors;
- versioned adapter contract;
- updated decisions and blockers;
- no silent fallback to API or Instant mode.

Exit evidence:

- repeatable tests against explicitly approved official versions;
- captured formats represented only by synthetic/redacted fixtures;
- recommendation confirmed or revised.

VELOCIRAPTOR-ADAPTER-COMPAT1 tested the exact official v0.77.1 Windows AMD64 asset and ended `compatibility_partial_blockers_remain`. The verified invocation, JSON/ZIP import, error semantics, and blockers are recorded in [velociraptor-adapter-compatibility.md](velociraptor-adapter-compatibility.md). The permitted next gate is VELOCIRAPTOR-ADAPTER-COMPAT-REVIEW1, not production adapter implementation.

### TRUST-LAUNCH-DEFER-CHECKPOINT1 disposition

The subsequent development-only trust-launch prototype supplied partial
evidence for private execution roots, file locking, environment allowlisting,
Job Object test behavior, and cleanup. It did not invoke Velociraptor and did
not resolve the loader, token, reparse, executable-image binding, or acceptable
non-elevated production-launch boundaries. Its source and normalized contract
are retained only as a WIP checkpoint.

```text
TrustLaunchStatus = Deferred
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
VelociraptorInvocationFromSecApp = ForbiddenByDefault
NextProductPath = ImportOnly
```

`AUDIT-PACKAGE-IMPORT1` was the next product direction and required its own
authorization. Its later bounded local-import implementation is separate from
this checkpoint. Stages that depend on a backend launcher remain blocked and
are not authorized by the import-only direction.

## Import-only product slice: AUDIT-PACKAGE-IMPORT1

The separately authorized slice implements one explicit local-file import for
strict JSON objects, JSONL object records, and a restricted audit-package ZIP.
It validates container bounds, canonical paths, exact manifest membership,
stored-byte and contract digests, core references, and local Draft 2020-12
contracts through an explicit reference gate. Results are normalized and the
default summary excludes materialized object values.

The slice has no backend, launcher, GUI, service, agent, elevation, network,
collection, remediation, or archive extraction. Ajv remains dev-only. The
automated tests use synthetic values and generate bounded ZIP bytes only at
test time. Passing the import suite is not a provenance, host-truth, production
readiness, or complete application-validation claim; independent review and
later product integration remain separate gates.

### Local import CLI

The reference CLI now connects explicit file selection to the bounded importer
and the installed offline Draft 2020-12 registry. It supports a readable summary
or a single JSON result, stable exit codes, and lowering-only input limits.
Targeted regression tests cover parser depth/Unicode, early JSONL bounds,
DEFLATE trailing data, ZIP name normalization, and source-path syntax.

This is the first directly runnable import entry point in the checkout. It
does not yet provide a Windows distribution or independent security-review
acceptance. Remaining product work is: select a supported external package
producer/conversion path; complete runtime and application validation; add
review domain normalizers and risk rules; build the UI; decide private
storage and public-export policies; then perform end-to-end Windows testing.
Backend launch remains deferred throughout that import-only path.

### Imported Windows protection reference profile

`windows-protection-v1` now maps four strict, versioned Observation payloads
to six deterministic checks and a private text/JSON/standalone-HTML report.
It runs only on an explicitly imported snapshot. Unknown, absent, unsupported,
and failed collection states preserve coverage gaps. Synthetic tests exercise
both rule outcomes, strict payload rejection, duplicate/run mismatches,
private output, and HTML escaping. Existing core contract schemas are unchanged.

This is a reference slice pending independent policy/security review, not a
real-host collection path or a production audit. No package producer,
provenance/freshness assurance, app-managed storage, public export, Windows
installer, or GUI is supplied. The next useful integration is explicit local
file selection and report viewing around this import-only pipeline, together
with a reviewed external producer/conversion contract. See
[the profile contract](windows-protection-import.md).

## Direct-launch development: BACKEND-LAUNCH-PLAN1

The user has lifted the development deferral. This newer authorization
supersedes the historical work restriction above, not the blocker results.
The first implemented slice is a pure planner for Version/Help diagnostics:
fixed argv, historical identity pin, lowering-only limits, exact blockers,
deterministic digest, strict schema, and a CLI that never executes a backend.

Next stages are ordered: select and review the native process boundary;
resolve token/root/reparse/image-load and verified-image binding requirements;
implement bounded IO/cancellation/tree cleanup; independently review evidence;
then enable explicitly authorized version/help/synthetic verification. Reviewed
read-only collectors and conversion to Observation follow only after that.
No automatic startup scan, server, API, service, UAC, native probe, or real
collection is introduced by the planner. The import-only path stays usable.
See [the concrete gate and lifecycle design](backend-launch-design.md).

The separately authorized `BACKEND-NATIVE-SYNTHETIC1` now supplies a narrow
self-launch helper: ten native scenarios passed in three final-source runs,
with temporary builds removed. Rights, bounded streams/deadlines, cancellation,
and owned-tree cleanup were checked. Linked-token metadata remains Present;
all nine production gates remain open. This is not a production adapter and
does not run Velociraptor or the old TrustLaunchProbe matrix. Only pure record
validation is automatic. See [the experiment scope](../tests/backend/native-synthetic/README.md).
The next trust-design work is EXE/root/DLL/reparse/image binding and selection
of the standard-user mechanism, followed by independent review; real backend
handshake and optional elevation each remain separately gated.

`BACKEND-IMAGE-TRUST-DESIGN1` completes the next documentation/research slice:
official Microsoft API facts, candidate comparison, protected-code/data
separation requirements, and sixteen Planned/NotRun acceptance vectors. It
recommends protected versioned installation with Standard operation unelevated;
DEPLOY-001 was subsequently approved for further design. Protected placement
alone is not a complete loader, image-binding or same-user process-isolation
solution. No native probe,
installer, policy deployment or gate closure occurred. See
[the design and deployment decision](backend-image-trust-design.md).

`PROTECTED-INSTALLER-DESIGN1` records that approval without granting host
installation authority. The proposed per-machine MSI boundary separates setup
from collection, leaves the external backend unbundled, and defines protected
code/policy versus user data, exact package admission, versioned selection,
failure recovery, repair and uninstall. All 22 installer cases are Planned/NotRun;
no MSI, custom action or system-side change exists.
See [the installer design](protected-installation-design.md).

`DEPLOYMENT-PLAN-CONTRACT1` implements the subsequent pure-model slice: two
development-only contracts, fixed operation scopes, synthetic confirmation and
generation/epoch checks, cancellation, ambiguous-publication recovery and
post-commit cleanup states. Exact-ID synthetic tests join `npm test`. No host
writer, authenticated receipt, persistent replay store, installer or launch
authority exists; all PI/native gates remain unchanged. Native protocol/trust
and recovery review remain required, not an automatic installation or lab run.
See [the contract and limits](deployment-plan-contract.md).

`MAINTENANCE-PROTOCOL-DESIGN1` adds the subsequent design proposal: a helper-owned
local IPC candidate, independent operation confirmation, bounded requests and
payloads, protected consume-before-effect admission, lost-reply handling and
freshly confirmed recovery. Peer PID/SID and UAC are not operation authority.
All 28 MP vectors are Planned/NotRun. No production wire schema, helper, journal,
pipe, UAC or installer was implemented. The subsequent bounded slice is recorded
below. See
[the protocol proposal and prerequisites](maintenance-protocol-design.md).

`MAINTENANCE-PROTOCOL-CONTRACT1` now implements three development-only schemas,
strict message direction/order and offer/confirmation binding, modeled durable
admission, status-only lost-reply handling and disjoint recovery targets. Its
MPC-001..053 synthetic vectors and completeness check join `npm test`. Payloads
are metadata only; local verification/confirmation/persistence are hypotheses,
not native evidence. No MP/PI/launch gate closes. Mechanism selection and review
continue below, still before independently reviewed and separately authorized
native implementation. See
[the implemented reference contract](maintenance-protocol-contract.md).

`MAINTENANCE-MECHANISM-REVIEW1` is an author review, not independent acceptance.
It records the short-lived helper/local-pipe candidate, protected-file writer
serialization/runtime gate and bounded journal/head direction. It fixes exact
null-selection recovery with five additional synthetic vectors. Confirmation
integrity, crash-to-quiescence, durable publication and packaging remain blocked.
Next safe slice: `MAINTENANCE-PERSISTENCE-MODEL1`, synthetic write/flush/head/reply
and crash ordering only, without filesystem writers or native calls. See
[the mechanism review and open obligations](maintenance-mechanism-review.md).

`MAINTENANCE-PERSISTENCE-MODEL1` now implements two new development schemas and
a pure fault model. MPS-001..040 plus completeness cover ordered journal/head
I/O hypotheses, all normal/compaction crash boundaries, counter/floor regression,
stale heads, lost replies, fresh recovery and retained lineage. Existing schemas,
dependencies and native evidence remain unchanged. It does not implement an OS
writer or resolve any MMR/native gate. It provides the separate persistence
assumptions used by the subsequent composition review. See
[the persistence model and limits](maintenance-persistence-model.md).

`MAINTENANCE-COMPOSITION-REVIEW1` adds 24 paired synthetic cases and exact-ID
completeness. It aligns lost-reply suspension and restart status for pending
publication, while documenting intentional abstraction differences and the
missing production authority binding. This is author self-review, not independent
acceptance. All native gates remain open. Next bounded slice:
`MAINTENANCE-STORE-CODEC1`, a strict development-only in-memory byte format/codec
with synthetic malformed-input tests, no file writer or recovery executor.
Native work still requires independent acceptance and separate authorization.
See [the composition review](maintenance-composition-review.md).

`MAINTENANCE-STORE-CODEC1` now implements that bounded whole-snapshot format and
strict in-memory codec, with a separate immutable development schema.
MSC-001..036 plus completeness cover golden bytes, malformed framing/JSON,
checksum layers, all normal/compaction prefixes and uncertainty preservation.
No physical store, append writer, recovery executor or production authority is
added. Remaining maintenance design work includes Admitted-candidate retirement,
full-journal capacity handling and interrupted checkpoint reconciliation, before
independent trust-boundary acceptance and any separately authorized native work.
See [the codec contract](maintenance-store-codec.md).

`MAINTENANCE-RECOVERY-POLICY1` records the design rules for these three gaps:
fresh metadata-only retirement, completion-plus-maintenance capacity before
admission, and exact old/new checkpoint classification with separately confirmed
reconciliation. Its documentation-only stage left existing behavior unchanged.
`MAINTENANCE-RECOVERY-MODEL2` now adds the separate v2 contract, pure fault model,
snapshot codec and RP-001..030 plus completeness. v1 files remain unchanged;
there is no automatic migration, native adapter or host writer. The nominal
budgets and bounded blocked crash states are now executable synthetic evidence,
not a physical durability proof. See [the model](maintenance-recovery-model-v2.md).

`MAINTENANCE-RECOVERY-FIX1` corrects four author-review findings in v2: candidate
epoch downgrade, minimum loss on a corrupt tail, terminal generation gaps and
expiry-cutoff mismatch. MRF-001..012 plus exact-ID completeness are added without
changing schemas, v1 or the original RP suite. The new regressions reproduced
failures before the model changes; see [the corrections](maintenance-recovery-fixes.md).

The separate recheck found three additional cases despite the green existing
suite. `MAINTENANCE-RECOVERY-FIX2` corrects nested unsupported expiry, impossible
terminal operation/outcome pairs and transaction-level status masking. MRR-001..010
plus completeness supply regression evidence without changing any schema or old
suite. See [the corrections and bounded recheck status](maintenance-recovery-recheck.md).

`COMPOSED-BOUNDARY-CONTRACT1` adds the next bounded step: a private test-only
correspondence/denial gate for deployment, protocol v1 and recovery v2. It covers
five ordinary operations at four complete boundaries and rejects spliced tuples,
authority domains, clocks, claims and unmapped recovery operations. It neither
changes the models nor supplies a production bridge. See [the exact scope and
review disposition](composed-boundary-contract.md).

`COMPOSED-RECOVERY-CONTRACT1` follows with a separate private test-only history
checker: one ordinary origin, up to three finalization/restoration/cleanup
attempts and bounded read-only historical queries. Entire prior states and fresh
authorization must match; no standalone Known snapshot grants authority. The
v2-only metadata operations stay explicitly unmapped. See [the contract and
independent disposition](composed-recovery-contract.md). Consolidated production
blocker review, metadata protocol parity and the maintenance/native trust boundary
remain separate acceptance work. All MMR/TL gates remain open. Read-only
Velociraptor execution now has user permission, but no launcher implementation
or technical acceptance is inferred. System-setting creation/deletion/change,
installation, UAC and other separately scoped operations remain unauthorized.

With subsequent explicit permission, `NATIVE-BOUNDARY-EXPERIMENT1` performs only
the bounded synthetic DLL/image/IPC/abrupt-exit experiment on the primary host.
Seven observations were repeated in three final-source runs. Its same-user
access and explicit local DLL mapping results reinforce the open native boundary;
the signature/pipe/cleanup observations are narrower than production guarantees.
Thirty-three pure normalized-record tests join npm test without native execution.
See [the exact scope and results](../tests/backend/native-boundary/README.md).
No installation/UAC/ACL or system-setting permission is inferred, and all TL/MMR
blockers remain Open. Selecting a process/bootstrap isolation mechanism and a
compatible preventive loader policy remains necessary before runtime acceptance.

The user approved `BACKEND-LAUNCH-MECHANISM-SELECTION1`'s separate-identity,
SCM-bootstrapped narrow broker for design (D-052). This is not permission to
implement or install a service. AppContainer remains optional worker containment;
exact worker identity, trusted confirmation and preventive loading are unproved.
See [selection, alternatives and eight existing-obligation checkpoints](backend-launch-mechanism-selection.md).
The agreed small release targets launcher, fixed backend adapter, reviewed
read-only protection profile, minimal UI/private report, packaging and end-to-end
acceptance. Defer automatic updates and broad forensic features, not trust or
interrupted-install safety. No further native experiment or system change is
authorized by this selection document; all TL/MMR blockers remain Open.

`SERVICE-LAUNCH-BROKER-DESIGN1` details the demand-start, own-process broker,
separate Standard supervisor in the requester's session, bounded command surface
and stop/recovery rules. It separates identification-only control IPC from a
still-unaccepted token-acquisition channel: no cross-session inherited pipes,
LocalSystem fallback or maintenance-consent reuse. Next, review the concrete
account/privilege, token handoff, process ownership and exact-confirmation
feasibility together (LS-001/002/003), before any service code or native trial.
See [the design and remaining decision gates](service-launch-broker-design.md).

`LAUNCH-CONFIRMATION-DESIGN1` refines LS-003/007: immutable broker-derived scope,
pinned complete presentation, a separate CC-only decision channel and internal
consume-before-create admission. No transferable UI permit or new ConsentReceipt
variant is introduced. Review cases remain Planned/NotRun; message consistency
does not prove protected human input or crash-consistent storage. Next, select
and independently assess the confirmation component's Windows bootstrap and
display/input mechanism. See [the design and explicit open gate](launch-confirmation-design.md).
No installation, keys, runtime code, UAC or system changes are authorized.

The 2026-11-06 [confirmation mechanism review](launch-confirmation-design.md#61-windows-mechanism-triage-2026-11-06)
narrows the next paper review to a concrete private-desktop bootstrap/owner/access
sequence. Ordinary UI/UIPI is insufficient alone; Credential UI introduces a
credential contract, and UAC/Hello do not independently close exact-scope consent.
The private-desktop path must resolve same-user access, session placement,
object substitution, input/transition integrity and safe restore within the
existing privilege budget. If it cannot, reject it and seek an explicit revised
architecture decision; do not silently broaden privileges or weaken the threat
model. DisplayInputProtection remains NotSelected and NativeApproval Disabled.

The subsequent [concrete bootstrap review](launch-confirmation-design.md#64-concrete-bootstrap-review-no-implementation-go-ahead)
completes that bounded paper review with NotAccepted / no implementation go-ahead.
It rejects Session 0 switching, the excluded service-token session rewrite, and
ordinary shared-SID desktop grants. A retained-handle alternative is not proved
impossible, but lacks accepted creation/attachment, input and crash-restoration
evidence. OWNER RIGHTS and input-origin flags are not complete solutions.
That review required a choice between native research and a scoped assurance
revision. D-056 now selects the latter, defined by TRUSTED-LOCAL-MVP1 above.
The stronger private-desktop route remains NotAccepted; host changes are not
authorized and existing model tests are not runtime acceptance. Other TL/MMR
gates stay Open.

The target includes Standard by default plus an optional user-confirmed
Elevated read-only pass (D-033), as already modeled by AuditPass. Plan the
consent UI and narrow temporary elevated helper alongside standard launching;
activation requires separate reviewed authorization, IPC/trust, and cleanup
implementation. Test refusal, UAC cancellation/failure, replay/scope mismatch,
and already-elevated-parent cases. Preserve Standard results and NotTested
coverage when elevation is unavailable. Do not treat Administrative consent as
network, memory, scan, reboot, remediation, sensitive-data, or export permission.
The current diagnostic planner remains non-executing and non-elevating.

## Stage 2: security foundations

Prerequisites:

- reviewed backend trust/update policy;
- reviewed narrow elevation design;
- exact retention periods for every raw, derived, log, export, and backup class;
- encrypted storage, storage ACL, key source/recovery/rotation/erasure, and backup design;
- temporary-file, crash-dump, paging, antivirus/indexer, and plaintext-staging design;
- documented SSD/snapshot/backup deletion limitations and export-copy deletion behavior;
- local-only semantics and compromised-host limitations;
- composition/deanonymization policy and multi-source corroboration policy;
- logical-path and reparse-point handling design;
- continuation-state authentication design;
- report sanitization design.

Deliverables:

- threat-model verification plan;
- consent receipt and action-log implementation plan;
- resource-limit policy;
- full schema/cross-object validation and migration plan;
- public-export canary suite design;
- independent security review findings.

Exit evidence:

- no unresolved critical trust-boundary design;
- every privileged operation has an explicit owner, input schema, and denial path.

## Stage 3: AUDIT-FOUNDATION1 implementation

Prerequisites:

- Stages 1 and 2 complete;
- area-specific observation schemas reviewed;
- initial deterministic rules and severity rationale reviewed;
- supported Windows version/edition matrix selected.

Implementation order:

1. standard-user orchestrator state machine;
2. backend adapter and raw-output integrity;
3. normalizers and area-specific schemas;
4. deterministic rules and findings JSON;
5. private Markdown report;
6. safe static HTML report;
7. manifest and SHA-256 verification;
8. redacted export;
9. separately approved elevated pass;
10. authenticated reboot continuation only if still required.

Exit evidence is defined in [AUDIT-FOUNDATION1.md](AUDIT-FOUNDATION1.md).

## Stage 4: broader audit parity

Candidate areas after foundation acceptance:

- network listeners/connections;
- WMI persistence;
- drivers and signature coverage;
- executable target ACLs;
- remote management;
- PowerShell policy/logging;
- DNS/proxy/hosts;
- installed software/runtime inventory;
- bounded significant-event analysis;
- Defender Offline diagnostics from existing logs only.

Each addition requires a parity-matrix update, privacy review, threat review, schema, deterministic rules, positive/negative tests, and explicit limitations.

## Stage 5: optional forensic workflows

Potentially separate profiles:

- targeted file acquisition;
- richer event collection;
- offline collection-container import;
- bounded threat hunting;
- reboot-aware collection;
- memory acquisition.

These are not extensions of default consent. File content, memory, network use, and large forensic evidence require distinct workflows, storage policy, and user approval.

## Deferred alternatives

- Local frontend/client and gRPC API remain fallbacks if the CLI contract is proven inadequate.
- Instant GUI may be used by developers or analysts in an approved lab, but it is not the SecApp UI.
- Fleet hunts and continuous monitoring are outside the single-machine first slice.
- Remediation remains outside the audit pipeline.

## Fork review gate

A fork review can be opened only with a reproducible, version-pinned blocker matching the criteria in [velociraptor-integration.md](velociraptor-integration.md). The review must include:

- failing official mode and exact source revision;
- security or contract requirement that cannot be met externally;
- upstream issue/discussion outcome when appropriate;
- long-term merge, security-update, and release maintenance cost;
- exit strategy if upstream later resolves the blocker.

Convenience is not a blocker.

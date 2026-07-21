# SecApp Roadmap

Status: Stage 0 accepted at `283da2e85dbdd7802308632aae29e4c2eea45400`; trust-launch deferred with blockers; import-only is next; no release dates are implied

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

`AUDIT-PACKAGE-IMPORT1` is the next product direction and requires its own
authorization. It is not part of this checkpoint. Stages that depend on a
backend launcher remain blocked and are not authorized by the import-only
direction.

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

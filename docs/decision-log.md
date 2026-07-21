# SecApp Decision Log

Status: architecture baseline accepted by ARCH-REVIEW6; trust-launch is deferred; import-only is the next product direction

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
Import-only development requires the separate `AUDIT-PACKAGE-IMPORT1` stage;
it is not started by this decision.

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

Automatic Velociraptor execution remains forbidden by default. The permitted
next product direction is the separately authorized `AUDIT-PACKAGE-IMPORT1`
import-only workflow, not runtime launcher or adapter implementation.

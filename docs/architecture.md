# SecApp Architecture

Status: targeted ARCH-FIX3 contracts complete; independent architecture and full-schema recheck required

Research baseline: 2026-07-18

Velociraptor capability source pin: release [v0.77.1](https://github.com/Velocidex/velociraptor/tree/v0.77.1), resolved source commit [3137c7f714ab344dd37d0df1d5393573e41b30a5](https://github.com/Velocidex/velociraptor/tree/3137c7f714ab344dd37d0df1d5393573e41b30a5)

## Evidence labels and pinning

- **Confirmed** means supported by official documentation or the pinned release source.
- **Proposed** means a SecApp design decision not proven with a backend binary.
- **Open** means a controlled experiment or security decision is still required.

The release/source pin identifies reviewed source text. It is not the runtime pin. A future runtime pin must independently record the binary version, file digest, signer/trust decision, acquisition metadata, and rollback policy. SecApp must not infer binary authenticity from a Git tag or source commit.

## Scope and non-goals

SecApp is a local Windows security-audit and forensic-collection system. Collection, assessment, consent/UI, reporting, and export are separate layers. The default profile is read-only and offline. Network use, elevation, reboot, memory acquisition, and remediation require separate exact consent.

This stage defines documentation and data contracts only. It implements no collector, adapter, rule engine, GUI, installer, elevation helper, or backend. It makes no claim of complete detection or safe runtime readiness.

Read-only describes requested capabilities. Reads can still update operating-system caches, trigger security-product logging, and cause a backend to write private output. These effects require runtime measurement.

## Confirmed upstream properties

- One Velociraptor binary exposes client, server, GUI, local query, local artifact collection, and offline-collector modes depending on arguments ([deployment overview](https://docs.velociraptor.app/docs/deployment/); release sources [query.go](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/bin/query.go), [artifacts.go](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/bin/artifacts.go), and [gui.go](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/bin/gui.go)).
- VQL is the query engine. Artifacts package VQL, parameters, sources, imports, and preconditions; custom definitions can be supplied separately ([artifact model](https://docs.velociraptor.app/docs/vql/artifacts/)).
- The supported external automation interface is streaming gRPC with mutual-certificate authentication. The internal REST surface is not the SecApp contract ([server API](https://docs.velociraptor.app/docs/server_automation/server_api/)).
- Client-side artifact execution is not sandboxed by implied_permissions. Source, dependencies, optional branches, VQL functions, parameters, and runtime behavior must all be reviewed ([artifact security](https://docs.velociraptor.app/docs/artifacts/security/)).

## Component boundaries

### Consent and UI

The UI presents exact collector, purpose, privacy classes, privilege, capabilities, network/mutation policy, limits, and known limitations. It creates a ConsentReceipt. It never constructs VQL or command strings and never handles secret keys.

### Orchestrator

The orchestrator owns the AuditRun/pass lifecycle, allowlist, CollectorDefinition validation, consent matching, action log, limits, cancellation, and reboot state. It passes typed values to an adapter and applies all rules in [integrity-model.md](integrity-model.md).

### Backend adapter

The proposed baseline launches an externally supplied, unmodified Velociraptor binary as a bounded local process. It uses fixed argument positions and an exact command-contract identifier. It verifies the approved binary identity and CollectorDefinition digest immediately before launch, uses a safe private working directory, and rejects any capability not declared transitively.

Acquisition, signer trust, update, rollback, elevation, and private storage remain unresolved. No release binary is part of SecApp.

### Collectors

Collectors acquire state only. They do not assign severity, suppress findings, render reports, or remediate. Built-ins are accepted only after release-specific transitive review. Custom artifacts use unique SecApp names, pinned content digests, Windows preconditions, bounded outputs, and no hidden download, execution, write, network, remediation, or memory behavior.

Windows.Sys.Users is excluded from the default profile in v0.77.1 because it declares FILESYSTEM_WRITE. Generic.Client.Info is also UnsafeForDefault when collected as a whole because its Users source calls Windows.Sys.Users. Windows.Registry.RDP transitively reaches Windows.Sys.Users through Windows.Registry.NTUser. The permissions metadata is evidence for review, not a security boundary.

### Normalizer

The normalizer converts untrusted backend rows into bounded area-specific Observation objects. One canonical execution_id is carried by Observation; provenance does not duplicate it. An invalid, unsupported, missing, or incomplete collection produces an error or coverage finding with confidence Not tested, never an absent/safe result.

### Rule engine

Rules are declarative. RuleDefinition uses a flat predicate graph with at most 64 predicates, depth 8, and at most 16 children per All/Any node. Evaluation order and missing/null/type-mismatch semantics are explicit. Application validation rejects duplicate IDs, missing references, unreachable nodes, and cycles.

### Reporters and export

Reporters consume validated objects. HTML requires contextual escaping, local assets, no active content, and a restrictive content-security policy. Export reconstructs a new package locally using an exact RedactionProfile digest and composition policy; it never copies a private run directory.

## AuditRun, AuditPass, and CollectorExecution lifecycle

AuditPass is a standalone versioned contract because the logical layout contains one `passes/<pass-id>.json` member per pass. AuditRun is a bounded index/summary that references passes, executions, observations, evidence, and findings; it never embeds the full graph.

One AuditRun contains:

1. one standard pass;
2. an optional separately consented elevated pass;
3. an optional reboot-continuation pass;
4. an optional post-reboot pass.

Each pass has its own ID, run binding, privilege class, consent receipt IDs, collector execution IDs, prerequisite IDs, reboot-planned marker, timestamps, and status. Exactly one Standard pass is first; optional kinds are unique. Elevated requires Administrative consent and only Elevated executions. Standard contains only StandardUser executions. RebootContinuation follows a pass that planned reboot and presents matching Reboot or DefenderOffline consent; PostReboot follows a valid continuation. A collector-empty pass is allowed only as explicit `NotTested` coverage-only state.

CollectorExecution states are:

- pre-execution: Planned, NotTested, BackendNotFound, ConsentDenied, PolicyRejected;
- active: Running;
- terminal: Succeeded, Failed, TimedOut, Cancelled, Partial.

Every state has an exclusive allowed-field set. Pre-execution forbids process/runtime/terminal metadata; BackendNotFound records only expected source identity and a structured absence error. Running requires started_at, applied limits, command contract, and observed backend identity while forbidding terminal fields. Succeeded requires exit zero, successful parser/import, count and raw digests, with no truncation, error, failure, timeout, cancellation, or partial marker. Failed, TimedOut, Cancelled, and Partial have distinct required and forbidden metadata as specified by the schema and [integrity-model.md](integrity-model.md).

## Consent and action authorization

ConsentReceipt binds `consent_type` to one exact `operation_code`, target, run, pass, action, host, expiry, and single-use nonce. Administrative, NetworkAccess, Reboot, DefenderScan, DefenderOffline, MemoryAcquisition, Remediation, SensitiveDataCollection, and Export are separate authorities; none implies another. Approved capabilities and privacy classes must be requested subsets and must cover, without exceeding, the collector contract.

ActionLog entries contain a structured operation and structured redacted parameters, not free-form requested operations. Sensitive fields use canonical field IDs and registry validation. Action-specific schema gates require collector/execution/command IDs and the relevant authorization structure. Application rules prove that presented receipts match the same run, pass, action, operation, target, collector, and privacy/capability scope.

EntryDigest is SHA-256 LowerHex of RFC 8785 JCS for the complete entry with only `entry_digest` removed. The previous digest remains included; sequence starts at zero with explicit null and has no gaps or duplicates. Local chaining detects modification only relative to a separately protected anchor.

## Data contracts

All schemas use Draft 2020-12, schema_version 1.0.0, immutable IDs under https://schemas.secapp.dev/v1/, strict root properties, bounded collections, UTC timestamps, privacy classes, provenance, and explicit digest semantics.

| Contract | Purpose |
|---|---|
| CollectorDefinition | Exactly one backend variant, explicit transitive capability set, policy/consent requirements, initial safety limits |
| ConsentReceipt | Single-use run/pass/action/operation/target-bound exact authority |
| CollectorExecution | Pre/active/terminal lifecycle, applied limits, parser/import status, raw-file digests |
| AuditPass | Standalone pass identity, privilege, prerequisites, consent and execution membership |
| Observation | One normalized statement linked to one execution |
| EvidenceReference | One canonical logical-path reference linked to one observation |
| RuleDefinition | Bounded flat expression graph and finding template |
| Finding | Separate Security or Coverage result with exact rule version/digest |
| ActionLog | Structured authorization/redaction record and precisely defined hash chain |
| AuditRun | At most 4 MiB index/summary with bounded object references |
| AuditManifest | Non-empty exact member/file inventory with required AuditRun/AuditPass/ActionLog roles |
| RedactionProfile | Fail-closed class/field policy, local-only semantics, profile digest |
| ExportManifest | Source/profile/composition-pinned export inventory |
| RebootContinuationState | Single-use authenticated resume state without commands, paths, or keys |
| ErrorObject | Shared bounded typed/redacted error |

Cross-object identity, path, digest, consent, ActionLog, rule-graph, timestamp, and size checks are normative in [integrity-model.md](integrity-model.md). Version and migration behavior is normative in [schema-compatibility.md](schema-compatibility.md).

Observation.data is the one explicit open payload point. It is accepted only after validation against its immutable area schema and a 1 MiB application byte limit. Full objects remain separate manifest members. Initial budgets are 4 MiB serialized AuditRun, 2 GiB decompressed run, and 4 GiB audit package.

## Assessment dimensions

- Severity: Critical, High, Medium, Low, Info.
- Confidence: Confirmed, Likely, Possible, Not detected, Not tested.
- Status: Open, Accepted risk, Remediated, Suppressed, False positive, Requires review.

The dimensions are independent. Coverage findings are distinct from security findings and use Info / Not tested / Requires review without an ordinary Observation.

## Security invariants

- Only a reviewed collector ID/version/digest may run.
- Artifact names, source names, and parameters are structured values, never interpolated command or VQL text.
- Empty or unknown capability sets fail closed.
- Forbidden network policy rejects NETWORK; ReadOnly rejects write/process/service/system-configuration capabilities.
- Elevated, network, reboot, Defender scan/offline, memory, remediation, sensitive collection, and export scopes require their own matching active ConsentReceipt type and exact operation.
- Transitive artifact dependencies and optional parameter branches are part of the capability contract.
- Backend output, archives, reports, localization strings, and schema payloads are untrusted and bounded.
- Logical/export paths use the one fail-closed grammar: every segment starts with ASCII letter/digit and continues only with ASCII letters, digits, period, underscore, or hyphen.
- Local hashes require an external trust anchor and do not prove host truth.

## Readiness and open decisions

Runtime work remains blocked pending:

1. official runtime binary acquisition, signer/hash trust, pinning, and rollback;
2. binary-backed CLI/container contract experiment;
3. narrow Windows elevation boundary;
4. encrypted storage and key lifecycle;
5. safe custom platform/users/local-admin/password-policy/WinRE collectors;
6. area-specific Observation schemas and reviewed rules;
7. supported Windows test matrix;
8. full Draft 2020-12 CI validator and cross-object test harness;
9. report HTML/CSP regression plan.

The architecture is ready only for independent recheck, not runtime implementation.

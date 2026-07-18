# AUDIT-FOUNDATION1

Status: ARCH-FIX3 design profile ready for independent recheck; not implemented and not runtime-ready

Source capability target: Velociraptor release v0.77.1, commit 3137c7f714ab344dd37d0df1d5393573e41b30a5

## Purpose

AUDIT-FOUNDATION1 defines a bounded, local, read-only Windows security-audit baseline. It separates standard and elevated passes, records coverage gaps, produces normalized observations and findings, and supports a separately reconstructed redacted export.

It does not remediate, install, configure, probe remote hosts, download tools, run memory acquisition, trigger Defender Offline, or claim that a host is secure.

## Required operating properties

- no intentional network use by default;
- standard-user pass first;
- exact separate consent for elevated, network, reboot, memory, remediation, and sensitive privacy scopes;
- one CollectorExecution per bounded invocation;
- no command strings or user-supplied VQL;
- release-specific transitive capability review;
- private raw output referenced by file digest;
- Not tested for denied, unsupported, missing, rejected, failed, or incomplete coverage;
- all structural and application rules from [integrity-model.md](integrity-model.md).

## AuditRun pass model

One run references exactly one standalone Standard AuditPass and may reference one each of separately authorized Elevated, RebootContinuation, and PostReboot passes. Standard is first. Each pass is stored under `passes/<pass-id>.json` and has an independent ID, run binding, privilege class, consent receipt IDs, execution IDs, prerequisite IDs, reboot marker, lifecycle, and timestamps.

Standard permits only StandardUser executions. Elevated permits only Elevated executions and requires same-run/pass Administrative consent. RebootContinuation requires a predecessor that planned reboot and a same-scope Reboot or DefenderOffline receipt. PostReboot requires a valid RebootContinuation. A zero-collector pass is valid only as explicit coverage-only `NotTested`.

No single mode field represents the entire run. A failed optional pass does not rewrite a completed standard pass; aggregate state becomes Partial or Failed according to explicit policy.

AuditRun is an index/summary rather than an evidence container. It contains bounded references and no embedded full pass, execution, observation, evidence, or finding objects.

## Coverage plan

| Area | Standard pass | Optional elevated pass | Collector decision at v0.77.1 | Coverage limitation |
|---|---|---|---|---|
| Platform/build/updates | Proposed VQL-native platform collector | Provider data denied to standard user | Generic.Client.Info as a whole is UnsafeForDefault because its Users source calls Windows.Sys.Users; use proposed SecApp.Windows.PlatformAndUpdates | Safe custom source and update completeness require experiment |
| Pending reboot | Read-only marker sources | Denied markers only | Proposed SecApp.Windows.PendingReboot | Markers are not authoritative |
| Defender | Status and bounded metadata | Protected state/events | Proposed SecApp.Windows.DefenderStatus | Provider absence and disabled state differ |
| Firewall | Windows.Sys.FirewallRules plus proposed profiles source after parameter/capability review | Denied policy stores | Built-in rules are Partial; SecApp.Windows.FirewallProfiles required | Stored rules differ from effective merged policy |
| Secure Boot, TPM, UAC, VBS | Read-only provider attempts | Complete protected queries | Proposed SecApp.Windows.SecurePlatform | Configuration differs from runtime/attestation |
| BitLocker | Non-secret volume state | Protected provider state | Proposed SecApp.Windows.BitLockerStatus | Never collect recovery material |
| Local users | Proposed SecApp.Windows.UsersReadOnly | Protected account data | Windows.Sys.Users is UnsafeForDefault due FILESYSTEM_WRITE | VQL-native source remains unproven |
| Local Administrators | Proposed VQL-native membership | Protected membership | SecApp.Windows.LocalAdministrators; built-in LocalAdmins excluded for EXECVE/PowerShell | Domain resolution may be unavailable offline |
| Password policy/Guest | Safe provider attempts | Complete effective policy if possible | Proposed SecApp.Windows.PasswordPolicyAndGuest | Safe effective-policy source remains a blocker |
| Network state | ListeningPorts and Netstat after exact review | Process attribution gaps | Built-ins can provide bounded snapshots | Volatile snapshot and PID races |
| Startup/services/tasks/WMI | Built-ins only with reviewed fixed parameters and narrow outputs | Protected items | Upload/command-bearing optional branches disabled; custom wrappers where necessary | Snapshot, unloaded profiles, parsing ambiguity |
| Drivers/signatures/software | Reviewed bounded built-ins | Protected target metadata | Built-ins provide partial inventory | Signed is not safe; inventories are incomplete |
| Remote management | Correlated read-only configuration | Protected services/policy | Proposed SecApp.Windows.RemoteManagement; Registry.RDP is UnsafeForDefault through transitive Windows.Sys.Users | Configuration, listener, firewall, and reachability differ |
| PowerShell/events | Bounded metadata only | Protected event channels | Custom policy/event collectors; avoid raw script bodies in default output | Logs can be absent, cleared, localized, or secret-bearing |
| DNS/proxy/hosts | Bounded local state | Protected stores | Reviewed DNSCache/HostsFile plus proposed policy collector | Cache is volatile; values are privacy-sensitive |
| WinRE/recovery | Safe source attempt | Complete recovery metadata | Proposed SecApp.Windows.RecoveryStatus | No command execution or configuration change; safe source unresolved |
| Defender Offline diagnostics | Existing bounded event metadata only | Protected logs | Proposed SecApp.Windows.DefenderOfflineDiagnostics | Does not run a scan or prove cleanliness |

The exact built-in source, dependency, parameter, field, capability, privacy, and safety review is in [audit-parity-matrix.md](audit-parity-matrix.md).

## Workflow

### Phase 0: plan

1. Load immutable local schemas, audit profile, rules, CollectorDefinitions, and composition policy by ID/version/digest.
2. Reject unsupported versions, duplicate keys/IDs, unresolved references, and unclassified capabilities.
3. Verify the exact runtime binary identity separately from the source pin.
4. Present scope, classes, limits, limitations, and planned passes.
5. Create Planned executions; do not create consent by default.

### Phase 1: standard pass

For each eligible collector:

1. re-evaluate transitive capability and parameter policy;
2. validate applicable ConsentReceipts;
3. record action and applied limits;
4. launch one bounded process only after all gates;
5. record lifecycle, backend/command contract, raw stdout/stderr and optional ZIP digests, parser/import status, count, truncation, cancellation/timeout source, and typed errors;
6. create Observations only for accepted Succeeded or Partial output.

BackendNotFound, ConsentDenied, PolicyRejected, NotTested, failure, timeout, or unsupported data produces coverage state, never a safe result.

### Phase 2: elevation decision

The UI presents only collectors whose standard coverage is insufficient, with exact additional capabilities and classes. An accepted ConsentReceipt is single-use and bound to run/pass/collector/definition/host/expiry. Denial records ConsentDenied/coverage without retrying elevated.

### Phase 3: optional elevated pass

Only the approved collector set runs. Standard output remains immutable. Elevated output has its own pass/execution IDs and provenance.

### Phase 4: normalize and evaluate

1. Enforce UTF-8, duplicate-key, depth, member, byte, row, and archive limits.
2. Validate each area payload schema.
3. Build the Execution to Observation to EvidenceReference chain.
4. Validate the complete object graph.
5. Evaluate bounded RuleDefinitions deterministically.
6. Emit Security findings only from observations; emit Coverage findings for pre-execution gaps without an ordinary observation.

### Phase 5: finalize and export

1. Finalize ActionLog chain.
2. Build a non-empty AuditManifest with exactly one AuditRun, one member per AuditPass, one ActionLog object (zero entries permitted), every referenced execution, exact unique IDs/paths, and raw file digests.
3. Compute object/manifest digests under [integrity-model.md](integrity-model.md).
4. Render private reports.
5. For public export, evaluate the exact RedactionProfile and composition policy locally.
6. Build ExportManifest with source/profile/composition digests, entries, omissions, warnings, and export manifest digest.

A local manifest digest is not provenance without a separate protected trust anchor.

## Canonical logical run layout

The following are logical identifiers, not filesystem paths:

    runs/<run-id>/run.json
    runs/<run-id>/passes/<pass-id>.json
    runs/<run-id>/executions/<execution-id>.json
    runs/<run-id>/observations/<observation-id>.json
    runs/<run-id>/evidence/<evidence-id>.json
    runs/<run-id>/findings/<finding-id>.json
    runs/<run-id>/consent/<receipt-id>.json
    runs/<run-id>/action-log/action-log.json
    runs/<run-id>/manifest.json
    exports/<export-id>/manifest.json

Every segment starts with an ASCII letter or digit and then uses only ASCII letters, digits, `.`, `_`, or `-`; all other strict rules are in integrity-model.md. Actual private storage root, ACLs, encryption, keys, retention, and deletion remain blockers.

## Initial aggregate limits

AuditRun is limited to 4 MiB serialized UTF-8/JCS, 4 pass references, 4,096 execution references, 10,000 observation references, 10,000 evidence references, 5,000 finding references, and 256 inline summaries of at most 2 KiB each. Total decompressed run members are limited to 2 GiB and the whole audit package to 4 GiB. These are initial safety limits and changes require reviewed boundary vectors.

## Reports

Private JSON/Markdown/HTML reports include:

- run/profile/schema/backend source and runtime pins;
- pass/execution lifecycle and coverage;
- findings with independent severity/confidence/status;
- errors, limitations, and resource-limit outcomes;
- consent and action identifiers without raw sensitive text;
- manifest/external-anchor limitations;
- explicit compromised-host and snapshot limitations.

Public reports contain only fields admitted by the exact RedactionProfile and composition policy. Report/localization content is escaped and tested as hostile input.

## Contract and security tests

Before runtime:

- full Draft 2020-12 validation and duplicate-key rejection;
- positive examples and every negative category in [schema-compatibility.md](schema-compatibility.md);
- cross-run/execution/evidence/finding/manifest mismatches;
- lifecycle contradictions and timestamp reversal;
- consent expiry/replay/scope escalation;
- path traversal/collision and digest self-reference;
- rule graph cycle/depth/operator-type failures;
- public redaction and composition bypass;
- reboot replay/rollback/stale/build/tag failures;
- output/record/JSON/ZIP/decompression limits;
- release-specific transitive artifact/parameter capability review;
- synthetic standard/elevated coverage across the supported Windows matrix;
- HTML/localization injection and CSP regression.

The official artifacts verify command is required for future custom artifacts but is not sufficient security validation.

## Acceptance and readiness

ARCH-FIX1 through ARCH-FIX3 resolve their targeted design blockers for recheck, but the architecture remains not ready for runtime. Runtime is blocked by:

- runtime binary trust/acquisition/update/rollback;
- binary-backed CLI/container contract;
- elevation boundary;
- private storage, retention, ACL, encryption, key, temp, backup, and deletion policy;
- safe custom platform/users/local-admin/password-policy/recovery collectors;
- area-specific schemas and reviewed rule thresholds;
- supported Windows matrix;
- full Draft 2020-12 validator and cross-object harness;
- report renderer/localization/CSP tests;
- external manifest trust anchor.

No blocker currently requires a Velociraptor fork.

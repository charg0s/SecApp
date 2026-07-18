# SecApp Privacy and Storage Model

Status: normative design policy; storage decisions below block runtime work

## Principles

- Collect the minimum data required for a named control.
- Keep raw backend output private and local unless a separate export is explicitly requested.
- Bind consent to purpose, run, pass, collector definition, capabilities, privacy classes, host, expiry, and one-time nonce.
- Treat all backend data and report content as untrusted.
- Preserve Not tested instead of converting denied or missing data into a safe result.
- Apply redaction locally before any exported bytes leave the private run boundary.

## Privacy classes and default actions

| Class | Examples | Default collection | Public export |
|---|---|---|---|
| Public | SecApp version, schema IDs, non-host-specific control names | Allowed | Include |
| SystemMetadata | OS family/build, abstract control state | Read-only profile | Include or Redact after composition review |
| PersonalMetadata | Username, SID mapping, account/profile metadata, local path containing a user component | Separate explicit consent | Never Include; Redact, Hash, or Exclude |
| NetworkMetadata | IP address, endpoint, MAC, DNS/cache value, proxy endpoint, SSID | Separate explicit consent | Never Include; Redact, Hash, or Exclude |
| SensitiveSecurityData | Service/task commands, firewall rules, installed-software combinations, security settings, Defender status/exclusions, event metadata | Exact control scope | Never Include; Redact, Hash, or Exclude |
| Secret | Tokens, credentials, recovery material, private keys, secret-bearing command content | Excluded unless a future exact design and consent exists | Exclude |
| MemoryContent | Process/system memory and dumps | Separate memory-acquisition workflow only | Exclude |

The following fields require explicit classification in every area schema:

- SSID: NetworkMetadata;
- hostname and FQDN: PersonalMetadata plus NetworkMetadata where linkable;
- username, account name, and profile identity: PersonalMetadata;
- IP, MAC, DNS name, listener, route, proxy, and gateway: NetworkMetadata;
- local filesystem or registry path: at least SensitiveSecurityData, and PersonalMetadata when user-identifying;
- installed-software combination: SensitiveSecurityData because combinations can fingerprint a host;
- Defender exclusions: SensitiveSecurityData and potentially Secret when they reveal protected locations or operational exceptions;
- command lines, script blocks, task actions, and service parameters: SensitiveSecurityData, escalating to Secret if content is secret-bearing.

Unknown fields have no default class. They reject normalization or export.

## ConsentReceipt

ConsentReceipt is a separate strict discriminated-union contract. It records user presence, exact authority binding, purpose code, consent type, requested and approved capabilities and privacy classes, presented/accepted/expiry times, consent-text and application versions, host-binding digest, one-time nonce, and revocation state.

- Administrative, NetworkAccess, DefenderScan, DefenderOffline, MemoryAcquisition, and SensitiveDataCollection are collector-scoped and require collector plus run/pass/action/operation/target binding.
- Export requires export plus run/action/operation/target binding, forbids pass and collector binding, and pins one RedactionProfile digest.
- Remediation requires run/pass/action binding and the same exact target in both scope and action binding. A related collector is allowed only together with a finding ID.
- Reboot requires run/pass/action plus workflow/stage binding. It may name only the collector that planned the workflow.

Foreign binding variants are rejected even if the required variant is also present.

The normative authority map is deliberately non-transitive:

| Type | Only permitted operation |
|---|---|
| Administrative | CollectPrivilegedReadOnly for a bound elevated read-only collector |
| NetworkAccess | UseNetwork or OnlineLookup for a bound destination/policy |
| Reboot | ScheduleRebootContinuation or PerformRebootContinuation |
| DefenderScan | RunDefenderScan |
| DefenderOffline | ScheduleDefenderOffline or PerformDefenderOffline |
| MemoryAcquisition | AcquireMemory with MEMORY_READ and MemoryContent |
| Remediation | Remediate one exact target |
| SensitiveDataCollection | CollectSensitiveData for enumerated sensitive classes |
| Export | Export one ID with one RedactionProfile digest |

Administrative does not permit network use or remediation. MemoryAcquisition does not permit remediation. Export does not permit collection. A Reboot receipt with Remediate is locally schema-invalid.

Application validation enforces:

- approved capabilities and privacy classes are subsets of their requested sets;
- collector requirements are a subset of the union of exact, actually presented receipts, without treating unrelated receipt types as authority;
- receipt run, pass, action, operation, target, collector/definition when applicable, and host bindings match;
- export, remediation action/target, and reboot workflow/stage bindings match their discriminator-specific scope;
- receipt is active and unexpired at launch;
- nonce has not been consumed;
- no conflicting active receipt changes the effective scope;
- one receipt cannot authorize a different run, pass, action, operation, target, collector, export, or broader scope.

Failure is ConsentDenied. Consent is not inferred from elevation, a previous audit, a checkbox default, or possession of an old receipt.

## ActionLog parameter privacy

ActionLog does not store a free-text requested operation. It stores an enum operation code, opaque canonical target reference, purpose code, and at most a short sanitized display string. `redacted_parameters` contains only canonical field ID, declared privacy class, redaction action, and either a sanitized value or digest. The original value is not a legal schema member.

PersonalMetadata, NetworkMetadata, SensitiveSecurityData, Secret, and MemoryContent cannot use IncludeSanitized. The application field registry fixes each canonical field's type, privacy class, permitted redaction actions, and sanitized representation; unknown IDs, class mismatch, raw values, and weakened actions reject the ActionLog entry. A log digest never declassifies its content.

## Redaction semantics

RedactionProfile is evaluated only on the local host:

1. resolve the class action;
2. resolve at most one canonical field rule;
3. apply the more restrictive result;
4. reject an unknown field or unassessed composition;
5. require a pseudonymization key ID for every Hash action;
6. record the exact profile and composition-policy digests in ExportManifest.

A field rule cannot weaken the class action. Conflicting field rules for one canonical path reject export. For public export, PersonalMetadata, NetworkMetadata, SensitiveSecurityData, Secret, and MemoryContent can never use Include; Secret and MemoryContent are always excluded.

Hashing is pseudonymization, not anonymization. Linkable pseudonyms require a keyed construction, purpose-specific key, key ID rather than key material in manifests, limited retention, and composition review.

## Composition and deanonymization

Individually redacted values can identify a host when combined. The composition policy evaluates combinations including:

- build plus rare installed-software versions;
- hostname token plus domain/network data;
- SSID plus gateway or IP prefix;
- account count plus uncommon SID/group structure;
- service/task command fingerprints;
- Defender exclusions plus local path tokens;
- event times plus software and network observations.

An unassessed combination rejects public export. Adding a new field or report join requires a new composition-policy digest and negative deanonymization tests.

## Private storage requirements before runtime

Runtime work is blocked until a reviewed storage decision specifies all of the following.

### Retention

- exact retention periods for raw stdout/stderr, collection ZIPs, evidence, observations, findings, reports, ActionLog, consent receipts, exports, and backups;
- whether retention is time-, run-, or user-action-based;
- legal hold behavior and maximum extension;
- expiry enforcement and audit behavior.

No default duration is selected by this architecture fix.

### Temporary files and process leakage

- private temp root and restrictive ACL owner;
- creation without predictable names, reparse traversal, or inherited broad permissions;
- crash-safe cleanup and orphan recovery;
- prevention or treatment of crash dumps;
- paging/swap exposure and whether sensitive workflows require operating-system protections;
- antivirus, search indexer, thumbnailer, telemetry, and backup exposure;
- safe working directory distinct from binary, definitions, output, and user-writable directories.

### Encryption and keys

- encryption-at-rest format and authenticated metadata;
- key source, generation, storage, recovery, backup, rotation, revocation, and destruction;
- separate keys or contexts for private runs, redaction pseudonyms, and reboot authentication;
- behavior when a key is unavailable or recovery fails;
- protection against plaintext staging before encryption.

Lack of an approved key path is a startup failure for private collection, not a reason to write plaintext.

### ACL and local-only semantics

Local-only means collection and redaction are intended to execute on the audited host without intentional network transfer. It does not mean the host, OS, security software, synchronization client, backup agent, or compromised administrator cannot access the data.

The storage design must define:

- owner and exact ACL principals;
- inheritance behavior;
- elevated and standard-process access;
- access checks before every open and after creation;
- reparse-point defenses;
- behavior on unsupported filesystems.

### Deletion and backups

Deletion must cover private raw output, derived objects, exports, temp files, logs, backups, recovery copies, and relevant keys. Cryptographic key erasure may make encrypted data inaccessible when key copies are controlled.

SecApp must not claim guaranteed physical erasure on SSDs, thin-provisioned storage, snapshots, cloud-synchronized folders, or backup media. Wear levelling, remapping, journaling, and retained snapshots can preserve prior blocks.

Export deletion is independent of private-run deletion. The system must track exported package identifiers and disclose that copies outside its control cannot be revoked.

## Compromised-host limitation and corroboration

A compromised host can forge API results, hide registry/files, race reads, tamper before hashing, manipulate time, or lie through kernel and firmware interfaces. Local hashes do not solve this.

Controls with high consequence should seek independent read-only sources where available, for example configuration plus runtime state plus event history. Multi-source corroboration improves confidence and records disagreement; it does not prove the host is trustworthy.

## Validation gates

Required privacy tests include:

- public Include attempts for every restricted class;
- Hash without a key ID;
- duplicate, unknown, and weakening field rules;
- cross-run or expired consent;
- consent type/operation mismatch and cross-action/pass receipt use;
- approved capability/privacy escalation and unrelated receipt substitution;
- raw sensitive ActionLog parameters and unknown field IDs;
- composition-policy substitution;
- plaintext temp/crash/output paths;
- backup and key-erasure failure;
- public report content injection;
- export deletion while copies/backups remain;
- compromised-source disagreement producing limitations rather than false confidence.

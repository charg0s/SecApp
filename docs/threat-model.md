# SecApp Threat Model

Status: design-stage threat model; controls are requirements, not tested implementation claims

## Security goals

- Default collection remains read-only, offline, bounded, and standard-user.
- Sensitive capabilities require exact active consent and narrow privilege.
- Backend, artifacts, output, archives, schemas, rules, and reports are untrusted.
- Missing or rejected collection remains Not tested.
- Private data is not copied into public export.
- Integrity claims distinguish modification detection from provenance and host truth.

## Assets and trust boundaries

Assets include backend binary/metadata, collector definitions, command contracts, consent receipts, private raw output, normalized objects, rules, manifests, ActionLog, redaction keys/profiles, reboot state, and reports.

Trust boundaries are:

1. user/UI to orchestrator;
2. standard process to any elevated component;
3. orchestrator to external backend process;
4. backend output/archive to parser/normalizer;
5. private storage to export;
6. current process to reboot continuation;
7. local mutable state to an external trust anchor.

## Threat register

| Threat | Asset | Attacker | Precondition | Impact | Prevention | Detection | Residual risk | Verification test |
|---|---|---|---|---|---|---|---|---|
| DLL search-order hijacking | Backend/orchestrator execution | Local user or malware able to place a library | Unsafe search path or writable binary/current directory | Code execution at collector privilege | Verified absolute executable identity, safe DLL search policy, non-writable binary directory, safe working directory, no user-writable PATH resolution | Loaded-module inventory and pre/post binary-directory ACL check | Compromised administrator or OS loader can still subvert | Plant synthetic same-name library in each prohibited search location; launch must reject or ignore |
| Unsafe current directory | Command contract and parser | Local user controlling working directory | Process inherits user-writable or evidence directory | Configuration/library substitution and unintended file access | Dedicated private directory with restrictive ACL; never use binary, definition, download, or export directory as current directory | ActionLog records working-directory policy ID, not raw path | ACL/OS compromise | Writable-current-directory negative launch |
| Temporary-directory ACL weakness | Raw output and keys | Other local principal | Predictable/shared temp or inherited broad ACL | Disclosure or replacement | Private temp root, owner-only ACL, unpredictable names, create-new semantics | ACL verification and unexpected-open audit | Elevated administrator can read | Pre-create/cross-user open and inheritance tests |
| Reparse-point or symlink race | Private output and export | Local filesystem attacker | Path component can be replaced between check/open | Write/read outside approved storage | Handle-based opens, no-follow/reparse checks, verified root identity, atomic create, post-open identity validation | Record volume/file identity and reject changes | Filesystem/administrator compromise | Swap directory/reparse point between validation and open |
| GitHub release/account compromise | Backend and source metadata | Supply-chain attacker | Trusted account/tag/release is changed or malicious at publication | Malicious binary or artifacts accepted | Separate source and runtime pins, explicit signer/hash policy, multiple trust metadata sources, staged review, rollback | Tag/commit/release metadata drift and signer mismatch | Trust roots can be compromised together | Tag move, signer change, and mismatched release metadata fixtures |
| Manifest substitution | Audit/export integrity | Local attacker | Manifest/digest and data share mutable storage | Altered set appears valid | External stored manifest digest or detached signature; exact membership rules | External-anchor mismatch | Compromised external store/key | Replace manifest and all local hashes; external check must fail |
| Outbound network despite prohibition | Privacy and isolation | Malicious artifact/backend or host process | NETWORK omitted or hidden in dependency/API | Data exfiltration | OS-level network isolation design, transitive review, fixed parameters, no server config, deny NETWORK | Network telemetry and controlled no-route test | Local kernel/administrator can bypass observation | Collector attempts DNS/TCP/HTTP while policy Forbidden |
| Transitive capability escalation | Host state and consent | Artifact author or updater | Dependency/optional branch uses write, exec, network, or memory | Unconsented sensitive action | Release-specific dependency graph, VQL/function review, pinned parameter values, CollectorDefinition capability superset rule | Static diff and runtime behavior trace | Dynamic VQL behavior can evade static inference | Hidden dependency and optional dangerous-parameter fixtures |
| Artifact permission metadata mistaken for sandbox | Host state | Reviewer error | Trust placed only in required/implied permissions | Unsafe artifact allowed | Treat metadata as evidence only; inspect source and dependencies | Matrix completeness check | Source analysis may miss native/plugin behavior | Artifact with empty permissions but explicit exec/upload call |
| Compromised host lies to auditor | Findings and evidence | Administrator, kernel malware, firmware | Audit runs on compromised target | False observations and clean report | Preserve limitations, corroborate independent sources, avoid absolute assurance, optional future remote trust anchor | Cross-source disagreement and integrity anomalies | Complete local compromise can forge all sources | Synthetic inconsistent provider/registry/event inputs |
| Audit evasion and race | Snapshot coverage | Malware or user | Adversary detects collector timing | State hidden or changed around read | Randomization only if later reviewed, multiple observations, timestamps, bounded re-checks, event corroboration | Inconsistent repeated snapshots | Short-lived changes remain invisible | Toggle synthetic state during collection |
| Unbounded ZIP/JSON output | Availability/storage | Malicious backend or file | Parser trusts declared sizes/counts | Memory/disk exhaustion | Limits from integrity-model.md, streaming parse, stop-before-allocation, partial/failure state | ResourceLimit error and ActionLog counters | Near-limit load can still affect host | Oversized row, deep JSON, count overflow, huge stdout |
| Decompression bomb/path archive attack | Storage and parser | Malicious archive | ZIP imported before path/ratio validation | Exhaustion or path overwrite | Reject nesting, validate names first, entry/count/ratio/expanded-byte limits, extract only to verified handles | Archive rejection metrics | Crafted compressor/parser bugs | High-ratio, nested, duplicate, traversal, and oversized entry ZIP fixtures |
| Parser differential | Object integrity | Malicious backend/report | Components parse duplicate keys, numbers, Unicode, or dates differently | Validation bypass | One strict parser profile, duplicate-key rejection, UTF-8 only, numeric/depth limits, schema plus cross-object checks | Cross-parser corpus in CI | Library defects | Duplicate keys, numeric extremes, invalid UTF-8, escaped-key collision |
| Stale or rollback backend | Collection semantics | Updater/local attacker | Older compatible-looking binary substituted | Known vulnerabilities or changed output | Runtime binary digest/version floor, source/runtime distinction, protected monotonic policy, rollback tests | Version/digest mismatch | Authorized rollback may retain flaws | Older signed binary and version-string spoof |
| Malicious localization/report content | User and report viewer | Backend data or translation contributor | Untrusted strings enter Markdown/HTML | Script/content injection or misleading UI | Contextual escaping, restrictive CSP, local assets, no active content, signed/reviewed localization catalog | Injection corpus and rendered DOM assertions | Browser/rendering defects | HTML, Markdown, bidi, formula, control-character payloads |
| Signature-check TOCTOU | Backend execution | Local filesystem attacker | File can change after verification before execution | Different binary executes | Verify/open stable handle, execute same identity where platform permits, re-verify identity immediately before/after launch | File identity and digest mismatch | Platform APIs may not bind verification to execution | Replace binary between hash and process creation |
| Consent replay or scope escalation | Privileged/privacy action | UI compromise or local attacker | Receipt not bound/expired/single-use | Unauthorized collection | Strict ConsentReceipt, protected nonce store, capability subset and host/run/pass/collector binding | Replay/conflict errors in ActionLog | Protected store compromise | Expired, cross-run, cross-host, broader-approved-capability cases |
| Reboot-state replay/rollback | Post-reboot authority | Local attacker | State file copied, reordered, or substituted | Wrong build/stage resumes | Exact authenticated fields, expiry, one-time nonce, monotonic sequence, build/executable/run/host binding, fail-closed startup | Replay/stale/tag errors | Key/store compromise | Replay consumed state, lower sequence, wrong build/tag length |
| Redaction bypass/composition | Public privacy | Report/export attacker or policy error | Field rule weakens class or combination identifies host | Personal/sensitive disclosure | More-restrictive precedence, unknown-field rejection, exact profile/composition digests, local reconstruction | ExportManifest and deanonymization corpus | Novel combinations can identify | Include bypass, duplicate field, profile substitution, rare-field combination |
| ActionLog deletion/rewrite | Audit accountability | Local administrator | Log and hashes are all locally mutable | Actions removed or reordered | Hash chain, sequence rules, manifest membership, optional external digest/signature | Chain/external-anchor mismatch | Compromised administrator can rewrite whole local chain | Remove/reorder/relink entries with and without external anchor |
| Cross-authority consent substitution | Privileged/privacy action | UI or orchestrator compromise | A receipt for one type/run/pass/action is accepted for another | Network, reboot, memory, export, or remediation occurs without exact authority | Disjoint type/operation mapping, exact target/action binding, subset checks, nonce history | CONSENT-001 through CONSENT-003 failures in ActionLog | Protected consent store or UI can still be compromised | Reboot-for-remediation, admin-for-network, export-for-collection fixtures |
| ActionLog sensitive-parameter disclosure | Audit accountability and privacy | Collector output or developer error | Raw target or personal/network/security data enters free text | Log becomes a secondary evidence leak | Structured operation codes, canonical field registry, restrictive redaction entries, no original-value field | ACTION-002 validation | Sanitized combinations can remain identifying | Raw sensitive value, wrong class, unknown field, weakening action fixtures |
| Pass privilege confusion | Host authority | Orchestrator/import attacker | Elevated execution is attached to Standard pass or receipt crosses pass | Privileged collection appears standard-authorized | Standalone AuditPass, privilege equality, exact receipt pass/action binding, deterministic prerequisites | PASS-001 through PASS-006 | Compromised host can falsify pre-validation inputs | Both privilege directions, consent binding, and reboot-prerequisite fixtures |
| Size-limit weakening | Availability and policy | Config/schema editor | Limits raised without review | Resource exhaustion | Versioned initial-limit contract, security review, negative tests for increases | Schema/config digest drift | Valid high-volume workloads may hit limits | Boundary plus one and aggregate amplification |

## Backend release-specific findings

At release v0.77.1:

- [Windows.Sys.Users](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/artifacts/definitions/Windows/Sys/Users.yaml) declares FILESYSTEM_WRITE and is UnsafeForDefault.
- Generic.Client.Info transitively calls Windows.Sys.Users through its Users source and is UnsafeForDefault as a whole.
- Windows.Registry.RDP reaches Windows.Sys.Users through Windows.Registry.NTUser and is UnsafeForDefault.
- [Windows.System.LocalAdmins](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/artifacts/definitions/Windows/System/LocalAdmins.yaml) requires EXECVE and invokes PowerShell; it is excluded.
- Windows.EventLogs.EvtxHunter declares FILESYSTEM_WRITE and is excluded.

Safe custom VQL-native replacements remain compatibility experiments, not confirmed collectors.

## Privacy and storage threats

Private storage additionally considers plaintext staging, paging, crash dumps, antivirus/indexer access, backups, snapshots, key recovery, key erasure, export copies, and SSD deletion limitations. Normative gates are in [privacy-model.md](privacy-model.md).

## Review gates

Runtime work requires independent approval of:

1. backend acquisition/signing/update/rollback;
2. elevation and consent protocol;
3. private storage/key lifecycle;
4. adapter output/limit behavior;
5. transitive artifact capability matrix for the exact runtime pin;
6. parser/archive differential corpus;
7. schemas, cross-object rules, and full validator;
8. custom artifact source and synthetic tests;
9. report CSP/localization injection tests;
10. compromised-host limitations in user-facing reports.

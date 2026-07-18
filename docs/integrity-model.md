# SecApp Integrity and Cross-Object Validation Model

Status: ARCH-FIX4 WIP design contract pending independent ARCH-REVIEW6; no accepted baseline, runtime implementation, production-ready schema claim, or provenance guarantee

## Scope and validation phases

JSON Schema Draft 2020-12 validates local object shape. Acceptance also requires the application rules indexed below. The phases are `Parse`, `Schema`, `Graph`, `Authorization`, `Canonicalize`, and `Finalize`. Failure to evaluate any applicable rule is a rejection, never a warning or an inferred safe result.

A local digest detects modification only relative to a separately trusted value. It does not prove who created data, make local storage tamper-proof, or establish truth on a compromised host.

## Digest vocabulary

| Digest | Logical object | Excluded value | Canonicalization | Algorithm / encoding |
|---|---|---|---|---|
| ContentDigest | Reviewed logical text | None | UTF-8 without BOM, LF, required final LF | SHA-256 / LowerHex |
| FileDigest | Exact stored bytes | None | Raw bytes, no decoding or normalization | SHA-256 / LowerHex |
| ObjectDigest | One JSON contract | Named digest value only | RFC 8785 JCS; array order preserved | SHA-256 / LowerHex |
| EntryDigest | One ActionLogEntry | Entire `entry_digest` field | RFC 8785 JCS; `previous_entry_digest` remains in the object | SHA-256 / LowerHex |
| Audit ManifestDigest | AuditManifest | `manifest_digest.digest` | Normalize `entries`, then RFC 8785 JCS | SHA-256 / LowerHex |
| Export ManifestDigest | ExportManifest | `manifest_digest.digest` | Normalize its three arrays, then RFC 8785 JCS | SHA-256 / LowerHex |
| ProfileDigest | RedactionProfile | `profile_digest.digest` | Sort field rules by canonical field ID, then RFC 8785 JCS | SHA-256 / LowerHex |

Digest metadata remains inside the hashed object. The excluded value is removed, not replaced with null, an empty string, or zero. JSON strings are UTF-8 as required by JCS. Absent and null are distinct: an absent optional member is absent from the canonical object; an explicit null is included. Array order is preserved unless the exact digest contract below first mandates sorting. Unknown algorithms, encodings, canonicalization identifiers, duplicate JSON keys, or non-I-JSON input are rejected as `DIGEST_CONTRACT_MISMATCH`.

### JCS-DIGEST1 canonicalization boundary

RFC 8785 property names are ordered by raw UTF-16 code units, independently of locale. String values and property names must contain only valid Unicode scalar sequences; no Unicode normalization is performed, so composed and decomposed strings remain distinct. Numbers use the ECMAScript JSON number serialization required by RFC 8785 and must be finite. Direct API input is limited to null, booleans, finite numbers, valid strings, dense arrays, and safe plain data objects. Undefined, functions, symbols, BigInt, NaN, infinities, sparse arrays, cycles, proxies, accessors, symbol-keyed properties, typed arrays, Date, Map, Set, and other non-plain objects are rejected as `JCS_INPUT_INVALID` before hashing.

Contract array normalization is a separate step from JCS property ordering. AuditManifest, ExportManifest, and RedactionProfile use the exact keys named by their contracts and the shared bytewise UTF-8 comparator; report or fixture enumeration uses a shared locale-independent code-unit comparator. No deterministic path uses `localeCompare`, `Intl.Collator`, or environmental locale/configuration.

JCS-DIGEST1 claims only its covered conformance set. Machine output uses `rfc8785_conformance_status: covered_conformance_set_passed`, `conformance_claim: CoveredSet`, a covered case count, explicit official/derived vector IDs, and `full_corpus_claimed: false`. It does not claim execution of the complete official RFC corpus.

### ContentDigest and FileDigest byte contracts

FileDigest hashes the exact materialized source bytes, including BOM, CR, LF, final newline state, NUL, and arbitrary byte values. Hex and Base64 are fixture transport encodings only; invalid, non-canonical, odd-length, or unsupported encodings are rejected before hashing.

ContentDigest first decodes strict UTF-8, removes one leading U+FEFF BOM, converts CRLF and lone CR to LF, and appends LF when the logical text does not already end with LF. Empty text therefore canonicalizes to one LF byte. Existing LF multiplicity, NUL, supplementary characters, and composed/decomposed Unicode are otherwise preserved; invalid UTF-8 is rejected and NFC/NFD normalization is forbidden. Permanent cases isolate BOM-only, LF-only, mixed CR/CRLF/LF, preserved NUL, and arbitrary invalid UTF-8 binary behavior.

### Digest required-ID completeness

Counts are not completeness evidence. The digest gate owns immutable exact required-ID sets for catalog digest cases, JCS conformance, direct API positives, direct API negatives, ProfileDigest, FileDigest, ContentDigest, permanent schema format/keyword/namespace guards, and checked arithmetic/checkedMultiply. Every required ID must exist exactly once in its assigned category, execute, remain unskipped, and produce its expected result. Optional cases are accepted only when explicitly marked additional and cannot mask a missing required ID.

Missing, duplicate, unexecuted, skipped, category-mismatched, and unequal required sets use `DIGEST_REQUIRED_CASE_MISSING`, `DIGEST_REQUIRED_CASE_DUPLICATE`, `DIGEST_REQUIRED_CASE_NOT_EXECUTED`, `DIGEST_REQUIRED_CASE_SKIPPED`, `DIGEST_CASE_CATEGORY_MISMATCH`, and `DIGEST_REQUIRED_SET_MISMATCH`. Every run performs six in-memory mutations for every required ID: removal, replacement by another ID's duplicate, direct duplication, category change, skipped, and not executed.

### RedactionProfile ProfileDigest

The canonical object is the complete schema-valid RedactionProfile. Remove only `profile_digest.digest`; require every `field_rules` item to use the exact `field` property; reject duplicate fields; sort `field_rules` by `field` ascending bytewise UTF-8; then apply JCS and SHA-256 LowerHex. `class_actions` is an object, not a second rule array, so its property order is handled only by RFC 8785 property-name ordering. Public/private scope, actions, paths, privacy classes, pseudonymization key ID, and composition policy all remain inside the digest.

### ActionLog EntryDigest and chain

Normative formula:

    EntryDigest = SHA-256(JCS(ActionLogEntry with the entire entry_digest field removed))

`previous_entry_digest` is included. The first entry has `sequence_number` 0 and explicit `previous_entry_digest: null`. Every later entry uses the preceding entry's verified lowercase-hex EntryDigest. Verification recomputes every entry in sequence order, rejects a first sequence other than zero, gaps, duplicates, decreasing timestamps, duplicate action IDs, previous-digest mismatch, entry `audit_run_id` mismatch, and an ActionLog `run_id` mismatch. Error code: `ACTION_LOG_CHAIN_INVALID`.

`log_digest` is the ObjectDigest of the ActionLog after entries have been verified and ordered by ascending `sequence_number`, excluding only `log_digest.digest`. An optional `external_anchor` is detached context for the verified chain digest. If declared, it must verify against a separately protected value or finalization fails. No ActionLog claim may use “tamper-proof” for a compromised administrator or host.

### AuditManifest ManifestDigest

The canonical object is the complete AuditManifest. Remove only `manifest_digest.digest`; reject duplicate `member_id` and duplicate `logical_path`; sort `entries` by canonical `logical_path`, then `member_id`, both ascending bytewise UTF-8; then apply JCS and SHA-256 LowerHex. Input array permutations that normalize to the same unique member set produce the same digest.

### ExportManifest ManifestDigest

The canonical object is the complete ExportManifest. Remove only `manifest_digest.digest`; reject duplicate export paths, source-member entries, omission IDs, and duplicate warning `(warning_code, subject_path)` pairs. Sort:

- `entries` by `export_logical_path`, then `source_member_id`;
- `omissions` by `omission_id`, then `source_logical_path`;
- `warnings` by `warning_code`, then `subject_path`.

Then apply JCS and SHA-256 LowerHex. ExportManifest has no redaction field-rule array. RedactionProfile independently sorts its own field rules by canonical field ID. Fields that do not exist in ExportManifest are never invented for its digest.

## Canonical logical path contract

One grammar is used by AuditManifest, ExportManifest, EvidenceReference, AuditRun references, archive member names, and contract fixtures:

- total length 1 through 1024 characters; each segment 1 through 128;
- each segment starts with an ASCII letter or digit;
- remaining characters are ASCII letters, digits, `.`, `_`, or `-`;
- `/` is the only separator; comparison is case-sensitive UTF-8 byte comparison;
- reject `.`, `..`, empty segments, repeated or trailing slash, absolute paths, drive/UNC forms, backslash, colon, controls, DEL, and non-ASCII;
- accepted input is never normalized into a different identifier.

Normative regex in every schema:

    ^(?!/)(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*[\\:\u0000-\u001F\u007F])(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127})(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$

`PATH-001` applies the shared vectors in `tests/contracts/paths/paths.json` to every path-bearing contract.

## Standalone AuditPass and package membership

AuditPass is a standalone versioned contract because the logical layout retains `passes/<pass-id>.json`. AuditRun is an index/summary and contains references, not embedded pass, execution, observation, evidence, or finding objects.

Every run has exactly one Standard pass and it is first. Each optional kind appears at most once. Pass and execution IDs are unique. Elevated follows Standard. RebootContinuation follows a pass whose verified `reboot_planned` is true and presents a matching active Reboot or DefenderOffline receipt. PostReboot follows a valid RebootContinuation. The prerequisite graph is acyclic, references only earlier passes, and has one deterministic ordered interpretation.

Standard pass executions are `StandardUser`; Elevated pass executions are `Elevated`. Any mismatch is rejected before launch/import. Elevated needs an Administrative receipt bound to the same run, pass, action, collector, and operation. A pass with zero collectors is valid only when `coverage_only` is true, state is `NotTested`, and a bounded coverage reason is recorded.

Minimum AuditManifest membership is exactly one AuditRun member, one AuditPass member for every AuditRun pass reference, one ActionLog member, and one member for every referenced CollectorExecution. The ActionLog object may contain zero entries, but the object and its manifest member remain required. A finalized manifest is never empty. SecApp defines no empty or Planned pre-run AuditManifest in version 1.0.0.

Logical role mapping is:

| Path class | Manifest role |
|---|---|
| `run.json` | AuditRun |
| `passes/<pass-id>.json` | AuditPass |
| `executions/<execution-id>.json` | CollectorExecution |
| `observations/<observation-id>.json` | Observation |
| `evidence/<evidence-id>.json` | Evidence (the EvidenceReference contract) |
| `findings/<finding-id>.json` | Finding |
| `action-log/action-log.json` | ActionLog |
| consent/redaction/export/continuation objects | ConsentReceipt / RedactionProfile / ExportManifest / RebootContinuationState |

Backend manifest metadata always contains expected source identity. `NotTested` and `BackendNotFound` forbid observed runtime identity. `Found` and `Started` require observed runtime version and runtime binary digest. This is the application-level `MANIFEST-003` state/identity rule so its negative vector remains structurally schema-valid and reaches the intended check. Missing backend state never fabricates version or digest.

## Consent type-to-operation mapping

One receipt authorizes only its exact operation code and target.

| Consent type | Allowed operation codes | Additional required scope |
|---|---|---|
| Administrative | CollectPrivilegedReadOnly | Elevated, read-only collector binding; no NETWORK, memory, write, control, or remediation capability |
| NetworkAccess | UseNetwork, OnlineLookup | NETWORK approved; exact collector/destination or policy target |
| Reboot | ScheduleRebootContinuation, PerformRebootContinuation | Exact continuation target |
| DefenderScan | RunDefenderScan | Exact Defender scan target |
| DefenderOffline | ScheduleDefenderOffline, PerformDefenderOffline | Exact offline workflow target |
| MemoryAcquisition | AcquireMemory | Collector binding, MEMORY_READ, MemoryContent |
| Remediation | Remediate | Exact target and at least one approved write/control capability |
| SensitiveDataCollection | CollectSensitiveData | Collector binding and enumerated sensitive privacy classes |
| Export | Export | Exact export ID and RedactionProfile digest; no collector binding |

XOBJ-011 dispatches four binding models. `CollectorExecution` applies only to `Administrative`, `NetworkAccess`, `DefenderScan`, `DefenderOffline`, `MemoryAcquisition`, and `SensitiveDataCollection` and requires collector definition/digest, execution, run, concrete pass, action, exact operation/target/purpose, and receipt membership. DefenderOffline remains collector-scoped under the existing schema and D-021; ARCH-FIX4 does not invent a reboot-scoped alternative.

`Export` requires run, exact Export action/manifest target, export ID, and loaded RedactionProfile digest and forbids receipt-level pass or collector-execution use. `Remediation` requires run, action binding, exact remediation target/operation, and approved requested scope; pass binding is checked only when the action is pass-scoped (all current v1 Remediation actions are), while a related collector is allowed only through an explicit finding-bound relation. `Reboot` requires run, exact workflow/stage/operation, nonce/replay protection, and the pass required by the current v1 workflow; a collector is optional only as `planned_by_collector` for an explicitly collector-triggered workflow. No model inherits CollectorExecution binding merely because another model uses consent.

Administrative never implies NetworkAccess. MemoryAcquisition never implies Remediation. Export never implies collection. `Reboot` plus `Remediate` is schema-invalid. Application validation rejects approved capability/privacy sets broader than requested, collector requirements not covered by presented receipts, receipt reuse, expiry, revocation, conflict, wrong host/run/pass/action/collector/target, binding-variant substitution, and nonce replay.

## Action authorization and redaction

ActionLog uses structured `operation_code`, `target_reference`, and `purpose_code`; optional display text is control-free and at most 160 characters. Sensitive arbitrary `requested_operation` text is forbidden.

- StartCollector requires collector, execution, command contract, audit run, and pass IDs.
- NetworkUse requires a same-scope NetworkAccess receipt, destination scope or policy, command contract, collector, and execution.
- Elevation requires a same-scope Administrative receipt and CollectPrivilegedReadOnly operation.
- Reboot requires a Reboot or DefenderOffline receipt matching the exact workflow, continuation reference, and next stage.
- DefenderScan requires a DefenderScan receipt, collector, execution, and command contract for the exact scan.
- MemoryAcquisition requires MemoryAcquisition consent, storage/privacy policy references, private destination class, and byte limit.
- Remediation requires at least one matching Remediation receipt, exact target, rollback and precondition policies, command contract, and `user_presence: true`.
- Export requires Export consent, RedactionProfile digest, and ExportManifest reference.

For every action type, its effect/authorization structure is mutually exclusive with every structure belonging to another action type. Routine actions forbid all effect authorization structures. `ACTION-004` rejects an otherwise complete action if even one foreign authorization structure is present.

`redacted_parameters` is an array of registry-backed canonical field IDs, privacy class, action, and either a sanitized value or digest. `additionalProperties: false` makes an original-value member impossible. PersonalMetadata, NetworkMetadata, SensitiveSecurityData, Secret, and MemoryContent cannot use IncludeSanitized. `ACTION-002` additionally validates each field against the immutable field registry and rejects unknown IDs, class mismatch, raw values, and weakening actions.

## Existing cross-object rule index

ARCH-FIX3 does not repurpose XOBJ-001 through XOBJ-018.

| Rule | Condition | Error code | Fail-closed result |
|---|---|---|---|
| XOBJ-001 | Run IDs match across the graph | RUN_ID_MISMATCH | Reject run/import |
| XOBJ-002 | Object IDs unique; execution belongs to one pass | EXECUTION_PASS_MISMATCH | Reject run |
| XOBJ-003 | Observation and execution links are reciprocal and execution succeeded/partial | OBSERVATION_EXECUTION_MISMATCH | Reject observation/dependents |
| XOBJ-004 | Evidence and observation links are reciprocal | EVIDENCE_OBSERVATION_MISMATCH | Reject evidence/dependents |
| XOBJ-005 | Security and Coverage finding reference rules remain distinct | FINDING_REFERENCE_MISMATCH | Reject finding |
| XOBJ-006 | Execution matches exact CollectorDefinition identity/digest | COLLECTOR_DEFINITION_MISMATCH | PolicyRejected; do not launch |
| XOBJ-007 | Finding matches exact RuleDefinition identity/digest | RULE_DEFINITION_MISMATCH | Reject evaluation/finding |
| XOBJ-008 | Finalized object/file membership is exact | MANIFEST_MEMBERSHIP_MISMATCH | Reject finalization |
| XOBJ-009 | Export source/profile/composition pins match | EXPORT_SOURCE_MISMATCH | Reject export |
| XOBJ-010 | Timestamp containment and order are valid | TIMESTAMP_ORDER_INVALID | Reject object |
| XOBJ-011 | Consent type dispatches to exact CollectorExecution, Export, Remediation, or Reboot binding model; common scope/replay/substitution checks remain mandatory | CONSENT_SCOPE_INVALID | ConsentDenied; do not launch |
| XOBJ-012 | Original ActionLog sequence/link checks remain mandatory | ACTION_LOG_CHAIN_INVALID | Reject log/finalization |
| XOBJ-013 | Reboot state authentication/replay checks pass | REBOOT_STATE_INVALID | Refuse continuation |
| XOBJ-014 | Rule graph IDs/references/reachability/acyclic/depth/count pass | RULE_GRAPH_INVALID | Reject rule |
| XOBJ-015 | Redaction field paths/classes never weaken policy | REDACTION_POLICY_INVALID | Reject export |
| XOBJ-016 | Manifest/export paths are unique and canonical | PATH_SET_INVALID | Reject manifest/export |
| XOBJ-017 | All documents/records/archives/aggregates remain bounded | SIZE_LIMIT_EXCEEDED | Stop and fail/partial explicitly |
| XOBJ-018 | Transitive backend capability is a declared subset | TRANSITIVE_CAPABILITY_MISMATCH | PolicyRejected; do not launch |

### XOBJ-GRAPH1 materialized graph contract

XOBJ-001 through XOBJ-018 are executable development/reference checks, not registry-only declarations. Their test-only input is one bounded materialized graph with an explicit `run_id` and deterministic collections for AuditRun, AuditPass, CollectorDefinition, CollectorExecution, Observation, EvidenceReference, Finding, ConsentReceipt, ActionLog, AuditManifest, ExportManifest, RedactionProfile, RebootContinuationState, and RuleDefinition. The graph also carries loaded collector/rule/profile/composition/manifest digest pins, consent and reboot replay history, an exact manifest-membership index, a canonical-field registry, a bounded transitive-capability graph, validation context, and aggregate size measurements.

The fixed source is `tests/contracts/xobj/materialized-graphs.json`. It is marked test-only, contains only synthetic identifiers, contains no absolute path or executable fixture content, and uses a fixed base plus data-only shared consent-variant setup and an allowlisted maximum of 64 combined `add`, `copy`, `remove`, or `replace` JSON-Pointer mutations. Materialization deep-clones the base, rejects missing collections, unknown collection kinds, absolute path values, invalid mutations, excessive depth/count/bytes, and then deep-freezes the result. Collection traversal and reported failures use stable identifier/rule order.

Duplicate IDs are preserved during materialization rather than collapsed into a map. XOBJ-002 then rejects them with `EXECUTION_PASS_MISMATCH`. This preserves the required schema-valid targeted negative while ensuring no consumer can silently overwrite one duplicate with another. Missing required rule input is distinct from a detected integrity violation and returns `XOBJ_GRAPH_INPUT_MISSING`; sufficient graph input must never produce the former generic `APPLICATION_RULE_INPUT_MISSING` result.

The mandatory development validation order is:

1. strict parse and schema validation of every constituent object;
2. object-local application rules;
3. bounded immutable graph materialization;
4. XOBJ rules in numeric order through the target rule;
5. digest and integrity checks.

Every registered XOBJ rule must have an implementation in the dispatch and at least one executed schema-valid positive and negative vector. Exit code 0 requires `registered_xobj_rules == executable_xobj_rules == covered_xobj_rules`, no uncovered rules, no skipped XOBJ vectors, and no XOBJ failure. Unknown rules, missing implementations, missing inputs, skipped vectors, and unexecuted vectors fail closed. The JSON result reports the three rule sets, vector counts, skipped count, exact primary-code map, and failures.

ARCH-FIX4 adds a second exact-set guard for XOBJ-011. `required_consent_variants`, `executable_consent_variants`, `executed_consent_variants`, and `positively_covered_consent_variants` must all equal `[CollectorExecution, Export, Remediation, Reboot]`; `negatively_covered_consent_variants` must cover the same set, `uncovered_consent_variants` and `skipped_consent_variant_vectors` must be empty, all nine consent types must remain dispatched, and immutable required positive/negative/substitution vector IDs must execute successfully. Permanent self-tests delete each non-collector positive, remove dispatch, simulate universal collector binding, skip a variant, and simulate an accepted substitution.

XOBJ-GRAPH1 is a development/reference validator for the current design contracts. It is not SecApp runtime code, does not establish provenance, and cannot prove source observations are truthful. A compromised host can still forge inputs or rewrite locally anchored state before presenting it to the validator.

## ARCH-FIX3 application rule index

Every row names one positive and one targeted negative fixed vector in `tests/contracts/index.json`.

| Rule | Condition | Phase | Error code | Fail-closed behavior | Positive / negative vector |
|---|---|---|---|---|---|
| PASS-001 | Exactly one Standard pass | Graph | PASS_CARDINALITY_INVALID | Reject run | RUN_STANDARD_ONLY_VALID / RUN_NO_STANDARD_INVALID |
| PASS-002 | Optional pass kinds and pass IDs are unique | Graph | PASS_KIND_DUPLICATE | Reject run | RUN_STANDARD_ELEVATED_VALID / RUN_TWO_ELEVATED_INVALID |
| PASS-003 | Standard pass cardinality/order and optional kind order are deterministic | Graph | PASS_ORDER_INVALID | Reject run | RUN_STANDARD_ONLY_VALID / RUN_STANDARD_NOT_FIRST_INVALID |
| PASS-004 | Execution privilege equals its pass privilege | Authorization | PASS_PRIVILEGE_MISMATCH | Do not launch/import | RUN_STANDARD_ELEVATED_VALID / RUN_ELEVATED_EXECUTION_IN_STANDARD_INVALID |
| PASS-005 | Administrative/reboot consent is exact-bound to run/pass/action/collector/workflow | Authorization | PASS_CONSENT_BINDING_INVALID | Do not launch/continue | RUN_REBOOT_VALID / RUN_REBOOT_WITHOUT_CONSENT_INVALID |
| PASS-006 | Prerequisites reference only earlier passes and the reboot chain is complete | Graph | PASS_PREREQUISITE_INVALID | Reject run/continuation | RUN_REBOOT_VALID / RUN_POST_REBOOT_WITHOUT_CONTINUATION_INVALID |
| CONSENT-001 | consent_type maps to exact operation_code | Schema + Authorization | CONSENT_OPERATION_MISMATCH | Reject receipt/action | CONSENT_REBOOT_VALID / CONSENT_REBOOT_REMEDIATE_INVALID |
| CONSENT-002 | Approved capabilities/classes are requested subsets and collector requirements are covered | Authorization | CONSENT_SCOPE_ESCALATION | ConsentDenied | CONSENT_NETWORK_VALID / CONSENT_ADMIN_CAPABILITY_ESCALATION_INVALID |
| CONSENT-003 | Receipt active, unexpired, unreplayed, non-conflicting, and exact-bound | Authorization | CONSENT_RECEIPT_INVALID | ConsentDenied | CONSENT_REBOOT_VALID / CONSENT_REPLAY_INVALID |
| CONSENT-004 | The discriminator has exactly its required binding variant and no foreign variant | Schema + Authorization | CONSENT_BINDING_VARIANT_INVALID | Reject receipt/action | CONSENT_EXPORT_VALID / CONSENT_EXPORT_WITH_COLLECTOR_BINDING_INVALID |
| ACTION-001 | Action-specific identifiers and matching receipt types/scopes are present | Authorization | ACTION_AUTHORIZATION_INVALID | Reject action; do not act | ACTION_NETWORK_VALID / ACTION_NETWORK_WITHOUT_CONSENT_INVALID |
| ACTION-002 | Registry-backed structured parameters contain no raw sensitive value | Authorization | ACTION_REDACTION_INVALID | Reject log/action | ACTION_REDACTED_PARAMETER_VALID / ACTION_RAW_SENSITIVE_PARAMETER_INVALID |
| ACTION-003 | EntryDigest, sequence, previous link, run binding, and optional anchor verify | Canonicalize | ACTION_LOG_CHAIN_INVALID | Reject log/finalization | DIGEST_ACTION_CHAIN_VALID / DIGEST_ACTION_GAP_INVALID |
| ACTION-004 | Exactly the action-specific effect/authorization structure is present; all foreign structures are absent | Schema + Authorization | ACTION_EFFECT_CONFLICT | Reject action; do not act | ACTION_NETWORK_VALID / ACTION_NETWORK_WITH_REBOOT_AUTH_INVALID |
| MANIFEST-001 | Required roles and referenced members are exact; ActionLog object exists | Finalize | MANIFEST_REQUIRED_ROLE_MISSING | Reject finalization | MANIFEST_MINIMUM_VALID / MANIFEST_MISSING_ACTION_LOG_INVALID |
| MANIFEST-002 | Type-specific sorting, uniqueness, and digest recomputation pass | Canonicalize | MANIFEST_ORDER_OR_DIGEST_INVALID | Reject manifest/export | DIGEST_MANIFEST_PERMUTATION_VALID / MANIFEST_DUPLICATE_PATH_INVALID |
| MANIFEST-003 | Backend availability state agrees with presence/absence of observed runtime identity | Finalize | BACKEND_IDENTITY_STATE_CONFLICT | Reject finalization | MANIFEST_BACKEND_FOUND_VALID / MANIFEST_BACKEND_NOT_TESTED_WITH_OBSERVED_INVALID |
| LIMIT-001 | AuditRun, references, records, raw streams, ZIP and aggregate/package budgets hold using checked unsigned arithmetic | Parse + Finalize | Limit-specific code below | Stop before allocation/finalization | LIMIT_RUN_BOUNDARY_VALID / LIMIT_RUN_OVERSIZED_INVALID |
| PATH-001 | Every logical path matches the single grammar without normalization | Parse + Schema | PATH_CANONICAL_INVALID | Reject object/archive | PATH_VALID_NESTED / PATH_INVALID_DOT_PREFIX |

## CollectorExecution lifecycle invariants

Pre-execution states have no start/end, process, runtime identity, limits, command contract, output, parser/import, count, truncation, timeout/cancellation/partial/failure metadata. BackendNotFound alone requires expected backend identity and a structured absence error.

Running requires start, applied limits, command contract, and observed backend identity, and forbids every terminal field. All terminal states require start/end, applied limits, command contract, and observed backend identity. Succeeded requires exit zero, successful parser/import, raw output digests, record count, no truncation/error/failure/timeout/cancellation/partial field. Failed requires a structured failure plus nonzero exit or parser/import failure and may retain available raw digests. TimedOut and Cancelled require only their distinct source and forbid the other source and Partial metadata. Partial requires explicit reason, parser/import results, record count, raw digests, and truncation marker. State is a single enum and cannot simultaneously classify the result another way.

## Initial aggregate safety limits

These are initial safety limits, not permanent performance targets. Lowering is allowed after review; raising requires a versioned security/compatibility decision and boundary tests.

| Object / aggregate | Initial limit |
|---|---:|
| Serialized AuditRun | 4 MiB |
| Pass references | 4 |
| Execution references | 4,096 |
| Observation references | 10,000 |
| Evidence references | 10,000 |
| Finding references | 5,000 |
| Inline summary records | 256 |
| One inline summary after UTF-8/JCS | 2 KiB |
| Total decompressed run members | 2 GiB |
| Total audit package stored plus expanded members | 4 GiB |
| One ordinary JSON contract | 16 MiB |
| Observation payload after UTF-8/JCS | 1 MiB |
| Raw output or one stored file | 1 GiB |
| Collector records | 1,000,000 |
| JSON nesting depth | 64 |
| Manifest / ActionLog entries | 100,000 |
| ZIP entries / expanded bytes / entry / ratio | 10,000 / 1 GiB / 256 MiB / 100:1 |
| Archive nesting | Rejected |

The required `AuditRun.package_limits` object carries exactly these normative limits; consumers reject substitutions rather than silently accepting producer-selected values. All additions and multiplications use checked non-negative safe-integer arithmetic before allocation. A negative, fractional, unsafe integer or overflow is `LIMIT_INTEGER_OVERFLOW`, never wrapping or saturating.

Limit failures are isolated as follows: serialized object or inline summary bytes use `LIMIT_SERIALIZED_OBJECT_EXCEEDED`; reference/list counts use `LIMIT_REFERENCE_COUNT_EXCEEDED`; decompressed run membership uses `LIMIT_DECOMPRESSED_BUDGET_EXCEEDED`; package stored-plus-expanded budget uses `LIMIT_PACKAGE_BUDGET_EXCEEDED`; ZIP count uses `LIMIT_ZIP_ENTRY_COUNT_EXCEEDED`; one expanded entry uses `LIMIT_ZIP_ENTRY_SIZE_EXCEEDED`; total expanded ZIP bytes use `LIMIT_DECOMPRESSED_BUDGET_EXCEEDED`; ratio uses `LIMIT_COMPRESSION_RATIO_EXCEEDED`; and checked arithmetic failure uses `LIMIT_INTEGER_OVERFLOW`.

AuditRun is never an evidence container. Full objects are separate manifest members, so a construction such as 100,000 observations each embedding 1 MiB cannot enter AuditRun. JSON Schema enforces counts/string lengths; `LIMIT-001` measures UTF-8/JCS serialized bytes and aggregate budgets before allocation/finalization.

## External anchors and limitations

An AuditManifest or ActionLog digest stored beside mutable data is not a trust anchor. A separately protected digest, detached signature with an approved trust policy, or other protected external record is required for provenance claims. Signing identities, runtime binary trust, protected storage, key rotation, rollback, and recovery remain pre-runtime decisions.

JSON Schema cannot compare arbitrary arrays/IDs/timestamps, walk graphs, remember nonces, measure serialized byte size, or recompute digests. A full Draft 2020-12 validator plus all application rules is required before architecture baseline acceptance. A compromised host can still forge source observations, race collection, or rewrite all locally anchored state.

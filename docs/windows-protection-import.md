# Imported Windows protection reference profile

Status: implemented reference slice; `policy_review: PendingIndependentReview`.
This is an offline interpretation of supplied SecApp observations, not a
collector, launcher, current-host scan, or production-accepted audit.

## Input contract

Use an explicitly selected local JSON Observation, JSONL stream, or supported
manifest-based audit ZIP through the bounded importer. Each full Observation
must satisfy the existing v1 core schema and its real JCS object digest. This
profile adds strict `data` schemas without modifying the core schemas. All
payload objects require `schema_version: 1.0.0`, disallow additional properties,
and allow only the enums below. State fields may be absent: omission means
not tested, never a default positive value. Bounds and UTF-8 policies of the
importer and outer Observation still apply.

| Area | data_schema | SecurityControl subject key | State fields and supported values |
|---|---|---|---|
| Defender | `urn:secapp:observation:defender-protection:1` | `control:defender` | `mode`: Active, Passive, Disabled, Unknown, Unsupported; `real_time_protection`: Enabled, Disabled, Unknown, Unsupported |
| Firewall | `urn:secapp:observation:firewall-profiles:1` | `control:firewall` | `domain`, `private`, `public`: Enabled, Disabled, Unknown, Unsupported |
| BitLocker | `urn:secapp:observation:bitlocker-os-volume:1` | `control:bitlocker-os-volume` | `protection`: On, Off, Unknown, Unsupported; `encryption`: FullyEncrypted, PartiallyEncrypted, NotEncrypted, Unknown, Unsupported |
| SecureBoot | `urn:secapp:observation:secure-boot-state:1` | `control:secure-boot` | `state`: Enabled, Disabled, Unknown, Unsupported |

Every field of these payloads is `SensitiveSecurityData`, including the
combination of states. The enclosing Observation must carry that privacy class,
the exact area/schema/subject binding, UTC `observed_at`, provenance metadata,
and an integrity digest. Provenance metadata remains an untrusted source claim.
Do not include computer names, paths, usernames, recovery keys, serial numbers,
or raw command output in these payloads. They have no corresponding field.

Only one observation per supported area and one run across all observations
are permitted. Duplicates are rejected, not resolved by timestamp or last write.
Unsupported payload URNs in a supported area become NotTested; their data is
not interpreted. Unsupported areas are counted and ignored. Known URNs with
invalid payloads or wrong bindings are rejected. The result still lists all
six checks if no relevant observations were supplied.

A supplied CollectorExecution must bind the observation and run correctly.
An unsuccessful execution makes its observations NotTested. A ZIP observation
without its execution likewise cannot yield an assessed state. Standalone
JSON/JSONL observations can be assessed without an execution record, but do
not prove that collection succeeded. A Partial execution permits evaluation
only of the explicitly known fields present; missing fields remain NotTested.
This is not full application/XOBJ/consent validation.

No supported external producer/converter is delivered here. Raw Velociraptor
JSON or arbitrary system output is not this contract. Mapping external values,
Windows version/edition support, trustworthy acquisition, and independent
collector review remain separate work.

## Six reference rules

All required states must be known before a rule is evaluated. Any known state
different from the expected state produces Concern. Otherwise the result is
NoConcernReported. Missing/Unknown/Unsupported states produce NotTested.

| Rule | Expected reported state | Concern priority |
|---|---|---|
| `rule:secapp.defender-realtime` | mode Active and real_time_protection Enabled | Medium |
| `rule:secapp.firewall-domain` | domain Enabled | Medium |
| `rule:secapp.firewall-private` | private Enabled | Medium |
| `rule:secapp.firewall-public` | public Enabled | Medium |
| `rule:secapp.bitlocker-os-volume` | protection On and encryption FullyEncrypted | Medium |
| `rule:secapp.secure-boot` | state Enabled | Low |

Defender Passive or Disabled mode is NotTested for this narrowly scoped
real-time rule: the profile cannot determine whether a different antivirus is
appropriate or active. Firewall rules do not establish the active network
profile or effective filtering policy. The BitLocker rule concerns only the
reported OS volume and does not assess recovery-key custody. Secure Boot does
not establish boot-chain integrity. These are deliberately preliminary SecApp
review priorities; the levels have not passed independent security review.

Concern uses confidence Possible and its stated severity. NoConcernReported
uses Info / Not detected; NotTested uses Info / Not tested. Every row retains
status Requires review. No outcome means that the host is safe or compromised.
`assessment_status: Complete` means six rules had supported data, not a
complete security audit. Partial and NotTested describe incomplete coverage.

## Private report and reproducibility

`--assess windows-protection-v1` emits readable text by default, one JSON
report with `--json`, or standalone HTML with `--html`. HTML and JSON are
mutually exclusive. All formats go to stdout; the CLI never saves a report.
Use Node directly rather than npm when consuming machine-readable/HTML output,
to avoid npm's command banner. The caller is responsible for any explicitly
saved copy; no encryption, retention, secure erasure, or redaction is promised.

The report schema is
`https://schemas.secapp.dev/v1/reports/windows-protection-report.schema.json`.
It carries `privacy_class: SensitiveSecurityData`,
`validation_scope: ImportedObservationProfile`,
`provenance_claim: NotEstablished`, and `freshness_claim: NotEvaluated`.
Only fixed rule text and selected observation IDs/timestamps/digests are
rendered; raw payloads and local source paths are not included. This remains
sensitive because it describes protection gaps and links observations.
It is neither an AuditRun nor an ExportManifest/public export.

`profile_digest` hashes the full deeply immutable reference profile with JCS.
`schema_digests` hash the exact local payload-schema bytes; `source_file_digest`
hashes exact imported bytes. Each used observation retains its verified object
digest. `report_digest` is JCS SHA-256 after excluding only `report_digest`.
These hashes provide reproducibility/modification detection, not authentication
or a protected trust anchor. No clock or freshness decision is introduced.

HTML has no scripts, links, external fonts, images, or network resources. All
dynamic text is HTML-escaped. A restrictive CSP disables default resources,
base URLs, and form actions; inline static styles are the only allowed resource
class. This is a private viewer, not authorization to publish a report.

## Verification and remaining gates

`npm run test:assessment` covers all six expected/adverse rule outcomes, every
payload schema's positive/negative vectors, coverage gaps, bindings, duplicate
domains, mixed runs, tampered digests, report constraints, CLI errors, HTML
escaping, and stdout-only operation with synthetic data. `npm test` also runs
the existing schema, contract, application, digest, and import suites.

Independent security review, a wider browser/accessibility regression matrix,
external producer integration, provenance/freshness policy, complete runtime
validation, private storage, public export, GUI, and Windows distribution remain
open. Automatic backend execution stays disabled. Direct-launch development
has subsequently reopened under [D-032](decision-log.md); technical launch
gates remain unresolved, and this assessment profile does not authorize collection.

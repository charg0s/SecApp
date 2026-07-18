# SecApp Schema Compatibility and Validation Policy

Status: normative design policy; local SCHEMA-VALIDATION1, XOBJ-GRAPH1, and JCS-DIGEST1 gates are available, while CI integration and ARCH-REVIEW5 remain later tasks

## Identifier and contract versioning

Every current contract uses:

- JSON Schema Draft 2020-12;
- an immutable major-family identifier of the form https://schemas.secapp.dev/v1/schema-name.schema.json;
- schema_version equal to 1.0.0;
- fail-closed handling for unknown properties, enum values, references, formats, and major versions.

The schemas.secapp.dev name is a contract namespace, not a claim that a network service currently exists. Runtime validation must use a local, digest-pinned schema registry and must not fetch schemas during an audit.

Once published, an identified schema document is immutable. Corrections made before the first architecture baseline is published do not create compatibility precedent.

## Change classification

| Change | Compatibility | Policy |
|---|---|---|
| Editorial documentation or new negative fixture with no validation/semantic change | Patch-compatible | Existing schema document stays byte-identical; documentation or test catalog receives its own versioned change |
| New area-specific Observation data schema selected through the existing data_schema extension point | Minor-compatible | Publish a new immutable area schema; existing core contracts remain unchanged |
| New optional capability represented through an already declared extension point | Minor-compatible only after old-reader tests | Old readers must preserve or explicitly reject it without interpreting it as safe |
| New root property, enum value, required field, field meaning, digest rule, lifecycle state, or privacy behavior | Breaking under strict contracts | Publish a new major-family schema and migration |
| Relaxed bound, privacy rule, consent rule, or fail-closed behavior | Security-sensitive breaking change | New major plus security review and negative tests |

Because root additionalProperties is false and enums are strict, an apparently additive core field or enum is not assumed minor-compatible.

## Migration policy

1. Detect schema ID and schema_version before interpreting any other field.
2. Reject an unknown major family with SCHEMA_MAJOR_UNSUPPORTED.
3. Never coerce, drop, rename, or default security-relevant fields silently.
4. Migrations are explicit pure transformations from one immutable input contract to one immutable output contract.
5. Preserve the original file digest, migration identifier/version/digest, warnings, and output object digest.
6. Validate before and after migration and run cross-object rules on the complete migrated set.
7. A failed or partial migration is Not tested; it is never a safe finding.
8. Downgrade migration is prohibited unless a separately reviewed lossless mapping exists.

No migration implementation is authorized at this stage.

## Validation pipeline and future CI

ARCH-FIX1 through ARCH-FIX3 used dependency-free subset checks. SCHEMA-VALIDATION1 subsequently installed the exact development-only Draft 2020-12 validator and lock file described below. XOBJ-GRAPH1 made all 18 registered cross-object rules executable over fixed synthetic materialized graphs. CI integration and independent architecture recheck remain later work; neither local gate is a runtime dependency or production-readiness claim.

Before accepting the architecture baseline, future CI must:

1. select one maintained Draft 2020-12 implementation with format assertion support;
2. pin its exact version and distribution digest in a reviewed dependency lock;
3. disable network reference retrieval and register all SecApp schemas by immutable ID from the checkout;
4. reject duplicate JSON keys before schema evaluation;
5. validate every schema against the official Draft 2020-12 metaschema;
6. resolve every local reference and JSON Pointer;
7. enable strict UUID, URI, and UTC date-time checks;
8. validate every embedded positive example and a generated minimal valid instance;
9. prove invalid required, enum, additional property, number type, lifecycle, policy, redaction, path, digest, rule graph, consent, cross-object, reboot, and size cases are rejected;
10. execute the application-level rules in integrity-model.md over complete synthetic object graphs;
11. record validator version, schema digests, test-vector digests, and deterministic results.

CI must fail if the validator reports an unknown keyword used for enforcement, skips a format assertion, resolves a network reference, or evaluates a test differently across supported implementations.

## Required negative-test catalog

At minimum, synthetic tests cover:

- duplicate JSON keys and duplicate immutable IDs;
- invalid required, enum, additionalProperties, format, and reference pointer;
- integer and non-integer numbers, strings, null, and booleans in parameter and numeric-operator positions;
- every CollectorExecution pre-execution, running, and terminal lifecycle contradiction;
- network, mutation, elevation, memory, secret, and default-profile policy contradictions;
- backend discriminator ambiguity, empty/unknown capabilities, and limit overflow;
- public redaction Include bypass, Hash without key, duplicate/unknown field rules, and policy weakening;
- absolute, drive, UNC, backslash, dot, parent, repeated-separator, trailing-separator, control-character, too-long, and duplicate logical paths;
- digest self-reference, wrong canonicalization, wrong raw-byte handling, and manifest/profile substitution;
- rule cycles, unknown references, duplicate IDs, unreachable predicates, excessive depth/count, and operator/value mismatches;
- expired, revoked, cross-run, cross-host, cross-collector, scope-escalated, conflicting, and replayed consent;
- cross-run execution/observation/evidence/finding links and incomplete manifest membership;
- reboot expiry, replay, rollback, wrong run/host/build/executable, invalid tag, and wrong tag length;
- oversized strings, arrays, objects, records, JSON documents, ZIP entries, expanded bytes, and compression ratios.

Security-relevant schema changes are not accepted without both a positive case and at least one targeted negative case that failed before the fix.

## ARCH-FIX3 legacy local validation status

The local check may report only:

- JSON parsing and duplicate-key scanning;
- unique IDs, Draft declaration, local reference and pointer resolution;
- embedded examples and selected keywords exercised by a purpose-built subset checker;
- every static fixture indexed by `tests/contracts/index.json`, including state, pass, consent, action, manifest, path, digest, and aggregate-limit vectors;
- explicit application-rule vectors with exact expected error codes;
- text hygiene, local links, secret/path scans, and Git inventory.

Those subset-only statements describe the earlier ARCH-FIX3 checkpoint. They do not describe the current SCHEMA-VALIDATION1/XOBJ-GRAPH1 local gate.

## SCHEMA-VALIDATION1 development gate

Version selection was performed on 2026-07-18 from package metadata returned by the configured official `https://registry.npmjs.org/` registry. The exact dev-only versions are `ajv@8.20.0` and `ajv-formats@3.0.1`; `package-lock.json` lockfile version 3 records exact HTTPS npm tarballs and SHA-512 integrity values. There are no runtime dependencies, lifecycle scripts, optional/native packages, or manually configured mirrors/CDNs. Installation uses `npm ci --ignore-scripts`; subsequent validation is offline.

Ajv uses its dedicated Draft 2020-12 class with `strict`, `strictSchema`, `strictTypes`, `strictTuples`, and `strictRequired` enabled; `allowUnionTypes` is false; `allErrors`, `validateSchema`, `validateFormats`, `unevaluated`, `discriminator`, and Unicode regular expressions are enabled. Defaults, coercion, removal of additional properties, `loadSchema`, and remote reference retrieval are disabled. Only the actually used `date-time`, `uri`, and `uuid` formats are registered.

The explicit no-op annotation allowlist is:

- `x-application-limits`;
- `x-application-rules`;
- `x-negative-tests`;
- `x-numeric-operator-cases`;
- `x-scalar-validation-cases`;
- `x-state-contract`.

Unknown custom keywords fail compilation. An annotation never mutates data, executes schema-provided code, or replaces application validation.

The gate is intentionally separated into schema, contract-vector, application-rule, and digest commands. `npm test` and `npm run validate:all` execute all four. Every validator accepts `-- --json`, is deterministic, writes no report into the repository, and exits nonzero on any incomplete or failed gate. The application evaluator uses `Parse`, `Schema`, `ObjectLocalApplication`, `GraphMaterialization`, `XOBJCrossObject`, and `DigestIntegrity` order and fail-closes unknown rules.

The schema command permanently self-tests rejection of invalid UUID, date-time, and URI values, an unknown ordinary keyword, an unknown `x-` keyword, and an unknown major schema namespace. It reports the actual recursively counted local `$ref` total and the lockfile's resolved origin under `locked_resolved_origin`; neither value is a network-access or vulnerability-audit claim. The application command permanently checks the exact safe-integer multiplication boundary and overflow rejection.

XOBJ graph fixtures are `FullContractInstance` vectors whose constituent objects all pass their production schemas before graph evaluation. The graph wrapper itself is deliberately test-only and has no production schema. Its materializer accepts only bounded data mutations, rejects unknown object kinds and absolute paths, and returns a deeply frozen graph. Missing required XOBJ input is `XOBJ_GRAPH_INPUT_MISSING`; a normative violation uses the exact XOBJ error code from `integrity-model.md`.

Application-gate exit code 0 additionally requires all 18 XOBJ IDs to be registered, executable, dispatched, positively covered, negatively covered, and actually executed, with zero skipped XOBJ vectors. Machine output includes `registered_xobj_rules`, `executable_xobj_rules`, `covered_xobj_rules`, `uncovered_xobj_rules`, positive/negative/skipped counts, and `xobj_failures`. Built-in self-tests prove fail-closed handling for an unknown rule, a missing implementation, a missing required input, an unknown graph kind, and a skipped-vector completeness state.

## JCS-DIGEST1 development gate

The digest command executes permanent JSON-compatible RFC 8785, Unicode, number, ProfileDigest, FileDigest, and ContentDigest fixtures plus direct in-memory cases that JSON files cannot represent. Direct cases cover undefined, functions, symbols, BigInt, non-finite numbers, lone surrogates, sparse arrays, cycles, accessors, proxies, symbol keys, typed arrays, and non-plain objects. Every rejection is controlled, every ProfileDigest fixture is nonempty and schema-valid, every FileDigest positive has an exact mutation digest, and ContentDigest cases materialize bytes before strict UTF-8/LF canonicalization.

Exit code 0 requires nonzero JCS conformance, direct positive, direct negative, ProfileDigest, byte-backed FileDigest, byte-backed ContentDigest, and structurally-only metadata counts, together with zero unsupported and zero skipped digest cases. JSON output exposes those counts, `canonical_sort_implementation`, and `rfc8785_conformance_status`. Locale-aware sorting, environmental configuration, network retrieval, and generated report files are outside the gate.

Dependency updates are never automatic. A maintainer must review current official npm metadata, choose compatible exact versions, install with `--save-exact --ignore-scripts`, review all package and lockfile URLs/integrity/transitive changes, perform an offline clean install, and rerun the complete deterministic gate twice. The lockfile is mandatory and must never be replaced by a floating range.

Passing SCHEMA-VALIDATION1 is a prerequisite for architecture baseline acceptance. It establishes validation behavior for the current synthetic design contracts; it does not establish runtime conformance, provenance, Velociraptor compatibility, or production readiness.

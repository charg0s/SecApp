# SecApp fixed contract vectors

This directory contains static synthetic contract fixtures only. It contains no audit evidence, host identifiers, secrets, binaries, executable validator, or runtime application code.

`index.json` is the normative vector manifest. Every entry names its fixture kind, schema/application expectation, exact expected error code, instance file and JSON Pointer, and the application rule when shape validation alone is insufficient.

Every vector has exactly one fixture kind:

- `FullContractInstance` is a complete schema object, or a vector containing explicitly listed complete schema instances. Positive objects carry their actual nonzero contract digest.
- `DigestProjection` is a deliberately bounded canonicalization, graph, path, ordering, or aggregate-limit projection. It is never presented to a schema as a complete object.
- `ShapeOnly` isolates a local schema boundary without claiming a complete contract. A `ShapeOnly` vector is never counted as an application-valid positive.

Some legacy-shaped category files use deterministic fixture composition to avoid duplicating large JSON objects:

- `base_instance` is deep-copied;
- `inherits` names another materialized vector in the same file;
- `merge_patch` applies JSON Merge Patch semantics, except that no fixture needs a literal null property in a patch;
- `base_entry` plus `entry_merge_patch` materializes a one-entry ActionLog;
- `remove` removes the named JSON Pointer after merge;
- `repeat_arrays` expands a declared item to an exact count for aggregate-limit tests only.

`xobj/materialized-graphs.json` is a separate test-only composition contract. It supplies one complete synthetic base graph and vectors containing only bounded `add`, `copy`, `remove`, or `replace` JSON-Pointer mutations. The harness does not execute fixture code: it deep-clones, validates the graph envelope, rejects unknown collection kinds and absolute paths, applies at most 64 data mutations, deterministically orders collections, and deep-freezes the result. Duplicate IDs are deliberately retained until XOBJ-002 rejects them, so no duplicate is silently overwritten during indexing.

The resulting materialized `instance` is the schema input. Files with `application_graph`, `application_projection`, or `measurement` provide only the bounded cross-object facts required by the named application rule. A conforming harness must perform strict JSON parsing and duplicate-key rejection before composition, full Draft 2020-12 validation when the future gate is installed, then the application rules in `docs/integrity-model.md`. Expected error codes are exact; an unrelated earlier rejection is a test failure. Schema-invalid vectors stop before application evaluation; schema-valid application negatives must name exactly one violated application rule.

Digest fixture files remain strict JSON, but JCS-DIGEST1 also names direct in-memory cases for values JSON cannot encode. Permanent `jcs_conformance_vectors` carry official RFC 8785 sources and exact canonical strings/digests. `profile_digest_cases` contain schema-valid public/private profiles with nonempty exact-`field` rules, permutations, mutations, and duplicate/fallback rejection. `file_digest_cases` materialize strict Hex/Base64 bytes and verify both original and mutation SHA-256. `content_digest_cases` materialize bytes and verify strict UTF-8, BOM removal, LF normalization, final LF, and Unicode preservation. These nested digest cases are executed by the digest gate and are intentionally not counted as complete contract records in the 201-vector catalog.

## Executable validation gate

The development-only gate is lockfile-pinned to Ajv's dedicated Draft 2020-12 implementation. Run the complete suite with `npm test` or `npm run validate:all`. The four phase-specific commands are:

- `npm run validate:schemas` for strict metaschema validation, compilation, local `$ref` resolution, formats, and embedded examples;
- `npm run validate:contracts` for index integrity and schema-positive/schema-negative expectations;
- `npm run validate:application` for deterministic application rules and checked limits after schema success;
- `npm run validate:digests` for strict JCS/SHA-256, ProfileDigest, byte-backed FileDigest/ContentDigest, direct API negatives, completeness, and applicable embedded digest examples.

Each command accepts `-- --json`. JSON output contains no absolute local paths, timestamps, environment variables, or npm configuration. Exit code 0 means that entire command passed; any unexpected acceptance, rejection, rule code, digest, index entry, unknown rule, or unknown custom keyword returns a nonzero exit code.

Schema-invalid vectors stop before application evaluation. `DigestProjection` and `ShapeOnly` are never presented as complete contract instances. Application negatives must produce exactly their primary `expected_error_code`; only explicitly declared `expected_additional_error_codes` are permitted.

Every XOBJ vector is a `FullContractInstance` graph whose 14 constituent object collections pass their production schemas before application evaluation. The graph then passes bounded materialization and every earlier XOBJ rule before the target rule runs. The current corpus has 19 positive and 32 negative XOBJ vectors covering XOBJ-001 through XOBJ-018, including a 64-predicate positive boundary. Exit code 0 requires the registered, executable, and covered XOBJ sets to be identical, zero uncovered rules, zero skipped XOBJ vectors, and zero XOBJ failures. `APPLICATION_RULE_INPUT_MISSING` is not an XOBJ result; absent rule-specific graph data is `XOBJ_GRAPH_INPUT_MISSING`.

# AUDIT-PACKAGE-IMPORT1

This directory contains only synthetic import fixtures and dependency-free
container tests. It contains no real audit evidence, machine identity, local
user path, software inventory, backend binary, generated report, or executable
archive fixture.

## Architecture boundary

The production-neutral core under `src/import/` implements Variant A. It owns
bounded local reads, strict UTF-8 JSON/JSONL parsing, the restricted ZIP
container profile, canonical logical paths, exact archive membership,
FileDigest/object/manifest digest checks, cross-object reference preparation,
normalization, and privacy-safe results. It never invokes Velociraptor or any
other process and performs no extraction, network access, elevation, or
remediation.

Full Draft 2020-12 validation is an explicit callback boundary. The shared
development adapter `tools/lib/import-reference-validator.mjs` connects that
boundary to the existing lockfile-pinned Ajv registry for both tests and CLI.
It checks installed dependency versions, validates and compiles all local
schemas, and rejects initialization warnings. `src/import/` does not import Ajv or a development command
entrypoint. Without the callback, the importer returns the controlled
`IMPORT_REFERENCE_VALIDATION_REQUIRED` rejection and never marks input
accepted.

## Input and result policy

`importAuditPackage` accepts an absolute, explicitly selected local
`sourcePath`, `expectedPackageKind` (`Auto`, `JsonObject`, `JsonLines`, or
`AuditPackageZip`), optional lowering-only limits, `privacyMode`
(`SummaryOnly` or `Private`), and the reference-validation callback. JSONL uses
LF record framing, accepts CRLF, rejects blank/non-object rows, and has an
explicit `Optional` or `Required` final-LF policy.

The restricted ZIP profile supports only non-ZIP64 single-disk archives with
stored or deflated regular-file members, no comments/extra fields/data
descriptors, canonical ASCII paths, no case collisions, and exact top-level
`manifest.json` membership. It rejects encrypted, multipart, self-extracting,
nested-archive, symlink, executable, traversal, hidden-data, unsupported-method,
CRC, size, entry-count, expanded-byte, and compression-ratio cases before
acceptance. Members are materialized in bounded memory and are never extracted
to the filesystem.

An accepted digest means modification detection relative to the imported
manifest only. Every result states `provenance_claim: NotEstablished`; no local
digest is presented as proof that the source host or package producer was
truthful.

Run the suite with:

```text
npm.cmd run test:import
```

## Reference CLI and regression coverage

`npm run import -- --source <local-file>` runs the same importer and schema
adapter as the tests. Use `node tools/import-audit-package.mjs ... --json` for
one JSON result without npm's command banner. `--kind` selects the expected
container; `--max-source-bytes` can only lower the limit; `--require-final-lf`
tightens JSONL framing. Unknown, repeated, or ambiguous arguments fail before
validator initialization. Default output is summary-only; imported findings
are not interpreted as trusted conclusions.

Plain import explicitly labels `validation_scope: ImportContractChecks` and
`assessment_status: NotPerformed`. Full XOBJ/consent/capability evaluation,
arbitrary domain payload validation, and a production runtime validator are still
separate work. The existing development-only dependency policy is preserved.

The explicit `--assess windows-protection-v1` option instead validates the
four supported payload schemas and emits a private snapshot assessment in
text, JSON (`--json`), or HTML (`--html`). That output is
`SensitiveSecurityData`, never a public export. No file is written by the CLI.
This does not widen the generic importer's acceptance or interpret imported
findings as trusted. See [assessment tests](../assessment/README.md) and the
[profile contract](../../docs/windows-protection-import.md).

Regression cases cover depth rejection before recursive parsing, finite
I-JSON values and paired Unicode, incremental JSONL count/line bounds, BOM-free
canonical ZIP names, complete DEFLATE stream consumption, and pure path checks
for alternate UNC spellings, device aliases, and alternate data streams. These
path tests do not access a network or exercise native reparse/loader behavior.
No new claim of protection against concurrent Windows reparse replacement is
made. Synthetic test files use unique OS temporary directories and are removed
after the tests; concurrent test runs do not share an output directory.

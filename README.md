# SecApp

SecApp is a fully open local security auditing and forensic collection system for Windows.

- Velociraptor is intended to be used as a separate, unmodified forensic backend.
- Collection, risk assessment, and the user interface are separated.
- Checks are read-only by default.
- Network access, administrative operations, rebooting, memory scanning, and remediation require separate, explicit consent.
- The project is at an early design stage.

Architecture checkpoint `04351799ad780602bf73324336f40ab300c80323` is a WIP checkpoint, not an accepted baseline. ARCH-REVIEW5 ended `fail_with_blockers`; ARCH-FIX4 narrows the two reproduced local-gate blockers, but the result still requires independent ARCH-REVIEW6. The local gates do not declare the schemas production-ready and do not prove runtime behavior, provenance, Velociraptor compatibility, or production safety.

## Development-only schema validation

SCHEMA-VALIDATION1 uses the locally installed, lockfile-pinned Ajv Draft 2020-12 validator. It is development infrastructure and is not a SecApp runtime dependency.

```text
npm ci --ignore-scripts
npm test
```

Individual gates are available as `npm run validate:schemas`, `npm run validate:contracts`, `npm run validate:application`, and `npm run validate:digests`. All validators support deterministic machine-readable output with `-- --json` and return exit code 0 only when their complete gate passes. Schema validation does not by itself declare the contracts production-ready.

XOBJ-GRAPH1 is part of `validate:application`. It materializes a bounded, immutable, synthetic cross-object graph and executes XOBJ-001 through XOBJ-018 after constituent schema validation. XOBJ-011 dispatches the four exact binding models `CollectorExecution`, `Export`, `Remediation`, and `Reboot`; DefenderOffline remains collector-scoped under the existing schema/decision model. Exit code 0 requires exact equality of required, executable, executed, and positively covered consent-variant sets, required negative/substitution coverage, and no skipped variant vector, in addition to complete coverage of all 18 XOBJ rules.

The graph harness is development/reference infrastructure, not SecApp runtime code or proof of provenance. A compromised host can still supply fabricated observations or rewrite locally anchored data.

JCS-DIGEST1 is part of `validate:digests`. It verifies the covered RFC 8785 examples/derived cases, ECMAScript number boundaries, Unicode preservation, strict direct-API rejection, complete nonempty ProfileDigest cases, exact raw-byte FileDigest cases, and byte-backed ContentDigest normalization. Completeness uses immutable exact required-ID sets rather than counts; every required ID is checked for presence, uniqueness, category, execution, skip state, and expected result, with six permanent in-memory false-positive mutations per ID. The RFC machine claim is limited to `covered_conformance_set_passed`, `conformance_claim: CoveredSet`, and `full_corpus_claimed: false`. This gate remains development/reference infrastructure and is not an integrity trust anchor.

# SecApp

SecApp is a fully open local security auditing and forensic collection system for Windows.

- Velociraptor is intended to be used as a separate, unmodified forensic backend.
- Collection, risk assessment, and the user interface are separated.
- Checks are read-only by default.
- Network access, administrative operations, rebooting, memory scanning, and remediation require separate, explicit consent.
- The project is at an early design stage.

## Development-only schema validation

SCHEMA-VALIDATION1 uses the locally installed, lockfile-pinned Ajv Draft 2020-12 validator. It is development infrastructure and is not a SecApp runtime dependency.

```text
npm ci --ignore-scripts
npm test
```

Individual gates are available as `npm run validate:schemas`, `npm run validate:contracts`, `npm run validate:application`, and `npm run validate:digests`. All validators support deterministic machine-readable output with `-- --json` and return exit code 0 only when their complete gate passes. Schema validation does not by itself declare the contracts production-ready.

XOBJ-GRAPH1 is part of `validate:application`. It materializes a bounded, immutable, synthetic cross-object graph and executes XOBJ-001 through XOBJ-018 after constituent schema validation. The application command returns exit code 0 only when all 18 rules are registered, implemented, dispatched, covered by executed positive and negative vectors, and no XOBJ vector is skipped. Missing graph input is reported separately as `XOBJ_GRAPH_INPUT_MISSING`; normative violations retain their exact stable XOBJ error code.

The graph harness is development/reference infrastructure, not SecApp runtime code or proof of provenance. A compromised host can still supply fabricated observations or rewrite locally anchored data.

JCS-DIGEST1 is part of `validate:digests`. It verifies official RFC 8785 serialization/property-order examples, ECMAScript number boundaries, Unicode preservation, strict direct-API rejection, complete nonempty ProfileDigest cases, exact raw-byte FileDigest cases, and byte-backed ContentDigest normalization. Machine output reports every coverage class and fails if a required class is empty, unsupported, or skipped. This gate remains development/reference infrastructure and is not an integrity trust anchor.

# SecApp

SecApp is a fully open local security auditing and forensic collection system for Windows.

- Velociraptor is intended to be used as a separate, unmodified forensic backend.
- Collection, risk assessment, and the user interface are separated.
- Checks are read-only by default.
- Network access, administrative operations, rebooting, memory scanning, and remediation require separate, explicit consent.
- A fixed, user-confirmed development launcher has completed one live Defender control check; a general product launcher is not delivered yet.

## Current first-release scope: direct Standard MVP (D-062)

The user approved [DIRECT-STANDARD-MVP1](docs/direct-standard-mvp.md): one
manually confirmed fixed read-only check under ordinary user rights on a trusted
Windows/session. The service and elevated collection are deferred from the MVP.
No UAC, audited-security-setting change or automatic scan belongs to this path.
D-063 permits only the pinned backend's event-source registration and normal
startup logging. Further permissions must be explained and requested explicitly;
prefer a supported straightforward path over complex permission workarounds.

D-064 additionally authorizes preparation and **one** explicitly confirmed UAC
control run: only the helper and pinned backend are elevated, for the same two
Defender fields. `tools/backend/defender-control` contains that route's candidate;
compile-only and run are separate, and no run is part of npm test. This is not
general elevated collection, a service installation or production acceptance.
D-065 permits creation of new private SecApp working directories and a verified
private backend copy. It does not permit changing existing directory permissions
or touching other projects. Build/run results remain separate from authorization.

On 2026-11-06 that single control run completed successfully: the pinned backend
exited with code 0, the helper reported an empty Job/closed streams, and SecApp's
bounded reader rendered a useful two-field result. Temporary control-run data and
binaries were removed after confirmed helper exit. No real result is stored here.
This is one working development slice, not a full audit or production acceptance.

The interactive development command is now implemented (D-066):

```text
npm.cmd run check:defender -- --help
npm.cmd run check:defender
```

Run it from an ordinary interactive Windows terminal in this checkout. It prepares
a new private workspace, shows the exact two-field scope and effects, asks for the
displayed one-use phrase, then requests Windows UAC. No `--yes`, redirected-input
consent or automatic retry exists. It needs the already acquired pinned backend;
there is no download/install step. The current fixed development layout requires
`C:\Windows`, `C:\Dev`, and the documented acquisition path.

On confirmed success the temporary data files are removed; the private directory
and its empty `controller.lock` remain, and the command says so. On uncertain
lifetime/cleanup, keep that directory for explicit follow-up; do not blindly delete
it or kill processes by name. Output is private terminal text, not an AuditRun or
an exported report. On 2026-11-06 a separately authorized interactive acceptance
run passed (D-067): CLI exit 0, useful result accepted by the bounded decoder,
and post-run inspection confirmed only the empty coordination file remained.
The source EventLog registration already existed and its checked values were
unchanged. This is one successful end-to-end path, not native failure-path coverage.

The first implemented slice decodes a bounded two-field Defender result and
renders a private text/HTML preview. It never launches Velociraptor or claims
that supplied output proves successful collection. Try the synthetic example:

```text
node tools/preview-defender-check.mjs --input tests/backend/fixtures/defender-normal.synthetic.jsonl
npm run test:direct-defender
```

The pure direct-operation policy now fixes the candidate EXE digest, query,
empty working-config file, environment names and resource limits. Its bounded
output gate rejects errors, cancellation and incomplete streams; it still returns
only an unverified preview and cannot start a process or grant launch admission.

The narrow interactive command now has one successful end-to-end acceptance.
Ordinary non-elevated launch, broader native failure/cancellation coverage and
release packaging remain unqualified; the successful path does not settle them.
Service/RPC qualification is not on this route.
D-062 and its scoped D-063 through D-067 additions take precedence over historical plans.

## Historical trusted-host/service scope (D-058 / D-061)

On 2026-11-06 the user approved [TRUSTED-HOST-MVP1](docs/trusted-host-mvp.md):
ordinary development and controlled integration for a trusted Windows/session,
not a same-user-malware-resistant execution environment. This broadens D-056's
confirmation-only exception. The service direction remains; basic backend trust,
safe launch, offline/private data handling and exact consent stay mandatory.
Installation changes require a presented exact manifest and explicit confirmation.
Historical strict tests are not marked Passed; no execution flag is enabled.

This historical scope is superseded by D-062 where it retains the service direction.
Historical stage descriptions below retain their original results and boundaries.

[BACKEND-DIAGNOSTIC-CONTRACT1](docs/backend-diagnostic-contract.md) specifies the
first proposed real-operation boundary: Version, then separately confirmed Help,
with release-specific output profiles and no collector authority. Current release
selection and native prerequisites remain unresolved; this is not a working launch.
The [initial official-source release review](docs/backend-release-review.md)
records a startup side-effect blocker in the v0.77.3 research candidate; no new
runtime binary pin is selected.

[BACKEND-ACQUISITION-VERIFY1](docs/backend-acquisition-verification.md) records
matching gzip/EXE hashes and a valid detached signature under the officially
pinned primary key, using previously acquired public-key material. No backend
execution occurred; key lifecycle, Windows image trust and runtime admission
remain unaccepted.

[BACKEND-TRUST-LAUNCH-SLICE1](docs/backend-trust-launch-slice-review.md) adds an
offline GnuPG cross-check, static Windows manifest/build observations and a
historical LocalService broker-account proposal. D-061 now permits designing
necessary targeted rights for a separate virtual service account in a future
installation; [the exact candidate list and boundaries](docs/broker-bootstrap-contract.md#8-d-061-scoped-service-account-rights-proposal)
still require exact-manifest review and separate installation confirmation. This
assigns no rights now and grants none to the UI/backend. Dependency follow-up, full Windows
image trust and supervisor-to-worker/offline/effects gaps still block launch;
no service was installed or backend executed.

## Direct-launch development state (still blocked)

The user has lifted the earlier restriction on developing direct Velociraptor
launch from SecApp. `BACKEND-LAUNCH-PLAN1` reopens that product direction without
declaring the nine historical launch blockers resolved. Current policy:

```text
TrustLaunchStatus = DesignReopened
BackendLaunchDevelopment = Authorized
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
VelociraptorInvocationFromSecApp = BlockedPendingTechnicalGates
ProductPaths = ImportOnlyAndDirectLaunchDevelopment
```

The existing strict-profile planner accepts only fixed `Version`/`Help` operations and lowering-only
time/output limits. It emits a non-executable plan; it does not open or verify a
binary, start a process, collect data, or call the retained prototype.

```text
npm run backend:plan -- --operation Version
node tools/plan-backend-launch.mjs --operation Version --json
```

Exit `2` means a valid plan with unresolved technical gates, not a test failure
or withdrawn development permission. No force/readiness override exists.
See [the direct-launch design and implementation sequence](docs/backend-launch-design.md).
The existing import and assessment workflow remains available. D-058 requires a
separately reviewed MVP admission contract, not flipping this planner's flags.

`BACKEND-NATIVE-SYNTHETIC1` separately exercises a self-launch-only native
helper: 10/10 cases passed in three final-source runs, including restricted
child rights, stream/deadline bounds, cancellation, tree cleanup, and a fault
before resume. Build outputs were temporary and removed. Linked-token metadata
is still present; no historical trust gate is declared closed. Velociraptor
was not run. See [scope, normalized results, and limits](tests/backend/native-synthetic/README.md).
Normal `npm test` validates that result record without executing native code.

`NATIVE-BOUNDARY-EXPERIMENT1` adds seven narrowly scoped native observations in
three final-source runs, under separate user permission. Default same-user
process access and explicit local DLL loading demonstrate remaining gaps, not
production acceptance. Its 33 pure record tests join `npm test`; native execution
does not. No Velociraptor, UAC, ACL or system-setting change occurred. See
[observations, reproduction boundary and limitations](tests/backend/native-boundary/README.md).

The user approved the separate-identity, SCM-bootstrapped narrow launch broker
for design under D-052. `SERVICE-LAUNCH-BROKER-DESIGN1` defines its proposed
roles, token/session boundary, bounded requests and failure handling. This is a
scoped change to the earlier no-service direction, not permission to implement
or install a service. Direct launch stays blocked; loader, isolation and exact
confirmation remain unproved. See [the broker design](docs/service-launch-broker-design.md)
and [mechanism selection and acceptance conditions](docs/backend-launch-mechanism-selection.md).

`LAUNCH-CONFIRMATION-DESIGN1` specifies how a separate confirmation component
would display the broker's frozen exact scope and return a bound decision;
one-use launch admission stays inside the broker. It does not trust an ordinary
UI approval flag, transferable permit or forwarded Hello result. Display/input
protection remains unselected and native approval disabled. See
[the confirmation and replay/crash design](docs/launch-confirmation-design.md).
The 2026-11-06 mechanism review rejects ordinary UI/UIPI as the sole boundary
and distinguishes secure credential prompting from exact launch consent. A
private-desktop bootstrap review ended NotAccepted for implementation:
shared-SID access is unsuitable and the retained-handle alternative still lacks
construction/input/recovery evidence. D-056 now selects the scoped trusted-local
MVP instead of continuing this stronger confirmation research. Remaining launch
gates and host-change permissions are not relaxed.

`BACKEND-IMAGE-TRUST-DESIGN1` now separates code-root protection, preventive
loading and verified-image binding. The user approved protected versioned
installation for further design, with unelevated everyday operation; actual
installation is not authorized. See [the design, API sources and acceptance
matrix](docs/backend-image-trust-design.md). All nine launch gates remain open.

`PROTECTED-INSTALLER-DESIGN1` defines the proposed per-machine installer,
separate maintenance consent, code/data permissions, package admission,
side-by-side update/recovery, and data-preserving uninstall. Its 22 acceptance
cases are Planned/NotRun. No installer or UAC entrypoint exists. See
[the installer design](docs/protected-installation-design.md).

`DEPLOYMENT-PLAN-CONTRACT1` adds strict development-only schemas and a pure
maintenance state model for Install, Update, EnrollBackend, Repair and Uninstall.
It checks synthetic confirmation bindings, generations, epoch floors and failure
transitions without performing host operations. Even a Completed projection
keeps installation and backend execution disabled. Run
`npm run test:deployment-model`; see [the model contract and limits](docs/deployment-plan-contract.md).

`MAINTENANCE-PROTOCOL-DESIGN1` proposes the separate UI/helper trust boundary:
helper-owned operation confirmation, local peer binding, durable single-use
admission and explicitly confirmed recovery. The UI cannot submit an authoritative
Approve/Commit command. All 28 protocol acceptance cases are Planned/NotRun;
no helper, UAC or installer entrypoint was added. See
[the protocol design and remaining gates](docs/maintenance-protocol-design.md).

`MAINTENANCE-PROTOCOL-CONTRACT1` implements separate development-only message,
scenario and projection schemas plus a pure protocol model. It checks local
confirmation binding, modeled consume-before-effect admission, lost replies,
bounded payload metadata and freshly confirmed recovery. No actual IPC, durable
store, UAC or installer exists. Run `npm run test:maintenance-protocol`; see
[the implemented contract and explicit limitations](docs/maintenance-protocol-contract.md).

`MAINTENANCE-MECHANISM-REVIEW1` records concrete helper/coordination/storage
candidates for further design and fixes journal-bound uninstalled-state recovery
in the pure model. The maintenance gate now has 53 synthetic cases plus exact-ID
completeness. Native lease, confirmation and durability blockers remain open;
this is not independent security acceptance. See
[the review and next pure persistence-model slice](docs/maintenance-mechanism-review.md).

`MAINTENANCE-PERSISTENCE-MODEL1` implements that development-only fault model:
separate journal/head write, flush and read-back hypotheses; lost replies;
conservative counters/generation/floor; fresh recovery and bounded compaction.
It has no real storage writer or durability proof. Run
`npm run test:maintenance-persistence`; see
[the model contract and deliberate limitations](docs/maintenance-persistence-model.md).

`MAINTENANCE-COMPOSITION-REVIEW1` compares the protocol and persistence models
at shared synthetic boundaries. It fixes local continuation after a lost reply
and pending-publication status after restart, with 24 paired cases plus exact-ID
completeness. It is author self-review, not independent acceptance or a runtime
bridge. Run `npm run test:maintenance-composition`; see
[the correspondence, differences and remaining obligations](docs/maintenance-composition-review.md).

`MAINTENANCE-STORE-CODEC1` adds a strict development-only byte codec for complete
synthetic storage snapshots. It checks framing, canonical JSON, checksums and
Known-state consistency without writing files or recovering an interrupted store.
Unknown state and conservative minima are preserved. Run
`npm run test:maintenance-store-codec`; see
[the snapshot format and non-authority boundaries](docs/maintenance-store-codec.md).

`MAINTENANCE-RECOVERY-POLICY1` specifies the versioned model's rules for
retiring unpublished candidates, reserving journal capacity and reconciling
interrupted checkpoints. The subsequent `MAINTENANCE-RECOVERY-MODEL2` implements
them in a separate v2 synthetic contract/model/codec, without changing v1 or
adding a host writer. RP-001..030 and exact-ID completeness now execute via
`npm run test:maintenance-recovery-v2`. No native trust gate is closed. See
[the model, recovery limits and next review](docs/maintenance-recovery-model-v2.md).

`MAINTENANCE-RECOVERY-FIX1` corrects four further review findings: epoch downgrade,
lost prefix minima, unsupported terminal generation gaps and expiry-boundary
disagreement. The same recovery test command now includes 13 additional tests;
schemas and original suites are unchanged. See [the fixes and regression
evidence](docs/maintenance-recovery-fixes.md). Independent acceptance remains pending.

`MAINTENANCE-RECOVERY-FIX2` addresses the separate review's nested-expiry bypass,
impossible terminal outcomes and unrelated-transaction status mismatch. Eleven
additional regressions join the same command (55 recovery tests total). See
[the corrections, recheck status and remaining gates](docs/maintenance-recovery-recheck.md).
The separate reviewer closed those three findings within the changed synthetic
boundaries. No production or native readiness is inferred.

`COMPOSED-BOUNDARY-CONTRACT1` adds a private test-only correspondence/denial gate
between deployment, maintenance protocol v1 and recovery v2. Thirty cases plus
exact-ID completeness recompute original scenarios and compare operation, full
tuples, counters, generations, sessions and time without converting model results
into authority. Run `npm run test:composed-boundary`. Native readiness still fails
with blockers; see [the scope, evidence and remaining work](docs/composed-boundary-contract.md).

`COMPOSED-RECOVERY-CONTRACT1` adds a separate private history checker for
finalization, permitted restoration and committed cleanup. It retains full
original scenarios, fresh per-attempt authorization and conservative historical
status; v2-only metadata operations remain explicitly unmapped. Run
`npm run test:composed-recovery` (26 tests). See [the contract and bounded review
disposition](docs/composed-recovery-contract.md). Production/native gates stay open.

The target product supports two explicit passes: StandardUser by default and
an optional Elevated read-only pass after informed user confirmation and the
reviewed Windows elevation flow. Administrative consent is scoped to exact
checks, not blanket permission for network, memory acquisition, reboot, or
remediation. The UI remains unprivileged; a narrow temporary helper owns only
the approved elevated work. Refusal/cancellation preserves partial results and
NotTested coverage, with no automatic elevation retry or fallback. This is a
future capability, not implemented elevation. The current Version/Help planner's
`elevation: Forbidden` applies only to those diagnostics, not the whole product.

## Historical trust-launch disposition

`TRUST-LAUNCH-DEFER-CHECKPOINT1` preserves the development-only trust-launch
prototype and its normalized contract as WIP evidence. It does not authorize
native-helper compilation, trust-launch probes, a production adapter, or any
Velociraptor invocation from SecApp. Automatic backend execution is disabled
fail closed, and the next product direction is an import-only workflow under a
separately authorized stage.

```text
TrustLaunchStatus = Deferred
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
VelociraptorInvocationFromSecApp = ForbiddenByDefault
NextProductPath = ImportOnly
```

The confirmed prototype observations and unresolved blockers are recorded in
[the trust-launch checkpoint](tests/compatibility/trust-launch/README.md).
The later, separately authorized `AUDIT-PACKAGE-IMPORT1` stage is implemented
without changing that policy at the time. The current development authorization
above supersedes the old deferral as a work restriction, not as a readiness result.

## Import-only core

`src/import/audit-package-importer.mjs` is the first bounded executable product
slice. It imports an explicitly selected local JSON object, JSONL stream, or a
restricted audit-package ZIP without filesystem extraction. The core performs
strict UTF-8/duplicate-key parsing, lowering-only resource limits, canonical
path and ZIP-profile checks, exact manifest membership, FileDigest and contract
digest verification, cross-object reference checks, normalization, and a
privacy-safe summary. Unsupported formats and invalid inputs produce controlled
results rather than escaping parser exceptions.

The implementation uses architecture Variant A: `src/import/` has no Ajv or
backend dependency. Full Draft 2020-12 validation is supplied through an
explicit reference-validation callback; absence of that gate fails closed.
The lockfile-pinned Ajv connection is shared by the development/reference CLI
and synthetic tests; it remains a development dependency.
See [the import contract and safety profile](tests/import/README.md) and run it
with `npm run test:import`.

Import verifies modification detection relative to the package manifest. It
does not prove package provenance, host truth, or producer honesty, and it
never invokes Velociraptor or another backend.

### Try a local import

With the existing development dependencies installed, run this synthetic example
from the repository root:

```text
npm run import -- --source tests/import/fixtures/error-object.json
```

For a single machine-readable JSON result, invoke Node directly:

```text
node tools/import-audit-package.mjs --source tests/import/fixtures/error-object.json --json
node tools/import-audit-package.mjs --help
```

The CLI accepts an explicitly selected local SecApp JSON/JSONL contract or
restricted manifest-based ZIP. Relative input paths are resolved against the
working directory. It uses the pinned offline Draft 2020-12 registry and emits
by default only a summary, with no imported field values, source path, archive extraction,
or report files. `Accepted` means the implemented import checks passed;
`assessment_status: NotPerformed` makes clear that no security assessment ran.
It does not accept arbitrary Velociraptor output or establish producer trust.

Exit codes are `0` for accepted input/help, `2` for rejected or unsupported
input, `64` for invalid arguments, and `1` for unavailable validation
infrastructure/internal failures. The CLI is a usable reference entry point,
not a packaged Windows release. UI, external producer/conversion support, full
application validation, private storage, and public-export work remain open.

### Assess an imported Windows protection snapshot

The opt-in reference profile evaluates six checks: Defender real-time
protection, the three Firewall profiles, BitLocker for the OS volume, and
Secure Boot. It accepts only the four explicitly versioned SecApp Observation
payloads described in [the profile contract](docs/windows-protection-import.md),
not arbitrary backend output. Try the entirely synthetic demo:

```text
node tools/import-audit-package.mjs --source tests/assessment/fixtures/windows-protection.jsonl --assess windows-protection-v1
node tools/import-audit-package.mjs --source tests/assessment/fixtures/windows-protection.jsonl --assess windows-protection-v1 --json
node tools/import-audit-package.mjs --source tests/assessment/fixtures/windows-protection.jsonl --assess windows-protection-v1 --html
```

Text, JSON, and standalone HTML are written to stdout only. The command does
not save reports, scan the computer, or launch a backend. Assessment output is
private `SensitiveSecurityData`, not a redacted/public export. Missing,
unsupported, or failed data produces `NotTested`; a reported expected state is
not a claim that the computer is safe. Provenance and freshness are not
established. The rules and severity policy are preliminary and await
independent review; this is not an accepted production audit. Run the synthetic
assessment and renderer suite with `npm run test:assessment`.

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

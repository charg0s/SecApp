# BACKEND-RELEASE-REVIEW1: diagnostic candidate triage

Current precedence: [D-058 / TRUSTED-HOST-MVP1](trusted-host-mvp.md) now permits
reviewed official asset acquisition and replaces a blanket no-system-change
policy with exact installation/working/logging effects. The static findings and
original no-download review record below remain unchanged. Event-source behavior
still needs an explicit effects disposition; this is not approval to execute the
candidate, alter existing registrations or elevate the backend for logging.

Subsequent [BACKEND-ACQUISITION-VERIFY1](backend-acquisition-verification.md)
resolved the compressed/extracted byte domains and verified detached-signature
cryptography using the pinned primary key. The original no-download source-review
record below is retained as history; candidate/runtime admission is still Blocked.

Date: 2026-11-06. Scope: read-only review of official release metadata and selected
source for [BACKEND-DIAGNOSTIC-CONTRACT1](backend-diagnostic-contract.md). The user
separately authorized these official-source reads, not downloading EXE/archive
payloads, signatures or keys, running programs, installing a service or changing
Windows. No asset was downloaded, unpacked, verified or executed in this review.

```text
ResearchCandidate = v0.77.3
SourceRevision = 7d287b0b988b35657e1b401f7b2ffebaf60dbcae
ReviewScope = PartialStaticDiagnosticStartup
RuntimeReleaseSelection = PendingCurrentReview
CandidateAdmission = Blocked
RuntimeBinaryVerification = NotPerformed
OutputProfiles = NotEstablished
ProductionLauncher = NotImplemented
```

## 1. Official metadata, not a verified runtime pin

The [official download page](https://docs.velociraptor.app/downloads/) identifies
0.77.3 as current. The [release](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.3)
is published, not a draft/prerelease; its API publication timestamp is
`2026-10-05T01:00:38Z`. The
[tag ref](https://api.github.com/repos/Velocidex/velociraptor/git/ref/tags/v0.77.3)
directly identifies commit `7d287b0b988b35657e1b401f7b2ffebaf60dbcae`.
This identifies a research candidate, not a product support/security decision.
The existing v0.77.1 planner/schema/compatibility pin is unchanged and historical.

The [release asset metadata](https://api.github.com/repos/Velocidex/velociraptor/releases/tags/v0.77.3)
reports `velociraptor-v0.77.3-windows-amd64.exe.gz`, 28,350,845 bytes,
SHA-256 `0b9cd957e5605da74994a6c29934da9af0e3af9c9b808f2274c826fba32dc3ae`.
That is metadata for the **compressed asset**, not a measured EXE digest.
The downloads table displays a different hash,
`3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32`;
this pass has not established its byte domain. Do not describe the two values
as a confirmed tamper event or silently pick one as the executable's pin.
Container, extracted PE and detached-signature coverage must be resolved and
independently verified before future acceptance. No signature/key payload was read.

## 2. Concrete startup findings

All source links below are pinned to the tag's exact commit. These are static
code observations and SecApp consequences, not host measurements or a complete
transitive initialization audit.

### Startup logging precedes diagnostic dispatch

[`bin/main.go`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/main.go)
calls `logArgv` before `app.Parse` and before command dispatch. Its error path
prints a message to stdout. Therefore fixed Version/Help arguments do not bypass
that call, and an event-log failure can also invalidate the strict output shape.

The Windows implementation in
[`bin/admin_windows.go`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/admin_windows.go)
calls `eventlog.InstallAsEventCreate` for the Velociraptor source; on error it
switches to `.NET Runtime`, opens the source and attempts an event containing
the invocation arguments, including argv[0]. No diagnostic-specific skip guard
is present in that function. This is an event-source installation attempt plus
logging, not a demonstrated mutation-free diagnostic path. This review does not
claim that a registry write succeeded on any host, or that Standard rights
guarantee its denial in every accepted launch context.

**Admission consequence:** the unmodified candidate cannot yet be accepted under
the no-system-configuration-change boundary. Before any execution, account for
this attempted installation and log data in the exact effects/privacy contract
and prove preventive denial of disallowed writes in the selected boundary, or
obtain a separately reviewed compatible upstream behavior/product decision.
Do not grant elevation, pre-create/repair an event source, weaken ACLs, suppress
errors with a patch, or accept a shim as an implicit workaround. Incidental OS
logging is distinct from configuration changes, but it is not zero side effects.

### Fixed arguments avoid run/autoexec selection, not all initialization

[`bin/transforms.go`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/transforms.go)
enters artifact run mode on `-r`/`--run`; neither diagnostic array includes them.
In main, nonempty pre-separator arguments skip the explicit empty-argv autoexec
branch. This supports rejecting caller-controlled arguments; it does not prove
that imported-package initialization has no filesystem/network/process effects.
Main imports the VQL plugin package before command dispatch. The full selected
build's initialization/dependency graph still needs review.

### Output depends on more than the command name

[`bin/version.go`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/version.go)
serializes `config.GetVersion()` with YAML and writes it to stdout; verbose mode
adds Go build information. This supports the fixed non-verbose template but
does not establish the official Windows asset's actual values or byte profile.

[`bin/flags.go`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/flags.go)
uses the `DEBUG` environment variable to determine whether generated config
flags are hidden. Consequently the future allowlist must not inherit `DEBUG`,
and Help cannot be matched independently of the reviewed environment.
[`bin/banner.go`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/banner.go)
returns early for `--nobanner`; this does not disable the earlier `logArgv` call.

[`bin/prompt.go`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/bin/prompt.go)
can print a prompt and read stdin when its flag is set or Explorer-parent
detection succeeds. The chosen supervisor topology, closed stdin, watchdog and
strict output rejection still need validation; lack of `--prompt` alone is not
the complete no-prompt predicate. Kingpin's help/termination behavior and the
Go/YAML/build metadata dependencies have not been transitively accepted here.

### Windows resources still need asset-level review

The source
[`winres.json`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/docs/winres/winres.json)
and [template](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/docs/winres/winres_template.json)
request execution level `highest`. The former still contains 0.77.1 resource
version values. Neither source file proves the actual released PE manifest,
build stamping or effective token behavior. Do not infer a new asset's manifest
from a template or carry forward RunAsInvoker as a production solution.
No compiled `.syso` resource was downloaded or inspected.

## 3. Disposition and next evidence

This is useful negative/limiting evidence: even Version/Help need startup-effect
review, and the current candidate has an unconditional Windows event-source
installation call before dispatch. It is not evidence of infection, a defect
introduced by SecApp, or permission to modify this computer.

Before selecting this release for runtime:

1. Complete the diagnostic startup/dependency and supported-platform review,
   including the event-source call's exact transitive effects, failure paths,
   no-prompt behavior, offline and write confinement. Review current security
   advisories for the actual Windows build; release recency is not that review.
2. Resolve compressed-versus-extracted identity and signature scope; review the
   acquisition/trust policy, then obtain separate permission before any asset,
   signature or key retrieval. Reading metadata alone cannot complete verification.
3. Establish the applicable immutable output profile without expanding runtime
   permission. Expected data may come from reviewed source/build evidence; any
   binary-backed experiment needs its own accepted boundary and authorization.
4. Resolve the existing service/token/image/loader/storage/ownership gates and
   independently review the composed implementation before real execution.

All TL/LS/MMR gates remain unresolved as previously recorded. No additional
general-purpose synthetic authority model, runtime code or schema is added.
The documentary diagnostic contract can be accepted while this candidate remains
blocked. This partial source review is not full release acceptance.

Independent review: AcceptedPartialSourceTriageRecordOnly on 2026-11-06. The
read-only reviewer independently checked the official metadata and cited source,
plus the README/roadmap/D-057 links, with no blocking findings for this record.
This does not accept a release, binary, output profile, native boundary or runtime.

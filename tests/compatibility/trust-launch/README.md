# Velociraptor trust-launch reference prototype

Status: WIP development-only Windows compatibility/security checkpoint;
trust-launch is deferred and automatic backend execution is disabled.

This directory contains only deterministic, privacy-safe source fixtures and
the expected contract for `VELOCIRAPTOR-ADAPTER-TRUST-LAUNCH1`. It does not
implement or authorize a production adapter, a SecApp runtime, elevation, a
collector expansion, or deployment.

The product disposition is normative:

```text
TrustLaunchStatus = Deferred
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
VelociraptorInvocationFromSecApp = ForbiddenByDefault
NextProductPath = ImportOnly
```

The retained expected diagnostic result is
`trust_launch_partial_blockers_remain`. It describes the historical prototype
contract, not authorization to satisfy it by launching Velociraptor.

## Checkpoint observations

The following results were confirmed before this documentation-only checkpoint
and were not rerun during it:

- compile-only passed;
- the private execution root and file locking were partially implemented;
- the environment allowlist passed;
- `TL-JOB-001` through `TL-JOB-010` passed;
- the parent/child process tree terminated without known orphan processes;
- timeout and cancellation cleanup passed;
- Velociraptor was not launched through the trust-launch prototype.

Open blockers are:

1. Adjacent marker `probe.dll` can be created in the execution directory.
2. The restricted child retains linked-token metadata.
3. No acceptable production non-elevated launch mechanism has been selected.
4. Reparse replacement protection is not proven.
5. Initial module inventory is not performed before resume.
6. Runtime module observation is not a preventive loader policy.
7. Four runtime modules remain categorized as `Unknown`.
8. Verified source bytes are not proven to be the mapped process image.
9. A production-safe DLL/image-load context is not implemented.

The prototype is offline. It uses only the already verified cached
Velociraptor v0.77.1 Windows AMD64 binary and a compiler already installed on
the machine. It must not download or restore packages, use administrative
rights, display or accept a UAC prompt, modify the registry or system settings,
or persist a compatibility shim.

## Tracked and external material

Tracked files contain source, stable case identifiers, normalized statuses,
generic path classes, and pinned public binary identity. They must not contain
compiled EXE/DLL/PDB files, raw stdout/stderr, PIDs, account or token identity,
absolute local paths, module paths, environment values, or machine evidence.

Every real run and compilation must use a cryptographically random,
create-new directory outside the repository, normally below:

```text
%LOCALAPPDATA%\SecApp\compat\trust-launch\<random-run-id>\
```

The cached binary remains a read-only source input. The runner copies verified
bytes into a private execution root, uses a different empty private current
directory, and retains raw bounded output only below that external run root.
The repository is never an execution directory or child current directory.

## Contract validation

The static fixture validator does not compile or execute Velociraptor:

```text
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File tools/compatibility/trust-launch/Test-TrustLaunchContract.ps1 \
  -ContractPath tests/compatibility/trust-launch/expected/trust-launch-contract.json
```

It verifies the exact unique mandatory and false-positive case-ID sets, the
pinned backend identity, the threat-model boundary, the three accepted module
path classes, the permitted Velociraptor commands, privacy fields, and the
expected non-ready decision. Count-only coverage is not sufficient.

This validator and the binary-backed prototype are deliberately not part of
`npm.cmd test` or `npm.cmd run validate:all`.

## Retained offline prototype (execution deferred)

The wrapper and helper sources are preserved for the WIP checkpoint. They must
not be compiled or run under this disposition unless a later, separate stage
explicitly authorizes the exact action. In particular, SecApp must not invoke
the wrapper or Velociraptor automatically.

The historical prototype entry point used the repository wrapper rather than
invoking a compiled helper directly:

```text
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File tools/compatibility/trust-launch/Invoke-TrustLaunchPrototype.ps1
```

The v0.77.1 cache path and expected SHA-256 are fixed inside the wrapper and
cannot be overridden. Run the static contract validator above as a separate
prerequisite gate. The wrapper discovers a local compiler without package
restore, compiles helpers only under an external private build root, invokes
the bounded probe, and removes compiled and raw material in `finally` cleanup.

Before each permitted Velociraptor launch the source cache file is opened and
its SHA-256 is recomputed against the pinned value. A launch is attempted only
after the identity, root, lock, token, Job, loader, handle, environment, and
bounded-output prerequisites for that launch have passed. Fail-closed
`NotTested` results after a blocker are correct prototype behavior.

The historical prototype contract limited workloads to `version`, `help`, and
the fully synthetic `SecApp.Compatibility.Synthetic` artifact. That allowlist
is retained as WIP metadata and is not current permission to launch any of
them. The runner must not use built-in machine collectors or a positive
`--hard_memory_limit` value.

## Exit meanings

- Exit `0`: the accepted trust-launch contract was satisfied. This is still
  only review evidence and not production authorization.
- Exit `2`: the diagnostic suite completed and detected documented blockers;
  the readiness gate remains red. This is the expected result for this stage.
- Exit `1`: the harness, compiler, fixture validation, or cleanup failed in a
  way that prevents a trustworthy prototype result.

A diagnostic suite can correctly exercise all reachable checks while the
production-readiness gate remains red. `Pass` means one named invariant held;
`Blocked` records a controlled fail-closed stop; `NotTested` never means safe.
The expected fixture describes the requirements, while an actual result may
remain `Fail`, `Blocked`, or `NotTested` and therefore cannot satisfy readiness.

## Cleanup

On normal exit, blocker exit, cancellation, timeout, and exception, the wrapper
must close process, thread, token, Job, file, directory, and pipe handles;
terminate the synthetic process tree; confirm no probe or Velociraptor process
remains; remove compiled EXE/DLL/PDB files and raw outputs; and delete the
scoped external run root. It must not alter the verified cache, ACLs outside
the scoped root, PATH, user/system environment, registry, services, tasks, or
Windows settings.

The expected contract intentionally keeps
`readiness.production_adapter_ready` and
`readiness.mandatory_cases_complete` false. Trust-launch review and production
launcher work are deferred. The next product direction is the separately
authorized import-only workflow; `AUDIT-PACKAGE-IMPORT1` is not started by this
checkpoint.

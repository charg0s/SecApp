# NATIVE-BOUNDARY-EXPERIMENT1

Date: 2026-09-30. Development-only, explicitly authorized synthetic native
experiment on the available primary computer. **Not a production acceptance.**
The unchanged historical SN suite was not rerun; only its shared C# types and
asInvoker manifest were compiled with a separate, fixed entrypoint.

The final source completed all seven observation cases in three consecutive
runs. [The normalized record](normalized-result.json) contains only fixed
vocabulary, source digests and booleans. No paths, PIDs, account/host identifiers,
raw output, compiler logs, dumps, runtime binaries or machine audit evidence
are retained. These are synthetic observations, not authenticated attestation.

```text
NativeObservations = CompleteWithinScope
ProductionReadiness = fail_with_blockers
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
VelociraptorExecuted = false
```

## Observations and limits

| Case | Observed result | Not established |
|---|---|---|
| NB-001 | Suspended self-child's reported image name and reopened-file hash agree with held source; attempted write-open denied | Verified bytes are the mapped image; source-lock causality; replacement/reparse resistance |
| NB-002 | Native LoadLibraryEx maps our inert unsigned managed PE DLL; returned module name matches | Managed payload execution or native DllMain sentinel coverage |
| NB-003 | Queried PreferSystem32 flag does not block explicit absolute loading of that local DLL | Safe implicit search order or preventive complete allowlist |
| NB-004 | Queried MicrosoftSignedOnly policy blocks the same fixture with error 577 | Creation-time/startup protection, arbitrary publisher/hash policy or compatibility with Velociraptor |
| NB-005 | A same-user synthetic sibling obtains CREATE_THREAD, VM_OPERATION, VM_WRITE and DUP_HANDLE rights on its still-live owned sibling | Injection success or an independent process security boundary |
| NB-006 | Real anonymous-pipe round trips deliver valid, wrong-challenge and duplicate replies; parent accepts only first valid match | Peer authenticity, secrecy, durable replay prevention or production IPC |
| NB-007 | Explicit abrupt supervisor termination (exit 23, no finally) is followed by retained leaf handle signaling, zero outer Job members and closed pipes | Atomic ordering with a maintenance lease/gate, comprehensive crash matrix |

NB-005 acquires and closes access handles only: no foreign process enumeration,
memory read/write, thread injection or handle duplication is performed. Targets
are supplied through the parent's private test pipe, checked against creation
time and the exact self-image name, and retained alive by the parent. This is
lab scoping, not a same-user-resistant authenticated targeting protocol.

The DLL is locally compiled C# with a constant only, no initializer or exports.
No native payload sentinel is executed. Each policy applies only to its dedicated
worker **after CLR startup**, not to Windows or the supervisor. No supported
Windows/collector matrix or early-loader proof is claimed. An alternative known
mapping/access outcome is representable without converting it into readiness.

Image name/hash agreement is deliberately labeled weaker than mapped-byte proof.
A write-open denial can also result from ordinary image mapping; the experiment
does not attribute it solely to the retained source handle. The four historical
Unknown modules and initial inventory were not examined.

## Safety and reproduction boundary

Only an already installed x64 .NET Framework compiler is used, without restore
or dependencies. Each created worker is suspended, assigned an unnamed
non-inherited kill-on-close Job at creation, checked for effective standard
rights using the historical predicate, then resumed. Jobs have a four-process
ceiling and no breakaway. Only three explicit standard-pipe handles are inherited.
Children receive SystemRoot/WINDIR and build-local TEMP/TMP only. The temporary
root uses default permissions; it is not a protected installation or sandbox.

Pipes retain at most 4 KiB; request frames at most 256 bytes. Frame/finish waits
are at most five seconds, cleanup three seconds, worker self-watchdog twenty
seconds, compiler twenty seconds per invocation and outer suite fifty-five
seconds. Abrupt exit uses TerminateProcess on the test supervisor itself, not
FailFast or an injected unhandled fault. This requests no crash dump. Cleanup
addresses only owned Jobs/processes and the exact unique temporary build root.
All three final runs confirmed temporary EXE/DLL removal.

No Velociraptor, old TrustLaunchProbe matrix, elevation, ACL/registry/PATH/service/
task change, reparse experiment, installer, memory scan or machine collector was
used. No network was used by the experiment; research was Microsoft Learn only.
This is not proof of OS-level network confinement or absence of incidental OS
logging. Binaries remain outside Git and no native run joins npm test or CI.

With a fresh explicit native-test authorization:

```text
node tools/backend/native-boundary/run-native-boundary.mjs --run-synthetic-only
```

The ordinary pure validation command never compiles or starts a native process:

```text
npm run test:native-boundary-result
```

## Disposition

The observed default same-user access and explicit DLL loading preclude treating
this ordinary writable-root/default-process-descriptor candidate as the required
security boundary. The signature experiment is useful narrow evidence, not a
complete replacement policy. All nine TL and all MMR blockers remain Open.
Protected installation/ACL changes remain unauthorized; no planner flag changes.
The next decision must address process/bootstrap isolation and a compatible
preventive loading policy; another successful Version/Help cannot establish them.
No independent native acceptance is claimed by this author-run experiment.

API references: [process rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights),
[process-local mitigation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy),
[image-load policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_image_load_policy),
[signature policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_binary_signature_policy).

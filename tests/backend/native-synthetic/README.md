# BACKEND-NATIVE-SYNTHETIC1

Status: development-only experiment completed; production launcher still
NotImplemented. No Velociraptor binary was located or invoked. The old
TrustLaunchProbe source, wrapper and matrix were not used or changed.

The user separately authorized compiling and running this narrow synthetic
helper. This is not authorization for real backend execution, machine data
collection, UAC, DLL/module/reparse probes, installation, or system changes.

## Scope and result

The final native source passed all ten cases in three consecutive local runs.
The normalized record is [normalized-result.json](normalized-result.json).
Only fixed-vocabulary outcomes, booleans, synthetic exit codes and source/manifest
digests are retained. No PIDs, user/host names, paths, token dumps, raw child
stdout/stderr, compiler output, binaries, or real audit data are recorded.
Source digests bind the record to reviewed source files, not to a trusted
compiler, protected attestation, authenticated runtime binary, or mapped image.

| Case | Required outcome |
|---|---|
| SN-001 | Current-token control emits exact fixed stdout/stderr and exits zero |
| SN-002 | Restricted-token child emits the same fixed output and exits zero |
| SN-003 | Restricted parent/leaf tree times out and is fully reaped |
| SN-004 | In-process cancellation token stops a confirmed parent/leaf tree |
| SN-005 | Stdout overflow stops the child; retained stdout stays at most 4 KiB |
| SN-006 | Stderr overflow stops the child; retained stderr stays at most 4 KiB |
| SN-007 | Exit 17 is preserved as NonZeroExit, never Completed |
| SN-008 | Root exits while a synthetic leaf holds pipes; supervisor stops/reaps it |
| SN-009 | Already-cancelled request creates no child |
| SN-010 | Injected post-create/pre-resume error terminates the suspended child |

For all nine cases that create a process, success requires effective standard
rights checked before resume, root termination, zero active Job members,
closed output pipes, and bounded buffers. SN-010 must never resume. SN-009's
false lifecycle fields mean no process/Job was created, not failed cleanup.
Null exit_code means no natural root exit code was observed; it is not zero.
A Pass for a timeout/nonzero/fault case means the expected failure was handled,
not that an audit operation succeeded.

Tree evidence requires both fixed parent and leaf handshakes plus Job accounting;
a count of two alone is not evidence that the intended synthetic leaf ran.
An early version's count-only flag was rejected by the independent result
checker and replaced with this handshake requirement before recording success.

Observed child policy: TokenIsElevated false, integrity at most Medium,
Administrators group not enabled, and no enabled privilege from the explicit
dangerous-privilege list. Linked-token metadata remained Present, including in
restricted children. The linked handle is closed without being used. This
proves neither absence of a linked token nor a complete privilege sandbox.
The historical no-linked-token blocker stays open. The observed configuration
is not a demonstrated genuinely non-admin account matrix or elevated-parent
test; no elevation was requested to create either test condition.

## Implementation boundaries

`tools/backend/native-synthetic/SyntheticLaunchHarness.cs` is a separate,
self-launch-only C# experiment, not a runtime adapter. Child mode names and
arguments are literals. There is no arbitrary executable/VQL/config/argument
interface. A fixed asInvoker manifest supplies no elevation request; an unsafe
effective parent token is rejected. There is no RunAsInvoker shim or fallback.

The experimental restricted path uses CreateRestrictedToken with
DISABLE_MAX_PRIVILEGE and six administrative-family deny-only groups, followed
by CreateProcessAsUserW. SN-001 deliberately uses CreateProcessW as a control,
never as a fallback from restricted launch. This local success does not select
or approve a production non-elevated mechanism.

Children are created suspended with an explicit inherited-pipe handle list and
atomic Job assignment. The unnamed non-inherited Job uses kill-on-close and a
four-process ceiling, without breakaway. Unsupported creation attributes or
policy/query failures fail closed. The inherited environment is replaced with
only SystemRoot, WINDIR, TEMP and TMP. This is construction of a lab environment,
not a new comprehensive environment-attack test.

Each pipe retains at most 4096 bytes. Nonblocking bounded pipe draining prevents
an output flood from starving timeout/cancellation handling. Each running case
has a four-second watchdog; the timeout-tree case expires 300 ms after the parent
handshake. Cleanup has a separate three-second bound. The leaf independently
exits after 15 seconds if it somehow outlives its supervisor. Cancellation is
in-process synthetic CancellationTokenSource signaling, not a tested IPC/UI
cancel protocol. Active-process limits are configured, not stress-tested here;
CPU/memory/network confinement and supervisor-crash injection are not covered.

The runner builds with the already installed Windows x64 .NET Framework compiler,
with no dependency restore/download, and runs only this EXE. Compiler and suite
have 20/45-second outer deadlines and 64 KiB stream caps. Only the precise random
temporary build directory is removed. Compiled output stays outside the repository;
the recorded runs confirmed its removal. The temporary directory is not claimed
to resist a concurrent same-user attacker; no ACL was modified. No production
private storage, source locking, reparse protection, image-byte binding, initial
module inventory or preventive DLL/image-load policy is implemented here.

## Reproduction (requires explicit native-test authorization)

```text
node tools/backend/native-synthetic/run-synthetic-launch.mjs --run-synthetic-only
```

It must run unelevated on Windows x64 with the existing Framework64 compiler.
Do not install a compiler or retry with elevation when prerequisites fail.
No native experiment is added to npm test or automatic CI.

```text
npm run test:backend-native-result
```

This second command only validates the checked-in normalized record, exact case
IDs, source hashes, and targeted invalid records. It never compiles or runs the
helper. The 28 pure tests are part of npm test. A stored record passing again
is not a new native run or independent security review.

## Remaining gates

All nine historical trust-launch blockers remain open in the planner. Next is
review of the production EXE/root/DLL/reparse/image-binding trust design and the
standard-user launch mechanism, including distinct account/elevation cases.
Only after applicable gates and independent review may a separately authorized
real Version/Help handshake be considered. Optional elevated collection remains
a future separately consented path, not a fallback from these tests.

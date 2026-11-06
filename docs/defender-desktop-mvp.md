# Minimal Defender desktop and shared report (D-068 / D-069)

## Scope

The user authorized a minimal interface and one report around the already working
Defender control check. UAC remains a personal user confirmation. No audited system
setting, existing ACL, protection policy, service, task, dependency or backend pin
is changed. No additional collector, network listener or download is introduced.
The D-068 implementation pass did not perform live collection or helper builds;
the subsequent operator-driven acceptance is recorded separately below as D-069.

Run `npm.cmd start` from an ordinary Windows terminal in the checkout. `--help`
has no window or collection effects. All other arguments are rejected. The window
uses installed Windows PowerShell 5.1/Windows Forms, no browser or UI framework
dependency. Its PowerShell file uses UTF-8 with BOM and LF so `-File` decodes Russian
correctly without an ExecutionPolicy override. An elevated window is rejected.

## Workflow and authority

1. Opening the window shows scope only; no workspace/compiler/backend execution.
2. Preparation is a separate button. It uses the unchanged, pinned controller,
   helper, manifest and private-workspace implementation from D-066/D-067.
3. After preparation the exact fields, helper digest, working directory, startup
   logging, time/resource bounds and data handling are displayed. A typed one-use
   phrase is bound to the immutable prepared run. It expires after 120 seconds.
4. Only the matching phrase can call the existing run path. The user then handles
   UAC personally. The ordinary window and Node owner are not elevated.
5. The same strict result/lifecycle decoder feeds the CLI and window report.
   Errors do not become safe findings; incomplete data remains NotTested.
6. Saving HTML requires a separate click and file dialog. Only a new `.html` file
   on a fixed/removable local drive is accepted; UNC/mapped network drives are not
   supported. No overwrite or automatic opening is performed. No raw result,
   hostname, username, run ID or workspace path is exported. The report is private,
   unencrypted, inherits destination permissions and is not an AuditRun package.
   No guarantee against reparse redirection on a hostile host is claimed.

Before prepare/confirm the window reads the exact existing Velociraptor EventLog
source's three values. Missing/different values block that click; no registration,
repair or policy change is attempted by the window. Ordinary backend startup logging
remains as disclosed under D-063. This is a trusted-host prerequisite check, not
protection against a concurrent privileged actor changing the source afterwards.

The UI sends only bounded ready/prepare/confirm/cancel messages over its inherited
private pipes. Commands are state-bound: double clicks/replayed input do not queue
a second run. There is no arbitrary operation, path, query or automatic confirmation.
One window supports at most one preparation/run; restart manually for a new check.

Cancellation before run discards only that prepared run. Closing while awaiting
confirmation requests the same discard. Closing during preparation/run/discard is
deferred in the UI. If the window disappears, the owner finishes preparation and
discards if unstarted, or waits for the already consented bounded run/cleanup.
It never infers helper exit from killing a controller and never retries collection.
There is no new in-flight cancellation/kill-tree control in this UI slice.
Uncertain lifetime/cleanup stays a visible follow-up, not a cleanup success claim.

## Report meaning

The result tab, CLI text and standalone HTML derive from one immutable normalized
presentation model. Severity, confidence and finding status remain separate.
The existing rule treats passive/unsupported Defender mode as NotTested, not as a
confirmed fault or safe state. Firewall, BitLocker, Secure Boot and other areas
remain untested. No claim of cryptographic provenance, full audit or absence of
malware is added. Working-Windows trust remains a prerequisite.

The file-output preview/import tools are not relabelled as live collection. The new
report renderer accepts only an internal decoded reading, not caller-crafted JSON.
HTML has no script, external assets, links or form actions and escapes rendered text.

## Automated verification

`npm test` includes the synthetic desktop/session/report tests. They cover no effects
on opening, exact confirmation, replay, cancel/expiry, disconnect before/after run,
failed output, cleanup warnings, unknown/passive states, shared CLI output, bounded
framing, malformed commands, safe report rendering and help/argument rejection.
They never invoke PowerShell, a compiler, UAC or Velociraptor.

`tests/backend/Test-DefenderWindowLayout.ps1` separately parses the view and constructs
only its controls without showing a window, reading registry/identity or running
the controller. This checks Windows PowerShell 5.1 syntax and basic layout/control
properties; it is not a visual test or live UI protocol test.

The checkpoint gate passed all 689 Node tests (including 33 desktop tests), all npm
validators, the separate Windows PowerShell 5.1 layout/view-state test and source-pin
verification. These tests do not substitute for the operator evidence below.

## D-069: narrow manual acceptance (2026-11-06)

The user requested manual acceptance, operated the preparation/confirmation controls
and personally handled UAC. No automated confirmation, background collection or
new permission to change audited settings was introduced.

| Case | Recorded outcome | Evidence and boundary |
|---|---|---|
| Window opening | Passed after startup correction | The first window did not appear. The UI host's `windowsHide` flag was changed to `false`; the operator then confirmed opening. The backend controller's hidden-process settings were not changed. |
| Cancel before collection | Passed, operator-reported | The operator supplied the preparation/discard messages. They reported no backend execution and deletion of prepared data, retaining the private directory/empty lock. This was not an independent filesystem audit. |
| Confirmed live check and report | Passed, operator-reported | The operator supplied a useful completed two-field report with the cleanup notice. The first completed GUI owner's exit code 0 was also observed after the window closed. No broader security finding is inferred. |
| Explicit HTML save | Passed, file inspected | A later operator-requested session produced a saved report outside the repository. Read-only inspection confirmed valid UTF-8, the expected result/limitations, and no scripts, forms or external resources. Browser rendering was not independently observed. |

The operator closed the first completed window before saving. Reopening did not
recover that in-memory result; a fresh manually confirmed session was needed to
exercise HTML save. No silent restore or automatic repeated collection is claimed.
The actual report, security values, raw messages, per-run identifiers, runtime
paths/digests and screenshots are not copied into Git. Only normalized outcomes
are recorded here. The report remains private at the operator's chosen location.

This accepts the narrow user path: open -> prepare -> explicit confirmation/UAC ->
useful report -> explicit save, plus cancellation before collection. It is not full
production qualification, independent attestation, or assurance about a compromised
host. The existing source/lifecycle gates remain in place; reported cleanup is not
promoted to an additional independent GUI-run filesystem/ACL check.

Remaining unqualified cases include resize/DPI and keyboard/tab coverage, native
failure/timeout/disconnect and UAC refusal, save-dialog cancellation, existing-file
rejection, and browser/print rendering. Synthetic coverage is kept distinct from
these real acceptance cases. No real data, screenshots of actual results or native
binaries belong in Git. The documentation/checkpoint step performs no new collection.

Development prerequisites (`C:\Windows`, `C:\Dev`, local pinned backend, Node.js,
installed .NET compiler) remain. USB portability and bootable offline collection
are not implemented by this UI. Running files from USB inside the same Windows
would not independently establish the truth of WMI answers.

# LAUNCH-CONFIRMATION-DESIGN1

Current scope note (D-058, 2026-11-06):
[TRUSTED-HOST-MVP1](trusted-host-mvp.md) defines the current broader trusted-host
scope, permission envelope and TL/LS/MMR applicability. Preserve D-056's ordinary
exact Standard intent protocol and disjoint consent safeguards. This document
remains the stronger confirmation design and its NotAccepted research record;
its protected CC/private desktop is not an MVP prerequisite. Historical results,
schemas and runtime flags are unchanged, not promoted to acceptance.

Date: 2026-10-11. Scope: design of exact displayed scope, confirmation delivery
and one-use launch admission for the D-052 service candidate. No installation,
Windows setting change, native/API probe, key enrollment or backend execution.
This is an author proposal, not independent security acceptance.
Windows mechanism triage and the bounded bootstrap review were added on
2026-11-06 in sections 6.1-6.4. The result is NotAccepted for implementation;
no execution or host-change authorization was expanded.

```text
ConfirmationProtocol = DraftForReview
DisplayInputProtection = NotSelected
ConfirmationComponent = NotImplemented
NativeApproval = Disabled
LaunchPermit = BrokerInternalSingleUse
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
```

This refines [SERVICE-LAUNCH-BROKER-DESIGN1](service-launch-broker-design.md),
especially LS-003. All TL/MMR gates remain Open. A complete message design is
not proof that a Windows dialog or its input is protected from same-user malware.

## 1. Three roles, not an approval flag in the ordinary UI

| Role | May do | Must not do |
|---|---|---|
| Ordinary SecApp UI | Request a registered operation; show non-authoritative preview/status; cancel its own action | Provide authoritative consent, display text, a trusted key, executable/arguments, or a ready/user-present flag |
| Confirmation component (CC) | Obtain one frozen offer directly from the broker; independently validate and display it; report an exact local decision over its own authenticated channel | Execute the backend, perform maintenance, collect credentials, accept approval from the ordinary UI or delegate its confirmation role |
| Launch broker | Derive the operation and scope from protected policy; authenticate CC; validate the decision and atomically consume its own admission record | Accept a portable UI-supplied permit, infer consent from startup/Hello success, or reuse approval for another action |

CC is a proposed separate, per-action process in the requester's session, from
protected installed code with fixed resources. It is not a mode switch in the
ordinary UI, webview, renderer plugin or elevated service window. This separation
reduces the intended trusted code surface; it does not establish process/input
isolation. Native bootstrap, token, image, owner/handle and desktop guarantees
must be accepted before this role can produce authority.

Services cannot directly interact with the user on modern Windows; Microsoft
describes a separate user-session application with IPC. That is a topology,
not proof of exact human consent. SecApp does not adopt the documentation's
autostart registry example or interactive-service approach.
[Service/UI separation](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services).

The first slice handles **one action and one backend invocation per offer**.
There is no wildcard approval for a whole future profile, queue, session or day.
Check items within that action must belong to its one registered operation and
definition. Distinct CollectorExecutions require distinct action authorities;
future batch presentation must not merge those authorities and is not designed
here. This does not register any new collector or imply its read-only safety.

## 2. Freeze the operation before displaying it

The ordinary UI supplies only a registered operation selection and permitted
lowering-only limits. The broker independently resolves the exact definition,
transitive capabilities, parameters, data classes and current deployment policy.
No arbitrary VQL, argument, description, path or remote endpoint crosses this
boundary. Current Version/Help stay diagnostic operations, not collector receipts.
The later protection profile is still conditional on collector review.

After binding the requester and CC, the broker freezes a strict private offer
before any authoritative presentation, with these binding groups:

| Binding group | Required contents |
|---|---|
| Domain and instance | Separate Standard-launch domain/version; host/deployment binding; broker instance; offer ID; fresh 256-bit CSPRNG nonce; fixed monotonic expiry |
| Requester and approver | OS-observed user/logon/session and retained requester process instance; separately observed CC instance; approver must match the requester for this Standard slice |
| Exact action | Run/action IDs; registered operation; for collection, concrete pass/execution/collector IDs and definition/profile digests; explicit diagnostic versus collection variant |
| Executed material | Current authenticated backend identity/digest, command-template and exact parameter bindings, supervisor/build/policy identities; never merely the historical compatibility pin |
| Effects and data | Complete reviewed check-item list, targets and purpose, transitive capabilities, privacy classes, Standard privilege, offline requirement, owned-output/storage/retention policy and coverage limits |
| Bounds | Time, stdout/stderr, other operation-specific resource limits, cancellation behavior; no client expansion |
| Presentation | Reviewed display-template/resource/locale versions and digests; consent text version; exact human-readable scope model |

Fields that belong to another variant are rejected, not ignored or filled with
dummy IDs. A missing required binding, unknown capability, unreviewed data class
or unsupported registry item blocks an offer with an actionable explanation.
No sensitive host data is collected just to prepare a consent screen.

OfferDigest is proposed as SHA-256 LowerHex over a fixed UTF-8 domain prefix
`SecApp.StandardLaunch.Offer.v1` plus LF, followed by RFC 8785 JCS of the complete
offer payload (the digest is an outer field, not inside that payload). Use the
existing strict [canonicalization rules](integrity-model.md). Reject duplicate
keys/IDs, non-I-JSON and unsupported versions before hashing. Preserve the
broker's declared check display/execution order; canonical set-valued ID lists
use unique ascending bytewise UTF-8 order. Do not sort by localized names.

The digest binds data; it does not authenticate the broker, CC or human. A
successful digest comparison cannot change an untrusted endpoint into CC.
The entire offer, including display resources and exact limits, stays frozen.
Any change invalidates it and needs a fresh offer and full confirmation, even
if the new scope appears narrower. No substitutions after the user presses Yes.

## 3. What the person must see

CC obtains the offer directly from the independently authenticated broker,
revalidates the protected registry/resources and derives the screen itself.
It never renders caller HTML, Markdown, arbitrary labels or backend output.

The main confirmation screen must expose, without an expandable advanced panel:

- every reviewed check item by specific name and purpose, with the source/target
  class and data categories read; not merely a label such as "quick scan";
- the requesting context and target computer in a privacy-preserving but
  unambiguous form, Standard rights and the fact that no elevation is requested;
- whether only reads of audited resources are allowed, and the separate
  SecApp-owned result/temp writes and retention behavior; never claim "no writes
  anywhere" just because Windows settings will not be changed;
- network/upload, remediation, service/configuration changes, reboot and other
  sensitive capabilities as explicitly excluded for this slice;
- the authenticated backend version/publisher context, workload/output limits,
  expected access/coverage limitations and the effect of Cancel;
- a clear choice to confirm exactly this action once or cancel, with no saved
  approval, default-Yes, automatic countdown acceptance or automatic retry.

Technical details may show full digests, stable IDs and definition versions,
but are not a substitute for readable scope. Displaying Defender, Firewall,
BitLocker or Secure Boot labels is not proof that collectors exist or safely
implement those checks. Unsupported checks remain unavailable/NotTested.

Build a bounded DisplayModel deterministically from the frozen non-presentation
scope fields and pinned resources, then include it in the final offer payload
before computing OfferDigest. DisplayModelDigest is proposed as SHA-256 LowerHex over
`SecApp.StandardLaunch.Display.v1` plus LF, followed by JCS of that model. It
binds the complete semantic text/values/order and template/locale versions.
Neither model nor its digest includes OfferDigest, avoiding a circular binding.
The model excludes only a derived remaining-time indicator; the fixed expiry
is already offer-bound.
CC recomputes this model, and the broker compares its expected digest. This is
a mismatch check, **not a screenshot, pixel-integrity or human-reading proof**.
Never accept an ordinary UI's claim that the screen was displayed or read.

Initial review limits: at most eight check items within the one action, each
with reviewed bounded text; complete offer and DisplayModel together fit one
16 KiB frame, with strings at most 1,024 UTF-8 bytes and depth at most eight.
All critical fields must remain available in the main confirmation view at
supported DPI, language and accessibility settings, without truncation or
ellipsis hiding scope. If that cannot be satisfied, reject this presentation;
do not silently omit checks or abbreviate security-relevant values. Additional
scrollable technical details do not carry otherwise hidden critical scope.

No claims of understanding from dwell time, scrolling or a focus event. Loss
of the protected interaction guarantee, lock/logoff/session change, unsupported
assistive interaction or uncertain display state invalidates the attempt;
accessibility must have a reviewed equivalent, not a hidden bypass. Unknown
locale/resource version fails closed. No host language, accessibility or desktop
setting is changed to make the dialog work.

## 4. Delivery to the service, without a transferable bearer permit

Use a dedicated broker/CC control channel, distinct from ordinary UI control
and from token acquisition. Both endpoints must be bound independently to their
retained process instances, protected code/policy and observed session/identity.
No identity based only on a claimed role, pipe name, PID, SID, nonce or certificate
name. Never ask the ordinary UI to relay CC's authorization message.

The proposed sequence is:

1. UI requests the fixed action. The broker checks accepted architecture and
   installation/trust/preparation prerequisites; unresolved gates produce Blocked,
   not a confirmation prompt that can waive them. Per-child runtime checks still
   occur after authorized creation and before resume.
2. Once the confirmation mechanism itself is accepted, the broker bootstraps
   and binds one CC instance. No backend is started to obtain confirmation.
3. CC fetches the frozen offer and sends a PresentationBound message containing
   OfferDigest, DisplayModelDigest and the fresh per-instance challenge binding.
   This records agreement only; it grants no launch authority.
4. The person makes an explicit decision through the accepted protected
   interaction. CC sends DecisionBound directly to the broker: exact offer and
   display digests, challenges, channel/instance binding, monotonic sequence
   number, and Accept or Decline. No raw credentials, token handles or reusable
   signing secrets are carried. Identity is observed, not trusted from fields.
5. The broker validates the message on that CC-only channel, checks the required
   interaction evidence and atomically admits/consumes the exact action as below.
   UI receives only bounded status; CC receives an acknowledgement, not a permit.

Message names are design labels, not implemented commands or production schema
IDs. The existing prohibition on public wire-level Approve remains: DecisionBound
is acceptable only on the separately authenticated CC role boundary, never on
the ordinary UI endpoint. A hash, JSON signature field, client timestamp or
`user_presence: true` is not that boundary. Its native realization is still open.

Reuse the broker's 16 KiB frame, 64-frame/1 MiB action and 2 MiB aggregate control
budgets across **all** channels, not once per role. One CC/offer at a time, no
queued approvals. Strict parsing rejects extra/duplicate fields, unsupported
variants, out-of-order and repeated decisions before any effect. No automatic
retransmission of Accept; a lost acknowledgement permits only a status query
on the still-bound channel, never a second admission attempt.

For this slice, both the requesting UI and CC remain bound until terminal
status. Acknowledgement may end the confirmation view, but is not permission
to detach CC or close its channel early. Unexpected loss follows the same
bounded-stop rule, including after admission. A future explicit CC handoff or
early-exit protocol would require a separate lifecycle review; none is implied.

## 5. One-use means at most one attempted execution, including crashes

The service owns a private admission record, conceptually a LaunchPermit. It
is neither an exported file nor a token accepted from another process. It is
not a promise of exactly-once execution: a crash may consume permission without
starting anything. The safe retry is a newly confirmed action, not reuse.

| State | Required next step or denial |
|---|---|
| Offered | Await the bound presentation within the original 30-second monotonic deadline |
| Presented | Await the exact CC decision; the deadline does not restart |
| DecisionValidated | Under one coordinator, recheck expiry, identities/session, cancellation, immutable scope, current trust/generation and all pre-creation prerequisites |
| AdmittedConsumed | Atomically bind the active-run/deployment lease and durably consume this action/offer before any backend creation; exactly one owner may advance |
| Running/Stopping | Execute only the frozen action after per-child pre-resume checks, with retained ownership and bounded whole-tree cleanup |
| Terminal or RecoveryRequired | No permission restoration, scope expansion, replay, automatic launch or restart continuation |

Decline, expiry, CC/UI disconnect before admission, session change, changed
policy/material or loss of interaction integrity invalidate the offer. After
admission, cancellation/disconnect follows the broker's stop rules. Serialize
Cancel and admission: if Cancel wins, no creation; if admission wins, stop the
owned attempt. A duplicate or competing Accept must never allocate a second
execution, even if the first has already exited successfully.

The consume record, run ownership and maintenance lease form one required
crash-consistent admission boundary. If write/flush/read-back or its outcome
is uncertain, create no backend, retain RecoveryRequired and block new launch
or maintenance publication. Do not pretend that JSON hashing, writing one file
or a successful Job test implements this atomicity. This remains LS-007/MMR work.

On broker restart, all old broker-instance/offer/channel bindings are invalid;
no saved wall-clock time resurrects a monotonic deadline. Reconcile existing
owned processes and leases before new admission. Retain bounded replay/lifecycle
metadata according to reviewed storage policy; inability to safely compact it
blocks admission, not eviction of live/uncertain records. The 30-second offer
expiry is not a retention policy or completed accessibility/usability validation.
An explicitly requested replacement offer starts a full new confirmation, never
extends an old approval. No raw screen contents, signatures, host identity data,
tokens or result streams go into public logs/repository fixtures.

## 6. Windows mechanism limits and the remaining acceptance gate

The baseline design uses an authenticated, protected CC-to-broker decision,
not a newly invented signing key in the ordinary UI. No crypto key is generated,
registered, reset or enrolled by this stage. Key lifecycle would add a separate
trusted-enrollment problem; a key submitted with its own proof is not an anchor.

Windows Hello UserConsentVerifier returns a verification result and can display
a caller-supplied message. Its desktop interop variant also returns an enum.
SecApp inference: forwarding that enum from an untrusted process cannot prove
an exact service action was displayed and approved. It can be an additional
local check only after CC's boundary is accepted, not its replacement.
[Verification API](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier.requestverificationasync?view=winrt-26100),
[desktop interop](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync).

KeyCredential.RequestSignAsync can request a cryptographic signature over data.
A future independently reviewed variant could bind a broker challenge, domain,
OfferDigest, DisplayModelDigest and instance/expiry to a properly enrolled key.
It would still need the same protected display/input and identity binding:
signing a digest does not by itself prove the user saw the corresponding scope.
No Hello enrollment requirement, key algorithm or fallback to a plain click is
selected here. Hardware/API unavailability would block that variant.
[Signing API](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.keycredential.requestsignasync?view=winrt-26100).

UAC normally protects its own elevation prompt using the secure desktop and
returns to the user desktop afterward. It does not turn a later SecApp scope
dialog into a secure-desktop dialog. A private desktop, signed process, higher
integrity label or an accessibility flag is not accepted here as a complete
human-intent proof. No UIAccess grant, desktop ACL change, custom credential
provider, policy edit or automatic elevation is proposed as a workaround.
[UAC interaction](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works).

The unresolved condition is concrete: show that the exact independently derived
scope remains authentic and complete through a genuine user's decision, despite
the in-scope same-user process attacker, and that only the bound CC can deliver
that decision. A peer-authenticated channel alone cannot meet this condition.
Do not assert a supported Windows solution or universal impossibility without
evidence. Until an implementation candidate satisfies it, NativeApproval stays
Disabled; the service must not accept this conceptual protocol at runtime.

### 6.1. Windows mechanism triage, 2026-11-06

This is a documentation review, not an experiment or an independent acceptance.
Keep DisplayInputProtection = NotSelected and NativeApproval = Disabled. The
reviewed APIs do not establish a complete candidate under all current SecApp
constraints. This is not a claim that Windows has no possible secure solution.

| Mechanism | Useful property | SecApp disposition for this slice |
|---|---|---|
| Ordinary same-integrity dialog on the user's desktop | Full custom scope presentation, no elevation | Reject as the sole human-input boundary; process separation and a signed file do not exclude peer-generated input |
| UAC followed by a higher-integrity SecApp dialog | Elevation bootstrap and integrity-level filtering | Not selected for Standard; changes the no-per-check-UAC path and still does not bind UAC to the later exact scope |
| Windows Hello verification or challenge signing | Local verification; signing can bind data | Additional factor only after trusted CC/bootstrap/display, not a replacement for those boundaries |
| Credential UI with CREDUIWIN_SECURE_PROMPT | Documented OS credential prompt on the secure desktop | Not selected: credential handling is outside CC's current contract, and no complete exact-scope receipt/display guarantee is established |
| CC on an explicitly secured private desktop | Desktop separation plus custom scope presentation | Retain only as a bounded paper-feasibility candidate; bootstrap, access, input and switch/restore guarantees remain unresolved |

The equal-integrity gap is concrete: SendInput is subject to UIPI, but its
documented integrity restriction permits input injection toward equal or lower
integrity applications. SecApp inference: a normal Standard dialog cannot cite
UIPI alone as evidence of a genuine user's decision. No injection was attempted.
[Input API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput).
Do not add UIAccess as a protection flag: Microsoft describes it as enabling
accessibility applications to drive higher-permission UI, not isolating a
consent application from input. No accessibility policy is changed or disabled.
[Manifest contract](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests).

Credential UI is a real documented secure-desktop option, so do not claim that
only UAC can request an OS-hosted prompt. CredUIPromptForWindowsCredentialsW
with CREDUIWIN_SECURE_PROMPT requests that surface, cannot combine that flag
with CREDUIWIN_GENERIC, and returns a credential BLOB to the caller. Its success
code is not documented as a service-bound launch approval. SecApp would need a
separately reviewed authentication/credential lifecycle, not forward success
or the BLOB as DecisionBound. No Windows password, PIN or credential BLOB is
requested, stored or transported by this design.
[Credential prompt contract](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creduipromptforwindowscredentialsw).

CREDUI_INFO supplies bounded message/title strings, not SecApp's complete
reviewed scope layout. The API contract alone does not establish that every
critical field is visible for all supported locales/DPI/accessibility variants.
A digest shown there plus details on an untrusted desktop is not an acceptable
substitute. This is an unproved guarantee, not a claim of an observed clipping bug.
[Prompt text contract](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credui_infow).
Do not install a custom credential provider, change credential-prompt policy,
enroll a key or add a password fallback to make this branch fit.

### 6.2. Private desktop: useful boundary, incomplete construction

Windows documents desktop-local window messaging/hooks and separately securable
desktop objects. A private desktop could therefore reduce interference from
the ordinary desktop. It is not the Winlogon/UAC desktop and must not be labeled
equivalent to it. Only WinSta0 in the relevant session is interactive; creating
a new private window station does not create another interactive trusted screen.
[Desktop separation](https://learn.microsoft.com/en-us/windows/win32/winstation/desktops),
[window-station model](https://learn.microsoft.com/en-us/windows/win32/winstation/window-stations).

Three documented details prevent treating CreateDesktop success as acceptance:

- CreateDesktop associates the object with the caller's current window station,
  permits an explicit security descriptor, and can succeed by opening an already
  existing desktop. SecApp must prove object origin and retained identity; a
  random name or successful call is not exclusive creation/authentication.
  Do not enable DF_ALLOWOTHERACCOUNTHOOK or fall back to inherited defaults.
  [Creation contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createdesktopw).
- Desktop access checks distinguish window creation, hooks, object access,
  switching, DACL modification and ownership. A user/logon SID shared by CC and
  the attacker is not process-instance identity. Object ownership and existing
  handles must be included, not only an allow/deny list applied after startup.
  [Desktop rights](https://learn.microsoft.com/en-us/windows/win32/winstation/desktop-security-and-access-rights),
  [owner/default-token rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object).
- SwitchDesktop requires access to a desktop in the caller's window station;
  cross-session and invisible-station targets fail. A Session 0 service cannot
  be assumed to switch the requester's screen directly. The trusted in-session
  bootstrap/switch/restore actor is part of the unresolved design.
  [Switch contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-switchdesktop).

The bootstrap must resolve a specific tension. CreateProcessAsUserW uses the
token's session; a requesting-user token preserves that user's context but does
not itself supply a separate security identity for CC. Reusing the broker's
service token in the user's session is not a free alternative: setting
TokenSessionId requires the documented Act As Part Of the Operating System
privilege, excluded by the current broker budget. Neither token path is an
accepted desktop-protection construction. Do not add SeTcb, LocalSystem,
credential logon or a privileged token/session transplant as an implicit fix.
[Process/session contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw),
[TokenSessionId requirement](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class).

The next paper review must fill this access/authority matrix with concrete
principals, creation APIs and effective rights. All rows are currently Open;
these are LS-002/003/007 obligations, not a new suite of passing model tests.

| Object or boundary | Required result before this candidate can advance |
|---|---|
| Interactive station and existing Default desktop | Account for the requester's existing station/desktop rights, clipboard/global atoms and switch-away paths; do not silently rewrite their ACLs |
| New confirmation desktop | Accepted owner/DACL and any applicable owner-rights controls from creation; exclude hostile join/window/hook/write/security-reset paths and handle leakage; reject existing-object substitution |
| CC process, threads, token and bootstrap | Accepted code/loader identity and access matrix before use; no peer memory/control/token/handle path that can manufacture DecisionBound |
| Input and visible scope | Exact DisplayModel stays authentic through decision; exclude synthetic/relayed input and lookalike-to-real-prompt races; a focus event or desktop name is insufficient |
| CC-only broker channel | Retained independently verified endpoint instance, not claimed SID/PID/name; no authority transfer through UI, clipboard or shared mutable storage |
| Switch, cancel and recovery | No backend before full admission; lock/session change or uncertain interaction invalidates consent; restore safely without overriding a Windows secure desktop or trapping the user |

Window-station rights include desktop creation, clipboard/global-atom access and
screen access. SecApp inference: securing only the new desktop leaves a parent
surface that must be assessed; this is not evidence that any listed path was
exploited on this computer. [Station rights](https://learn.microsoft.com/en-us/windows/win32/winstation/window-station-security-and-access-rights).
Do not claim that polling the current desktop provides an atomic display/input
guarantee. Interrupted interaction means denial, not switch-back-and-continue.
The proposed UI/CC control lifetimes in section 4 remain in force after Accept.

### 6.3. Bounded next decision, not permission to build

Author recommendation: examine the private-desktop construction above first
because it could accommodate custom exact-scope presentation without first
adopting credential collection or per-check elevation. This is a research
priority, not a production selection, a new user approval or a claim that the
construction is feasible. Section 6.4 records the subsequent bounded review.

The next deliverable is one concrete bootstrap/owner/access sequence against
the matrix, including a non-bypassable interaction transition and safe exit.
If no supported construction satisfies the existing account/privilege budget
and same-user threat model without unapproved system-policy changes, reject
this route and return to an explicit product/architecture decision. Do not
compensate with more receipt formats, synthetic success counts or ordinary UI
confirmation. Native testing, if later justified, needs separate authorization;
the main computer is not implicitly authorized as a security-experiment host.

No scope expansion is made here: no service/desktop creation, ACL edits, account
or privilege grants, UAC, Hello enrollment, input injection, backend execution
or native compilation. The import/report path remains available. Future optional
Elevated collection is preserved, but cannot be used to bypass this Standard gate.

### 6.4. Concrete bootstrap review: no implementation go-ahead

Disposition on 2026-11-06: **NotAccepted / no-go for production implementation
under the current evidence and constraints**. This is the author's bounded
review, not an independent audit, a native test failure or an impossibility
proof for every Windows design. The service direction remains approved for
design; DisplayInputProtection stays NotSelected and NativeApproval Disabled.

Let B be the broker in Session 0, U the authenticated Standard requesting user,
S that user's existing interactive session, C the proposed confirmation process,
and A a hostile process in S with U's ordinary user/logon SIDs. These are role
labels, not actual account names, handles, SIDs or machine observations.

| Construction examined | Concrete issue | Disposition |
|---|---|---|
| B creates/switches a desktop in Session 0 | The object belongs to B's station/session, not S; SwitchDesktop is not a cross-session user-screen API | Reject this topology |
| B moves its own service token to S and launches C as that service identity | The TokenSessionId rewrite needs the privilege excluded by the broker budget; this is not the already-in-session user-token route | Reject within the current budget; no SeTcb/LocalSystem fallback |
| B launches C with U's token in S; C opens a desktop by name with ordinary user/logon-SID grants | The grant used by C is also available to A; process-instance identity is not expressed by that shared SID | Reject this shared-SID authorization construction |
| B launches protected C in S; C creates/uses an explicitly secured desktop through retained handles, without a shared-SID reopen grant | Potential alternative, but exact creation/attachment rights, owner control, handle isolation, input and crash restoration are unproved | Not accepted; preserve as a research hypothesis, not an executor recipe |

The first two rows follow the session and creation contracts cited in section
6.2. For the third row, the conclusion concerns ordinary SID-based grants to
matching identities, not every possible token or access-control construction.
Restricting C's token is not a solution by itself: restricted-token access must
pass both the enabled-SID and restricting-SID checks. Adding a restricting SID
does not make a grant to U inaccessible to an unrestricted A with the same
enabled U SID. This is a SecApp deduction from the documented access algorithm,
not a token probe. [Restricted-token checks](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens).

Ownership must be handled precisely. The OWNER RIGHTS SID can suppress the
owner's implicit READ_CONTROL/WRITE_DAC rights when used in an ACE. Therefore
"the owner always bypasses every DACL" is not a valid impossibility argument.
But that mechanism does not itself supply a C-only identity, revoke already
held handles, establish secure bootstrap or prove desktop input integrity.
Its exact use for each proposed object remains unaccepted; no SDDL is approved
by this review. [OWNER RIGHTS semantics](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).

The retained-handle hypothesis has the following explicit sequence and stop
points. It must not execute until the corresponding gates and experimental
authority are separately satisfied:

1. B binds the requester and obtains a constrained U token already in S through
   the separately authenticated token channel. Missing rights, linked-token
   failure or uncertain peer identity blocks here; no session rewrite.
2. B creates fixed C suspended with CreateProcessAsUserW, no inherited handles,
   fixed environment and reviewed process/thread/token/loader protection. The
   broker retains lifecycle ownership before C's first instruction. File ACLs
   alone do not satisfy this step, and existing TL gates remain prerequisites.
3. Only a trusted headless bootstrap of C may prepare the desktop in S. Before
   any scope window or hook, it must obtain a verified new object with explicit
   owner/DACL and the required access, using a fresh thread where necessary.
   C must be able to attach/render while A cannot reopen/join/reset security or
   obtain the desktop handle. The exact descriptor and creation/attachment
   semantics are the first unresolved construction point, not a promised success.
4. Bind C's retained instance to the dedicated broker channel; then freeze the
   offer. Switch/display only after verified desktop and channel binding. No
   arbitrary names, serialized handle values or UI-provided approval cross in.
5. Accept only the exact decision through the proved interaction boundary.
   Desktop polling, an input-origin enum or a digest alone cannot supply the
   missing guarantee. The display-to-input transition remains unresolved.
6. B rechecks and atomically consumes the one-use offer with run ownership,
   then performs constrained backend creation and the required pre-resume
   checks. Neither C startup nor a switch permits backend creation beforehand.
7. Decline, timeout, lock, disconnect or crash denies/terminates the owned
   attempt. Safe screen restoration must also survive C's death; a watchdog
   thread inside C alone cannot survive its process exit. An independent
   in-session recovery actor or supported OS restoration guarantee needs its
   own trusted bootstrap/rights proof. Neither is established here. Recovery
   must not unlock the session, override Windows secure UI or revive consent.

Two startup details matter to step 3. By-name desktop connection opens the
named object for MAXIMUM_ALLOWED; an inherited-desktop route uses an inherited
handle instead. Cross-session inheritance from B is unavailable, so it cannot
be assumed as the solution. Multiple inherited desktop handles are documented
as ambiguous. SetThreadDesktop also fails when the calling thread already has
windows/hooks on another desktop. The sequence above therefore does not begin
with an ordinary GUI and harden it after display.
[Thread attachment](https://learn.microsoft.com/en-us/windows/win32/winstation/thread-connection-to-a-desktop),
[SetThreadDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setthreaddesktop).

Input-source checking has an explicit limitation: GetCurrentInputMessageSource
reports message metadata, and IMO_HARDWARE includes input injected by a UIAccess
application, not only hardware. SecApp must not equate that value to a physical
click or informed human approval. This does not show that an arbitrary Standard
attacker can obtain UIAccess, or that any installed accessibility tool is hostile.
The supported accessibility/input trust boundary remains to be specified, with
no disabling of host accessibility settings.
[Source API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getcurrentinputmessagesource),
[Origin values](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ne-winuser-input_message_origin_id).

CloseDesktop is not a screen-recovery protocol: it cannot close a handle still
used by a thread in the process or the process's initial desktop handle. The
review must not infer safe visible-desktop restoration merely from process
termination or handle closure. [CloseDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-closedesktop).

This completes the currently bounded paper review. Do not start the service or
CC implementation, repeat nominal receipt models or continue calling this an
accepted private-desktop mechanism. The next decision requires user direction:

- retain the current threat model and obtain a separately reviewed, exact
  research-prototype plan plus an isolated Windows test environment and explicit
  native-test permission; validate the unresolved construction, interaction and
  recovery points before independent acceptance. A prototype result may still
  reject the route, and does not close other TL/MMR gates;
- or explicitly revise the first-release assurance scope, for example to a
  trusted-local-session MVP without a claim of same-user-malware-resistant
  confirmation. That is a material threat-model/architecture decision requiring
  updated requirements and independent re-review, not a switch to enable this
  blocked planner. It does not waive binary trust, bounded execution, read-only
  collection, separate elevated consent or safe storage requirements.

Neither option is selected or authorized by "begin the MVP plan". No VM,
hypervisor, service, account, privilege, ACL, registry value, credential provider,
key or system setting is created/changed here; no native code or backend runs.
The original computer is not an implicit fallback test environment.

## 7. Existing consent domains and review cases

This internal Standard launch admission is not a new ConsentReceipt variant.
Keep the immutable [receipt schema](../schemas/consent-receipt.schema.json) and
[XOBJ-011 domain rules](integrity-model.md) unchanged. A launch permit cannot
authorize Administrative, NetworkAccess, SensitiveDataCollection, MemoryAcquisition,
DefenderScan/Offline, Export, Remediation, Reboot or maintenance. Standard rights
do not imply non-sensitive data. If an operation needs another consent domain,
this first slice rejects it; its future separately reviewed flow must validate
every exact required authority, not stretch this confirmation.

Optional Elevated read-only collection remains a future product path, with its
own scope and user confirmation. Neither installation approval nor Standard
Accept grants it. A batch UI in a later design would need disjoint permits per
action and must still respect the existing one-active-action/no-queue policy
unless that policy is explicitly revised.

Review the following scenarios as part of LS-003/007, all **Planned / NotRun**:

- one exact offer, accepted through the trusted role, yields one consumed
  admission; decline and unavailable protection yield zero executions;
- change any check, target, data class, parameter, privilege, limit, backend,
  registry/template/locale or instance binding between display and admission;
- hide/truncate a critical field, mismatch display order/text, substitute a
  lookalike prompt or inject a decision from a same-user/ordinary UI process;
- forge PresentationBound, send a correct digest with untrusted Accept, replay
  Hello success, supply a new public key or sign a different action's challenge;
- duplicate/race Accept, race Cancel, change session, expire during confirmation,
  lose acknowledgement, disconnect or crash at each consume/create boundary;
- reuse the decision across restart, maintenance generation, user, action,
  authority domain, backend revision or completed execution;
- exhaust protocol/replay-store limits without bypass, overflow, unbounded log
  growth or evicting uncertain ownership.

The design is complete enough to review message/data consistency; platform
protection and crash-consistent admission are not proved. Section 6.4 records
the no-go and required next decision; independent acceptance must still cover the
cases above. No implementation, synthetic native matrix or system change is
authorized by the existence of this document.

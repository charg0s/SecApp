# TRUSTED-LOCAL-MVP1

Current precedence: [D-058 / TRUSTED-HOST-MVP1](trusted-host-mvp.md) supersedes
this document's confirmation-only assurance exception and blanket permission/
gate applicability statements. This remains the D-056 historical baseline;
its protocol/consent safeguards apply except where D-058 explicitly revises them.
The D-056 review below is not acceptance of the later requirements change.

Date: 2026-11-06. D-056 records the user's selection of the second path:
a limited first release for a trusted local session, without a guarantee of
same-user-malware-resistant launch confirmation. This document changes the
Standard confirmation assurance scope, not the execution readiness flags.

```text
FirstReleaseTarget = TrustedLocalMvp
ScopeDecision = ApprovedByUser
StandardConfirmationAssurance = TrustedSessionExplicitIntent
SameUserResistantConfirmation = NotClaimedForMvp
ServiceDirection = RetainedForDesign
ArchitectureDeltaReview = AcceptedScopedDeltaOnly
RuntimeAcceptance = BlockedPendingRemainingGates
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
HostDeployment = NotAuthorized
```

## 1. Exact scope change and its cost

For the first Standard release, assume that the user's session and SecApp's
trusted UI/controller have not already been independently compromised. A normal
application confirmation can record the intended exact action under this
assumption. It is not an OS-protected proof that a genuine person saw and
approved that action in the presence of hostile same-user code.

If that assumption fails, a hostile process may interfere with confirmation,
read data available to the user, tamper with application state or mislead the
report viewer. This is a statement of an unclaimed guarantee, not evidence of
an exploit on this computer or a claim that every peer has every access right.
Hashes do not restore trust if the attacker also controls the data and verifier.

The exception concerns an independently pre-existing session compromise. It
does **not** excuse a compromise introduced through SecApp's own parsing,
rendering, artifact handling or IPC. Untrusted imported packages, backend
output, collector definitions and displayed strings remain adversarial input.
An HTML/JSON/VQL injection that turns them into launch authority is still a
security defect under this MVP. Other-user access, unintended privilege use,
unsafe filesystem access and supply-chain substitution remain in scope.

Do not add a client-supplied `trusted_session: true`, a malware-detector result
or a "continue anyway" switch as runtime evidence. Trusted-session operation
is a documented product assumption, not a condition SecApp can certify merely
by starting. Known failed trust/storage/launch checks still block; uncertainty
does not turn into a clean or independently attested result.

This is a narrower exception to the [threat model](threat-model.md), not removal
of its full local-attacker register. A further reduction of process, token,
file/loader or network guarantees requires its own explicit decision/review.
The user has not approved those reductions through the confirmation choice.

## 2. Minimum architecture: retain the service direction

D-052's narrow demand-start service remains the selected direction for design.
Choosing a weaker confirmation assurance did not select a portable direct-child
launcher, remove the service or authorize its installation. A future no-service
proposal must be assessed and chosen separately, not silently substituted here.

The proposed first-release flow is:

1. Ordinary unelevated SecApp UI selects a registered Standard operation.
2. The broker independently prepares a frozen exact offer from protected policy
   and checks its own installation, identity and preparation prerequisites.
3. The trusted UI/controller displays the broker's exact check/data/effect scope
   and bounds, then submits a one-action confirmation or cancellation.
4. The broker revalidates the caller/session, offer, required consent domains
   and current prerequisites, and consumes admission with run ownership before
   creating the constrained Standard supervisor/backend tree.
5. Unprivileged bounded parsing/normalization feeds assessment and a private
   report. The UI shows progress/cancel and preserves honest NotTested coverage.

Steps 4-5 are not implemented by this document. Service account/privilege,
token/session, loader/image binding, offline confinement, private storage and
crash-consistent ownership remain independent acceptance work.

The separately protected confirmation component, private desktop, Hello signing
and a same-user-resistant display/input proof from
[LAUNCH-CONFIRMATION-DESIGN1](launch-confirmation-design.md) are not prerequisites
for the MVP's narrower **Standard intent** claim. Preserve that research and
its NotAccepted disposition; do not rename a normal UI into a trusted CC or
mark the stronger construction Passed. The stronger path can be revisited later.

Keep trusted confirmation/controller code separate from untrusted report content.
Report rendering must not expose a launch/approval bridge, arbitrary navigation
or executable backend text. Use reviewed fixed presentation resources and typed,
escaped values. UI containment/sanitization is required even though independent
pre-existing same-user compromise is outside the confirmation guarantee.

## 3. Scoped Standard confirmation protocol delta

This replaces only the strict CC-only decision requirement for the scoped MVP.
It does not change an existing wire schema, create a new ConsentReceipt variant
or reinterpret historical fixtures as executable requests.

The UI uses the broker's frozen offer, not its own arbitrary commands or prose.
It shows every selected check, data/privacy class, purpose, Standard privilege,
offline requirement, resource limits, coverage limits, owned result/temp writes,
retention behavior and cancellation effect. No default Yes, remembered approval,
hidden scope expansion or automatically accepted retry. A changed field needs
a newly displayed offer and confirmation. One offer covers one action/backend
invocation; distinct CollectorExecutions keep distinct exact authorities.

A proposed `ConfirmStandardOffer` request on the bound local UI/broker channel
may reference offer ID, action binding, exact offer/display digests, fresh nonce
and instance-local expiry/sequence. The name is a design label, not an implemented
public API. Its meaning is "this trusted-session UI reports this exact intent",
not "Windows proved a human approved it". Under pre-existing session compromise,
that intent may be forged; the MVP does not claim otherwise.

The broker must still derive commands and validate all other gates itself.
No `ready`, `verified`, `execution_enabled`, token handle, image path, raw argv,
VQL, output destination or client-selected assurance mode is accepted as an
override. User/SID/session binding is not described as proof of human presence.
The service must not become a generic privileged execution or data-access proxy.

Keep the existing single-active-action/no-queue bounds, local peer binding,
strict parser, frame/action budgets, original expiry and lowering-only limits.
Decline, changed scope, expiry, disconnect or cancellation invalidates pending
intent. Duplicate requests cannot allocate another execution. Consume-before-
create and durable run/lease reconciliation remain required; lost acknowledgements
allow bounded status inspection, not automatic re-admission. Restart invalidates
old offers and never resumes collection or restores spent permission.

Unlike the strict CC design, this MVP does not need a separate CC process to stay
connected. The requesting UI/controller and broker remain bound through terminal
status; their disconnect/cancel/crash stop rules still apply to the owned run.
No detached background completion or auto-elevation is introduced.

This protocol delta explicitly supersedes the old public-Approve prohibition
only for the newly reviewed Standard intent request. It is not permission to
add an approval endpoint to maintenance, Elevated, or the historical strict CC
protocol. A copied JSON record/digest is never sufficient runtime authority.

## 4. Privacy and other consent domains are not bundled

Standard privilege does not mean non-sensitive collection. The target protection
profile's Defender/Firewall/BitLocker/Secure Boot observations are classified as
SensitiveSecurityData in [the existing reference profile](windows-protection-import.md).
Its eventual collection flow must obtain exact SensitiveDataCollection authority
and enforce the existing CollectorExecution bindings; a launch-intent click or
installation approval is not a substitute. No real collector is registered here.

For that fixed Standard read-only profile, the separately presented data-scope
consent may use the same trusted-session UI assumption. It still produces its
own exact domain-bound authority; it is not inferred from confirming launch.
This does not extend the exception to Administrative, network, Secret,
MemoryContent, remediation, reboot, export or maintenance workflows.

Registered Version/Help diagnostics remain a separate initial integration step,
not a receipt permitting subsequent machine collection. If an operation requires
additional domains and the corresponding reviewed flow is unavailable, reject
the operation. Do not invent a permissive dummy receipt to make it pass.

Keep [ConsentReceipt and privacy rules](privacy-model.md) and
[XOBJ-011](integrity-model.md) unchanged: exact run/pass/execution/action/operation/
target/purpose/digest, capability and privacy bindings, expiry and single use.
Administrative, network, memory, DefenderScan/Offline, reboot, remediation,
export and maintenance remain separate. A Standard intent cannot grant them.

The MVP does not implement Elevated collection. The future optional, explicitly
confirmed read-only Elevated pass remains a product goal; its stronger authority
and maintenance boundaries are not weakened by this scope decision. No UAC,
service setup, ACL change, credential/key enrollment or host-policy edit follows
from choosing the MVP. Each later mutation needs its own explicit authorization.

## 5. Retained blockers and honest status mapping

| Area | Effect of this decision |
|---|---|
| Same-user-resistant Standard screen/input | NotClaimedForMvp; ordinary exact intent is proposed under the trusted-session assumption, not proof that the strict gate passed |
| Service account, caller binding, token/session, process/handle ownership | Remain unresolved; no change to the privilege budget or linked-token acceptance predicate |
| Binary authentication, root/reparse, verified bytes and mapped image, initial/future DLL policy | All nine historical TL records and planner blockers stay Open; no reclassification to Passed or deletion of Unknown evidence |
| Offline confinement, bounded execution and whole-tree cleanup | Still mandatory; file/packet/module observation alone does not prove preventive enforcement |
| Private storage | Retention, encryption/key lifecycle, temp/crash/paging/backup, ownership and cleanup decisions still required before sensitive runtime collection |
| Parsing, normalization, assessment and reports | Existing reference implementations are reusable, but hostile-input controls and independent domain/runtime review remain required |
| Maintenance and Elevated authority | No assurance reduction; original unresolved gates remain blocking for those paths |

In particular, scope approval does not turn the old linked-token metadata result
into an accepted token, an observed module list into a loader policy, or the
historical v0.77.1 pin into a currently suitable runtime release. No new download,
release selection, native test, code/schema/dependency change or execution flag
is part of this pass. The current diagnostic planner intentionally stays Blocked.

## 6. Bounded implementation order and release criteria

1. **Scope rebaseline (this pass).** Record D-056, update current-document
   precedence and independently review that only the selected assurance changed.
   Acceptance of this delta is not acceptance of the complete runtime.
2. **First real-operation contract.** Start with fixed Version/Help and bounded
   output mapping. Specify the exact release trust, launch/token/loader and
   private-storage/offline boundaries needed for that operation; review before
   implementation. [BACKEND-DIAGNOSTIC-CONTRACT1](backend-diagnostic-contract.md)
   now records that proposed boundary; current release/output profiles and native
   prerequisites remain unresolved. Do not add another general-purpose synthetic
   authority model merely to label the operation ready.
3. **Accepted launcher and diagnostic integration.** Implement and test only the
   separately authorized native slice after applicable gate review. Installation
   and native execution still need their exact permissions and test boundary.
4. **Useful protection collection.** Review fixed read-only definitions and
   transitive capabilities for the chosen release; design sensitive-data consent,
   normalization and private storage. Integrate with existing rules/report code.
   Four target areas are not four already implemented collectors. Unsupported
   areas stay NotTested; an all-NotTested result is not a useful end-to-end success.
5. **Minimal UI/package and end-to-end acceptance.** Complete operation selection,
   readable exact confirmation, progress/cancel, private results and explicit
   save. Verify refusal, tampering, resource limits, crashes and recovery. No
   automatic updates, scheduled collection, remote API, public export or repair
   feature is required for this first slice.

The intended user outcome remains a manual, local read-only check with genuine
current observations and a bounded private report. A functioning import demo,
planner result or ordinary confirmation screen alone does not meet that outcome.
Review criteria for the revised protocol include exact confirm/decline, changed
offer, duplicate/restart replay, foreign-domain receipt, attempted ready/verified
override, report-content-to-launch injection and unknown/denied coverage. These
are required future tests, not new tests executed by this document.

## 7. User-facing limitations and review record

Proposed visible wording for the MVP:

> This version assumes a trusted local user session. It does not guarantee
> confirmation or report integrity against malware already controlling that
> session. Results describe the checks performed and available evidence; they
> do not certify that Windows is free of malware.

Show the scope limitation during onboarding and in the private report; do not
hide it only in an advanced panel or use a hash as an assurance badge. Existing
import reports must still say they assess a supplied snapshot until an actually
reviewed direct-collection provenance path exists.

If compromise is suspected, do not market the MVP as an independent examiner
of its own environment or silently launch remediation/offline scans. A future
separately designed workflow could use an independently trusted collection or
analysis environment; neither it nor a guarantee against kernel/firmware
compromise is supplied by this scope change.

Independent review status: AcceptedScopedDeltaOnly on 2026-11-06. A separate
read-only reviewer checked this document and all eight cross-document changes,
including the Standard sensitive-data consent distinction, with no blocking
findings. Review is limited to the requirements/architecture delta and document
consistency; the concrete collection/consent flow still needs its own review.
Native feasibility, implementation security, full historical-gate closure and
production acceptance remain outside this pass. No host operations or real-host
evidence are produced.

# TRUSTED-HOST-MVP1

Date: 2026-11-06. D-058 records the user's approval of ordinary development,
bounded backend integration and a broader trusted-host first-release scope.
This supersedes D-056's confirmation-only exception in
[TRUSTED-LOCAL-MVP1](trusted-local-mvp.md). D-061 subsequently permits designing
necessary targeted service-account rights for a future separately confirmed
installation; the exact rights proposal is not yet installation approval. It is
not evidence that historical security failures have been fixed, and it does not
enable an existing executor.

```text
FirstReleaseTarget = TrustedHostMvp
ScopeDecision = ApprovedByUser
RequirementsReview = AcceptedRequirementsRebaselineOnly
ServiceDirection = Retained
DevelopmentPermission = AuthorizedWithinReviewedSlices
OfficialAssetAcquisition = AuthorizedForReviewedCandidate
ControlledExecution = AuthorizedSubjectToApplicableGatesAndExactScope
Installation = ConditionalOnPresentedManifestAndConfirmation
RuntimeAcceptance = BlockedPendingApplicableMvpReview
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
HistoricalStrictProfile = DeferredNotPassed
```

## 1. What the first release promises

Assume an independently uncompromised Windows installation and user session,
trusted SecApp code/controller and trustworthy platform security services.
The first release performs a manually selected, fixed read-only Standard check,
then bounded parsing, assessment and private reporting. It does not certify
that its own host is uncompromised or resist malware already controlling the
same user's files, processes, handles, UI or local evidence. This is a documented
assumption, never a runtime `trusted_host` flag or an antivirus result that
overrides a failed check.

Unlike D-056, this exception covers the first-release local process/file/loader
assurance, not only the confirmation screen. Active same-user tampering,
administrator/kernel compromise and hostile modification of the verifier are
outside its guarantee. The stronger isolation work is deferred, not passed.

Still in scope: compromise introduced by SecApp itself; hostile packages,
artifacts, backend output, reports and strings; accidental misuse; unauthorized
other-user access; wrong executable/release; path traversal and unsafe writes;
unintended elevation; replay/scope confusion; unbounded resources; and false
success/coverage. No parser/rendering/IPC exploit may be dismissed as a trusted-
host exception. Release authentication and transitive collector review remain
required; an authenticated binary is not permission for arbitrary behavior.

The trusted-host assumption also limits resistance to pre-existing same-user
interference during the initial installation UI. It does **not** merge installation
and collection authority or replace UAC, exact displayed installation scope,
package trust or protected component ownership. Optional Elevated collection is
not part of this MVP and retains its separate future design/consent review.

## 2. Permission envelope: authorization is not readiness

| Work | User-approved scope | Still requires a concrete boundary |
|---|---|---|
| Repository implementation | Edit SecApp sources, implement the adapter/launcher and run local builds/pure tests | Independent review of the applicable architecture slice before runtime development; preserve unrelated WIP and immutable published schemas |
| Official backend acquisition | Selected official asset, detached signature and public key in a dedicated external acquisition directory; verification without system trust-store import | Review exact URLs/version/metadata, compressed versus executable byte domains and key provenance; no execution just because download succeeded |
| Controlled execution | Fixed Version, separately confirmed Help, then specifically reviewed read-only collectors; owned-process stop and owned-temp cleanup | Accepted launch boundary, exact test/operation/limits/effects, current asset trust and required consent; no generic shell/VQL/native-probe permission |
| Installation | In principle: SecApp-owned code/data directories and ACLs, one narrow service and required installation/event-source registration; scoped rollback/uninstall | Show and review the exact paths/keys/service/account/rights/effects first, obtain explicit installation confirmation and any UAC; no installation in this pass |
| Missing build tools | Only the concrete agreed tool list if existing tools are insufficient | No dependency/toolchain installation by implication, no package-manager scripts or PATH changes without their specific review |

Opening `C:\Dev\SecApp` as the writable workspace is an approved workflow
direction, not a change to the active tool sandbox. Until the user/app changes
that workspace, use the existing explicit repository-write permission boundary;
do not alter Windows permissions to work around it.

D-061 permits proposing necessary targeted grants only to the separate SecApp
service account in a future installation. The exact rights, holder and effects
must be reviewed and separately confirmed; no grant is authorized now. See
[the current account-rights proposal](broker-bootstrap-contract.md#8-d-061-scoped-service-account-rights-proposal).
No blanket admin session, LocalSystem fallback, broad/group grant or automatic
UAC loop is authorized. The installer and any future administrative helper are
limited-purpose authorities, not permission to run the entire UI or backend
elevated. Standard collection remains the default.

The future installer must independently derive/validate its exact mutation plan
against protected package/ownership policy before effects. A caller's approval
flag, copied manifest or UAC acceptance alone is not scoped installation authority.
Keep requester/operation binding, replay rejection, other-user separation and
refusal on unknown ownership; the trusted-host assumption does not remove them.

Keep real evidence, raw stdout/stderr, dumps, downloaded assets/signatures/keys,
compiled EXE/DLL/PDB and caches outside Git. No commit, push, tag, Git config
change, Windows security-policy change or Defender Offline troubleshooting
mutation follows from D-058.

## 3. Replace zero system change with an exact effects boundary

Do not change the settings being audited: Defender, firewall, BitLocker, Secure
Boot, WinRE, UAC and other protection settings remain untouched. No remediation,
reboot, memory acquisition, Defender exclusions, driver, scheduled task, global
PATH/trust-store change or audit-data upload is included.

Separately approved installation may create only its listed SecApp-owned
components and registrations. Ordinary operation may use reviewed private
working/result/temp files and disclosed normal event logging. These are effects
to specify, not a promise of no writes anywhere. Retention, encryption/key and
crash behavior still need the existing privacy review before sensitive collection.
Do not edit existing unrelated registrations or erase system logs during cleanup.

The [v0.77.3 startup finding](backend-release-review.md) remains valid: Windows
startup calls event-source installation before Version/Help dispatch and may
log argv. Under D-058 the existence of an installation-related effect is no
longer an absolute product-policy rejection. Its exact keys, access, existing-
source behavior, runtime fallback and logged data still require review and an
explicit effects disposition. This is not permission to let an ordinary check
reconfigure Windows, pre-create that source now or run the backend elevated.

Network access for approved acquisition is separate from collection. The MVP
retains the offline collection requirement and its enforcement review; no
service proxy, runtime metadata fetch or firewall-policy change is implied.

## 4. Historical TL findings versus current MVP obligations

The old records, expected JSON, immutable launch-plan schema and tests remain
unchanged. They describe the strict profile and may still say Open/Blocked.
The current planner is a diagnostic of that historical contract, not the future
MVP admission authority. Never change its flags or reinterpret its digest as
permission. A later executable contract must identify its own reviewed scope.

| Historical gate | Retained MVP requirement | Stronger guarantee deferred, not passed |
|---|---|---|
| TL-ADJACENT-DLL | Protected installed code/policy, safe known working/search context, no adjacent unapproved content accepted at preparation | Resistance to an already-compromised same-user session placing/substituting code during the run |
| TL-LINKED-TOKEN | Validate effective Standard rights, requester/session identity and handle ownership; no service/admin token or automatic elevation | Absence of linked-token metadata as an unconditional acceptance requirement; its presence alone is not effective elevation |
| TL-NON-ELEVATED-MECHANISM | Select and test a supported Standard service/supervisor launch route for supported accounts; no shim or elevated fallback | Same-user-malware-resistant worker/handle isolation; the mechanism itself is still required |
| TL-REPARSE-REPLACEMENT | Trusted protected code ancestry, reject unsafe/reparse/alias paths, create-new private outputs and safe cleanup | Adversarial replacement-race proof against an already-compromised same-user session; hostile imported paths remain in scope |
| TL-INITIAL-INVENTORY | Validate authenticated executable, launch policy and applicable pre-run conditions without executing workload to obtain trust | Complete pre-resume module inventory as a mandatory proof before any diagnostic |
| TL-PREVENTIVE-LOAD-POLICY | Review Windows loader/search/creation controls for the supported protected deployment; reject known unsafe context | Exact preventive allowlisting of every initial/future module against same-user malware; observation is still not prevention |
| TL-UNKNOWN-MODULES | Investigate concrete new trust/policy violations; historical classifications are not an allowlist | Requiring the four historical Unknown observations to be resolved before any narrower MVP work; no relabeling to Known/Passed |
| TL-IMAGE-BYTE-BINDING | Authenticate actual installed bytes, stabilize the protected path/file through creation, reject detected changes and maintenance overlap | Adversarial source-to-mapped-image attestation beyond the trusted-OS/protected-installation model; hashes are not described as that proof |
| TL-PRODUCTION-LOAD-CONTEXT | Composed protected deployment, fixed environment/arguments, Standard rights and safe working/data directories | Complete same-user-resistant loader/process isolation, not ordinary launch-context review |

This changes applicability, not past evidence. No single relaxation closes a
retained requirement. The existing prototype is not a production launcher and
its unsafe paths/Unknown-pass behavior must not be wired into the MVP.

## 5. Service and maintenance scope

Keep the chosen narrow demand-start service; this decision does not silently
switch to a portable launcher. Account/privilege selection, authenticated
requester binding, Standard token/session handoff, protected code, exact commands
and ownership/cleanup still need review and tests. The service must not become
an arbitrary execution, network or filesystem proxy. No automatic scan on start.

LS-001..008 are mapped individually below. All retained technical checks are
PendingAcceptance, not Passed; the service product direction alone was already
approved. No native test result is promoted to a new claim.

| Checkpoint | Retained MVP requirement and current status | Deferred assurance only |
|---|---|---|
| LS-001 | Service direction approved; package/bootstrap, account/SID/privileges and exact installation manifest PendingAcceptance | No general installation safety requirement is removed |
| LS-002 | Effective Standard worker rights, correct user/session, exact process/thread/token/handle ownership, no cross-user/service-rights leak or elevated fallback PendingAcceptance | Resistance to already-compromised same-user process/handle interference; linked metadata alone is not an elevation verdict |
| LS-003 | Authenticated bound local channel, exact trusted-host intent, expiry/single-use/replay and cross-domain rejection PendingAcceptance | Same-user-malware-resistant human display/input or peer proof; no protected confirmation desktop is required |
| LS-004 | Authenticated installed bytes, protected stable ancestry/path/file lifetime, unsafe-path rejection and maintenance exclusion PendingAcceptance | Stronger adversarial replacement and mapped-image attestation beyond that trusted-host model |
| LS-005 | Safe fixed loader/search context and reviewed supported creation controls; known unsafe configurations rejected, PendingAcceptance | Exhaustive pre-resume inventory and exact preventive allowlisting of all future modules against same-user malware |
| LS-006 | Preventive offline boundary, private storage and correct user-context/useful collector visibility PendingAcceptance | No additional data/privacy/offline guarantee is removed by this decision |
| LS-007 | Deadline/output/process bounds, timeout/cancel/crash cleanup, owned-tree/generation/quiescence evidence PendingAcceptance | No cleanup or maintenance-conflict guarantee is removed |
| LS-008 | Independent review and controlled positive/negative implementation evidence for this scoped profile before real handshake/end-to-end acceptance, PendingAcceptance | Strict-profile research results need not all become Passed; applicable MVP failures still block |

The first installed version can exclude automatic/hot updates, generic repair,
multi-version maintenance and reboot continuation. Define a separate narrow
initial-install/uninstall contract before implementing effects, rather than
claiming to implement all historical maintenance models with fewer checks.

| Historical maintenance area | First-release disposition |
|---|---|
| MMR-001 bootstrap/trust | Package/code trust, protected ownership and correct privileged peer remain mandatory; pre-existing same-user malware resistance is not claimed |
| MMR-002 confirmation | Exact displayed installation plan plus explicit UAC where required; no protected-desktop/independent-human-proof claim on a compromised session; installation is never collection consent |
| MMR-003 run/quiescence | Mandatory: no maintenance publication/removal over a live or uncertain owned run; lost liveness alone cannot prove cleanup |
| MMR-004 durability | Mandatory for implemented initial-install/run state: incomplete or contradictory state blocks; generic journal compaction/multi-generation recovery may be deferred with the absent workflow |
| MMR-005 packaging/ownership | Mandatory owned-object scope, trust and rollback behavior; full multi-version update/retirement protocol is not an MVP feature |
| MMR-006 retirement | No generic retirement endpoint or reuse of an Admitted record as authority; any failed-install cleanup needs its own reviewed ownership/consent contract |

Published maintenance schemas and reference models are not weakened. No omitted
feature may remain reachable through an undocumented IPC endpoint, installer
custom action or recovery fallback. Uncertain installed state blocks launch;
uninstall preserves user evidence and does not erase system logs.

## 6. Minimum acceptance gates and next work

The revised profile still requires evidence for each implemented slice:

1. **Backend trust and fixed operation:** official release/asset/signature/key
   policy, exact bytes and command contract; source/startup effects and output
   profile reviewed. Version strings/exit zero are not authentication.
2. **Standard launch boundary:** supported account/session route, protected
   code and safe paths/environment, exact handles/commands, no elevated fallback,
   no generic privileged service API or caller `ready/verified` override.
3. **Exact authority and effects:** trusted-host ordinary intent with domain-
   bound one-use action; distinct Version/Help and sensitive-collection consent;
   approved installation effects separated from read-only audited resources.
4. **Bounded lifecycle:** deadlines, per-stream and memory/process budgets,
   cancellation, crash/disconnect handling, whole-tree cleanup and honest failure.
   Cleanup uncertainty cannot produce success or allow conflicting maintenance.
5. **Private safe data handling:** existing hostile-input/schema/digest/consent
   rules, safe report rendering, reviewed retention/encryption/temp/crash policy,
   offline enforcement and honest NotTested coverage. No plaintext fallback or
   claim that local integrity proves absence of malware.
6. **Independent review and controlled evidence:** positive and targeted negative
   cases for actual requirements; document scope limitations in onboarding/report.
   Approval of this requirements change alone is not runtime acceptance.

Next implementable work is the bounded acquisition/verification slice: resolve
the v0.77.3 candidate's compressed/executable identities and signature coverage,
without executing it. Then finalize the narrower launch/effects/account contract
and independently review that slice before native implementation. Ordinary build
and scoped tests are allowed when that boundary is accepted; do not invent another
generic readiness model to replace the missing concrete implementation.

First real integration remains Version -> separately confirmed Help -> reviewed
read-only protection collection -> existing assessment/private report -> minimal
UI/package acceptance. No all-NotTested report counts as useful completion.

There is only the user's main computer available. D-058 does not authorize the
old TrustLaunchProbe matrix, arbitrary DLL/token/reparse probes, destructive
fault injection or installation failure experiments on it. Ordinary pure tests
remain usable; any later native test must state its bounded effects and accepted
test environment. No VM/security feature is installed by implication.

Independent requirements review: AcceptedRequirementsRebaselineOnly on 2026-11-06.
The read-only reviewer checked this document and all fifteen related changes;
no blocking findings remain for the requirements delta. Retained technical gates
are still PendingAcceptance; this does not accept runtime, service, installer or
native implementation. That pass changed documentation only; no binary acquisition,
compilation, native execution, UAC or Windows mutation. D-061's later narrow
permission delta is reviewed separately in the decision log/account proposal.

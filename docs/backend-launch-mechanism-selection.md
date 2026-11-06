# BACKEND-LAUNCH-MECHANISM-SELECTION1

Date: 2026-10-11. Scope: documentation-only mechanism comparison for the agreed
small first release. No native experiment, backend execution, installation,
service/account/profile creation, UAC, ACL or Windows configuration change.

Current overlay (D-058, 2026-11-06):
[TRUSTED-HOST-MVP1](trusted-host-mvp.md) broadens the trusted-host MVP beyond
confirmation and defines current permissions plus TL/LS/MMR applicability.
The service direction is retained. The statuses/comparison below are the earlier
stronger-profile record, not current blanket permission restrictions or proof
that every strict gate is required for MVP. No native mechanism is accepted yet.

## Recommendation and decision boundary

The user approved **a protected, narrowly scoped launch broker with a separate
Windows security identity and SCM-controlled bootstrap**, with a separately
constrained backend worker, for design on 2026-10-11 (D-052). This selects the
architectural direction, not a proved safe mechanism or permission to implement
a service. The next design is [SERVICE-LAUNCH-BROKER-DESIGN1](service-launch-broker-design.md).

```text
MechanismRecommendation = SeparateIdentityScmBroker
ProductDecision = ApprovedForDesign
NativeAcceptance = fail_with_blockers
ServiceImplementation = NotAuthorized
HostDeployment = NotAuthorized
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
```

This approval changes the earlier no-service direction in
[DEPLOY-001](protected-installation-design.md) only for the narrow launch broker.
A demand-start service still has persistent installed registration even if its
process stops when idle. Do not describe it as a no-install temporary helper.
Maintenance remains separate; no updater, scheduled scanner, installation,
service registration or system change is authorized on this computer.

The goal remains an unelevated UI and Standard collection without per-check UAC,
plus a future separately confirmed Elevated pass. A broker's own rights must
not silently become collector rights. Do not select LocalSystem, store a user
password, grant new account privileges or enable impersonation just because a
launch attempt otherwise fails. Account, worker token and required broker rights
must be justified together before native implementation.

## What the evidence does and does not decide

[NB-005](../tests/backend/native-boundary/README.md) obtained dangerous access
rights between two same-user synthetic processes with default descriptors.
It did not test every possible explicitly secured process descriptor, prove
injection, or prove that every same-user design is impossible. NB-003 showed
that PreferSystem32 did not prohibit explicit local DLL mapping. NB-004 blocked
one inert managed PE only after CLR startup. None selects a production loader.

Windows process access depends on process-object security, separately from file
permissions. Default process descriptors derive from a creator token; the
created-process handle itself carries broad rights. Therefore code-root ACLs
alone do not close the process/handle gap. This is a SecApp inference from the
[process access contract](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

Object ownership and default token ownership also matter. A design must account
for owner security-reset authority, inherited rights and any applicable
owner-rights controls, not merely remove one allow ACE after launch.
[Object ownership](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object).
No particular descriptor, ownership assignment or process-hardening sequence is
approved here. Closing a child handle does not protect a compromised supervisor.

## Candidate comparison

| Candidate | Useful property | Remaining obstacle | Disposition |
|---|---|---|---|
| UI directly creates same-user worker, with default descriptors | Small implementation; no per-run UAC | Observed dangerous peer access; mutable bootstrap and loader gaps | Reject as the required production boundary |
| Same-user protected files plus explicit process/thread descriptors | Could improve access control without a service | Trusted supervisor startup, ownership, retained handles and same-user request/confirmation remain unproved | Not ruled out universally; no accepted complete candidate currently |
| AppContainer/LPAC launched by ordinary UI | Resource, capability and network restrictions for a worker | Does not by itself establish an untampered launcher, exact user intent or collector coverage | Possible additional worker containment, not the whole launch mechanism |
| Short-lived elevated broker per run | Candidate different-integrity bootstrap without installed service registration | Repeated UAC changes the Standard UX; exact consent and worker identity still unresolved | Alternative only after a separate product decision, not fallback |
| Separate-identity SCM broker plus constrained worker | OS-managed bootstrap and separately securable control plane; target of no per-run UAC after setup | Persistent registration, extra trusted code, IPC/consent, rights and loader proof | Approved for design (D-052); not technically accepted or deployed |
| Device-wide App Control policy / driver-based protection / VM | May supply other boundaries | Changes deployment assumptions; VM observations are not automatically host observations | Not selected for the small local release |

AppContainer's dual-principal checks constrain access by both user and package/
capability identities. LPAC can restrict registry/COM access further; profiles
and capability selection are explicit setup concerns. This creates a collector
compatibility question, not permission to broaden ACLs until collection works.
Package SID, profile name or a successful launch alone is not accepted SecApp
caller authentication. No profile is created by this stage.
[AppContainer launch and capability model](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).

## Proposed broker boundary

These are requirements for the recommended candidate, not implemented behavior.

1. **Bootstrap and identity.** Preserve the protected versioned code/policy root.
   Bind the broker image, dependencies, SCM registration, account, service SID
   and effective object rights to reviewed installation state. SCM launches a
   service in its configured account context; service SIDs offer object-scoping
   tools, not automatic complete isolation. A shared service account is not by
   itself a per-product identity. [Service accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts),
   [service SID](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).
2. **Narrow command surface.** Accept registered operation/profile IDs and bounded
   action bindings only. No arbitrary image, shell/VQL string, path, environment,
   DLL, remote endpoint or user-supplied readiness flag. Start permission for the
   broker is not permission to collect. No scan on service start or crash restart;
   starting, authorizing and executing are separate steps. Client rights must
   exclude service reconfiguration, ownership/DACL changes and global stop of
   other runs. [Service access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).
3. **Worker identity.** Prefer preserving the authenticated requesting user's
   Standard context while independently securing process/thread objects and
   retained handles from creation. If that combination cannot meet isolation,
   changing to a separate worker principal needs an explicit scope decision.
   Service-context HKCU or profile data must never be labeled interactive-user
   observations. LocalService, for example, has its own HKCU, enabled privileges
   including impersonation, and anonymous network credentials rather than a
   network prohibition. It is not an automatically safe collector token.
   [LocalService](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account).
4. **Creation API candidate.** Evaluate CreateProcessAsUserW with an independently
   obtained, constrained primary token, fixed absolute application path and
   fixed arguments. Specify process/thread security, environment, handle list,
   Job and required creation-time policies before workload. Its privilege and
   session requirements must be satisfied explicitly, with no credential prompt,
   token theft, elevated retry or alternate API fallback. It still selects an
   image by name, not a verified file handle. [API contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
5. **Channel and consent.** Use a bounded local channel with independent peer/
   process/session binding and fresh single-use action scope. A same-user SID,
   PID, nonce or working pipe does not show that the human approved the action.
   A compromised UI can submit syntactically valid requests. The trusted exact-
   confirmation path remains a blocking requirement, not a checkbox delegated
   back to that UI. Services do not directly provide an interactive trusted
   dialog. Do not use interactive services or an autostart registry entry.
   [Service/UI separation](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services).
6. **Different authorities.** Launch control cannot install, repair, update,
   change security settings or consume a maintenance receipt as collection
   consent. Elevated collection remains disabled until separately designed and
   accepted. Parser/report handling stays outside the privileged broker; a
   malformed backend response must not gain service-level parsing authority.

The broker creates a potential confused-deputy and denial-of-service surface.
It must not gain broad privileges to compensate for an untrusted client.
Protect broker, supervisor, worker, threads, tokens and control handles together;
hardening only the worker does not suffice. Cancellation must be scoped to the
owned run. Unexpected identity, incomplete cleanup or recovery uncertainty blocks
new work. Existing Job experiments do not prove maintenance-lease atomicity.

## Loader, file and offline requirements remain separate

Retain current release authentication, immutable installed code, stable path/
handle lifetime, reparse/replacement rejection and verified-bytes-to-image proof.
All nine TL gates remain Open. Neither SCM nor an explicit process DACL closes
those gates, and linked-token criteria are not relaxed by this document.

Investigate creation-time signature/image-load restrictions against the exact
unchanged backend and dependency set. Signature categories are predefined;
MicrosoftOnly is not an arbitrary Rapid7 publisher/hash allowlist. NB-004 does
not establish startup compatibility or an exact release dependency policy.
Do not infer main-image incompatibility solely from its publisher either: that
needs specific creation-time evidence. [Signature-policy contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_binary_signature_policy).

If no supported policy satisfies the required dependency coverage, reject this
candidate or propose an explicitly reviewed evidence-policy change. Never
substitute observation for prevention, empty pre-resume inventory for success,
or install App Control/device policies as an implicit workaround. A future
AppContainer worker can be evaluated for offline confinement only with exact
capabilities and collector/provider behavior reviewed. No network-capable broker
proxy may bypass the worker policy. This stage does not establish offline
confinement, prevent all backend filesystem writes or authorize host changes.

## Small-release scope and acceptance checkpoints

Keep the agreed path: approved launcher -> Version/Help -> constant synthetic
collection -> reviewed read-only Defender/Firewall/BitLocker/Secure Boot profile
-> existing assessment/report pipeline. A profile's useful coverage under the
actual worker identity is an acceptance condition; an all-NotTested report is
not a completed useful collector integration. Missing individual coverage still
must be reported honestly. This document makes no new upstream capability claim.

No automatic updater, scheduled collection, generic remote API, memory acquisition,
remediation or reboot continuation is needed for that slice. Basic installation
trust, interrupted-install refusal/recovery and safe private storage cannot be
deferred. A first immutable installed version can defer hot updates, not bypass
active-run ownership or recovery uncertainty.

The following eight technical checkpoints remain **Planned / NotRun**. The user
approval portion of LS-001 is complete; its technical review is not. They
organize existing obligations, not eight new model suites or proof requirements.

| ID | Evidence needed before accepting this candidate |
|---|---|
| LS-001 | Product direction approved for design under D-052; signed bootstrap, account/service SID and installation mutation scope still require independent review |
| LS-002 | Exact broker/Standard-worker token and process/thread/handle owner/access matrix; same-user access negatives, including broker compromise paths; no elevated fallback |
| LS-003 | Authenticated local channel and exact human-action confirmation, with malicious same-user client, forged reply and replay negatives |
| LS-004 | Stable authenticated source-to-mapped-image chain, protected ancestry and replacement/reparse negatives |
| LS-005 | Creation-time preventive policy compatible with complete approved dependencies; prohibited initial/later load negatives and no Unknown |
| LS-006 | Offline/private storage behavior and useful collector visibility under the real worker identity; no service-profile/user-profile confusion |
| LS-007 | Timeout, cancel, broker/supervisor crash, bounded output and retained generation/quiescence evidence in the composed boundary |
| LS-008 | Independent native/security acceptance, then separately authorized real backend handshake and bounded read-only end-to-end run |

Direction selection and user design approval are complete; production mechanism
acceptance is not. If the service candidate fails the technical review, keep
launch blocked and return to an explicit alternative decision. Do not silently
weaken the same-user threat model or turn Standard into Elevated.

No code, schema, dependency, historical native record or launcher flag changes
are part of this stage. Git work-tree status checks returned an error during
the original selection pass; no Git configuration was changed. File-level
SHA-256 inventory matched the prior 198-file checkpoint before documentation
edits; it is not a substitute claim about a clean Git index/work tree.

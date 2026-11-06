# PROTECTED-INSTALLER-DESIGN1

Current precedence: [D-058 / TRUSTED-HOST-MVP1](trusted-host-mvp.md) replaces
blanket development/acquisition refusals and narrows first-release maintenance
scope. Installation is approved only in principle: exact owned paths/keys/service/
account/rights and rollback effects must be reviewed, presented and explicitly
confirmed before mutation/UAC. The older statuses below are historical, not
permission to skip that manifest or to implement every maintenance feature.
No installer or service has been run; audited security settings remain untouched.

Status: protected-installation direction approved for design under DEPLOY-001;
installer implementation, package build, independent review and host deployment
are not approved or completed by this document. Researched 2026-09-29 using
official Microsoft Learn documentation and the existing SecApp contracts.

```text
DeploymentDesignChoice = ProtectedPerMachine
InstallerImplementation = NotImplemented
HostInstallAuthorization = NotGranted
AutomaticUpdateAndRepair = Disabled
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
```

This stage changes documentation only. It does not compile a helper/MSI, invoke
Windows Installer or UAC, acquire a backend, change permissions/registry/Windows,
install dependencies, or run any installer/native acceptance test.

## 1. Design decisions and boundaries

- Use machine-protected, versioned code and policy locations. Normal use stays
  Standard; optional Elevated collection retains separate scoped consent.
- Prefer a signed x64 per-machine Windows Installer package for SecApp-owned
  files and product registration. This is an authoring target, not an existing
  installer, selected third-party toolchain or supported Windows release matrix.
- Installation, update, backend enrollment, repair and uninstall are explicit
  maintenance operations. There is no startup repair, scheduled updater, driver,
  startup scan or automatic UAC fallback. D-052 supersedes the original blanket
  no-service direction only for a narrow demand-start launch broker, approved
  for design, not implementation or host installation. See the
  [service boundary and proposed installation delta](service-launch-broker-design.md).
- No arbitrary command, destination directory, script, transform, downloaded
  extension or installer custom-action payload crosses the maintenance boundary.
- Velociraptor remains a separate unmodified product. The SecApp MSI does not
  bundle, re-sign, patch, fork or redistribute its executable, detached signature
  or public key. A future separately approved enrollment operation may verify
  and copy an already acquired official asset into protected storage without
  changing its bytes. Acquisition and that copy are not authorized now.
- Installing SecApp may end in BackendNotEnrolled or LaunchBlocked. Those are
  valid deployment outcomes; installation success is never launch readiness.
  Import-only operation does not depend on backend enrollment.

Microsoft distinguishes per-machine and per-user contexts; ALLUSERS=1 selects
per-machine, while ALLUSERS=2 permits context switching. SecApp's proposed
package must reject per-user fallback or destination/property overrides that
weaken its deployment boundary, rather than presenting such a fallback as the
same protected mode. [Installation context](https://learn.microsoft.com/en-us/windows/win32/msi/installation-context),
[ALLUSERS](https://learn.microsoft.com/en-us/windows/win32/msi/allusers).

The existing C# synthetic harness, trust-launch wrapper and development Node/Ajv
tools are not production installer/supervisor binaries. Production runtime
packaging, build provenance, code-signing identity and certificate lifecycle
remain prerequisites; no development dependency is silently shipped as runtime.

## 2. Separate consent and privilege domains

| Component/operation | Intended authority | Must not do |
|---|---|---|
| SecApp UI, importer, parser, renderer | Interactive Standard context | Install, repair, elevate itself, or write protected code/policy |
| Installation/maintenance transaction | Explicitly confirmed fixed operation; reviewed Windows elevation path | Collect audit data, invoke a backend, grant future collection consent |
| Standard supervisor and backend | Reviewed non-elevated launch boundary | Reuse setup authority or retry with elevated rights |
| Proposed launch broker service (D-052) | Independently admitted fixed Standard launch; separate service identity | Install/repair/update itself, confer maintenance consent, or pass its own rights to the backend |
| Optional Elevated collection helper | Fresh action-bound collection consent plus reviewed elevation | Install/update/repair, expand check scope or persist a service |

Before maintenance, show operation, authenticated publisher, exact component
versions/digests, affected location classes, data-preservation behavior, offline
behavior and any blocking condition. A package filename or an unprivileged UI
claim of verification is not authority. Revalidate at the privileged boundary.
Cancellation/decline means no operation and no retry loop. Being already elevated
does not waive the explicit maintenance scope confirmation.

The current Administrative ConsentReceipt only authorizes
CollectPrivilegedReadOnly, not software installation. Do not reuse that receipt
or insert installer operations into immutable v1 ActionLog/ConsentReceipt enums.
Maintenance needs its own reviewed, versioned request/receipt protocol, including
operation, component identities, manifest/policy digests, expected deployment
generation, machine binding, one-time nonce and expiry. It must reject replay,
scope substitution and caller-controlled destinations. That protocol is not
implemented or assigned a production schema ID in this stage.

The subsequent [maintenance protocol proposal](maintenance-protocol-design.md)
defines helper-owned confirmation, local peer binding, protected single-use
admission and separate recovery. It remains DesignOnly: its 28 acceptance cases
are Planned/NotRun, and PID/SID/UAC or a client receipt cannot replace the helper's
independent validation and exact operation confirmation.

Setup approval is not approval for network access, reboot, data migration or
deletion, security-control changes, or elevated auditing. The installer must not
launch Velociraptor for version/help/health checks and must not auto-start SecApp
from its elevated context when installation finishes. The user starts the app
later in their ordinary session. Installation using another administrator's
credentials must not create audit storage in that administrator's profile.

## 3. Location and permission contract

These are logical layout proposals, not literal paths to create. Resolve known
folder locations through the reviewed platform mechanism; do not trust caller
environment variables, string prefixes or a conventional folder name as proof
of the security boundary. ProgramFiles64Folder is the installer-provided x64
program-files location. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/msi/programfiles64folder).

| Location class | Intended contents | Intended access |
|---|---|---|
| ProgramFiles64Folder / SecApp / App / version-id | Published SecApp binaries and fixed resources | SYSTEM and Administrators maintain; ordinary Users read/execute |
| ProgramFiles64Folder / SecApp / Backend / asset-id | Separately enrolled exact backend bytes and public release metadata | Same machine-protected ownership; ordinary Users read/execute |
| ProgramFiles64Folder / SecApp / Policy / policy-id | Approved release/dependency manifests, verifier policy and public trust anchors | SYSTEM and Administrators maintain; Users read only |
| CommonAppDataFolder / SecApp / Deployment / Published | Minimal selected component tuple and generation | SYSTEM and Administrators maintain; Users read only |
| CommonAppDataFolder / SecApp / Deployment / Private | Transaction journal, private candidate staging and recovery state | SYSTEM and Administrators only; not a runtime-user drop directory |
| Interactive user's future private data root | Audit data, reports, consent and run storage | Outside installer ownership; blocked on the existing privacy/storage design |

The intended machine-object owner is the built-in Administrators group, not
the interactive user's SID. Use well-known SID identities, not localized names:
SYSTEM S-1-5-18, Administrators S-1-5-32-544, Users S-1-5-32-545. The final explicit
descriptors and inheritance rules require review and native tests. Do not ship
an untested SDDL string from this prose. A successful ACL-setting call alone is
insufficient: verify effective create/write/delete/rename/security-change rights
on files, parents, staging and selectors, including filtered-admin accounts.

Ordinary users receive no write, delete-child, ownership or DACL modification
rights on code/policy/deployment objects. Published directories must not inherit
broader permissions. Private candidate files cannot be exposed as runtime code
before verification and final security checks. Existing untrusted/reparse roots
must be rejected, not recursively taken over or "repaired" on the spot.

MsiLockPermissionsEx can express security for installer-owned objects, but its
existence is not proof that this layout is safe. Use one reviewed permissions
authoring approach, check failures and validate the resulting ownership and
access. [Microsoft table contract](https://learn.microsoft.com/en-us/windows/win32/msi/msilockpermissionsex-table).

No payload, report or secret belongs in MSI properties, cabinets, deployment
selectors, machine-wide logs or product registration. Installer-managed Windows
cache/rollback files are not SecApp scratch space and must not be manually
deleted. User audit storage is neither created nor migrated by installation;
its encryption, retention and cleanup gates in [privacy-model.md](privacy-model.md)
remain unchanged. Uninstalling code does not authorize deleting user evidence.

## 4. Package and backend admission

The following sequence is required, not implemented:

1. Bound the request to an exact operation and authenticated manifest. A source
   file selected by the user is untrusted input, never an executable command or
   trusted destination. Resolve acquisition consent separately; no implicit URL
   download, certificate retrieval or dependency restore.
2. Authenticate the installer/verifier itself before relying on it. Review its
   startup dependencies and DLL context: checks inside a verifier cannot protect
   code that ran before those checks. UAC displaying a publisher is not the whole
   SecApp package/scope/rollback policy.
3. Validate package identity, signature/trust policy, complete membership,
   whole-file digests, architecture, supported platform, dependency tuple and
   security epoch. No arbitrary MST/MSP, additional cabinet, custom action or
   increased limit is accepted merely because the outer package is signed.
   MSI signatures can cover multiple resource types; all used resource paths
   need explicit review. [Microsoft signatures](https://learn.microsoft.com/en-us/windows/win32/msi/digital-signatures-and-windows-installer).
4. Across the elevation boundary, independently re-establish source identity
   and bounded content. Never trust a UI-supplied verified flag, temporary path,
   source ACL, digest cache or inherited writer handle. Stage from a stable
   bounded read into a new maintenance-owned candidate and verify the copied
   bytes again; no link-preserving copy or extraction into a published tree.
5. For backend enrollment, require the reviewed current release size/digest,
   detached signature/key identity, PE architecture and Authenticode policy.
   The v0.77.1 historical pin and offline no-revocation observation are not a
   current approval. Never alter the official bytes, execute them to obtain
   identity, or automatically remove origin/security metadata to bypass checks.
6. Validate code-root ancestry, no-follow/reparse and alias policy, security
   descriptors, expected exact file set and version bindings. Unknown or unsafe
   existing content rejects the transaction; do not trust a suffix such as .exe.
7. Enroll verified components as deployment inventory only. Activating a selected
   tuple cannot set execution_enabled, close launch gates or manufacture a
   collection authorization. The native launcher still revalidates its own
   runtime conditions on each explicit action.

Cryptographic authenticity, offline trust freshness and revocation are separate
questions. If the chosen offline policy lacks required trust information, fail
closed with TrustDataUnavailable; do not silently fetch it or relabel stale data
as fresh. SecApp's no-network intent is not a claim that all OS/UI/security-agent
behavior on the host is network-isolated.

## 5. Version selection and transaction model

Select one compatible tuple: SecApp version, supervisor version, optional backend
asset, policy version, contract compatibility and security epoch. Version strings
are not filesystem paths. The selector contains bounded identifiers resolved
under protected roots, no command lines, paths, secrets or caller-provided code.
A digest in untrusted mutable storage is not a trust anchor; protect selector,
rollback floor and verifier policy from the in-scope ordinary attacker.

All maintenance writers must be serialized. Runtimes must bind a run to one
generation and retain the required identity/lease handles until the owned tree
is reaped. Before publishing or removing a version, maintenance must establish
that no compliant runtime can start on or still owns the affected generation.
Busy/uncertain means defer, not kill processes or fall back to an unsafe update.
A PID file, named-object name, filesystem scan or empty user-supplied lease list
alone cannot establish this condition. A concrete OS admission/lease primitive
with anti-squatting, permissions and crash semantics remains a blocking design
item; this state model does not pretend to implement that primitive.

| State | Required evidence before next state | Failure/cancellation behavior |
|---|---|---|
| Requested | Fixed operation, fresh confirmation, authenticated desired tuple and expected current generation | Reject without privileged mutation |
| Prepared | Maintenance admission acquired; private staging and journal identities/security established; current generation recorded | Remove only owned unpublished candidates; preserve current selection |
| Staged | Exact bounded copied package/member set; independent destination verification; no execution | Reject candidate; never select partial bytes |
| Verified | Component/policy signatures, byte identity, final security and compatibility all pass | Preserve current generation if still permitted |
| PublishPending | Runtime admission closed; affected generation quiescent; complete durable intent and candidate ready | On interruption require explicit recovery, not guessing from folder names |
| Committed | Complete selector generation and security floor durably consistent; actual files agree with the selected tuple | Return Installed or BackendNotEnrolled; launcher gates still apply |
| CleanupPending | Committed generation revalidated; old components unreferenced and safe to remove | Keep inactive remnants and report cleanup pending; never falsify success of deletion |

Publishing a selector and its journal/floor is not assumed to be one filesystem
transaction. Implementation must define exact write/flush/replace ordering,
durability assumptions and recovery at every interruption point. Do not combine
half of one generation with another. A missing/corrupt/inconsistent descriptor
or ambiguous journal yields RecoveryRequired and blocks new direct launches.
Read-only startup may detect this; it may not auto-repair or invoke UAC.

### Recovery and rollback

- Before publish intent: the previously committed selection remains usable only
  if its independent validation and security floor still permit it. Discard only
  the unpublished, identified candidate; no broad recursive deletion.
- After publish intent but before a complete consistent commit: do not guess
  whether old or new files should run. An explicit maintenance recovery action
  revalidates the journal, both tuples and owned objects, then completes a valid
  commit or restores a still-permitted previous tuple.
- After commit: cleanup failure does not revert policy or delete the newly
  selected generation. Keep machine-private recovery metadata until the
  explicit cleanup succeeds; report outstanding work.
- Functional recovery cannot lower the protected security epoch. A newly revoked
  or below-floor former version is not a fallback; if no permitted tuple remains,
  launch stays blocked. Ordinary setup/uninstall/reinstall must not reset that
  floor to permit an old signed release. Floor reset and emergency downgrade are
  outside the initial workflow and require a separate recovery/trust decision.
- MSI rollback and SecApp selector/backend enrollment are distinct transaction
  domains. Never assume rollback in one reverses the other. Prefer declarative
  MSI actions for MSI-owned resources; any necessary fixed custom action needs
  separately reviewed rollback/idempotence and interruption tests. Reject a
  required transaction when rollback is disabled. Microsoft documents limits
  on undoing direct system changes made by custom actions.
  [Rollback custom actions](https://learn.microsoft.com/en-us/windows/win32/msi/rollback-custom-actions),
  [installer rollback](https://learn.microsoft.com/en-us/windows/win32/msi/rollback-installation).

Side-by-side versions are an intended update discipline, not permission to
accumulate unlimited copies. Retained-version/storage bounds and recovery-journal
retention must be fixed in the next contract review. Do not remove the last
permitted rollback candidate, erase evidence or weaken a limit to make space.

## 6. MSI integration, repair, uninstall and reboot policy

The initial authoring target is per-machine, offline and explicitly initiated.
Use fixed signed content; no nested installers or downloaded prerequisites.
The authoring framework, stable product/upgrade identities, component ownership,
major-upgrade ordering and code-signing pipeline must be selected and tested
before producing an MSI. Product registration, protected owned resources and
reviewed non-advertised shortcuts remain in the proposed mutation scope. D-052
adds a design-only delta for one launch-broker registration, its identity,
reviewed security descriptors and bounded owned state; exact changes still need
independent review and separate host-install approval. No service is installed
by this document. PATH, tasks, Defender exclusions, firewall rules, trust-store
certificates, device policies, collection settings and reboot continuation remain
excluded. Do not use advertised entrypoints to turn normal launch
into implicit repair/elevation. No exact MSI GUIDs or ready-to-run commands are
invented in this design.

Files in use cause Busy/defer. Never automatically close another application,
terminate an audit or relaunch it elevated. MSI/Restart Manager behavior must be
authored and checked accordingly, including non-default host policy; a single
property is not accepted as proof of the whole behavior.
[Microsoft Restart Manager control](https://learn.microsoft.com/en-us/windows/win32/msi/msirestartmanagercontrol).

Use the reviewed no-automatic-reboot policy, with REBOOT=ReallySuppress as an
authoring requirement, no ForceReboot/ScheduleReboot actions, and no custom reboot
commands. Microsoft distinguishes this value from Suppress, which does not
suppress all mid-installation restart cases. A reboot-required outcome is not
"ready to run"; record the pending state and require a separate user decision.
Do not create a scheduled continuation or consume an audit Reboot receipt.
[Microsoft REBOOT property](https://learn.microsoft.com/en-us/windows/win32/msi/reboot).

Repair verifies and restores only approved package-owned objects under an exact
manifest and current floor. It does not recursively reset ACLs of an arbitrary
existing directory, trust data found in the cache, or reset a failed launch gate.
Unsafe ownership, unknown files or reparse components require controlled recovery.

Uninstall first prevents new product launches through the reviewed admission
boundary and waits for owned activity to finish; otherwise it defers. It removes
only proven package/enrollment-owned code and registrations. It does not delete
external source binaries/caches or enumerate other users' profiles. Preserve
user data by default, disclose any retained protected security-floor/tombstone
state, and offer no silent full wipe. Removing audit data requires a separate
privacy-aware operation, with no claim of physical erasure. Windows Installer
must manage its own product cache; SecApp never purges it directly.

## 7. Planned acceptance cases

All cases below are Planned / NotRun. They are not native/install evidence or
executed test fixtures. Each needs bounded synthetic inputs and isolated lab
authorization before system-side testing.

| ID | Required result |
|---|---|
| PI-001 | Valid SecApp-only install reaches Installed/BackendNotEnrolled without a backend process |
| PI-002 | Valid separately authorized enrollment preserves exact official bytes; no backend invocation |
| PI-003 | Declined/cancelled/expired confirmation causes no mutation, UAC retry or authority reuse |
| PI-004 | Other-admin credentials do not create user data in the wrong profile or leave interactive-user-owned code |
| PI-005 | Wrong signer/hash, unknown member, altered resource or incompatible tuple rejected before publish |
| PI-006 | Source replacement across elevation/copy cannot change admitted destination bytes |
| PI-007 | Per-user fallback, writable target/property/transform override and custom-action injection rejected |
| PI-008 | Same-user file/adjacent-content/owner/DACL modification denied for code, policy and selector |
| PI-009 | Pre-created roots, ancestor/leaf reparse swaps, hard links and alternate streams cannot redirect writes/deletes |
| PI-010 | Concurrent maintenance or squatted coordination object cannot publish conflicting generations |
| PI-011 | Active run and new-launch race cause Busy/defer; no process killing or in-place overwrite |
| PI-012 | Crash/cancel/disk-full/access-denied at every transaction boundary yields an unambiguous permitted state or RecoveryRequired |
| PI-013 | Replayed journal/consent, stale expected generation and foreign component/machine binding rejected |
| PI-014 | Missing/corrupt selector or mismatched floor cannot pick a version by directory enumeration |
| PI-015 | Failed update never reactivates a revoked/below-floor version; reinstall does not reset the floor |
| PI-016 | Partial MSI/custom-action/enrollment failure cannot claim cross-domain atomic rollback |
| PI-017 | Locked old files or cleanup failure preserve the committed generation and report remaining work |
| PI-018 | Repair/uninstall stay within manifest-owned objects; user evidence and external sources remain untouched |
| PI-019 | Offline trust-data failure causes no hidden downloads, revocation retrieval or dependency installation |
| PI-020 | Reboot-required/files-in-use outcomes cause no forced reboot, app shutdown or scheduled continuation |
| PI-021 | Setup success never closes a trust-launch gate, creates audit consent or launches an elevated UI |
| PI-022 | Logs, MSI properties and retained diagnostics contain no secrets, raw evidence or unapproved personal paths |

## 8. Next implementation boundary

DEPLOY-001 is resolved only as a product-design choice. The subsequent artifact
`DEPLOYMENT-PLAN-CONTRACT1` now implements strict development-only contracts and a pure state model for
fixed maintenance intents, generation/epoch rules, cancellation/recovery and
negative substitutions. It must have no filesystem writer, process/UAC entrypoint,
installer invocation, arbitrary command or ready-to-execute output. Pure model
tests cannot close PI or native launch gates. See [the model contract and
limitations](deployment-plan-contract.md); it supplies no installer code or
authenticated production maintenance receipt.

Remaining implementation blockers are concrete, not a renewed request to choose
portable versus installed deployment:

1. production artifact/build/signing and runtime packaging identities;
2. authenticated maintenance consent/protocol, trust freshness and rollback-floor
   storage, including uninstall/recovery semantics;
3. exact tested security descriptors and supported filesystem/OS matrix;
4. cross-process admission/lease and crash-consistent selector publication;
5. MSI ownership/action ordering, bounded retention and cross-domain recovery;
6. all nine [image/launch gates](backend-image-trust-design.md), private audit
   storage, offline enforcement, and independent composed-boundary review.

No package, installer script, service, production adapter, new schema, executable
model or native result is created by this design-only stage.

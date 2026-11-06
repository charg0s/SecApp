# DEPLOYMENT-PLAN-CONTRACT1

Status: implemented development-only contracts and pure synthetic state model.
This is not an installer, privileged protocol, authentication system, rollback
store, or evidence of successful deployment. HostInstallAuthorization remains
NotGranted; InstallerImplementation remains NotImplemented. All nine launch
gates and the 22 PI acceptance cases retain their previous status.

## Contract and authority boundary

The Draft 2020-12 scenario/projection schemas live in `schemas/development/`
under immutable `/v1/development/` identifiers. They do not change the existing
v1 ConsentReceipt, Administrative authority, ActionLog or AuditPass. In these
isolated development schemas, PublicSynthetic means synthetic fixture metadata
only, not permission to publish real deployment data. Fixed synthetic machine
names and bounded synthetic component IDs replace host names, paths and SIDs.
Do not put real data or secrets into IDs or digest fields.

`tools/lib/deployment-model.mjs` accepts only plain bounded data. It performs
no file access, process launch, clock read, network operation, UAC, installation
or cleanup. Time is supplied explicitly as canonical UTC whole seconds. The
model uses only strict data checks and existing JCS/SHA-256 helpers. Ajv remains
a pinned development-only test dependency, not a new production dependency.

Every output has installation, backend execution, UAC, network, reboot, user-data
deletion, automatic recovery and filesystem writes disabled. Installer status
is NotImplemented and launch status is Blocked, even for Completed projections.
There is no command, destination, arbitrary MSI property, transform, callback,
readiness flag, force override, native bridge or execution API.

The input is a hypothetical snapshot, fixed intent, synthetic confirmation,
declared used-nonce set and event trace. Every event represents an assumed
condition, not an implemented verifier: for example Verify does not authenticate
a package, BeginPublish does not acquire a lock or establish quiescence, and
Commit does not flush or publish anything. A model result cannot authorize a
host operation or close any installer/image-load acceptance case.

## Fixed operations and identity binding

| Operation | Model scope |
|---|---|
| Install | No current selection; desired SecApp tuple without a backend |
| Update | Existing selection; backend identity unchanged; changed full manifest |
| EnrollBackend | Existing selection with no backend; add only backend identity and changed full manifest |
| Repair | Exact same complete tuple, including every identity, digest and epoch |
| Uninstall | Existing selection to null; preserve security floor and all user data |

Backend replacement/removal, recovery execution, emergency downgrade and floor
reset are intentionally absent. They require separately reviewed future
contracts. Package signatures, actual manifest membership/compatibility, current
revocation data, byte identities and ACLs are not verified by this model.

`maintenanceBindingDigest` computes SHA-256 of JCS over exactly
`{machine_id, snapshot, intent}`. The snapshot includes generation, floor and
the complete old tuple; intent includes operation, expected/next generation and
the full desired tuple, including manifest and policy digests. Confirmation
must match this binding, operation, machine and expected generation exactly.
Only an Approved SyntheticMaintenanceConfirmation, not an audit receipt, is
accepted. It has a nonce and a positive window of at most 300 seconds, with
`issued_at <= simulated_at < expires_at`; a nonce in used_nonces is rejected.

This is scope/replay **modeling**, not authenticated consent or real single use.
The caller can fabricate all fields and recompute hashes. The supplied nonce
list is not trusted storage, no nonce is persisted, and identical calls produce
identical results. Confirmation is marked consumed only in the projection at
Prepare. A production protocol must establish identity/authentication, trusted
time, atomic nonce consumption and protected durable state independently.

The next generation must equal the snapshot generation plus exactly one, using
safe nonnegative integers and rejecting overflow before addition. A desired
epoch cannot be below either the protected floor hypothesis or current epoch.
A selected tuple already below the floor produces RecoveryRequired immediately.
At BeginPublish the conservative minimum floor becomes the maximum of old floor,
old epoch and candidate epoch. Uncertain publication cannot assume the higher
floor was never persisted; successful commit and uninstall preserve it.

## Lifecycle and failure model

The only forward chain is:

```text
Requested -> Prepared -> Staged -> Verified -> PublishPending
          -> Committed -> CleanupPending -> Completed
```

Each transition requires its exact event. Skipped/repeated steps, cleanup before
commit and events after a terminal failure/completion raise the controlled
DEPLOYMENT_MODEL_INPUT_INVALID error without echoing input. Invalid shapes also
raise that error. Structurally valid admission denials return Rejected without
processing events. Output data is deeply frozen; caller data is not mutated.

| Boundary | Cancel/failure/crash | Other outcomes |
|---|---|---|
| Before PublishPending | Cancelled or Rejected; unchanged snapshot | Busy/RebootRequired defer; missing trust or rollback support rejects |
| PublishPending | RecoveryRequired; no presumed selected tuple | Any uncertain event requires recovery; conservative epoch floor retained |
| After Commit | CleanupPending; keep committed generation and floor | No automatic rollback or claim that remnants were deleted |
| Inconsistent state at any boundary | RecoveryRequired; selection unknown | Never infer a valid selection from a state label |

TrustUnavailable after commit also yields RecoveryRequired, not merely pending
cleanup: the projected selection cannot remain trusted without required trust
data. The conservative floor still remains in force.

PublishPending itself exposes no selected snapshot. RecoveryRequired is terminal
in this model: it cannot resume, choose old/new files, retry UAC or consume old
approval. Completing recovery needs a future explicit freshly authorized
protocol and independent revalidation. A floor reservation may conservatively
prevent fallback to the old epoch; availability does not override this rule.

Completed outcome is Uninstalled, BackendNotEnrolled or InstalledLaunchBlocked,
never Ready. Post-commit cleanup failure is a distinct incomplete outcome even
though the committed tuple is retained. No shared transaction across MSI and
selector/enrollment is claimed.

## Limits, validation and next boundary

Scenarios have at most 32 events, 64 distinct used nonces and 64-character
synthetic identifiers. The five-minute confirmation bound is a fixed model
policy, not a reviewed production consent lifetime. These limits do not settle
production disk/version retention or journal lifetime. That remains open.

`scenario_digest` is SHA-256 of the entire scenario's JCS; `result_digest` is
SHA-256 of the entire projection's JCS excluding only result_digest. Neither
is a signature or trust anchor. JSON Schema validates structure and the explicit
non-authority invariants; relational/state/digest validation additionally
requires the model and comparison with its complete deterministic output.
The model is stricter than JSON representation in rejecting negative zero,
accessors/proxies, exotic prototypes, hidden/symbol properties and sparse arrays.
It also rejects noncanonical dates, including leap-second labels.

Run `npm run test:deployment-model` or the full `npm test`. DP-001 through DP-040
are exact required pure-model vectors, with a separate completeness check; no
count-only acceptance or skipped required vector is allowed. Tests compile both
schemas in the existing strict offline Ajv2020 registry, include schema-valid
semantic negatives and targeted unsafe output mutations, and do not invoke
native code. They are not PI-001 through PI-022 native test evidence.

The subsequent [maintenance protocol design](maintenance-protocol-design.md)
proposes the helper authority boundary, durable single-use admission, bounded
messages and separately confirmed recovery. It is not implemented authentication
and does not change this model's synthetic schema/operations. The next bounded
implementation slice is a separate development-only message/state contract model.
Packaging/signing identities, OS/filesystem support, protected storage/retention,
runtime leases and native fault tests still require their own review and
authorization. No installer or backend execution is enabled here.

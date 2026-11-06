# BACKEND-IMAGE-TRUST-DESIGN1

Current precedence: [D-058 / TRUSTED-HOST-MVP1](trusted-host-mvp.md) maps the
stronger image/loader/local-attacker proofs below to retained MVP safeguards and
deferred guarantees. This document retains the earlier research requirements;
it does not force every strict proof back onto the trusted-host MVP. No historical
finding becomes Passed and no unsafe concrete launch context is thereby accepted.

Status: design proposal completed; DEPLOY-001 approved for further installer
design, not implementation or deployment. Independent review remains pending.
Researched 2026-09-29 using local sources and, with separate user permission,
official Microsoft Learn documentation. No binaries were downloaded,
compiled or executed; no native probes, UAC, ACL/registry changes or installation
were performed. This document grants no launch authority.

## Outcome and selected design direction

Keep the existing nine launch gates open. The synthetic supervisor establishes
bounded lifecycle observations, not trusted image loading. Do not extend it into
a production adapter by adding a caller-supplied executable path.

The user-confirmed design direction is a protected, versioned installation
for executable code and trust policy, with everyday Standard operation remaining
unelevated. Installation/update authority is separate from collection authority;
optional Elevated collection still requires fresh scoped consent. This approves
further design, not building/running an installer or changing this computer.
The next design is recorded in [PROTECTED-INSTALLER-DESIGN1](protected-installation-design.md).

A protected installation addresses a different problem from a restricted child
token. It is not, by itself, a proof of preventive DLL policy, mapped-image
identity, same-user process isolation, or protection from a compromised OS.
Those remain explicit acceptance conditions below.

## Existing evidence, not new measurements

- The historical prototype permits creation of an adjacent `probe.dll` marker.
  This demonstrates writable placement, not that the marker was loaded.
- The new [synthetic experiment](../tests/backend/native-synthetic/README.md)
  passed ten lifecycle cases in three final-source runs. Its restricted child
  remained effectively non-elevated with linked-token metadata Present.
- Four historical module classifications remain Unknown. No module inventory
  or new classification was performed in this stage.
- The [historical compatibility record](velociraptor-adapter-compatibility.md)
  identifies Rapid7 LLC Authenticode signing with offline, no-revocation checks.
  That is neither a current runtime trust review nor Microsoft signing.
- A digest recorded next to writable code cannot authenticate that code against
  an attacker who can replace both. The existing external-anchor requirement
  in [integrity-model.md](integrity-model.md) still applies.

## Documented API facts and SecApp inferences

These are API contracts, not results on a supported Windows/Velociraptor matrix.
Each SecApp inference deliberately stops short of a production proof.

| Documented fact | SecApp consequence |
|---|---|
| SetDefaultDllDirectories controls the calling process, including default dependency searches. | Calling it in the supervisor does not establish the child's loader policy. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories) |
| SetDllDirectory with an empty string removes the current directory; the API can also affect children of ordinary unpackaged/unprotected Win32 processes. | It is a distinct API with different inheritance behavior; it does not remove every unsafe source or constitute a complete preventive policy. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setdlldirectoryw) |
| NoRemoteImages excludes remote images; NoLowMandatoryLabelImages excludes low-label images; PreferSystem32Images gives System32 priority. | These controls do not amount to an exact allowlist of all local medium-integrity images. Preference is not System32-only enforcement. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_image_load_policy) |
| Binary signature policy offers Microsoft, Store and related predefined signing categories. | It is not an arbitrary Rapid7 publisher/hash allowlist. Neither compatibility with the pinned main image nor complete rejection of undesired DLLs is assumed. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_binary_signature_policy) |
| Creation attributes can specify child mitigations, inherited handles and Job assignment, with version-specific availability. | Required controls must be selected and applied before workload; unsupported required controls mean rejection, not dropping bits or retrying without them. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) |
| CreateFile sharing constrains conflicting opens while handles live; OPEN_REPARSE_POINT changes how the opened reparse object is handled. | Locks are useful evidence, not a transitive proof for every path component, writable adjacent name or later image load. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) |
| CreateProcessAsUserW identifies the application by name/path. Its restricted-caller-token exception concerns SE_ASSIGNPRIMARYTOKEN_NAME, not every privilege requirement. | It is not a documented verified-file-handle execution interface. Local restricted launch success does not establish all-account compatibility or image-byte binding. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw) |
| EnumProcessModulesEx can fail or be inaccurate when the loader list is uninitialized or changing. | An empty pre-resume list is not proof of no modules; resuming unknown code merely to make enumeration work is not an accepted workaround. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodulesex) |
| GetMappedFileName returns a mapped file's name. | A name, or a later reopen of that name, is not by itself evidence that previously authenticated bytes back the image. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew) |
| Filesystem security descriptors contain owner and discretionary access information; ownership includes security-reset authority in the documented model. | Owner-only access for the same user is not an independent principal boundary. Evaluate owner, WRITE_DAC/WRITE_OWNER, inherited rights and all relevant parent objects, not just a read-only flag. [Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/security-descriptors) |

No undocumented process-creation syscall, process hollowing, loader injection,
in-process patch of the unmodified backend, or compatibility shim is selected
to bridge these gaps. No native API constant is changed by this review.

## Candidate comparison

| Candidate | Standard operation | Main limitation | Disposition |
|---|---|---|---|
| Portable same-user directory plus random names and file locks | Could avoid setup elevation | No accepted same-user root/policy separation or complete loader/image binding proof | Retain for explicit development experiments only; not selected for production |
| Protected versioned installation; short-lived Standard supervisor | Target: no UAC for normal checks; separate approved setup/updates | Requires deployment ownership/ACL design, loader enforcement and process/IPC trust review | User-approved design direction under DEPLOY-001; not sufficient alone |
| AppContainer or separate-principal boundary | Potentially tighter resource/process separation | Collector visibility, identity, capabilities, setup and data transfer need review | Alternative research path, not an automatic fallback |
| App Control for Business deployment | Policy enforcement can apply without per-check UAC once provisioned | Device policy, administrator deployment, compatibility and recovery implications | Optional managed-environment candidate only; not a default product side effect |

AppContainer has file, registry, network and process isolation controls; whether
the required collectors remain useful inside the selected capabilities is a
SecApp question, not a confirmed compatibility claim.
[Microsoft AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation).

App Control offers file rules and an explicit user-mode enforcement option.
Audit mode is not prevention. Its Hash rules use Authenticode/PE image hashes;
do not substitute them for SecApp's whole-file SHA-256 release-byte check.
Deployment would need separate authorization, OS support review, recovery and
compatibility testing; SecApp must not silently install or weaken such policy.
[Microsoft App Control rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create).

## Proposed protected-installation contract

The following requirements describe the preferred candidate, not an implemented
guarantee. A failed requirement keeps direct execution blocked.

1. **Trust bootstrap.** Independently authenticate the SecApp supervisor, policy
   and backend release. The same attacker must not be able to replace verifier,
   trust anchor and payload together. Distinguish current release verification,
   permitted signer/key identities, exact whole-file bytes and rollback floor.
   The historical pin is not automatically the next supported production release.
2. **Code root.** Ordinary runtime users may read/execute but not create, replace,
   rename or change security on code, manifests, sidecar configuration or relevant
   ancestors. The code root is not the user-owned temp directory. Its path label,
   owner name, or presence beneath a conventional install location is not proof
   of these properties. Supervisor/dependencies need the same protection as the
   backend: a supervisor cannot bootstrap trust after untrusted startup code ran.
3. **Updates.** Use separately authorized, verified side-by-side versions. Bind a
   run to one version/policy and retain its stable handles. Do not replace active
   files in place, trust a user-editable current-version selector, or overwrite
   through reparse points. Failed update/recovery leaves the prior approved
   version or a blocked state, never an unverified fallback.
4. **Data separation.** Working, temp and output locations are data-only trust
   classes, separate from code, definitions, downloads and export. A private
   name is not proof against a same-user attacker. Loader/config lookups must
   not consume attacker-controlled data locations. If that cannot be enforced
   for the chosen unchanged backend, the candidate fails. Storage privacy,
   retention and crash behavior remain separately required.
5. **Handle/path lifetime.** Select a precise supported local-filesystem and
   path-resolution strategy. Establish and retain root/component/file identities,
   reject unreviewed reparse tags and aliases, and account for rename, hard-link,
   alternate-stream and pre-existing writer/mapping cases. A string prefix check,
   one leaf no-follow flag or a pre/post pathname comparison is insufficient.
6. **Image binding.** Document the whole chain from the authenticated held file
   through stable path resolution to the process image mapping, including each
   remaining OS assumption and update race. Do not report TL-IMAGE-BYTE-BINDING
   closed from FileId, GetMappedFileName or matching pre/post hashes alone.
7. **Preventive loading.** Select a supported creation-time policy that rejects
   prohibited image sources before their code runs, and review startup imports,
   dependent loads, delayed loads, extension points and explicit absolute loads.
   Reduced search order and runtime observation are supplemental controls. Define
   exactly which images/signing classes are allowed; an OS-signature category
   is not automatically a release-specific exact dependency allowlist.
8. **Initialization boundary.** Keep the child suspended until applicable checks
   pass. Define what initial mappings can be inspected without running workload
   and what later loads are prevented by policy. If the historical pre-resume
   inventory requirement needs a different evidence model, propose and independently
   review that change explicitly; do not turn an unavailable inventory into Pass.
9. **Rights and authority.** Standard begins from a verified unelevated parent;
   unsafe/elevated parents are rejected rather than silently de-elevated. The
   restricted-token route remains a candidate subject to a genuinely standard
   account, filtered-admin and refusal matrix. No linked-token criterion is
   relaxed here. Installation consent never authorizes Elevated collection.
10. **Process/IPC boundary.** Protected files do not establish process-object or
    request/result-channel isolation. Review same-user process access, helper
    substitution, handle duplication, request scope/replay and response spoofing.
    Process access is governed separately by process-object security.
    [Microsoft process access](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
    If the in-scope adversary requires a different principal or broker, stop for
    an explicit design/authority decision; do not silently exclude that attacker.
11. **Fail-closed completion.** Preserve the tested Job/IO/timeout/cancellation
    responsibilities, but re-test them with the composed production boundary.
    No unsupported mitigation, Unknown image, cleanup error or missing observation
    becomes an execution permission or a clean audit finding.

No persistent service is proposed by the protected-installation candidate.
There is no claim yet that all its requirements can be satisfied without one
or without another isolation mechanism. Read-only/offline collection and an
OS-level network policy still need their own evidence.

## Required evidence, not executed tests

Every row is Planned / NotRun. A marker placement test alone is not a loader
test. Future executable fixtures must be inert, synthetic and separately
authorized; never load unknown DLLs or real collectors to test prevention.

| ID | Review/negative vector and required result | Related gates |
|---|---|---|
| IT-001 | Approved version and reviewed dependency set complete a bounded synthetic workload without Unknown | All; positive control, not sufficient alone |
| IT-002 | Altered binary, signer/key substitution, stale trust data or disallowed rollback rejected before creation | Binary trust prerequisites |
| IT-003 | Ordinary same-user write/adjacent placement/security-change attempts against code/policy/ancestors denied | TL-ADJACENT-DLL, TL-PRODUCTION-LOAD-CONTEXT |
| IT-004 | Leaf or ancestor reparse/rename replacement across prepare/verify/create rejected or demonstrably cannot redirect | TL-REPARSE-REPLACEMENT, TL-IMAGE-BYTE-BINDING |
| IT-005 | Pre-existing writer/mapping, alternate stream, hard-link and pathname-alias cases cannot substitute execution bytes | TL-IMAGE-BYTE-BINDING |
| IT-006 | Prohibited same-name DLL in code/CWD/temp/PATH/dependency search locations cannot execute its inert sentinel | TL-ADJACENT-DLL, TL-PREVENTIVE-LOAD-POLICY |
| IT-007 | Prohibited delayed and explicit-path image loads blocked before sentinel execution, including local medium-label images | TL-PREVENTIVE-LOAD-POLICY |
| IT-008 | Missing mitigation, audit-only policy, unsupported OS or ineffective child policy rejected without weaker retry | TL-PREVENTIVE-LOAD-POLICY, TL-PRODUCTION-LOAD-CONTEXT |
| IT-009 | Empty/uninitialized/truncated initial inventory cannot pass; permitted and disallowed initial mappings distinguished | TL-INITIAL-INVENTORY |
| IT-010 | Each of four historical Unknowns classified with reviewed provenance/policy, or blocked; directory name alone insufficient | TL-UNKNOWN-MODULES |
| IT-011 | Source lock/identity/hash look-alikes do not override failed proof about the actual process image | TL-IMAGE-BYTE-BINDING |
| IT-012 | Standard/filtered-admin cases meet reviewed criteria; unsafe parent, rights mismatch and unsupported token launch rejected | TL-LINKED-TOKEN, TL-NON-ELEVATED-MECHANISM |
| IT-013 | Concurrent authorized update binds each run to one approved version; interruption cannot select partial/unverified content | TL-IMAGE-BYTE-BINDING, trust/update prerequisites |
| IT-014 | Missing setup or user refusal preserves import-only availability and NotTested coverage, with no UAC loop | Deployment and consent prerequisites |
| IT-015 | Helper/request/response substitution, replay and same-user process interference handled under reviewed boundary | Supervisor and exact-authority prerequisites |
| IT-016 | Timeout/cancel/crash/cleanup error under the complete policy leaves no unaccounted owned tree or success result | Supervisor/cleanup prerequisites |

Result records must separate required, executed, passed, failed and NotRun IDs;
absence of executable evidence cannot be represented by an all-Pass fixture.
No new evidence record is created by this design-only stage. No planner/schema
or historical expected result is changed.

## Deployment decision and remaining authorization boundary

**DEPLOY-001 (ApprovedForDesign):** the user confirmed protected-installation
design as the next product path, with explicit setup/update confirmation,
everyday Standard mode without elevation, and separately consented optional
Elevated checks. D-036 and [the installer design](protected-installation-design.md)
record the continuation. Approval to design it is not permission to implement or
run an installer, change ACLs, enable App Control, deploy a service, or start
Velociraptor on this computer.

Portable/no-setup is not the selected production direction; it remains an
alternative only if the user later changes the deployment requirement. Do not
quietly choose weaker guarantees to make a launch button work. Native DLL/reparse
experiments, installation and any first real Version/Help handshake each require
their own bounded authorization.

# BROKER-RPC-FEASIBILITY1

Date: 2026-11-06. Read-only QP-0 follow-up to
[the bootstrap contract](broker-bootstrap-contract.md#10-narrow-qualification-plan-and-wip-checkpoint)
after WIP checkpoint `7df849e72418aa9732bd08ba9a4be66a5048a4f4`.
The user authorized continued mechanism/design review, not installation or native
experiments. D-058/D-061 remain the permission and requirements boundary.

```text
CurrentTwoBindingCandidate = NoGoForNativeImplementation
ExplicitTokenHandleAlternative = ProposedForContractReview
RequirementsRebaseline = NotPerformed
QP0 = IncompleteConcreteMechanismRequired
NativeImplementationAdmission = BlockedPendingConcreteGaps
HostDeployment = NotPerformed
ProductionLauncher = NotImplemented
AutomaticBackendExecution = Disabled
```

## 1. Decision and documentary limit

Do not advance the section 9 IDENTIFY-control / IMPERSONATE-token candidate to
native implementation merely because its API settings and test plan are written.
The reviewed public API contracts do not establish all the required composed
properties below. This is insufficient evidence for this candidate, not a claim
that Windows cannot implement a secure broker, nor a failed native experiment.

| Retained obligation | What is established | What is still missing |
|---|---|---|
| Authenticate the recipient before exposing client authority | Local RPC supports expected-principal authentication; V4 provides an expected SID | Composed ordering for the proposed transport impersonation plus an accepted server-instance/generation mechanism |
| Reject cross-client, stale-instance and replayed authority | RPC context handles have documented session-scoped state semantics | A concrete integration with the protected service owner, generation, exact consent, restart and durable one-use admission |
| Protect the initial service process/thread/token | SCM logs on the service account and attaches its token | Exact initial object-security provenance/effective access; a post-entrypoint observation cannot establish the earlier interval |
| Bound work, cancellation and resources | Fixed records and application admission can bound application-owned data/work | Independent limits on initiation, RPC runtime work/allocation and cleanup; the chosen RPC knobs are not hard ceilings |

Sources: [binding authentication](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingsetauthinfoexw),
[QoS V4](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos_v4_w),
[context state](https://learn.microsoft.com/en-us/windows/win32/rpc/maintaining-state-on-the-server-between-calls),
[service accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts).
The missing guarantees are SecApp's assessment of these sources, not Microsoft
statements that the platform is unsafe.

There is a concrete limit correction: `RpcServerRegisterIf3.MaxCalls` is ignored
on the proposed non-autolisten interface, not merely an imprecise per-interface
cap. `RpcServerListen.MaxCalls` is a suggested process-wide concurrency limit,
not an absolute bound. `MaxRpcSize` does not limit ncalrpc, and
`RPC_C_OPT_CALL_TIMEOUT` is ignored for local/async calls. None can be presented
as enforcement of the proposed budgets.
[RegisterIf3](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3),
[ServerListen](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverlisten),
[binding timeout](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingsetoption).

Also, ncalrpc IMPERSONATE is not an offline boundary: Microsoft describes a
one-hop remote call on the client's behalf even at that level. The independent
preventive offline requirement remains; no network permission is added.
[RPC impersonation](https://learn.microsoft.com/en-us/windows/win32/rpc/client-impersonation).

## 2. Concrete alternative to review, not an accepted replacement

Study one authenticated, identification-only RPC session with a typed server
context and an explicitly transferred Standard primary-token capability. Do not
open a second impersonation-capable channel or mutate the first one's QoS.
This replaces the proposed transport handoff mechanism, not the security goals.

Windows documents MIDL `system_handle(sh_token, explicit-access-mask)` for local
token-handle transfer, available from Windows 10 1607 / Server 2016 with MIDL
`-target NT100` or later. The `[in]` duplicate lasts for the call; retaining it
requires a separate local duplicate. The default mask preserves source access,
so omitting the mask is unacceptable. No raw numeric handle, serialized token,
credential or caller-selected handle type belongs in a generic message.
[system_handle](https://learn.microsoft.com/en-us/windows/win32/midl/system-handle),
[sh_token](https://learn.microsoft.com/en-us/windows/win32/midl/sh-token).

Proposed sequence, with no IDL, stubs or executable implementation in this pass:

1. Protected installation policy fixes `S`, `U`, code and installed generation.
   Before listening, the broker must own an exclusive protected generation/run
   lease and reconcile durable state. A lock alone is not crash recovery or proof
   that an earlier run's children stopped. Ambiguous prior ownership blocks;
   there is no automatic recovery, second owner or alternate service account.
2. Establish only the reviewed expected-account IDENTIFY binding. Verify the
   actual first-call Standard caller context and permitted logon/session. There
   is no token capability in discovery or context creation. Account targeting is
   not itself proof of protected-principal exclusivity or process identity.
3. Create a server-owned typed context holding the exact caller binding, active
   generation, frozen operation/offer, monotonic expiry and one-use state. Use
   that context for subsequent fixed operations, with operation/domain/state
   checks on every call. Do not copy it to a new binding/interface or accept a
   caller's serialized substitute. Private scope still waits for accepted peer
   binding; a nonce or echoed generation cannot authenticate a peer.
4. After displaying and confirming the frozen Standard operation, prepare only
   a separate primary-token object derived from the actual Standard controller
   identity. No linked/elevated-token selection, session rewrite or arbitrary
   caller token is permitted. A proposed wire mask is the existing creation
   requirement `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` (`0x000B`),
   not ALL_ACCESS or an adjustable mask. This is a capability, not mere metadata.
   [Creation token access](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
5. A dedicated fixed method would receive that typed token with the existing
   context. It must compare actual token user/logon/authentication/session and
   effective Standard rights against the authenticated caller and frozen offer,
   and reject foreign, elevated, mismatched or expired inputs. Caller-reported
   token attributes are not evidence. Atomic one-use admission and the existing
   durable lease rules still precede any future child creation.
6. If retention is allowed, keep a noninheritable local duplicate with exactly
   the reviewed rights and explicit ownership. Never close the RPC-owned input
   manually or retain its borrowed numeric value after return. Close only owned
   duplicates on rejection/cleanup; do not export a service token or expose a
   generic duplication endpoint. These are future implementation obligations.
7. Restart, lost session, cancellation or ambiguous completion must not move the
   context/token/intent to another instance or trigger another admission. Local
   context destruction is not proof of server cleanup or non-execution. A lost
   reply remains uncertain until the owned state is resolved.

RPC documents context validity within the existing client/server session and
rejection of unknown contexts; context handles can manage the binding. Use
`type_strict_context_handle`, which includes interface/type restrictions; do not
combine it with `strict_context_handle`. These properties support the proposed
state binding but do not provide human consent, one-use admission, a durable
generation lease or a proof of the server executable.
[context lifetime](https://learn.microsoft.com/en-us/windows/win32/rpc/maintaining-state-on-the-server-between-calls),
[client context use/cleanup](https://learn.microsoft.com/en-us/windows/win32/rpc/client-development-using-context-handles),
[type-strict contexts](https://learn.microsoft.com/en-us/windows/win32/midl/type-strict-context-handle).

## 3. What this alternative does not solve

- IDENTIFY limits transport impersonation, not the authority of an explicitly
  transferred primary token. The token is available to the receiving procedure;
  manager-level checks are not a pre-transfer recipient-authentication boundary.
  The reviewed sources do not establish the required ordering between expected-
  principal/context validation and handle duplication. Do not assume IDL parameter
  order solves it. The alternative's exposure boundary must be reviewed anew.
- `CompareObjectHandles` can establish that two handles reference the same kernel
  object, without query rights. It does not establish that a supplied process
  handle belongs to the actual RPC peer. Returning a handle and comparing it
  after transfer cannot retrospectively authenticate the capability recipient.
  No process-handle exchange is selected as the missing pre-transfer proof.
  [object comparison](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-compareobjecthandles).
- Direct cross-process `DuplicateHandle` requires PROCESS_DUP_HANDLE access;
  do not grant it to the UI over the broker as a shortcut. Explicit masks must
  be reviewed at every duplication, not inferred from source-handle limitations.
  [DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle).
- The new mechanism does not establish initial SCM object security, resource
  ceilings, bounded cancellation, controller-call instance association or the
  preventive offline boundary. An RPC context is not a retained OS process handle.
- Do not remove `SeImpersonatePrivilege` from the proposed entitlement table yet.
  A full transitive API review must establish whether the final broker needs it;
  no privilege has been granted or removed in this pass.
- Existing no-caller-token-handle rules, schemas and historical results remain
  unchanged. The proposal cannot be wired around them: an independently reviewed
  explicit contract replacement is required before implementation.

## 4. Required next decision, without widening authority

D-058 retains authenticated peer binding, cross-user separation, exact intent,
replay rejection, restart/quiescence and safe ownership. It defers stronger
same-user-malware-resistant peer proof. Exact retained-SCM-handle correlation is
a proposed means, not permission to ignore those retained goals.

The next useful design deliverable is one explicit equivalence argument for
protected-principal exclusivity plus typed-context/generation ownership: why
only the admitted broker can receive a token, how stale/restarted instances and
foreign logons are excluded, and when authority becomes available. This must
include initial object protection and bounded lifecycle, not just successful
authentication. A service SID, nonce and optimistic lease claim are insufficient.

If that concrete replacement preserves the retained goals, it can undergo the
existing independent technical review without another blanket permission request.
If it instead accepts wrong-instance authority exposure, unknown initial ownership
or unbounded work, that is a material assurance change: stop and present the exact
change to the user. Do not silently label it a trusted-host simplification.

Neither compilation nor more synthetic models can supply a missing platform
guarantee or algorithm. QP-1 is not admitted by this review; QP-2/3 still require
their exact reviewed effects/environment and authorization. Only the main host
is available; no disposable environment is assumed or created.

Review activity: repository and official Microsoft documentation reads only,
plus this documentation delta. No runtime/source/schema changes, generated IDL,
compilation, tests, service installation, token/handle/module/Job/reparse probes,
Velociraptor execution, UAC or Windows changes.

Independent review: AcceptedDocumentaryFeasibilityReviewOnly on 2026-11-06.
The read-only reviewer checked this review and both linked-document deltas; no
blocking documentary findings remain. This does not accept the alternative
mechanism, replace a contract or admit native implementation/compilation/testing.

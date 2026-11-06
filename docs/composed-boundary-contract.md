# COMPOSED-BOUNDARY-CONTRACT1

## Scope and disposition

This is a test-only correspondence and denial contract between the existing
deployment model, maintenance protocol v1 and recovery v2. It is not a production
adapter, storage migration, consent converter or native implementation. The
comparison helper is private to
[`test-composed-boundary.mjs`](../tests/maintenance/test-composed-boundary.mjs);
it has no exports and no production caller. Existing models, codecs, fixtures,
schemas, dependencies and native sources are unchanged.

The motivating composed review reproduced a real abstraction gap, not a runtime
bypass: an Update that adds a backend is rejected by deployment and protocol,
but recovery v2 can complete the opaque digest/epoch replacement. Its codec can
decode that internally consistent synthetic state as Known. Neither result is
operation authority. CBC-008 retains this example and requires the combined
boundary to reject it. Recovery v2 is not silently extended with full-tuple
semantics; the original operation-aware models must also accept.

`COMPOSED_NATIVE_READINESS = fail_with_blockers` remains in force. Passing this
contract is only bounded synthetic regression evidence. All MMR and nine TL
gates remain Open, with no backend execution, UAC, installation, system-setting
changes or network use in this stage. Independent disposition is recorded below.

## Inputs and non-authority result

The private wrapper has exactly five keys: `boundary`, `deployment`, `protocol`,
`recovery`, and `claims`. The three model members are original complete scenarios,
not projections. `claims` is null or the complete three claimed projections.
The wrapper is bounded to 16 MiB/depth 24, using the existing hostile-object guard
before property access, schema validation or hashing. Each scenario and computed
projection passes its complete strict offline Draft 2020-12 schema; the existing
model-specific application checks still run. No remote schema fetch occurs.

All three outputs are recomputed. If claims are supplied, every field must equal
the recomputed output, not just the result digest, state, Known or Completed label.
Rehashed but substituted output fields still reject. Original denial, missing
confirmation, uncertainty or an unsupported boundary cannot be overridden by
claims. No model's confirmation is used to authorize another model.

The only successful result is a frozen comparison marker:

```json
{
  "comparison": "MatchedSyntheticBoundary",
  "boundary": "Completed",
  "execution_enabled": false,
  "launch_status": "Blocked",
  "authority": "None"
}
```

`boundary` may instead name one of the other three supported boundaries below.
There is no selected store, executable, capability, trust verdict or ready token
in this result. Rejection uses `COMPOSED_BOUNDARY_MISMATCH`, without raw input in
the error. Results, all projections and decoded Known documents are rejected by
the existing launch planner both directly and as caller-supplied readiness or
consent. Its nine blockers remain Open.

## Explicit correspondence

Only an ordinary fresh maintenance transaction from a declared stable synthetic
anchor is covered. Protocol journal and last result are null; the v2 initial
anchor has no terminal, records or active lineage. This deliberately excludes
historical restart/terminal mapping. Initial counters, generations, floors,
machine and selected state must agree, and the v2 initial generation floor must
equal generation. Protocol payload members are empty: no actual payload-byte
mapping is claimed.

| Concern | Required comparison |
|---|---|
| Operation | Exact same Install, Update, EnrollBackend, Repair or Uninstall in deployment and protocol; v2 operation Maintenance, target None, null origin |
| Full tuples | Exact deployment/protocol equality of old and desired tuples, including app, supervisor, nullable backend, policy, compatibility, epoch, manifest digest and policy digest |
| v2 selection | Null maps only to null; otherwise `{digest: JCS-SHA256({domain: "SecApp-Test-Composed-Boundary-Tuple-v1", tuple}), epoch: tuple.security_epoch}` |
| Counter | Protocol initial counter equals replayed v2 counter; one admission advances it once; both transactions equal `synthetic-tx-(counter+1)`; deployment has no counter and supplies no substitute |
| Generation/floor | Same expected generation, checked next generation, retained maximum security floor and v2 publication generation floor; no downgrade or gap coercion |
| Lineage | Fresh null offer origin becomes the exact current transaction origin on admission; active previous, candidate, stage and target generation are compared |
| Context | v2 session = protocol channel, peer = client instance, approver = local Confirm approver; helper, policy and confirmation-text digests match |
| Session challenge | JCS-SHA256 with domain `SecApp-Test-Composed-Boundary-Session-v1` over helper/client instances, channel and both protocol challenges |

The v2 confirmation version stays `SyntheticMetadataConsent-v2`. Deployment
binding digest/nonce, protocol offer/confirmation digests, and v2 offer/confirmation
remain separate domains with separate validations. An Audit ConsentReceipt,
metadata authorization or another model's digest is never a substitute.

For the test-only clock mapping, protocol `simulated_at` is a declared synthetic
origin. Deployment and v2 admission times equal origin plus protocol Reserve
milliseconds. Deployment issued time equals origin plus Confirm milliseconds;
all expiry representations equal origin plus the verified protocol offer expiry.
Mapped offsets must be whole seconds; no truncation, local clock, epoch guessing
or real session-resume claim is permitted. The fixtures use Confirm at 4000 ms,
Reserve at 5000 ms and expiry at 302000 ms. Every model still enforces its own
expiry/replay rules. Subsecond offsets and mismatched origins reject.

## Supported boundaries and deliberate asymmetry

| Boundary | Deployment | Protocol | v2 records / result | Selection interpretation |
|---|---|---|---|---|
| Admitted | Prepared | Admitted | Admission / Active | Previous selection known, possibly null |
| Blocked | PublishPending | PublishPending | Admission, Block / Active | No externally known selection |
| Committed | Committed | Committed | Admission, Block, Commit / Active | Deployment/protocol show candidate; v2 deliberately still withholds known selection |
| Completed | Completed | Completed | Admission, Block, Commit, Complete, delivered Result acknowledgement / Completed | Candidate known, possibly null for Uninstall |

Each v2 record boundary includes all six modeled write/flush/readback/head
observations. A partial prefix, lost reply, incomplete checkpoint, Unknown
storage or unsupported phase does not match. The reconstructed v2 selection at
Commit may be compared internally, but that must not promote its conservative
`selection_known=false` projection. This is an explicit difference in model
abstraction, not something to erase for convenient equality.

RecoverPublication, FinishCommittedCleanup, RetireAdmittedCandidate,
CompactTerminalState and ReconcileCheckpoint have no ordinary deployment-model
analogue in this contract. Independently valid examples must reject here, not
be translated into Install/Update/Repair or used to authorize them. Mapping
those recovery/historical operations is a separate future design/review task.

The subsequent [COMPOSED-RECOVERY-CONTRACT1](composed-recovery-contract.md) supplies
a separate bounded test-only history comparison for the three protocol recovery
targets and read-only historical queries. It does not change this CBC contract
or its accepted test source; v2-only metadata operations remain unmapped.

## Executable coverage

Run `npm run test:composed-boundary`; it is included in `npm test`.
CBC-001..030 plus exact-ID completeness are 31 Node tests, with zero skips.

| IDs | Coverage |
|---|---|
| CBC-001..005 | Five operations at all four boundaries, recomputation with/without claims, determinism and immutability |
| CBC-006..013 | Every tuple field, operation-scope gap, null, machine, counter, generation/floor and every v2 context field |
| CBC-014..020 | Disjoint authority domains, foreign audit consent, decline, exact expiry cutoff, replay/stale offer, origin and generation |
| CBC-021..027 | Unknown, every incomplete normal v2 prefix, checkpoint uncertainty, rehashed claims, denial masking, Known codec non-authority, all five non-ordinary operations |
| CBC-028..030 | All nine launch gates stay Open, hostile wrappers before access, deterministic frozen result, clock mismatch and floor retention after Uninstall |

Semantic negatives validate all three original scenario shapes before rejection.
Tests explicitly marked structural target the earlier object/schema boundary.
Splicing tests also prove independent model acceptance where relevant, so rejection
is not accidentally attributed to an already invalid constituent. Codec frames
are synthetic in-memory buffers only. This is not exhaustive fuzzing, a formal
refinement proof, physical durability or authentication evidence.

## Independent disposition and remaining work

The separate read-only reviewer returned bounded PASS with no actionable findings
in this contract's declared scope. The reviewer independently ran all 31 CBC tests
with zero failures/skips, then evaluated the exact private helper in memory with
20 positive comparisons and 189 targeted denials (cross-boundary splices, rehashed
claims, deployment stops, minimum-counter and confirmation-time mismatches).
These extra checks are separate review evidence, not additional registered CBC
tests. No file changes, network or native actions were used by that review.

The reviewed test source SHA-256 is
`514208b95b73697ea3398dd6aa1423987816886b525c2defe9140f45e7b61461`.
The main agent's complete npm gate passes all four validators and 398 Node tests,
including the 31 new tests; the independent reviewer ran the bounded CBC gate,
not that full npm gate. This accepts only the stated correspondence/denial
coverage. Historical/recovery/metadata mapping, payload bytes, persistent
single-use, real confirmation authenticity/clocks, durable storage, crash
quiescence, MSI and native launch are explicitly not accepted.

The larger composed review's blockers remain: complete end-to-end operation and
authority mapping; trusted bootstrap/helper/peer/confirmation against same-user
substitution; physical durable consumption and protected journal storage;
crash-to-quiescence rather than a model-only gate release; MSI/selector/payload
ownership and retention; all nine image/loader/TL gates and action-bound launch
authority. No production adapter, native compilation or probe is authorized by
this contract. Further recovery correspondence and independent acceptance must
precede any separately authorized native work.

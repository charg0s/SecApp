# COMPOSED-RECOVERY-CONTRACT1

## Scope and conclusion

This test-only follow-up to [COMPOSED-BOUNDARY-CONTRACT1](composed-boundary-contract.md)
compares recovery sessions against their complete synthetic history, including
the original deployment operation. A standalone Known snapshot, successful v2
replay or a Completed claim cannot replace that history. Deployment remains the
original operation witness: there is no invented deployment recovery operation
or new deployment confirmation that substitutes for recovery authorization.

The private checker in
[`test-composed-recovery.mjs`](../tests/maintenance/test-composed-recovery.mjs)
has no exports or production callers. The old CBC suite, all models, codecs,
schemas, dependencies and native sources stay unchanged. There is no runtime
bridge, migration, store writer, installation, UAC, network access or backend
invocation. `COMPOSED_NATIVE_READINESS = fail_with_blockers` still applies.

## Closed original-history input

The wrapper contains exactly `deployment`, `steps`, `observations`, and `claims`.
It passes the existing hostile-object guard before access, hashing or validation,
with a 16 MiB/depth 24 ceiling. The checker accepts two to four steps: one ordinary
origin and one to three recovery attempts. Up to four read-only status observations
may follow. These are deliberately bounded test histories, not new journal limits.

Each step contains a named boundary and the complete original protocol and v2
scenarios. The origin's full deployment scenario is also required. Every model
input/output passes its full strict offline Draft 2020-12 schema and the existing
application checks. Outputs are recomputed from those inputs; optional claims
must equal the complete recomputed deployment, step and observation outputs.
No state label, digest, codec checksum or caller-supplied success flag overrides
denial. Shapes and semantic negatives are distinguished in the tests.

The origin is one of Install, Update, EnrollBackend, Repair or Uninstall, starting
from a declared stable synthetic anchor with no active/terminal history. Full old
and desired tuples must match deployment/protocol and the CBC test-only digest/epoch
mapping in v2, with exact null semantics. Counter, machine, generation and floor
also match. A v2 journal sequence has no protocol/deployment analogue; it is
validated by v2 replay, never invented as another model's authority.

For each subsequent step, the entire declared protocol store must match the
preceding accepted trace, including the historical journal, lineage entries,
offer/confirmation digests, prior/current tuples and terminal fields. The entire
v2 storage and minimum must exactly equal the preceding recomputed output.
Dropping, reordering, duplicating or replacing history rejects even when a foreign
run is independently valid. Historical offers are replayed as history after their
expiry, not reused as a current confirmation.

At protocol PublishPending, its output remains null. The private test constructs
an expected restart declaration from the original full-tuple input and accepted
trace for comparison only. This declared Known hypothesis is NOT a recovered real
store, a proof of durable writes or a promotion of Unknown into trusted selection.
No such declaration is exported by the checker.

## Recovery operation mapping

| Protocol recovery target | v2 operation and target | Required history |
|---|---|---|
| FinalizeCandidate | RecoverPublication / FinalizeCandidate | Unresolved publication; exact original candidate |
| RestorePermittedPrevious | RecoverPublication / RestorePermittedPrevious | Unresolved publication; exact previous tuple or null, still permitted by preserved floor |
| FinishCommittedCleanup | FinishCommittedCleanup / None | Committed selection; exact current tuple or null; no new generation |

Each attempt consumes a fresh modeled counter and binds the same original
transaction, complete retained lineage and current transaction. Repeated recovery
must not erase the original candidate/previous tuple or lower the highest
generation/floor. Finishing cleanup consumes a counter without changing generation.
The ordinary deployment model still validates only the original maintenance scope;
each subsequent recovery must independently pass protocol and v2 scope checks.

Finalize/restore are compared at Admitted, Blocked, Committed and Completed.
Cleanup-only is compared at Admitted and Completed; its v2 active stage is already
Committed while the protocol session is Admitted. Every v2 record boundary needs
all six modeled I/O observations. Partial traces, Unknown storage/evidence,
unknown coordination/quiescence and unresolved lost replies reject.

RetireAdmittedCandidate, CompactTerminalState and ReconcileCheckpoint are v2-only
metadata operations with no protocol v1/deployment authority analogue. Valid
standalone v2 examples are retained as explicit composed denials. This contract
does not convert them into Update/Repair, authorize them via a status query, or
claim a cross-model correspondence for them. Supporting that mapping would require
a separate versioned protocol decision and review, not weakening this checker.

## Session and clock boundaries

Each recovery session needs separate protocol and v2 authorization. The CBC
session/challenge mapping is retained; channel and both synthetic challenge labels
must be fresh across the bounded history. Both challenge roles share one used-label
set: swapping a previous helper/client pair cannot renew either label.
Helper/client instances, helper identity,
policy, consent-text and approver remain fixed in this contract's scope. This is
equality of declared synthetic facts, not authenticated peer or user presence.

Each restart origin must follow the preceding protocol trace. v2 admission equals
that origin plus Reserve milliseconds, and v2 expiry equals the verified protocol
expiry. Mapped offsets are whole seconds, without truncation or local-clock reads.
The original deployment confirmation time is also bound to the original protocol
Confirm event. v2 has no separate confirmation-occurrence timestamp: no extra
field or unsupported proof of the same human confirmation event is fabricated.
Each model retains its own expiry, scope and confirmation digest domain. Fixtures
place sessions ten minutes apart, proving historical expiry is not renewed consent.

## Historical status and non-authority output

Status observations are new original read-only query scenarios against the exact
final state, with no v2 authorization and no admission/write events. They cannot
advance counters, alter storage, refresh confirmation or clear publication
uncertainty. Old ancestors of a completed transaction are Retired; only the exact
retained terminal is Completed. An unresolved committed protocol journal reports
Active while v2 reports RecoveryRequired. Both remain non-authority; that deliberate
asymmetry is compared rather than overwritten. Earlier observations cannot serve
as authorization for a later step.

Query-only observer identities are not required to equal the maintenance-session
identities. Each query scenario retains its own model checks, but this gate
compares the exact final state and read-only behavior, not an authenticated common
query principal. That limitation grants no maintenance or execution authority.

The only success marker is frozen and contains no state usable for execution:

```json
{
  "comparison": "MatchedSyntheticRecoveryHistory",
  "steps": 2,
  "execution_enabled": false,
  "launch_status": "Blocked",
  "authority": "None"
}
```

`steps` is the checked history length. A mismatch returns the controlled
`COMPOSED_RECOVERY_MISMATCH` error without raw inputs. Marker, projections and
Known codec round trips are rejected by the launch planner directly and as
injected readiness/consent. All nine exact TL blocker IDs remain Open.

## Coverage and independent disposition

Run `npm run test:composed-recovery`, also included in `npm test`. CRH-001..025
plus exact-ID completeness add 26 Node tests with unique registration and zero
skips. The first six cases cover all five ordinary origins, three recovery targets,
supported boundaries, multi-attempt history and current/ancestor status queries.
Remaining cases cover every tuple field, history splicing, stale/tampered lineage,
generation/floor, separate authority, context/clock substitutions, every incomplete
recovery I/O prefix, Unknown/lost replies, unmapped metadata operations, rehashed
claims, query-only fences, hostile inputs and unchanged launch gates.

The separate review reproduced one narrow freshness mismatch: independent
per-role used-label sets allowed old helper/client challenges to be swapped in a
new, independently reauthorized session. CRH-025 reproduced the acceptance before
the correction. Both roles now use one shared challenge set; channel labels have
their own set. No model, schema or native change is involved, and this was not a
runtime authority bypass.

The independent focused recheck on 2026-09-30 closed this P2 finding and returned
bounded PASS for the combined CBC + CRH scope, with no further actionable findings.
The reviewer ran all 57 combined tests with zero failures/skips, and separately
accepted two positive controls while rejecting six independently valid freshness
substitutions (including one-sided cross-role reuse and reuse from the first
session in a later attempt). Query-identity equality remains the explicit
non-authority limitation described above.

The reviewed CRH source SHA-256 is
`de4d33b924a6d0267749a476e959edadfa0fc4c790e92960bdd39b86b1e465f9`.
The main agent's complete npm gate passes all four validators and 424 Node tests,
including 26 new CRH tests. The reviewer independently ran the 57-test combined
CBC/CRH gate, not the full npm gate. No model, schema, codec, original CBC source
or native source change was needed for this stage or correction.

This bounded pass accepts only the stated history correspondence/denial coverage.
It cannot establish exhaustive refinement/fuzzing,
real provenance/authentication, persistent single-use or safe native execution.

## Remaining production gates

The next decision is a consolidated review of the remaining production blockers,
not automatic activation of native work. Trusted bootstrap and confirmation,
same-user substitution defenses, protected durable storage, crash-to-quiescence,
MSI/selector/payload ownership and retention, payload-byte binding, all nine image
and loader gates, and action-bound launch authority remain unresolved. Metadata
protocol parity is a separate design question. Any real helper/installation/UAC
or Windows changes still require their own authorization and acceptance.

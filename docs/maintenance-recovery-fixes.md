# MAINTENANCE-RECOVERY-FIX1

Status: four author-review findings corrected in the pure v2 reference model,
with executable regression evidence. This is not independent acceptance, native
implementation or permission to cross a launch gate.

Subsequent independent review found three additional counterexamples, including
a nested unsupported-time bypass of the expiry check. The historical FIX1 evidence
below is not full acceptance; see [FIX2 and its recheck](maintenance-recovery-recheck.md).

The previous 343 Node tests passed while the additional review counterexamples
still reproduced. The new MRF-001..012 suite first ran against the unchanged
model: ten regression cases failed, two control cases passed, and the exact-ID
gate correctly failed because not all cases had passed. After the corrections,
all twelve cases and the gate pass. The original RP-001..030 suite is unchanged.

## Findings and corrections

| Finding | Corrected invariant | Regression IDs |
|---|---|---|
| F-001: current epoch 6, persisted floor 4, candidate 5 reached Completed and codec acceptance | Candidate epoch must be at least max(persisted floor, current selected epoch), in offer preparation, admission and historical replay | MRF-001..003 |
| F-002: corrupt tail discarded counter/generation/floor from a valid prefix | Every fully verified prefix contributes conservative minima before the next record is inspected; failure still blocks | MRF-004..006 |
| F-003: terminal anchor generation 7 / generation_floor 8 was Stable | A terminal anchor must have equal generation and generation_floor; a legitimate publication gap requires retained active lineage | MRF-007..009 |
| F-004: v2 accepted confirmation at expiry while the protocol rejected it | Both preparation and admission require now strictly before expiry; the generated default expiry is five minutes after simulated_at | MRF-010..012 |

### Epoch and snapshot integrity

The scope check is shared by preparation, live synthetic admission and replay.
Rehashing a substituted offer therefore cannot bypass the new epoch rule. Equal
and higher candidates still succeed; null remains an exact uninstalled selection,
not a numeric epoch. No lower epoch is accepted because the persisted floor has
not yet caught up with the selected version.

The snapshot codec is unchanged. Its existing Known-state replay check now
rejects an unsafe historical completion rather than encoding or decoding it as
Known. Tests independently construct a correctly checksummed frame, so decoder
rejection does not depend on the encoder's refusal. No stored bytes are migrated,
rewritten or silently normalized.

### Conservative prefix observations

Reconstruction uses a private observer after the anchor and each completely
verified record transition. Only the simulation's monotonic minimum accumulator
receives those observations; no caller callback or authority is introduced.
Validation still stops at the first invalid link, digest or semantic transition.
The failing record and every later record supply no reconstructed-state minima.
Stronger independent minima and header observations are never decreased. For
conflicting generation fields, the conservative maximum is retained while the
state remains blocked.

The reproduced two-record prefix establishes counter 11, generation 8 and floor
5 even if a later corrupt record leaves an older 10/7/4 head visible. The corrected
projection retains 11/8/5 and RecoveryRequired, without a selected-state claim.
It preserves the entire original storage object, including the corrupt tail;
it does not truncate a journal to make it appear valid. Repeated inspection
retains those minima. A corrupt chain still fails the codec's chain checks.

These observations are synthetic consistency evidence, not authentication of
native disk bytes or a physical torn-write recovery algorithm.

### Terminal versus active generation gaps

A compact anchor is terminal and has no active journal from which to justify
generation uncertainty. Mismatched generation/generation_floor therefore fails
with AnchorInvalid; neither a matching head digest nor a Known label promotes it.
The model keeps conservative minima and does not manufacture recovery history.

A real synthetic Block transition still permits current generation 7 and highest
possibly published generation 8 in a retained active journal. Fresh authorized
publication recovery advances to generation 9; subsequent compaction succeeds.
Thus the correction rejects an unsupported terminal state, not all publication
gaps. Unknown snapshot documents remain Unknown, never repaired by decoding.

### Expiry boundary

`RECOVERY_LIMITS.offer_ms` is 300000, matching the protocol's five-minute default
offer interval. A newly prepared default offer uses simulated_at plus that
interval, not an already expiring simulated_at value. Explicit expired/equal-time
offers are rejected by preparation, and the same exclusive bound is rechecked
at admission. Dates outside the supported four-digit UTC representation reject
without counter consumption. Inputs and existing offer digests are not altered
to extend an expiry.

The test pairs protocol confirmation and v2 admission immediately before, at and
after the cutoff; their allow/deny decisions agree. This does not make their
different digests, time representations or confirmation authorities interchangeable.
Historical admitted records are not renewed; fresh admission still needs a fresh
exact offer and confirmation. Native clock selection and trust remain unimplemented.

## Verification and compatibility

```text
npm run test:maintenance-recovery-v2
npm test
```

The recovery command runs the original 31 RP tests plus 13 MRF tests. Positive
controls and semantic negatives pass full strict offline Draft 2020-12 validation
before evaluation. The fixed required-ID list requires unique successful execution
and zero skipped cases. The complete Node gate is now 356 tests plus the existing
schema, contract, application-rule and digest validators.

All identified JSON schema documents, v1 models/codecs/tests, the original v2 RP
suite, codec and fixture helpers, package lock, dependencies and native source
remain unchanged. These are corrections to an unaccepted WIP implementation of
existing invariants, not new wire fields, digest domains, migrations or relaxed
validation. Rejected unsafe histories are not compatibility successes.

Next is independent recheck and composed-boundary review before native work.
All six MMR and nine TL blockers remain Open; these local fixes do not close
them. There is no filesystem writer, IPC adapter, native helper compilation,
probe, Velociraptor invocation, UAC, network, installation, system-settings change,
commit or push in this stage. Read-only backend permission is unchanged and does
not waive technical prerequisites or permit system modifications.

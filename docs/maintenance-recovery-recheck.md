# MAINTENANCE-RECOVERY-FIX2

Status: three findings from a separate read-only reviewer corrected in the pure
v2 model and input validator, then independently rechecked with a bounded PASS.
This is not native acceptance, a protected store or permission to cross a launch
gate. All six MMR and nine TL blockers remain Open.

## Review and corrections

The independent recheck of FIX1 returned `fail_with_blockers` despite all 356
existing Node tests passing. The author independently reproduced all three
findings before changing code:

| Finding | Reproduced result before this correction | Corrected invariant |
|---|---|---|
| R-001 / P1: nested unsupported expiry | A rehashed offer with `2016-12-31T23:59:60Z` passed the schema; all six operations consumed admission, ordinary completion returned Delivered and the codec retained Known | Every current and historical timestamp slot must have a finite, exact supported representation; fresh admission requires expiry strictly greater than now |
| R-002 / P2: impossible terminal operation/outcome | A compact Maintenance anchor with CandidateRetired or MetadataAuthorized was Stable and codec-accepted Known | Terminal anchors must use the same operation/outcome pairs as valid journal transitions |
| R-003 / P2: unrelated status overwritten | After restarting Admission/Block at counter 11, queries for retired counters 9 and 10 also reported RecoveryRequired | Publication recovery status applies to the queried unresolved lineage; unrelated spent transactions keep their own terminal/retired status |

### Supported time is distinct from freshness

The full unchanged Draft 2020-12 schema permits RFC 3339 leap-second spelling,
but the model's ECMAScript clock cannot represent it. The bounded input validator
now checks the top-level time, a directly supplied offer, the scenario's current
authorization offer, and every stored record's historical offer. Only these
schema-defined slots are visited after the plain-data and strict-schema gates.
Non-finite parses and noncanonical round trips reject with
`RECOVERY_V2_INPUT_INVALID`; no date is normalized or silently repaired. The codec
wraps the same rejection as `RECOVERY_V2_CODEC_INVALID`, including independently
framed input bytes and Unknown documents.

Preparation and fresh intake also use a positive `expiry > now` condition, so an
unordered comparison cannot allow admission. Before/equal/after cutoff behavior
and the five-minute default are unchanged. Historical supported expiry is checked
for representability only, not compared to the current inspection time. Aging a
valid historical approval therefore neither destroys completed history nor grants
a new admission. New work still needs a fresh exact offer and confirmation.

### Terminal consistency

The accepted terminal pairs are:

| Operation | Terminal outcome |
|---|---|
| Maintenance, RecoverPublication, FinishCommittedCleanup | Completed |
| RetireAdmittedCandidate | CandidateRetired |
| CompactTerminalState, ReconcileCheckpoint | MetadataAuthorized |

A null terminal remains valid. All twelve other enum combinations fail anchor
reconstruction with AnchorInvalid, preserving the storage and conservative
minima. Known snapshots without a checkpoint candidate reject through the existing
codec replay gate. Unknown snapshots retain their exact blocked bytes and remain
blocked on inspection; decoding is not repair. Correctly paired metadata outcomes
do not claim physical payload deletion or grant authority. The terminal digest
still is not independently authenticated by these consistency checks.

### Transaction status versus global uncertainty

A coherent restarted unresolved lineage returns RecoveryRequired for each member
of that lineage. The latest unrelated retained terminal returns its own Completed
or CandidateRetired outcome; older spent counters return Retired. The store's
global status remains RecoveryRequired and selection remains unknown. Same-session
admitted work retains its Active progress status. Incomplete I/O and checkpoint
uncertainty still override all transaction-specific replies conservatively.

A retired query cannot clear a lost current reply, consume authority or resume
effects. Only an exact current-transaction query can release that existing
session's reply-loss fence. No protocol bridge or new status authority is added.

## Regression evidence

`test-maintenance-recovery-recheck.mjs` adds MRR-001..010 and an exact-ID
completeness gate. The new suite first ran against unchanged FIX1 code: five
regression cases failed, five control cases passed and completeness failed.
After correction, all eleven tests pass. The unchanged RP and MRF suites plus
MRR now run 55 recovery tests through `npm run test:maintenance-recovery-v2`.

MRR uses a separate full strict offline schema gate to prove that the semantic
counterexamples remain structurally valid; application rejection is not mistaken
for a schema failure. Coverage includes all six admission operations, every public
timestamp container, historical aging, encoder and independently framed decoder
rejection, all 18 terminal pairs, actual successful transitions, multi-attempt
lineage, retained terminal outcomes, incomplete I/O, checkpoint uncertainty,
lost replies, input immutability and disabled host effects.

The full `npm test` gate passed: 367 Node tests, zero failures/skips, plus the
existing schema, contract, application-rule and digest validators. Dependencies
and package-lock are unchanged; only the recovery test command is extended.

## Recheck and remaining boundary

The separate read-only reviewer reproduced the original counterexamples against
the before-state and verified their rejection/corrected status in the changed
source. R-001, R-002 and R-003 are resolved within this bounded pure-synthetic
scope; no new actionable finding was reported in the changed boundaries.
The reviewer independently ran all 55 recovery tests and 157 existing protocol,
persistence, composition and v1 codec tests, with zero failures/skips. Additional
in-memory checks covered a later historical admission's unsupported timestamp,
a valid leap day, old history inspected in year 9999, null selection, and an old
origin query that cannot release the current transaction's lost-reply fence.

The reviewed source is bound to these SHA-256 values (not host evidence):

| File | SHA-256 |
|---|---|
| tools/lib/maintenance-recovery-validation.mjs | `4f2ae8669301d0e342ae34459d54f1cf6c34ab4f370d3145d36562b471b756c2` |
| tools/lib/maintenance-recovery-model.mjs | `ac5c7851ecc114bb9530d32e56c276bed084b178017a0b6c40e9048898e24ad6` |
| tests/maintenance/test-maintenance-recovery-recheck.mjs | `3b3bd5bb42ee1e7357e3d9cd72ea8a9121029d018c5ad8c89a2581516d37514c` |

This recheck closes only the three recorded implementation findings, not general
v2/composition acceptance, formal refinement, exhaustive fuzzing, physical
durability, authentication, quiescence or any native/production readiness gate.

All schema documents and identifiers, v1 models/codecs/tests, the original RP/MRF
suites, v2 codec and fixture helpers, native source, dependencies and lockfile are
unchanged. There is no migration, host writer, automatic repair, installation,
native helper compilation, probe, Velociraptor invocation, UAC, network, system
settings change, commit or push. The remaining work is broader composed trust-
boundary and native prerequisite acceptance; these corrections cannot supply it.

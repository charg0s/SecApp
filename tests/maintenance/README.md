# Maintenance protocol reference gate

Run `npm run test:maintenance-protocol` or `npm test`. All fixtures are synthetic
in-memory objects; tests do not create pipes, launch a native helper, call UAC,
persist a journal, install anything or invoke Velociraptor. Existing lockfile-pinned
dev dependencies are used without changes.

Exact required IDs MPC-001 through MPC-053 are checked for uniqueness,
registration, successful execution and zero skips, plus a completeness test.
They must not be relabeled as the design's native MP acceptance evidence.

| IDs | Coverage |
|---|---|
| MPC-001..008 | Fixed operations, exact messages/directions, peer hypotheses, sequence/channel/transaction/digest/offer binding |
| MPC-009..018 | Local confirmation and approver binding, head race, durable/unwritten/uncertain admission, replay, scope, counter/generation/epoch limits and challenges |
| MPC-019..026 | Lost responses, status-only retry, payload authorization/order/limits, control decoding and synthetic clocks |
| MPC-027..031 | Cancellation, crash/disconnect, missing verification/quiescence, trust loss and post-commit cleanup failure |
| MPC-032..039 | Separate fresh recovery authority, new generations, rollback floor, original journal and bounded lineage |
| MPC-040..048 | Non-authority output invariants, hostile bytes/direct API values, exact limits/IDs, immutable deterministic output, source dependency guard and unresolved launch gates |
| MPC-049..053 | Journal-bound null recovery, fresh generation/floor preservation, payload and target substitution denial, fresh confirmation/replay checks, crash and committed cleanup |

Every semantic denial first passes the structural scenario schema. Shape
negatives explicitly reject unsafe authority/field/version substitutions. The
control decoder tests operate on bounded byte buffers, not IPC streams. The
512 MiB intake test transmits no bytes: it checks 8192 small chunk metadata
records. The source dependency guard is not a native sandbox/security proof.

ReviewOffer, Confirm, Reserve, VerifyPayload and Commit are synthetic local
facts supplied to the simulator. They do not authenticate anything or persist
consumption. Re-running a scenario is deterministic, not a real one-time token.
The model's limitations and unimplemented native gates are normative in
[the contract](../../docs/maintenance-protocol-contract.md).

## Persistence fault-model gate

Run `npm run test:maintenance-persistence`, also included in `npm test`. This is
a separate pure model with new development schemas, not a real store or native
extension of the protocol. The immutable required set MPS-001..040 is checked
for exact registration, successful execution and zero skips, plus completeness.

| IDs | Coverage |
|---|---|
| MPS-001..009 | Complete path, every prefix, known/unwritten/torn writes, flush/re-read separation and premature replies/stale heads |
| MPS-010..019 | Quiescence and blocked publication, every normal crash boundary, committed cleanup, lost replies and fresh/interrupted recovery |
| MPS-020..029 | State/machine/confirmation/replay binding, journal/anchor/head corruption, minimum watermarks and exact null recovery |
| MPS-030..036 | Compaction and every crash boundary, no premature retirement, unknown restart, arithmetic and lineage/record caps |
| MPS-037..040 | Hostile direct API objects, strict schema/authority negatives, deterministic immutable output, source guard, exact launch blockers and event/coordinator/status limits |

Semantic denials are structurally schema-valid. Re-read, durability, coordinator
and quiescence results are synthetic hypotheses. Tests allocate bounded metadata
only and never write a persistence file, call native APIs or perform power-loss
experiments. Minimum watermark observations are supplied assumptions, not a
protected host source. The gate does not claim full physical journal retention,
record framing or adversarial whole-machine rollback protection. See
[the persistence contract](../../docs/maintenance-persistence-model.md).

## Protocol/persistence correspondence gate

Run `npm run test:maintenance-composition`, also included in `npm test`. This
author-review gate compares paired synthetic hypotheses using both existing
strict validators. It introduces no new schema, production adapter or combined
authority output. All semantic negatives are structurally valid before model
evaluation. MCC-001..024 is an exact required set with a separate completeness
check for registration, successful execution and zero skips.

| IDs | Coverage |
|---|---|
| MCC-001..004 | Five normal operations at shared boundaries, unwritten/uncertain admission and no premature acknowledgment during any record's six I/O observations |
| MCC-005..010 | Lost replies including local progress, exact/retired status, no repeated effects, restart RecoveryRequired versus same-session Active |
| MCC-011..016 | All recovery targets, floor denial, null selections, interrupted lineage, conservative crash differences and compaction/status preservation |
| MCC-017..024 | Declined/stale bindings, persistence success without protocol scope authority, noninterchangeable digests, unknown storage, lineage cap, overflow, absent retirement and immutable deterministic output |

MCC-005, MCC-007 and MCC-009 reproduced failures before the two narrow reference
model corrections. MCC-018 intentionally demonstrates an abstraction gap:
opaque-target persistence success cannot replace full protocol scope checks.
Known restart contexts and tuple-digest correspondence are test-only fabricated
hypotheses, not recovery of real storage or authorization from a projection.
This is bounded regression coverage, not independent/native acceptance or a
formal refinement proof. See [the review](../../docs/maintenance-composition-review.md).

## Synthetic store codec gate

Run `npm run test:maintenance-store-codec`, also included in `npm test`.
MSC-001..036 is an immutable exact required set plus a completeness check for
unique registration, successful execution and zero skips. A new development-only
snapshot document schema is validated by the existing strict offline Ajv2020
registry; no existing schema or dependency is changed.

| IDs | Coverage |
|---|---|
| MSC-001..007 | Independently framed golden bytes, lifecycle snapshots, every normal/compaction prefix, null selection, recovery lineage and conservative minima |
| MSC-008..017 | Checksums, magic/version, every golden-frame truncation, trailing/concatenated frames, exact length bounds, UTF-8/BOM, duplicate keys, canonical spelling, malformed/scalar/deep/large JSON |
| MSC-018..027 | Required metadata, forbidden authority/versions, timestamps, document/component/intent hashes, chain/machine binding, Known semantic replay and minimum regression |
| MSC-028..036 | Stale-head uncertainty, checkpoint retention, foreign model denial, bounded views, hostile/shared/resizable/direct-API inputs, record/lineage limits, ownership and unchanged launch gates |

Semantic negatives pass the complete structural schema first; shape failures
and unsafe API objects target earlier boundaries explicitly. Malformed frame
tests independently recompute outer framing where needed to reach inner checks.
The fixture digest/header golden is fixed in test source, not generated by the
codec under test. All frames are synthetic in-memory Buffers; no storage file,
real journal, raw report, machine evidence or binary fixture is created.

A decoded document is not a trusted store, session-resume ticket or launcher
approval. Unknown data remains Unknown; invalid Known data rejects instead of
being repaired. The gate does not demonstrate append-write durability, native
recovery, exhaustive fuzz coverage or independent security acceptance. See
[the byte format and explicit limitations](../../docs/maintenance-store-codec.md).

## Recovery v2 acceptance

[MAINTENANCE-RECOVERY-MODEL2](../../docs/maintenance-recovery-model-v2.md) implements
the RP-001..030 plan in `test-maintenance-recovery-v2.mjs`. Run
`npm run test:maintenance-recovery-v2`; it also joins npm test. Thirty cases plus
exact-ID completeness use full strict Draft 2020-12 validation and zero skips.
The new v2 schema/model/codec are separate from unchanged v1 files. They exercise
fresh retirement, record/byte reservation, checkpoint classification/reconciliation,
every write/flush/readback/head/retirement interruption, codec round trips,
lost replies, bounded lineage, disabled effects and old-reader rejection.

`test-maintenance-recovery-fixes.mjs` adds MRF-001..012 plus exact-ID completeness
to that same command, for 44 recovery tests total. It covers the four subsequent
review findings with schema-valid positive/negative inputs, unsafe-history codec
rejection and protocol/v2 cutoff comparisons. The original RP suite is unchanged.
See [the reproduced failures and corrections](../../docs/maintenance-recovery-fixes.md).

`test-maintenance-recovery-recheck.mjs` adds MRR-001..010 plus completeness, bringing
the same command to 55 tests. It covers the separate review's three findings:
all six operations' nested expiry, supported historical dates without renewed
authority, all terminal operation/outcome pairs, unrelated retired and retained
terminal status, unresolved multi-attempt lineage, checkpoint/I/O uncertainty and
lost-reply fences. A separate full strict schema gate distinguishes schema-valid
unsupported date representations from application rejection; encoder and independent
decoder frames are checked. See [FIX2 and its recheck](../../docs/maintenance-recovery-recheck.md).

Current regressions preserve the existing fences: MCC-023 rejects implicit
retirement; MPS-032 rejects status-only compaction; MPS-036 enforces hard record
and lineage caps; MPS-031/034 and MSC-004/029 retain incomplete checkpoints and
block restart. These old cases retain their narrower v1 meaning. RP evidence is
synthetic, not native durability, confirmation integrity, exhaustive fuzzing or
independent acceptance. No installed binary, helper compilation, probe, Windows
setting, network or real machine evidence is used by the new suite.

## Deployment/protocol/recovery v2 composed boundary

Run `npm run test:composed-boundary`, also included in `npm test`.
`test-composed-boundary.mjs` keeps its correspondence helper private: it is not
an exported bridge or runtime API. CBC-001..030 plus exact-ID completeness add
31 tests with zero skips. They recompute all three original scenarios, compare
full claims and explicitly bind operation, old/desired tuples, counter/origin,
generation/floor, session context and time. Semantic negatives pass the complete
constituent schemas first; structural negatives are marked separately.

The five ordinary operations are checked at Admitted, Blocked, Committed and
Completed boundaries. All incomplete normal v2 I/O prefixes, Unknown/checkpoint
states, foreign consent, rehashed output claims and unmapped recovery operations
reject. The Update-with-hidden-enrollment abstraction gap is retained as a
denial regression. No projection, Known codec document or successful comparison
can unlock the launch planner. All nine TL gates remain Open. See
[the mappings, limitations and independent disposition](../../docs/composed-boundary-contract.md).

## Recovery history correspondence

Run `npm run test:composed-recovery`, also included in `npm test`.
`test-composed-recovery.mjs` adds CRH-001..025 plus exact-ID completeness (26 tests).
The original CBC test source stays unchanged. The new private checker recomputes
an original deployment witness, complete protocol/v2 history and optional
read-only status observations. It covers all five ordinary origins, finalization,
permitted restoration, committed cleanup, repeated recovery and exact lineage.

Semantic negatives are schema-valid; structural/hostile cases are separate.
Partial I/O, Unknown, stale or borrowed consent, foreign histories, rehashed
claims and v2-only metadata operation substitution reject. The null protocol
projection is not promoted by a declared restart hypothesis; the successful
marker contains no store or execution authority. All nine TL gates stay Open.
See [the scope, explicit asymmetries and review](../../docs/composed-recovery-contract.md).

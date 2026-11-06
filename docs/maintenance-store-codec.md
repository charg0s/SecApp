# MAINTENANCE-STORE-CODEC1

Status: implemented development-only whole-snapshot byte codec, operating solely
on explicit synthetic in-memory data. This is not a production on-disk format,
append-record writer, streaming reader, installer, native helper, recovery
executor or authenticated store. All prior MMR/TL blockers and native IT/PI/MP
acceptance statuses are unchanged. Independent acceptance remains pending.

```text
StoreCodec = SyntheticSnapshotOnly
ProtectedStore = NotImplemented
NativeImplementation = Blocked
AutomaticRecovery = Disabled
AutomaticBackendExecution = Disabled
ProductionLauncher = NotImplemented
```

## Document contract and API

The new immutable Draft 2020-12 development identifier is
`https://schemas.secapp.dev/v1/development/maintenance-store-document.schema.json`.
The schema references existing persistence storage/watermark definitions without
changing those schemas. Required fields are schema_version 1.0.0, model_kind
MaintenanceStoreDocument, PublicSynthetic/SyntheticModelOnly classification,
an explicit UTC simulated_at timestamp, usage SyntheticReferenceOnly,
execution_enabled false, minimum, storage and document_digest. Unknown fields,
versions, classes and authority substitutions reject; there is no migration.

`tools/lib/maintenance-store-codec.mjs` exports:

- `encodeMaintenanceStore(document)`: validate an already populated synthetic
  document, including its digests, and return a new caller-owned Buffer;
- `decodeMaintenanceStore(bytes)`: validate one complete bounded frame and
  return a detached deeply frozen document;
- frozen `MAINTENANCE_STORE_CODEC_LIMITS` and `MaintenanceStoreCodecError`.

There are no path, handle, source-selection, filesystem, stream, clock, environment,
network, process, privileged-operation or limit-override arguments. Encoding
does not manufacture confirmations, repair hashes or classify a snapshot Known.
Decoding returns data, not a persistence projection, recovery plan, Ready status
or authorization token. No CLI, production consumer or protocol bridge is added.

The offline strict Ajv2020 validator uses the existing pinned development
dependencies and static schema imports. JSON parsing reuses the bounded strict
import parser; transitive file-reader exports are not called by this codec.
No dependency/lockfile change or installation is required.

## Exact frame layout

The frame contains exactly one complete snapshot, not independently appendable
journal records. Integers in the header are unsigned big-endian; offsets below
are zero-based byte offsets.

| Offset | Length | Required bytes |
|---|---|---|
| 0 | 8 | ASCII `SA_MSC01`, hex `53415f4d53433031`, synthetic format v1 only |
| 8 | 4 | Exact payload byte length N, at least 2 and at most 4194304 |
| 12 | 32 | Raw SHA-256 of bytes 0..11 followed directly by the payload |
| 44 | N | UTF-8 RFC 8785/JCS representation of the complete document |

Total frame length must equal 44 + N and must not exceed 4194348 bytes.
There is no terminator, trailing LF, padding, compression, optional extension,
concatenated second frame or accepted trailing data. These binary-payload rules
do not change the repository's UTF-8/LF/final-newline rule for source files.

The actual input view length is bounded before copying or inspecting the
declared length. The decoder snapshots exactly the supplied view, checks magic,
exact length and the full frame checksum before parsing JSON. It does not
allocate a payload buffer using an unchecked header value.

The payload must already be canonical: reject BOM, invalid UTF-8, duplicate keys
(including escaped aliases), extra whitespace, key reordering, alternate number
or escape spelling, invalid scalar values and trailing JSON. Encoding may accept
different plain-object insertion order and emits one canonical representation;
decoding never silently normalizes an alternate byte representation.

`document_digest` is JCS/SHA-256 of the entire document after excluding only that
field. It includes classification, version, timestamp, usage, disabled execution,
minimum and storage. The frame checksum separately binds its magic/length prefix
and exact payload bytes. Neither checksum is a signature, MAC or protected trust
anchor. Rewriting all facts and recomputing checksums is not prevented.

MSC-001 pins a fixed baseline's exact 44-byte header, 1195-byte payload length,
document digest and whole-frame SHA-256. Its expected framing was materialized
independently of the codec using the shared canonicalization contract. No binary
fixture or machine evidence is stored in the repository.

## Storage consistency versus certainty

The codec validates each anchor, head, candidate checkpoint, record, intent and
confirmation digest; exact record order, sequence and previous-digest links;
matching synthetic machine labels; and safe-integer transaction counters.
The serialized minimum cannot be below visible anchor/head/checkpoint counter,
generation/floor values or retained record transaction counters. It may preserve
higher conservative observations that are no longer visible in the old head.

For explicitly Known storage with no candidate checkpoint, the existing pure
persistence model additionally replays the complete chain with no events, no
intent and coordinator Unknown. A stale head, invalid transition, impossible
floor, stale binding or regression below minimum rejects the codec operation.
This is an additional synthetic consistency check, not a test of disk durability.
Even a consistently replayed pending publication exposes no selected state when
evaluated by that model.

Unknown storage and incomplete checkpoint hypotheses are preserved exactly;
the codec neither pretends they are Known nor attempts semantic recovery. It
still checks their structure, individual hashes, chain links, machine labels
and the explicit bounds above. It does not claim their phases/head are mutually
consistent, or reconstruct missing physical bytes. The persistence model rejects
their restart as RecoveryRequired. A malformed or checksummed-but-inconsistent
Known snapshot is rejected, never automatically relabeled or repaired.

Examples pinned by tests:

- a possibly effective reservation can retain minimum.counter 11 while the
  visible head still says 10 and integrity stays Unknown;
- a partially published checkpoint keeps both its candidate and old records;
- Known null selection remains explicitly uninstalled without clearing its floor;
- an Unknown null remains unknown, never an uninstalled success;
- after normal publication, a truncated retained chain with an old tail cannot
  become a last-good-prefix fallback;
- protocol/persistence scope and confirmation boundaries remain separate.

The serialized minimum is itself a supplied synthetic assertion, **not** an
external trusted watermark. Consumers must not use attacker-controlled snapshot
minima to replace stronger external observations. Loss of a minimum that is not
represented elsewhere cannot be detected when all hashes are rewritten. There
is no anti-cloning, administrator/offline rollback or provenance guarantee.

This is a storage-image snapshot, not a running-session checkpoint. Volatile
I/O buffers, pending_stage, coordinator ownership, quiescence, offer expiry and
reply-loss state are not serialized or resumed. Some model prefixes have a
declared Known but stale head while publication is still in progress; this
codec rejects those inconsistent Known images. Successful encoding/decoding
does not authorize re-entry into an interrupted session or consumption of an
old confirmation.

## Input safety and bounds

The byte API accepts local-realm Buffer or exact Uint8Array views with fixed,
non-shared ArrayBuffer backing. It rejects proxies, subclasses, other view types,
detached/undersized views, SharedArrayBuffer, resizable buffers and own shadows
of buffer/byteLength/byteOffset/length/iterator properties. Intrinsic typed-array
accessors inspect the bounded view without invoking caller getters. Unrelated
properties such as a replaced subarray/toJSON method are inert and never read;
copying uses a fresh intrinsic view, not caller methods or iterators.

The object API reuses the existing guarded plain-data copy. Proxies, getters,
coercion hooks, exotic prototypes, cycles, sparse arrays, symbols, hidden keys,
negative zero, unsafe/non-finite numbers and invalid Unicode reject before
schema traversal or hashing. The document is bounded to 4 MiB canonical bytes
and depth 12. The shared guard also enforces 200000 nodes, 4096-byte strings,
32 object keys and its fixed array bounds. The byte parser bounds text depth
before recursive parsing; parsing allocations are bounded by the payload cap.

Existing persistence limits remain: at most 64 records, 16 KiB per canonical
record, 1 MiB canonical record array, and 8 KiB per head/anchor/checkpoint.
The semantic replay enforces the 16-attempt active lineage limit for Known
non-checkpoint state. Tighter schema/count bounds often reject before byte caps
are reachable. Unknown/checkpoint data does not gain semantic acceptance merely
by passing those caps.

Encoder failures use MAINTENANCE_STORE_DOCUMENT_INVALID; decoder failures use
MAINTENANCE_STORE_BYTES_INVALID. Messages are constant and contain no original
input values, keys, offsets, source paths, parser diagnostics or partial result.
There is no empty-store initialization, truncation, prefix salvage or recovery
fallback on error. Returned bytes are mutable caller-owned copies; returned
documents are deeply frozen, detached copies. Built-in/global runtime compromise
is outside the direct-API input threat model.

## Verification and next boundary

Run `npm run test:maintenance-store-codec`, also included in `npm test`.
MSC-001..036 is an immutable exact required-ID set plus completeness, requiring
unique registration, successful execution and zero skips. Tests validate the
new schema with the full strict offline Draft 2020-12 implementation. Semantic
negatives are structurally valid; explicit shape and hostile-API negatives
exercise their respective earlier rejection boundaries. Raw malformed frames
are fabricated in memory with independent framing, never written as evidence.

Coverage includes golden bytes, all normal/compaction prefixes, complete and
interrupted recovery, every truncation of the golden frame, exact bounds,
malformed framing/JSON/Unicode, checksum layers, scope metadata, replay, minima,
hostile API objects, shared/resizable buffers and deterministic ownership.
This is bounded regression coverage, not fuzzing, formal proof, independent
security acceptance or physical fault testing. Existing schemas, models, native
source and normalized native evidence remain unchanged.

The next design work must resolve the remaining explicit maintenance recovery
and capacity policies: ordinary Admitted-candidate retirement, full-journal
handling, and interrupted checkpoint reconciliation. This codec implements none
of those authorities. A future per-record append format, physical writer,
protected bootstrap, runtime lease and native helper need separate design,
independent trust-boundary acceptance and explicit authorization; no host
experiment is implied by this stage's completion.

The subsequent [recovery policy](maintenance-recovery-policy.md) now specifies
those next-model requirements and a Planned/NotRun acceptance matrix. It adds
no codec behavior: v1 still preserves Unknown/checkpoints, rejects inconsistent
Known snapshots and cannot carry the proposed new maintenance authorities.

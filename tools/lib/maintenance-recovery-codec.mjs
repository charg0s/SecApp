import { createHash } from "node:crypto";
import { types } from "node:util";
import { jcs } from "./jcs.mjs";
import { checkedRecoveryData, recoveryDigest, freezeRecovery } from "./maintenance-recovery-validation.mjs";
import { inspectRecoverySnapshot } from "./maintenance-recovery-model.mjs";
import { parseJsonObjectBytes } from "../../src/import/import-json.mjs";

const magic = Buffer.from("SA_MSC02", "ascii");
const HEADER = 44, MAX = 4194304;
const invalid = () => { throw new Error("Invalid synthetic recovery snapshot."); };
export class RecoveryCodecError extends Error {
  constructor() { super("Invalid synthetic recovery v2 snapshot."); this.code = "RECOVERY_V2_CODEC_INVALID"; }
}
function verify(x, key, domain) { if (x[key] !== recoveryDigest(x, key, domain)) invalid(); }
function checkedDocument(value) {
  const doc = checkedRecoveryData("document", value), d = doc.storage;
  verify(doc, "document_digest", "Document");
  verify(d.anchor, "anchor_digest", "Anchor"); verify(d.head, "head_digest", "Head");
  for (const a of [d.checkpoint_candidate, d.obsolete_checkpoint].filter(Boolean)) verify(a, "anchor_digest", "Anchor");
  for (const part of [d.anchor, d.head, d.checkpoint_candidate, d.obsolete_checkpoint].filter(Boolean)) {
    if (part.machine_id !== d.anchor.machine_id || doc.minimum.counter < part.counter
      || doc.minimum.generation < part.generation_floor || doc.minimum.security_floor < part.security_floor) invalid();
  }
  let seq = d.anchor.sequence, tail = d.anchor.anchor_digest;
  for (const r of d.records) {
    verify(r, "record_digest", "Record");
    if (seq === Number.MAX_SAFE_INTEGER || r.sequence !== seq + 1 || r.previous_digest !== tail) invalid();
    const counter = Number(r.transaction_id.slice("synthetic-tx-".length));
    if (!Number.isSafeInteger(counter) || r.transaction_id !== `synthetic-tx-${counter}` || counter > doc.minimum.counter) invalid();
    if (r.authorization) {
      verify(r.authorization.offer, "offer_digest", "Offer");
      if (r.authorization.confirmation.decision !== "ApprovedSynthetic"
        || r.authorization.confirmation.offer_digest !== r.authorization.offer.offer_digest) invalid();
    }
    seq = r.sequence; tail = r.record_digest;
  }
  const analysis = inspectRecoverySnapshot(d, doc.minimum);
  // Interrupted representations and Unknown remain blocked snapshots. Never
  // discard a candidate, lower a minimum or grant an authority while decoding.
  if (d.integrity === "Known" && !d.checkpoint_candidate && analysis.classification === "ConflictOrUnknown") invalid();
  return doc;
}
const proto = Object.getPrototypeOf(Uint8Array.prototype);
const getter = key => Object.getOwnPropertyDescriptor(proto, key).get;
const bufferOf = getter("buffer"), lengthOf = getter("byteLength"), offsetOf = getter("byteOffset");
const resizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "resizable")?.get;
function snapshot(value) {
  if (types.isProxy(value) || !types.isUint8Array(value)
    || ![Buffer.prototype, Uint8Array.prototype].includes(Object.getPrototypeOf(value))) invalid();
  for (const key of ["buffer", "byteLength", "byteOffset", "length", Symbol.iterator]) {
    if (Object.getOwnPropertyDescriptor(value, key)) invalid();
  }
  const b = bufferOf.call(value), size = lengthOf.call(value);
  if (!types.isArrayBuffer(b) || types.isSharedArrayBuffer(b) || resizable?.call(b) || size < HEADER + 2 || size > MAX + HEADER) invalid();
  return Buffer.from(new Uint8Array(b, offsetOf.call(value), size));
}
const checksum = b => createHash("sha256").update(b.subarray(0, 12)).update(b.subarray(HEADER)).digest();
export function encodeRecoveryStore(value) {
  try {
    const payload = Buffer.from(jcs(checkedDocument(value)), "utf8");
    if (payload.length > MAX) invalid();
    const out = Buffer.alloc(HEADER + payload.length); magic.copy(out); out.writeUInt32BE(payload.length, 8);
    payload.copy(out, HEADER); checksum(out).copy(out, 12); return out;
  } catch { throw new RecoveryCodecError(); }
}
export function decodeRecoveryStore(value) {
  try {
    const b = snapshot(value);
    if (!b.subarray(0, 8).equals(magic) || b.readUInt32BE(8) !== b.length - HEADER || !b.subarray(12, HEADER).equals(checksum(b))) invalid();
    const payload = b.subarray(HEADER);
    const parsed = parseJsonObjectBytes(payload, { maxJsonBytes: MAX, maxJsonDepth: 20 }, "Synthetic recovery store").records[0].value;
    const doc = checkedDocument(parsed);
    if (!Buffer.from(jcs(doc), "utf8").equals(payload)) invalid();
    return freezeRecovery(doc);
  } catch { throw new RecoveryCodecError(); }
}

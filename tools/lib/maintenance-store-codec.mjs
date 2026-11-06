import { createHash } from "node:crypto";
import { types } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { AJV_OPTIONS } from "./constants.mjs";
import { jcs, jcsSha256, digestWithExclusion } from "./jcs.mjs";
import { boundedProtocolCopy } from "./maintenance-protocol-validation.mjs";
import { checkedPersistenceData } from "./maintenance-persistence-validation.mjs";
import { simulateMaintenancePersistence } from "./maintenance-persistence-model.mjs";
import { parseJsonObjectBytes } from "../../src/import/import-json.mjs";
import scenario from "../../schemas/development/maintenance-persistence-scenario.schema.json" with { type: "json" };
import document from "../../schemas/development/maintenance-store-document.schema.json" with { type: "json" };

export const MAINTENANCE_STORE_CODEC_LIMITS = Object.freeze({
  header_bytes: 44, payload_bytes: 4194304, frame_bytes: 4194348, json_depth: 12
});
const limits = MAINTENANCE_STORE_CODEC_LIMITS;
const magic = Buffer.from("53415f4d53433031", "hex"); // SA_MSC01, synthetic v1 only.
const warnings = [];
const ajv = new Ajv2020({ ...AJV_OPTIONS, logger: {
  log() {}, warn(value) { warnings.push(value); }, error(value) { warnings.push(value); }
} });
addFormats(ajv, { mode: "full", formats: ["date-time"], keywords: false });
ajv.addSchema(scenario); ajv.addSchema(document);
const gate = ajv.getSchema(document.$id);
if (warnings.length) throw new Error("Store codec development schemas produced strict-validation warnings.");

export class MaintenanceStoreCodecError extends Error {
  constructor(code) {
    super(code === "MAINTENANCE_STORE_BYTES_INVALID"
      ? "Invalid synthetic maintenance store bytes."
      : "Invalid synthetic maintenance store document.");
    this.name = "MaintenanceStoreCodecError"; this.code = code;
  }
}
const invalid = () => { throw new Error("Invalid synthetic store data."); };
function freeze(value) {
  if (value !== null && typeof value === "object") { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function digestMatches(value, key) {
  if (value[key] !== digestWithExclusion(value, key)) invalid();
}
function checkedDocument(value) {
  const copy = boundedProtocolCopy(value, limits.payload_bytes, limits.json_depth);
  if (!gate(copy)) invalid();
  const ms = Date.parse(copy.simulated_at);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().replace(".000Z", "Z") !== copy.simulated_at) invalid();
  digestMatches(copy, "document_digest");
  const disk = checkedPersistenceData("storage", copy.storage);
  digestMatches(disk.anchor, "anchor_digest"); digestMatches(disk.head, "head_digest");
  if (disk.checkpoint_candidate) digestMatches(disk.checkpoint_candidate, "anchor_digest");
  const machine = disk.anchor.machine_id;
  if (disk.head.machine_id !== machine || (disk.checkpoint_candidate && disk.checkpoint_candidate.machine_id !== machine)) invalid();
  // Preserve supplied conservative minima. Do not derive smaller ones from an
  // older visible head, discard Unknown, or synthesize a fresh empty store.
  for (const item of [disk.anchor, disk.head, disk.checkpoint_candidate].filter(Boolean)) {
    if (copy.minimum.counter < item.counter || copy.minimum.generation < (item.generation_floor ?? item.generation)
      || copy.minimum.security_floor < item.security_floor) invalid();
  }
  let sequence = disk.anchor.sequence, prior = disk.anchor.anchor_digest;
  for (const record of disk.records) {
    if (sequence === Number.MAX_SAFE_INTEGER || record.sequence !== sequence + 1 || record.previous_digest !== prior) invalid();
    digestMatches(record, "record_digest");
    const counter = Number(record.transaction_id.slice("synthetic-tx-".length));
    if (!Number.isSafeInteger(counter) || record.transaction_id !== `synthetic-tx-${counter}` || copy.minimum.counter < counter) invalid();
    if (record.intent) {
      const { intent_digest, confirmation_digest, ...scope } = record.intent;
      if (record.intent.transaction_id !== record.transaction_id
        || intent_digest !== jcsSha256({ domain: "SecApp-Synthetic-Persistence-Intent-v1", scope })
        || confirmation_digest !== jcsSha256({ domain: "SecApp-Synthetic-Persistence-Confirmation-v1",
          intent_digest, transaction_id: record.transaction_id })) invalid();
    }
    sequence = record.sequence; prior = record.record_digest;
  }
  // Only an explicitly Known, non-checkpoint snapshot can be replay-checked.
  // This remains a synthetic consistency test, never proof of disk durability.
  // Unknown/checkpoint snapshots retain their uncertainty without repair.
  if (disk.integrity === "Known" && disk.checkpoint_candidate === null) {
    const result = simulateMaintenancePersistence({ schema_version: "1.0.0", model_kind: "MaintenancePersistenceScenario",
      privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly", simulated_at: copy.simulated_at,
      storage: disk, minimum: copy.minimum, intent: null, coordinator: "Unknown", events: [] });
    if (result.reason !== "None") invalid();
  }
  return copy;
}

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedGetter = name => Object.getOwnPropertyDescriptor(typedArrayPrototype, name).get;
const getBuffer = typedGetter("buffer"), getLength = typedGetter("byteLength"), getOffset = typedGetter("byteOffset");
const getResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "resizable")?.get;
function snapshotBytes(value) {
  // Never consult caller getters, iterators, coercion hooks or Buffer methods.
  if (types.isProxy(value) || !types.isUint8Array(value)
    || ![Buffer.prototype, Uint8Array.prototype].includes(Object.getPrototypeOf(value))) invalid();
  for (const key of ["buffer", "byteLength", "byteOffset", "length", Symbol.iterator]) {
    if (Object.getOwnPropertyDescriptor(value, key)) invalid();
  }
  const backing = getBuffer.call(value);
  if (!types.isArrayBuffer(backing) || types.isSharedArrayBuffer(backing) || getResizable?.call(backing)) invalid();
  const length = getLength.call(value), offset = getOffset.call(value);
  if (length < limits.header_bytes + 2 || length > limits.frame_bytes) invalid();
  // Snapshot exactly this view, not unused prefix/suffix bytes in its backing.
  return Buffer.from(new Uint8Array(backing, offset, length));
}
function frameDigest(bytes) {
  return createHash("sha256").update(bytes.subarray(0, 12)).update(bytes.subarray(limits.header_bytes)).digest();
}

// Complete in-memory snapshots only. No path, file handle, stream, filesystem
// writer, native API, migration, recovery executor or production store format.
export function encodeMaintenanceStore(value) {
  try {
    const checked = checkedDocument(value);
    const payload = Buffer.from(jcs(checked), "utf8");
    if (payload.length > limits.payload_bytes) invalid();
    const frame = Buffer.alloc(limits.header_bytes + payload.length);
    magic.copy(frame, 0); frame.writeUInt32BE(payload.length, 8);
    payload.copy(frame, limits.header_bytes); frameDigest(frame).copy(frame, 12);
    return frame;
  } catch { throw new MaintenanceStoreCodecError("MAINTENANCE_STORE_DOCUMENT_INVALID"); }
}

export function decodeMaintenanceStore(value) {
  try {
    const frame = snapshotBytes(value);
    if (!frame.subarray(0, 8).equals(magic)) invalid();
    const length = frame.readUInt32BE(8);
    if (length < 2 || length > limits.payload_bytes || frame.length !== limits.header_bytes + length) invalid();
    if (!frame.subarray(12, limits.header_bytes).equals(frameDigest(frame))) invalid();
    const payload = frame.subarray(limits.header_bytes);
    const parsed = parseJsonObjectBytes(payload, { maxJsonBytes: limits.payload_bytes, maxJsonDepth: limits.json_depth }, "Synthetic store").records[0].value;
    const checked = checkedDocument(parsed);
    // Reject alternate spellings, whitespace, key reordering and trailing LF.
    // Encoding is canonical; decoding does not silently normalize input bytes.
    if (!Buffer.from(jcs(checked), "utf8").equals(payload)) invalid();
    return freeze(checked);
  } catch { throw new MaintenanceStoreCodecError("MAINTENANCE_STORE_BYTES_INVALID"); }
}

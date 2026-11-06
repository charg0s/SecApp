import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createSchemaRegistry } from "../../tools/lib/schema-registry.mjs";
import { jcs, digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { simulateMaintenancePersistence } from "../../tools/lib/maintenance-persistence-model.mjs";
import { encodeMaintenanceStore as encode, decodeMaintenanceStore as decode, MAINTENANCE_STORE_CODEC_LIMITS as limits } from "../../tools/lib/maintenance-store-codec.mjs";
import { baseStorage, intentFor, recoveryIntent, harness, hash, copy } from "./synthetic-persistence.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const registry = createSchemaRegistry(root);
for (const name of ["maintenance-persistence-scenario", "maintenance-store-document"]) {
  const schema = JSON.parse(await readFile(path.join(root, `schemas/development/${name}.schema.json`), "utf8"));
  assert.equal(registry.ajv.validateSchema(schema), true); registry.ajv.addSchema(schema);
}
const gate = registry.ajv.getSchema("https://schemas.secapp.dev/v1/development/maintenance-store-document.schema.json");
assert.deepEqual(registry.warnings, []);
const required = Object.freeze([
  "MSC-001", "MSC-002", "MSC-003", "MSC-004", "MSC-005", "MSC-006",
  "MSC-007", "MSC-008", "MSC-009", "MSC-010", "MSC-011", "MSC-012",
  "MSC-013", "MSC-014", "MSC-015", "MSC-016", "MSC-017", "MSC-018",
  "MSC-019", "MSC-020", "MSC-021", "MSC-022", "MSC-023", "MSC-024",
  "MSC-025", "MSC-026", "MSC-027", "MSC-028", "MSC-029", "MSC-030",
  "MSC-031", "MSC-032", "MSC-033", "MSC-034", "MSC-035", "MSC-036"
]);
const cases = [];
const vector = (id, label, fn) => cases.push({ id, label, fn });
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const seal = doc => { doc.document_digest = digestWithExclusion(doc, "document_digest"); return doc; };
function document(result = harness(baseStorage(), null).project()) {
  return seal({ schema_version: "1.0.0", model_kind: "MaintenanceStoreDocument", privacy_class: "PublicSynthetic",
    provenance: "SyntheticModelOnly", simulated_at: "2026-09-29T12:00:00Z", usage: "SyntheticReferenceOnly",
    execution_enabled: false, minimum: copy(result.watermarks), storage: copy(result.storage), document_digest: "" });
}
function restart(doc) {
  return simulateMaintenancePersistence({ schema_version: "1.0.0", model_kind: "MaintenancePersistenceScenario",
    privacy_class: "PublicSynthetic", provenance: "SyntheticModelOnly", simulated_at: doc.simulated_at,
    storage: doc.storage, minimum: doc.minimum, intent: null, coordinator: "Unknown", events: [] });
}
// Independent framing helper deliberately bypasses the encoder so targeted
// payload negatives have a valid outer frame checksum and exact length.
function frame(payload) {
  const body = typeof payload === "string" ? Buffer.from(payload, "utf8") : payload;
  const prefix = Buffer.alloc(12); prefix.write("SA_MSC01", 0, "ascii"); prefix.writeUInt32BE(body.length, 8);
  const checksum = createHash("sha256").update(prefix).update(body).digest();
  return Buffer.concat([prefix, checksum, body]);
}
const unchecked = doc => frame(jcs(doc));
function frozen(value) {
  if (value !== null && typeof value === "object") { assert.equal(Object.isFrozen(value), true); Object.values(value).forEach(frozen); }
}
function roundTrip(doc) {
  assert.equal(gate(doc), true, JSON.stringify(gate.errors));
  const before = copy(doc), bytes = encode(doc), result = decode(bytes);
  assert.deepEqual(result, doc); assert.deepEqual(doc, before); frozen(result);
  assert.deepEqual(bytes, unchecked(doc)); assert.equal(result.execution_enabled, false);
  assert.equal(result.usage, "SyntheticReferenceOnly"); return result;
}
function rejectedBytes(bytes) {
  assert.throws(() => decode(bytes), error => {
    assert.equal(error.name, "MaintenanceStoreCodecError"); assert.equal(error.code, "MAINTENANCE_STORE_BYTES_INVALID");
    assert.equal(error.message, "Invalid synthetic maintenance store bytes."); return true;
  });
}
function rejectedDocument(doc, shape = true) {
  assert.equal(gate(doc), shape, JSON.stringify(gate.errors));
  assert.throws(() => encode(doc), { code: "MAINTENANCE_STORE_DOCUMENT_INVALID", message: "Invalid synthetic maintenance store document." });
  rejectedBytes(unchecked(doc));
}
function resealStorage(doc, kind) {
  const object = doc.storage[kind]; const field = kind === "head" ? "head_digest" : "anchor_digest";
  object[field] = digestWithExclusion(object, field); return seal(doc);
}

vector("MSC-001", "fixed v1 golden frame pins byte order, header, canonical payload and hashes", () => {
  const doc = document(), bytes = encode(doc); roundTrip(doc);
  assert.equal(bytes.length, 44 + 1195); assert.equal(bytes.readUInt32BE(8), 1195);
  assert.equal(bytes.subarray(0, 44).toString("hex"), "53415f4d53433031000004aba7efa2a7daf7a7d9ae114781bfa53535838a72f4559ec477904b6a290773e654");
  assert.equal(sha(bytes), "c819bfb44630181f2773dadf0247753ff9b59a4bb4c53cd6711a5c53735d5bb0");
  assert.equal(doc.document_digest, "d2e7ad5a3752f0d072b4a8635acad852dd960d03a3eeaae1e2da6653368ac5f9");
});
vector("MSC-002", "stable admitted blocked committed and terminal snapshots retain meaning", () => {
  const h = harness(); const results = [h.project(), h.reserve().project(), h.block().project(), h.commit().project(), h.complete().project()];
  for (const result of results) {
    const decoded = roundTrip(document(result)), projected = restart(decoded);
    assert.equal(projected.reason, "None"); assert.deepEqual(projected.watermarks, result.watermarks);
    assert.equal(projected.selection_known, result.selection_known); assert.equal(projected.selected_digest, result.selected_digest);
    assert.ok(Object.values(projected.effects).every(value => value === false));
  }
});
vector("MSC-003", "all ordinary I/O prefixes preserve uncertainty or reject inconsistent Known state", () => {
  const input = harness().full().input;
  for (let count = 0; count <= input.events.length; count += 1) {
    const prefix = copy(input); prefix.events.length = count;
    const doc = document(simulateMaintenancePersistence(prefix)), projected = restart(doc);
    if (doc.storage.integrity === "Known" && projected.reason !== "None") rejectedDocument(doc);
    else {
      const decoded = roundTrip(doc); assert.deepEqual(decoded.minimum, doc.minimum);
      if (doc.storage.integrity === "Unknown") { assert.equal(restart(decoded).status, "RecoveryRequired"); assert.equal(restart(decoded).selection_known, false); }
    }
  }
});
vector("MSC-004", "all compaction prefixes retain old records and incomplete checkpoint", () => {
  const h = harness().full(); const start = h.input.events.length; h.compact();
  for (let count = start; count <= h.input.events.length; count += 1) {
    const input = copy(h.input); input.events.length = count;
    const doc = roundTrip(document(simulateMaintenancePersistence(input)));
    assert.equal(doc.minimum.counter, 11); assert.equal(doc.minimum.security_floor, 5);
    if (count > start && count < h.input.events.length) {
      assert.notEqual(doc.storage.checkpoint_candidate, null); assert.equal(doc.storage.records.length, 4);
      assert.equal(restart(doc).status, "RecoveryRequired");
    }
  }
});
vector("MSC-005", "explicit uninstalled null is distinct from Unknown and never resets floor", () => {
  const disk = baseStorage({ security_floor: 5, selection_epoch: 5 });
  const result = harness(disk, intentFor(disk, { selection_digest: null, selection_epoch: 0 })).full().compact().project();
  const decoded = roundTrip(document(result)), next = restart(decoded);
  assert.equal(next.selected_digest, null); assert.equal(next.selection_known, true); assert.equal(next.watermarks.security_floor, 5);
  const uncertain = copy(decoded); uncertain.storage.integrity = "Unknown"; seal(uncertain);
  assert.equal(restart(roundTrip(uncertain)).selection_known, false);
});
vector("MSC-006", "recovery snapshots keep original and fresh confirmation-bound lineage", () => {
  const first = harness().reserve().block().project();
  const second = harness(first.storage, recoveryIntent(first.storage)).reserve().project();
  const decoded = roundTrip(document(second));
  assert.equal(decoded.minimum.counter, 12); assert.equal(decoded.minimum.generation, 8);
  const reserves = decoded.storage.records.filter(record => record.record_kind === "Reserve");
  assert.equal(reserves.length, 2); assert.equal(reserves[1].intent.origin_transaction_id, reserves[0].transaction_id);
  assert.notEqual(reserves[0].intent.confirmation_digest, reserves[1].intent.confirmation_digest);
  assert.equal(restart(decoded).selection_known, false);
});
vector("MSC-007", "possible consumption beyond old visible head survives serialization", () => {
  for (const outcome of ["Torn", "Unknown"]) {
    const doc = roundTrip(document(harness().write("Reserve", outcome).project()));
    assert.equal(doc.storage.head.counter, 10); assert.equal(doc.minimum.counter, 11); assert.equal(doc.storage.integrity, "Unknown");
    assert.equal(restart(doc).watermarks.counter, 11); assert.equal(restart(doc).status, "RecoveryRequired");
  }
});
vector("MSC-008", "each checksum byte and payload corruption is rejected", () => {
  const good = encode(document());
  for (const index of [...Array.from({ length: 32 }, (_, i) => i + 12), 44, good.length - 1]) {
    const bytes = Buffer.from(good); bytes[index] ^= 1; rejectedBytes(bytes);
  }
});
vector("MSC-009", "magic and format version are exact with no migration or fallback", () => {
  const good = encode(document());
  for (let index = 0; index < 8; index += 1) { const bytes = Buffer.from(good); bytes[index] ^= 1; rejectedBytes(bytes); }
  rejectedBytes(Buffer.from(jcs(document())));
  rejectedBytes(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), good]));
});
vector("MSC-010", "every truncated prefix rejects rather than returning last good data", () => {
  const bytes = encode(document());
  for (let end = 0; end < bytes.length; end += 1) rejectedBytes(bytes.subarray(0, end));
});
vector("MSC-011", "trailing bytes padding and concatenated frames reject", () => {
  const bytes = encode(document());
  for (const tail of [Buffer.from([0]), Buffer.from("\n"), Buffer.from(" "), bytes]) rejectedBytes(Buffer.concat([bytes, tail]));
});
vector("MSC-012", "length is bounded before allocation and must match exact frame size", () => {
  const good = encode(document());
  for (const length of [0, 1, 2, 1194, 1196, limits.payload_bytes, limits.payload_bytes + 1, 0xffffffff]) {
    const bytes = Buffer.from(good); bytes.writeUInt32BE(length, 8); rejectedBytes(bytes);
  }
  const little = Buffer.from(good); little.writeUInt32LE(1195, 8); rejectedBytes(little);
  rejectedBytes(Buffer.alloc(limits.frame_bytes + 1));
});
vector("MSC-013", "payload must be strict UTF-8 without BOM or replacement decoding", () => {
  for (const bytes of [Buffer.from([0xff]), Buffer.from([0xc0, 0xaf]), Buffer.from([0xe2, 0x82]),
    Buffer.from([0xed, 0xa0, 0x80]), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(jcs(document()))])]) rejectedBytes(frame(bytes));
});
vector("MSC-014", "duplicate keys including escaped aliases reject before schema validation", () => {
  const text = jcs(document());
  for (const bad of [text.replace("{", '{"schema_version":"1.0.0",'),
    text.replace('"counter":10', '"counter":10,"counter":10'),
    text.replace('"counter":10', '"counter":10,"\\u0063ounter":10')]) rejectedBytes(frame(bad));
});
vector("MSC-015", "alternate JSON spelling and whitespace are not silently canonicalized", () => {
  const doc = document(), text = jcs(doc);
  for (const bad of [text + "\n", " " + text, JSON.stringify(doc), JSON.stringify(doc, null, 2),
    text.replace('"counter":10', '"counter":1e1'), text.replace('"counter":10', '"counter":10.0'),
    text.replace("PublicSynthetic", "\\u0050ublicSynthetic"), text.replaceAll(":", ": ")]) {
    assert.notEqual(bad, text); rejectedBytes(frame(bad));
  }
});
vector("MSC-016", "bad JSON roots scalars Unicode and unsafe numbers reject", () => {
  for (const text of ["null", "[]", "true", "42", '"x"', "{}{}", '{"x":NaN}', '{"x":1e999}',
    '{"x":"\\ud800"}', '{"\\udc00":0}', '{"x":-0}', '{"x":9007199254740992}', '{"x":1,}', '{"x":"\\q"}']) rejectedBytes(frame(text));
  rejectedBytes(frame(jcs(document()).replace('"counter":10', '"counter":9007199254740992')));
});
vector("MSC-017", "depth nodes strings keys and record count are bounded", () => {
  rejectedBytes(frame('{"x":' + "[".repeat(1000) + "0" + "]".repeat(1000) + "}"));
  rejectedBytes(frame(JSON.stringify({ x: "a".repeat(4097) })));
  rejectedBytes(frame(JSON.stringify(Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`x${i}`, 0])))));
  rejectedBytes(frame(JSON.stringify({ x: Array.from({ length: 25 }, () => Array(8000).fill(0)) })));
  const doc = document(harness().full().project()); doc.storage.records = Array(65).fill(doc.storage.records[0]); seal(doc);
  rejectedDocument(doc, false);
});
vector("MSC-018", "every envelope required field is mandatory", () => {
  for (const key of Object.keys(document())) { const doc = document(); delete doc[key]; rejectedDocument(doc, false); }
});
vector("MSC-019", "unknown schema versions fields authority and metadata are rejected", () => {
  for (const [key, value] of [["schema_version", "2.0.0"], ["schema_version", "1.1.0"], ["model_kind", "MaintenancePersistenceProjection"],
    ["privacy_class", "SensitiveSecurityData"], ["provenance", "Verified"], ["usage", "Production"], ["execution_enabled", true],
    ["path", "synthetic-forbidden"], ["launch_status", "Ready"], ["limits", {}]]) {
    const doc = document(); doc[key] = value; seal(doc); rejectedDocument(doc, false);
  }
});
vector("MSC-020", "timestamp is exact UTC seconds with no clock lookup or normalization", () => {
  for (const simulated_at of ["2026-02-30T12:00:00Z", "2026-09-29T12:00:00+00:00", "2026-09-29T12:00:00.000Z", "2026-09-29"]) {
    const doc = document(); doc.simulated_at = simulated_at; seal(doc); rejectedDocument(doc, false);
  }
});
vector("MSC-021", "valid framing cannot hide a stale complete document digest", () => {
  const doc = document(); doc.simulated_at = "2026-09-29T12:00:01Z"; rejectedDocument(doc);
  const digest = document(); digest.document_digest = hash("foreign-document"); rejectedDocument(digest);
});
vector("MSC-022", "anchor head and checkpoint checksums are independently verified", () => {
  for (const kind of ["anchor", "head", "checkpoint_candidate"]) {
    const doc = kind === "checkpoint_candidate"
      ? document(harness().full().event("WriteCheckpoint", { result: "Complete" }).project()) : document();
    const field = kind === "head" ? "head_digest" : "anchor_digest";
    doc.storage[kind][field] = hash("corrupt"); seal(doc); rejectedDocument(doc);
  }
});
vector("MSC-023", "record intent and confirmation hashes cannot be hidden by outer rehashing", () => {
  for (const field of ["record_digest", "intent_digest", "confirmation_digest"]) {
    const doc = document(harness().reserve().project()), record = doc.storage.records[0];
    if (field === "record_digest") record[field] = hash("corrupt");
    else { record.intent[field] = hash("corrupt"); record.record_digest = digestWithExclusion(record, "record_digest"); }
    seal(doc); rejectedDocument(doc);
  }
});
vector("MSC-024", "sequence gaps duplicate reordered and foreign-machine chains reject", () => {
  for (const mutate of [d => { d.storage.records[0].sequence += 1; }, d => { d.storage.records[1] = copy(d.storage.records[0]); },
    d => { d.storage.records.reverse(); }, d => { d.storage.records[0].previous_digest = hash("foreign"); },
    d => { d.storage.head.machine_id = "synthetic-machine-b"; resealStorage(d, "head"); }]) {
    const doc = document(harness().full().project()); mutate(doc); seal(doc); rejectedDocument(doc);
  }
});
vector("MSC-025", "Known state requires semantic replay rather than checksum-only acceptance", () => {
  const doc = document(harness().reserve().block().project());
  doc.storage.records[1].record_kind = "Commit";
  doc.storage.records[1].record_digest = digestWithExclusion(doc.storage.records[1], "record_digest");
  doc.storage.head.tail_digest = doc.storage.records[1].record_digest; resealStorage(doc, "head"); rejectedDocument(doc);
  const invalidEpoch = document(); invalidEpoch.storage.anchor.security_floor = 5;
  invalidEpoch.minimum.security_floor = 5; resealStorage(invalidEpoch, "anchor"); rejectedDocument(invalidEpoch);
});
vector("MSC-026", "serialized minimum cannot regress below visible component or record bounds", () => {
  for (const field of ["counter", "generation", "security_floor"]) {
    const doc = document(harness().full().project()); doc.minimum[field] -= 1; seal(doc); rejectedDocument(doc);
  }
  const doc = document(harness().write("Reserve").flush("Journal").project());
  assert.equal(doc.storage.head.counter, 10); doc.minimum.counter = 10; seal(doc); rejectedDocument(doc);
  const max = Number.MAX_SAFE_INTEGER;
  const edge = document(harness(baseStorage({ counter: max, sequence: max, generation: max,
    security_floor: max, selection_epoch: max, last_transaction_id: `synthetic-tx-${max}` }), null).project());
  assert.equal(roundTrip(edge).minimum.counter, max);
  edge.minimum.counter = max + 1; seal(edge); rejectedDocument(edge, false);
});
vector("MSC-027", "higher minima are preserved on Unknown not coerced down into Known", () => {
  const doc = document(); doc.minimum.counter = 11; seal(doc); rejectedDocument(doc);
  doc.storage.integrity = "Unknown"; seal(doc);
  const decoded = roundTrip(doc); assert.equal(decoded.minimum.counter, 11); assert.equal(restart(decoded).status, "RecoveryRequired");
});
vector("MSC-028", "stale head requires rejection when Known and stays uncertain when Unknown", () => {
  const doc = document(harness().full().project()); doc.storage.head = baseStorage().head; seal(doc); rejectedDocument(doc);
  doc.storage.integrity = "Unknown"; seal(doc);
  const decoded = roundTrip(doc); assert.deepEqual(decoded.storage.head, baseStorage().head);
  assert.equal(decoded.minimum.counter, 11); assert.equal(restart(decoded).selection_known, false);
});
vector("MSC-029", "checkpoint candidate cannot be promoted or old records discarded by decoding", () => {
  const doc = document(harness().full().event("WriteCheckpoint", { result: "Complete" }).flush("Checkpoint").read("Checkpoint").project());
  assert.equal(doc.storage.integrity, "Known");
  const decoded = roundTrip(doc); assert.equal(decoded.storage.records.length, 4);
  assert.notEqual(decoded.storage.checkpoint_candidate, null); assert.equal(restart(decoded).reason, "StorageUnknown");
  const removed = document(harness().full().project()); removed.storage.records.pop(); seal(removed); rejectedDocument(removed);
});
vector("MSC-030", "other projections and schemas are not accepted as store documents", () => {
  const projection = harness().full().project(); rejectedDocument(projection, false);
  const doc = document(); doc.storage.authority = "Approved"; seal(doc); rejectedDocument(doc, false);
});
vector("MSC-031", "Buffer and exact Uint8Array views use only their bounded byte region", () => {
  const doc = document(), good = encode(doc), larger = Buffer.concat([Buffer.from("prefix"), good, Buffer.from("suffix")]);
  assert.deepEqual(decode(new Uint8Array(good)), doc);
  assert.deepEqual(decode(new Uint8Array(larger.buffer, larger.byteOffset + 6, good.length)), doc);
  assert.deepEqual(decode(larger.subarray(6, 6 + good.length)), doc);
  rejectedBytes(larger);
  const result = decode(good); good.fill(0); assert.deepEqual(result, doc); frozen(result);
});
vector("MSC-032", "byte API rejects unsafe types hooks shared and resizable backing", () => {
  let touched = false; const good = encode(document());
  const proxy = new Proxy(good, { get() { touched = true; throw Error("trap"); }, getPrototypeOf() { touched = true; throw Error("trap"); } });
  const hook = { valueOf() { touched = true; return good; }, [Symbol.iterator]() { touched = true; return good.values(); } };
  class CustomBytes extends Uint8Array {}
  for (const value of [null, undefined, "synthetic-path", [], {}, hook, proxy, good.buffer, new DataView(good.buffer), new Uint16Array(64), new CustomBytes(good)]) rejectedBytes(value);
  for (const key of ["buffer", "byteLength", "byteOffset", "length", Symbol.iterator]) {
    const bytes = Buffer.from(good); Object.defineProperty(bytes, key, { get() { touched = true; throw Error("getter"); } }); rejectedBytes(bytes);
  }
  rejectedBytes(new Uint8Array(new SharedArrayBuffer(good.length)));
  const resizable = new ArrayBuffer(good.length, { maxByteLength: good.length + 1 });
  assert.equal(resizable.resizable, true); new Uint8Array(resizable).set(good); rejectedBytes(new Uint8Array(resizable));
  const detached = new Uint8Array(good); structuredClone(detached.buffer, { transfer: [detached.buffer] }); rejectedBytes(detached);
  assert.equal(touched, false);
});
vector("MSC-033", "object API rejects proxies getters coercion exotic or unbounded data without execution", () => {
  let touched = false;
  const proxy = new Proxy({}, { ownKeys() { touched = true; throw Error("trap"); } });
  const getter = document(); Object.defineProperty(getter, "storage", { get() { touched = true; throw Error("getter"); } });
  const hook = document(); hook.toJSON = () => { touched = true; return {}; };
  for (const value of [proxy, getter, hook, new Date(), new Map(), undefined]) assert.throws(() => encode(value), { code: "MAINTENANCE_STORE_DOCUMENT_INVALID" });
  for (const change of [d => { d.storage = d; }, d => { d.storage.records = Array(2); }, d => { d.minimum.counter = -0; },
    d => { d.minimum.counter = Infinity; }, d => { d.minimum.counter = 1n; }, d => { d[Symbol("hidden")] = true; },
    d => { Object.defineProperty(d, "hidden", { value: true }); }, d => { d.simulated_at = "\ud800"; }]) {
    const doc = document(); change(doc); assert.throws(() => encode(doc), { code: "MAINTENANCE_STORE_DOCUMENT_INVALID" });
  }
  assert.equal(touched, false);
});
vector("MSC-034", "record and lineage boundaries and compacted replay survive the codec", () => {
  let disk = baseStorage(), latest;
  for (let i = 0; i < 16; i += 1) { latest = harness(disk).full().project(); disk = roundTrip(document(latest)).storage; }
  assert.equal(disk.records.length, 64);
  assert.equal(harness(disk).write("Reserve").project().reason, "LimitExceeded");
  let active = harness().reserve().block().project();
  for (let i = 1; i < 16; i += 1) active = harness(active.storage, recoveryIntent(active.storage)).reserve().block().project();
  assert.equal(roundTrip(document(active)).storage.records.filter(record => record.record_kind === "Reserve").length, 16);
  const compacted = roundTrip(document(harness().full().compact().project()));
  const old = intentFor(baseStorage());
  assert.equal(harness(compacted.storage, old).write("Reserve").project().reason, "IntentRejected");
});
vector("MSC-035", "canonical determinism ownership and inert byte properties cannot run caller code", () => {
  const doc = document(), reversed = Object.fromEntries(Object.entries(doc).reverse());
  assert.deepEqual(encode(doc), encode(reversed)); assert.equal(Object.isFrozen(doc), false);
  const a = encode(doc), b = encode(doc); assert.notEqual(a, b); a.fill(0); assert.deepEqual(decode(b), doc);
  let touched = false; const bytes = encode(doc);
  for (const key of ["subarray", "equals", "toJSON", "valueOf"]) Object.defineProperty(bytes, key, { get() { touched = true; throw Error("getter"); } });
  assert.deepEqual(decode(bytes), doc); assert.equal(touched, false); assert.equal(Object.isFrozen(limits), true);
});
vector("MSC-036", "codec has no host writer or authority and all historical launch gates remain open", async () => {
  const source = await readFile(path.join(root, "tools/lib/maintenance-store-codec.mjs"), "utf8");
  assert.doesNotMatch(source, /node:(?:fs|net|http|child_process)|\b(?:fetch\s*\(|eval\s*\(|process\.|Date\.now\s*\()/u);
  const { planBackendLaunch } = await import("../../src/backend/launch-plan.mjs");
  const plan = planBackendLaunch({ operation: "Version" }); assert.equal(plan.execution_enabled, false);
  assert.deepEqual(plan.blockers.map(item => item.id), ["TL-ADJACENT-DLL", "TL-LINKED-TOKEN", "TL-NON-ELEVATED-MECHANISM", "TL-REPARSE-REPLACEMENT", "TL-INITIAL-INVENTORY", "TL-PREVENTIVE-LOAD-POLICY", "TL-UNKNOWN-MODULES", "TL-IMAGE-BYTE-BINDING", "TL-PRODUCTION-LOAD-CONTEXT"]);
  assert.ok(plan.blockers.every(item => item.status === "Open"));
});

assert.equal(new Set(required).size, required.length);
assert.equal(new Set(cases.map(item => item.id)).size, cases.length);
assert.deepEqual(cases.map(item => item.id).sort(), [...required].sort());
const executed = new Set();
for (const item of cases) test(`${item.id}: ${item.label}`, async () => { await item.fn(); executed.add(item.id); });
test("store codec gate: exact required IDs passed with zero skipped cases", () => {
  assert.deepEqual([...executed].sort(), [...required].sort());
});

import { types } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { AJV_OPTIONS } from "./constants.mjs";
import { jcs, jcsSha256 } from "./jcs.mjs";
import { parseJsonObjectBytes } from "../../src/import/import-json.mjs";
import deployment from "../../schemas/development/deployment-scenario.schema.json" with { type: "json" };
import message from "../../schemas/development/maintenance-message.schema.json" with { type: "json" };
import scenario from "../../schemas/development/maintenance-scenario.schema.json" with { type: "json" };
import projection from "../../schemas/development/maintenance-projection.schema.json" with { type: "json" };

// Reference/development validation only. Static schema imports are code assets;
// there is no remote schema loader or host-data reader/writer in this API.
const warnings = [];
const ajv = new Ajv2020({ ...AJV_OPTIONS, logger: {
  log() {}, warn(value) { warnings.push(value); }, error(value) { warnings.push(value); }
} });
addFormats(ajv, { mode: "full", formats: ["date-time"], keywords: false });
for (const schema of [deployment, message, scenario, projection]) ajv.addSchema(schema);
const validators = {
  message: ajv.getSchema(message.$id), scenario: ajv.getSchema(scenario.$id),
  projection: ajv.getSchema(projection.$id),
  store: ajv.compile({ $ref: `${scenario.$id}#/$defs/store` })
};
if (warnings.length) throw new Error("Maintenance development schemas produced strict-validation warnings.");

export class MaintenanceProtocolInputError extends Error {
  constructor() {
    super("Invalid synthetic maintenance protocol input.");
    this.name = "MaintenanceProtocolInputError";
    this.code = "MAINTENANCE_PROTOCOL_INPUT_INVALID";
  }
}
function invalid() { throw new MaintenanceProtocolInputError(); }

export function boundedProtocolCopy(value, maxBytes = 16 * 1024 * 1024, maxDepth = 12) {
  let nodes = 0;
  const ancestors = new Set();
  function walk(item, depth) {
    if (++nodes > 200000 || depth > maxDepth) invalid();
    if (item === null || typeof item === "boolean") return;
    if (typeof item === "number") {
      if (!Number.isSafeInteger(item) || Object.is(item, -0)) invalid();
      return;
    }
    if (typeof item === "string") {
      if (item.length > 4096 || Buffer.byteLength(item, "utf8") > 4096) invalid();
      return;
    }
    if (typeof item !== "object" || types.isProxy(item) || ancestors.has(item)) invalid();
    ancestors.add(item);
    const keys = Reflect.ownKeys(item);
    if (Array.isArray(item)) {
      if (Object.getPrototypeOf(item) !== Array.prototype || item.length > 8392 || keys.length !== item.length + 1) invalid();
      for (let index = 0; index < item.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) invalid();
        walk(descriptor.value, depth + 1);
      }
    } else {
      if (![Object.prototype, null].includes(Object.getPrototypeOf(item)) || keys.length > 32) invalid();
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (typeof key !== "string" || key.length > 64 || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) invalid();
        walk(descriptor.value, depth + 1);
      }
    }
    ancestors.delete(item);
  }
  try {
    walk(value, 0);
    const canonical = jcs(value);
    if (Buffer.byteLength(canonical, "utf8") > maxBytes) invalid();
    return JSON.parse(canonical);
  } catch { invalid(); }
}

export function checkedProtocolData(kind, value) {
  if (!Object.hasOwn(validators, kind)) invalid();
  const copy = boundedProtocolCopy(value, kind === "message" ? 65536 : 16 * 1024 * 1024,
    kind === "message" ? 8 : 12);
  if (!validators[kind](copy)) invalid();
  if (kind === "scenario" || kind === "projection") {
    const ms = Date.parse(copy.simulated_at);
    if (!Number.isFinite(ms) || new Date(ms).toISOString().replace(".000Z", "Z") !== copy.simulated_at) invalid();
  }
  return copy;
}

// In-memory control JSON body decoder, NOT a native framing/stream reader.
// PayloadChunk is metadata only and is intentionally not accepted here.
export function decodeMaintenanceControlFrame(bytes) {
  try {
    if (bytes === null || typeof bytes !== "object" || types.isProxy(bytes) || !types.isUint8Array(bytes)) invalid();
    const proto = Object.getPrototypeOf(Uint8Array.prototype);
    const get = (name) => Object.getOwnPropertyDescriptor(proto, name).get.call(bytes);
    const length = get("byteLength");
    const buffer = get("buffer");
    if (length === 0 || length > 65536 || types.isSharedArrayBuffer(buffer)) invalid();
    const snapshot = Buffer.from(Buffer.from(buffer, get("byteOffset"), length));
    const parsed = parseJsonObjectBytes(snapshot, { maxJsonBytes: 65536, maxJsonDepth: 8 }).records[0].value;
    const result = checkedProtocolData("message", parsed);
    if (result.type === "PayloadChunk" || result.payload_digest !== jcsSha256(result.payload)) invalid();
    return result;
  } catch { invalid(); }
}

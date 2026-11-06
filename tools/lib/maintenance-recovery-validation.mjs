import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { AJV_OPTIONS } from "./constants.mjs";
import { boundedProtocolCopy } from "./maintenance-protocol-validation.mjs";
import { jcs, jcsSha256 } from "./jcs.mjs";
import schema from "../../schemas/development/maintenance-recovery-v2.schema.json" with { type: "json" };

const warnings = [];
const ajv = new Ajv2020({ ...AJV_OPTIONS, logger: {
  log() {}, warn(x) { warnings.push(x); }, error(x) { warnings.push(x); }
} });
addFormats(ajv, { mode: "full", formats: ["date-time"], keywords: false });
ajv.addSchema(schema);
const gates = Object.fromEntries(["scenario", "storage", "offer", "document", "projection"].map(name =>
  [name, ajv.compile({ $ref: `${schema.$id}#/$defs/${name}` })]));
if (warnings.length) throw new Error("Recovery v2 strict-schema warning.");
export class RecoveryInputError extends Error {
  constructor() { super("Invalid synthetic recovery v2 input."); this.code = "RECOVERY_V2_INPUT_INVALID"; }
}
export const recoveryBytes = value => Buffer.byteLength(jcs(value), "utf8");
export function recoveryDigest(value, field, domain) {
  const { [field]: omitted, ...body } = value;
  return jcsSha256({ domain: `SecApp-Synthetic-Recovery-v2-${domain}`, body });
}
export function checkedRecoveryData(kind, value) {
  try {
    const copy = boundedProtocolCopy(value, 4194304, 20);
    if (!Object.hasOwn(gates, kind) || !gates[kind](copy)) throw new Error();
    const disk = kind === "storage" ? copy : copy.storage;
    // Inspect every timestamp slot in the schema-validated bounded shape,
    // including nested current and historical offers. RFC 3339 leap seconds
    // are not representable by this model's ECMAScript clock; never normalize
    // them or let NaN satisfy an admission check. History is checked for a
    // supported representation only, not re-expired against the current time.
    const times = [copy.simulated_at, copy.expires_at, copy.authorization?.offer.expires_at,
      ...(disk?.records ?? []).map(record => record.authorization?.offer.expires_at)];
    for (const time of times.filter(value => value !== undefined)) {
      const parsed = Date.parse(time);
      if (!Number.isFinite(parsed) || new Date(parsed).toISOString().replace(".000Z", "Z") !== time) throw new Error();
    }
    if (disk && ([disk.anchor, disk.head, disk.checkpoint_candidate, disk.obsolete_checkpoint].filter(Boolean).some(x => recoveryBytes(x) > 8192)
      || recoveryBytes(disk.records) > 1048576 || disk.records.some(x => recoveryBytes(x) > 16384))) throw new Error();
    return copy;
  } catch { throw new RecoveryInputError(); }
}
export function freezeRecovery(value) {
  if (value !== null && typeof value === "object") { Object.values(value).forEach(freezeRecovery); Object.freeze(value); }
  return value;
}

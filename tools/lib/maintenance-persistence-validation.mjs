import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { AJV_OPTIONS } from "./constants.mjs";
import { boundedProtocolCopy } from "./maintenance-protocol-validation.mjs";
import { jcs } from "./jcs.mjs";
import scenario from "../../schemas/development/maintenance-persistence-scenario.schema.json" with { type: "json" };
import projection from "../../schemas/development/maintenance-persistence-projection.schema.json" with { type: "json" };

const warnings = [];
const ajv = new Ajv2020({ ...AJV_OPTIONS, logger: {
  log() {}, warn(value) { warnings.push(value); }, error(value) { warnings.push(value); }
} });
addFormats(ajv, { mode: "full", formats: ["date-time"], keywords: false });
ajv.addSchema(scenario); ajv.addSchema(projection);
const gates = {
  scenario: ajv.getSchema(scenario.$id), projection: ajv.getSchema(projection.$id),
  storage: ajv.compile({ $ref: `${scenario.$id}#/$defs/storage` })
};
if (warnings.length) throw new Error("Persistence development schemas produced strict-validation warnings.");

export class MaintenancePersistenceInputError extends Error {
  constructor() {
    super("Invalid synthetic maintenance persistence input.");
    this.name = "MaintenancePersistenceInputError";
    this.code = "MAINTENANCE_PERSISTENCE_INPUT_INVALID";
  }
}
export const persistenceBytes = value => Buffer.byteLength(jcs(value), "utf8");
export function checkedPersistenceData(kind, value) {
  try {
    if (!Object.hasOwn(gates, kind)) throw new MaintenancePersistenceInputError();
    // Reuse the existing proxy/getter/cycle/scalar guard before Ajv or hashing.
    const copy = boundedProtocolCopy(value, 4 * 1024 * 1024, 12);
    if (!gates[kind](copy)) throw new MaintenancePersistenceInputError();
    if (kind !== "storage") {
      const ms = Date.parse(copy.simulated_at);
      if (!Number.isFinite(ms) || new Date(ms).toISOString().replace(".000Z", "Z") !== copy.simulated_at) throw new MaintenancePersistenceInputError();
    }
    const disk = kind === "storage" ? copy : copy.storage;
    if (persistenceBytes(disk.anchor) > 8192 || persistenceBytes(disk.head) > 8192
      || (disk.checkpoint_candidate && persistenceBytes(disk.checkpoint_candidate) > 8192)
      || persistenceBytes(disk.records) > 1048576 || disk.records.some(record => persistenceBytes(record) > 16384)) throw new MaintenancePersistenceInputError();
    return copy;
  } catch { throw new MaintenancePersistenceInputError(); }
}

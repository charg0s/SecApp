import { fileURLToPath } from "node:url";
import { createSchemaRegistry, dependencyVersions } from "./schema-registry.mjs";
import { validateSupplyChain } from "./supply-chain.mjs";
import { schemaIdForContractKind } from "../../src/import/import-normalization.mjs";

// Development/reference adapter shared by the CLI and synthetic tests.
// The importer itself remains independent of Ajv and this registry.
export function createImportReferenceValidator() {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  validateSupplyChain(root);
  const versions = dependencyVersions();
  if (versions.ajv !== "8.20.0" || versions["ajv-formats"] !== "3.0.1") {
    throw new Error("Import reference validator dependency version mismatch.");
  }
  const registry = createSchemaRegistry(root);
  const validators = new Map();
  for (const { schema } of registry.schemas) {
    if (!registry.ajv.validateSchema(schema)) throw new Error("Invalid local schema.");
    const validate = registry.ajv.getSchema(schema.$id);
    if (typeof validate !== "function") throw new Error("Missing local schema validator.");
    validators.set(schema.$id, validate);
  }
  if (registry.warnings.length !== 0) throw new Error("Local schema registry emitted a strict warning.");
  return ({ contractKind, schemaId, value }) => {
    if (schemaIdForContractKind(contractKind) !== schemaId) return false;
    const validate = validators.get(schemaId);
    return typeof validate === "function" && validate(value) === true;
  };
}

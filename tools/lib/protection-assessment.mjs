import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createSchemaRegistry } from "./schema-registry.mjs";
import { parseStrictJson } from "./strict-json.mjs";
import { sha256LowerHex } from "./jcs.mjs";
import { WINDOWS_PROTECTION_PROFILE as PROFILE } from "../../src/assessment/windows-protection-profile.mjs";
import { assessWindowsProtection } from "../../src/assessment/windows-protection.mjs";
import { reject } from "../../src/import/import-errors.mjs";

const REPORT_ID = "https://schemas.secapp.dev/v1/reports/windows-protection-report.schema.json";

export function createProtectionAssessment(referenceValidator) {
  if (typeof referenceValidator !== "function") throw new Error("Reference schema validator is required.");
  const registry = createSchemaRegistry(fileURLToPath(new URL("../../", import.meta.url)));
  const schemaDigests = {};
  for (const domain of PROFILE.domains) {
    const bytes = readFileSync(new URL(`../../schemas/observations/${domain.file}`, import.meta.url));
    const schema = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (schema.$id !== domain.schema_id || schema.$schema !== "https://json-schema.org/draft/2020-12/schema"
      || schema.properties?.schema_version?.const !== "1.0.0" || !registry.ajv.validateSchema(schema)) throw new Error("Invalid local domain schema.");
    registry.ajv.addSchema(schema, domain.schema_id);
    registry.ajv.getSchema(domain.schema_id);
    schemaDigests[domain.schema_id] = sha256LowerHex(bytes);
  }
  const reportSchema = parseStrictJson(readFileSync(new URL("../../schemas/reports/windows-protection-report.schema.json", import.meta.url), "utf8"));
  if (reportSchema.$id !== REPORT_ID || !registry.ajv.validateSchema(reportSchema)) throw new Error("Invalid report schema.");
  const validateReport = registry.ajv.compile(reportSchema);
  if (registry.warnings.length !== 0) throw new Error("Schema compilation warning.");
  const validateObservation = async (observation) => {
    if (await referenceValidator({ contractKind: "Observation", schemaId: "https://schemas.secapp.dev/v1/observation.schema.json", value: observation }) !== true) return false;
    const validate = registry.ajv.getSchema(observation.data_schema);
    return typeof validate === "function" && validate(observation.data) === true;
  };
  return async (importResult) => {
    const report = await assessWindowsProtection(importResult, { validateObservation, schemaDigests });
    if (!validateReport(report)) reject("ASSESSMENT_REPORT_INVALID", "Assessment", "Generated report failed its local schema.");
    return report;
  };
}

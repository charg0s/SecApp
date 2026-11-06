import { isImportError, reject } from "./import-errors.mjs";

export async function runReferenceValidation(subjects, referenceValidator) {
  if (typeof referenceValidator !== "function") {
    reject("IMPORT_REFERENCE_VALIDATION_REQUIRED", "Schema", "A reference-validation function is required for acceptance.");
  }
  for (const subject of subjects) {
    let result;
    try {
      result = await referenceValidator({
        contractKind: subject.contractKind,
        schemaId: subject.schemaId,
        value: structuredClone(subject.value)
      });
    } catch (error) {
      if (isImportError(error)) throw error;
      reject("IMPORT_REFERENCE_VALIDATOR_FAILED", "Schema", "The reference validator failed in a controlled boundary.");
    }
    const valid = result === true || result?.valid === true;
    if (!valid) reject("IMPORT_SCHEMA_VALIDATION_FAILED", "Schema", "Imported contract failed reference schema validation.");
  }
}

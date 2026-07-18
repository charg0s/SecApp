export const TOOL_VERSION = "1.0.0";
export const DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema";
export const SCHEMA_NAMESPACE = "https://schemas.secapp.dev/v1/";
export const SCHEMA_VERSION = "1.0.0";

export const ANNOTATION_KEYWORDS = Object.freeze([
  "x-application-limits",
  "x-application-rules",
  "x-negative-tests",
  "x-numeric-operator-cases",
  "x-scalar-validation-cases",
  "x-state-contract"
]);

export const AJV_OPTIONS = Object.freeze({
  strict: true,
  strictSchema: true,
  strictTypes: true,
  strictTuples: true,
  strictRequired: true,
  allowUnionTypes: false,
  allErrors: true,
  validateSchema: true,
  validateFormats: true,
  useDefaults: false,
  coerceTypes: false,
  removeAdditional: false,
  unevaluated: true,
  discriminator: true,
  unicodeRegExp: true
});

export const FIXTURE_KINDS = Object.freeze([
  "FullContractInstance",
  "DigestProjection",
  "ShapeOnly"
]);

export const PATH_PATTERN = /^(?!\/)(?!.*\/\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*[\\:\u0000-\u001F\u007F])(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127})(?:\/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$/u;

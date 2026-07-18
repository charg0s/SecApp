import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { AJV_OPTIONS, ANNOTATION_KEYWORDS, DRAFT_2020_12, SCHEMA_NAMESPACE, SCHEMA_VERSION } from "./constants.mjs";
import { compareUnicodeCodeUnits } from "./order.mjs";
import { readStrictJson } from "./strict-json.mjs";

const require = createRequire(import.meta.url);

export function dependencyVersions() {
  return {
    ajv: require("ajv/package.json").version,
    "ajv-formats": require("ajv-formats/package.json").version
  };
}

function collectAnnotations(value, result = new Set()) {
  if (Array.isArray(value)) value.forEach((item) => collectAnnotations(item, result));
  else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (key.startsWith("x-")) result.add(key);
      collectAnnotations(item, result);
    }
  }
  return result;
}

export function loadSchemas(root) {
  const directory = path.join(root, "schemas");
  const files = fs.readdirSync(directory).filter((file) => file.endsWith(".json")).sort(compareUnicodeCodeUnits);
  const schemas = files.map((file) => ({
    file: path.posix.join("schemas", file),
    absoluteFile: path.join(directory, file),
    schema: readStrictJson(path.join(directory, file), path.posix.join("schemas", file))
  }));
  const ids = new Set();
  for (const item of schemas) {
    const schema = item.schema;
    validateSchemaIdentity(item.file, schema);
    if (ids.has(schema.$id)) throw new Error(`${item.file}: duplicate $id ${schema.$id}`);
    ids.add(schema.$id);
  }
  const annotations = [...schemas.reduce((set, item) => collectAnnotations(item.schema, set), new Set())].sort(compareUnicodeCodeUnits);
  const unknown = annotations.filter((keyword) => !ANNOTATION_KEYWORDS.includes(keyword));
  if (unknown.length) throw new Error(`Unknown custom annotation keywords: ${unknown.join(", ")}`);
  const referenceCount = schemas.reduce((total, item) => total + countSchemaReferences(item.schema), 0);
  return { schemas, annotations, referenceCount };
}

export function validateSchemaIdentity(file, schema) {
  if (schema.$schema !== DRAFT_2020_12) throw new Error(`${file}: unsupported $schema ${JSON.stringify(schema.$schema)}`);
  if (typeof schema.$id !== "string" || !schema.$id.startsWith(SCHEMA_NAMESPACE)) throw new Error(`${file}: invalid immutable $id`);
  if (schema.$id !== `${SCHEMA_NAMESPACE}${path.basename(file)}`) throw new Error(`${file}: $id does not match immutable namespace/file name`);
  if (schema.properties?.schema_version?.const !== SCHEMA_VERSION) throw new Error(`${file}: schema_version must be const ${SCHEMA_VERSION}`);
}

export function countSchemaReferences(value) {
  if (Array.isArray(value)) return value.reduce((total, item) => total + countSchemaReferences(item), 0);
  if (!value || typeof value !== "object") return 0;
  return Object.entries(value).reduce((total, [key, item]) => total + (key === "$ref" ? 1 : 0) + countSchemaReferences(item), 0);
}

export function createSchemaRegistry(root) {
  const warnings = [];
  const logger = {
    log: () => {},
    warn: (message) => warnings.push(String(message)),
    error: (message) => warnings.push(String(message))
  };
  const ajv = new Ajv2020({ ...AJV_OPTIONS, logger });
  addFormats(ajv, { mode: "full", formats: ["date-time", "uri", "uuid"], keywords: false });
  for (const keyword of ANNOTATION_KEYWORDS) ajv.addKeyword({ keyword, valid: true, errors: false });
  const loaded = loadSchemas(root);
  for (const item of loaded.schemas) ajv.addSchema(item.schema, item.schema.$id);
  return { ajv, warnings, ...loaded };
}

export function formatAjvErrors(errors = []) {
  return errors.map((error) => ({
    instance_path: error.instancePath || "/",
    schema_path: error.schemaPath,
    keyword: error.keyword,
    message: error.message ?? "schema validation failed"
  }));
}

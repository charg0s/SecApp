import fs from "node:fs";
import path from "node:path";
import { FIXTURE_KINDS } from "./constants.mjs";
import { jsonPointerGet, readStrictJson } from "./strict-json.mjs";
import { isXobjRecord, materializeXobjRecord, xobjSchemaSubjects } from "./xobj-graph.mjs";
import { compareUnicodeCodeUnits } from "./order.mjs";

function listJson(directory, root, result = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => compareUnicodeCodeUnits(a.name, b.name))) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) listJson(absolute, root, result);
    else if (entry.isFile() && entry.name.endsWith(".json")) result.push(path.relative(root, absolute).split(path.sep).join("/"));
  }
  return result;
}

function countBy(records, field) {
  const result = {};
  for (const record of records) {
    const key = String(record.descriptor[field]);
    result[key] = (result[key] ?? 0) + 1;
  }
  return result;
}

export function loadVectorCatalog(root) {
  const indexFile = path.join(root, "tests", "contracts", "index.json");
  const index = readStrictJson(indexFile, "tests/contracts/index.json");
  if (!Array.isArray(index.sources)) throw new Error("tests/contracts/index.json: sources must be an array");
  const records = [];
  const vectorIds = new Set();
  const sourceFiles = new Set();
  const documents = new Map();

  for (const source of index.sources) {
    if (typeof source.file !== "string" || !source.file.startsWith("tests/contracts/") || path.isAbsolute(source.file)) {
      throw new Error(`Invalid contract source path: ${JSON.stringify(source.file)}`);
    }
    if (sourceFiles.has(source.file)) throw new Error(`Duplicate contract source: ${source.file}`);
    sourceFiles.add(source.file);
    const absolute = path.join(root, ...source.file.split("/"));
    if (!fs.existsSync(absolute)) throw new Error(`Missing contract source: ${source.file}`);
    const document = readStrictJson(absolute, source.file);
    documents.set(source.file, document);
    if (!Array.isArray(source.vectors) || source.vector_count !== source.vectors.length) {
      throw new Error(`${source.file}: index vector_count mismatch`);
    }
    for (const descriptor of source.vectors) {
      if (typeof descriptor.vector_id !== "string" || vectorIds.has(descriptor.vector_id)) {
        throw new Error(`Duplicate or invalid vector_id: ${JSON.stringify(descriptor.vector_id)}`);
      }
      vectorIds.add(descriptor.vector_id);
      if (!FIXTURE_KINDS.includes(descriptor.fixture_kind)) throw new Error(`${descriptor.vector_id}: invalid fixture_kind`);
      const fixture = jsonPointerGet(document, descriptor.json_pointer);
      if (fixture.vector_id !== undefined && fixture.vector_id !== descriptor.vector_id) throw new Error(`${descriptor.vector_id}: index pointer resolves to another vector`);
      if (fixture.vector_id === undefined && descriptor.instance_pointer === undefined) throw new Error(`${descriptor.vector_id}: non-vector index target has no instance_pointer`);
      for (const field of ["fixture_kind", "expected_schema_valid", "expected_application_valid", "expected_error_code", "rule_id"]) {
        if (Object.hasOwn(descriptor, field) && Object.hasOwn(fixture, field) && descriptor[field] !== fixture[field]) {
          throw new Error(`${descriptor.vector_id}: index/source mismatch for ${field}`);
        }
      }
      if (descriptor.instance_pointer) jsonPointerGet(document, descriptor.instance_pointer);
      records.push({ source: source.file, descriptor, fixture, document });
    }
  }

  const actualSources = listJson(path.join(root, "tests", "contracts"), root)
    .filter((file) => file !== "tests/contracts/index.json");
  const orphans = actualSources.filter((file) => !sourceFiles.has(file));
  const missing = [...sourceFiles].filter((file) => !actualSources.includes(file));
  if (orphans.length || missing.length) throw new Error(`Contract source inventory mismatch; orphan=${orphans.join(",")}; missing=${missing.join(",")}`);

  if (index.counts?.total_vectors !== records.length) throw new Error("index counts.total_vectors mismatch");
  const kindCounts = countBy(records, "fixture_kind");
  for (const kind of FIXTURE_KINDS) {
    if ((index.counts?.by_fixture_kind?.[kind] ?? 0) !== (kindCounts[kind] ?? 0)) throw new Error(`index fixture count mismatch for ${kind}`);
  }
  for (const field of ["expected_schema_valid", "expected_application_valid"]) {
    const actual = countBy(records, field);
    for (const key of ["true", "false", "null"]) {
      if ((index.counts?.[`by_${field}`]?.[key] ?? 0) !== (actual[key] ?? 0)) throw new Error(`index ${field} count mismatch for ${key}`);
    }
  }
  return { index, records, documents };
}

function materializeSource(root, sourceFile, source) {
  const baseDirectory = path.dirname(path.join(root, ...sourceFile.split("/")));
  const absolute = path.resolve(baseDirectory, source.file);
  const contractsRoot = path.resolve(root, "tests", "contracts");
  if (!absolute.startsWith(`${contractsRoot}${path.sep}`)) throw new Error(`Digest source escapes tests/contracts: ${source.file}`);
  const document = readStrictJson(absolute, path.relative(root, absolute).split(path.sep).join("/"));
  const vector = document.vectors?.find((item) => item.vector_id === source.vector_id);
  if (!vector) throw new Error(`Digest source vector does not exist: ${source.vector_id}`);
  return jsonPointerGet(vector, source.instance_pointer);
}

export function schemaSubjects(root, record) {
  const { fixture, descriptor } = record;
  if (isXobjRecord(record)) return xobjSchemaSubjects(materializeXobjRecord(record));
  if (Array.isArray(fixture.schema_instances)) {
    return fixture.schema_instances.map((item) => ({ schemaId: item.schema_id, instance: item.instance }));
  }
  if (fixture.source) {
    return [{ schemaId: fixture.schema_id, instance: materializeSource(root, record.source, fixture.source) }];
  }
  if (fixture.instance) return [{ schemaId: fixture.schema_id ?? descriptor.schema_id ?? descriptor.schema_ids?.[0], instance: fixture.instance }];
  if (fixture.shape) return [{ schemaId: fixture.schema_id ?? descriptor.schema_id ?? descriptor.schema_ids?.[0], instance: fixture.shape }];
  if (descriptor.instance_pointer) {
    const schemaIds = descriptor.schema_ids ?? (descriptor.schema_id ? [descriptor.schema_id] : []);
    const instance = jsonPointerGet(record.document, descriptor.instance_pointer);
    if (schemaIds.length === 1) return [{ schemaId: schemaIds[0], instance }];
  }
  return [];
}

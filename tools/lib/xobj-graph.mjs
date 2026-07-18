import path from "node:path";
import { compareUnicodeCodeUnits } from "./order.mjs";

export const XOBJ_COLLECTION_SCHEMAS = Object.freeze({
  audit_runs: "https://schemas.secapp.dev/v1/audit-run.schema.json",
  audit_passes: "https://schemas.secapp.dev/v1/audit-pass.schema.json",
  collector_definitions: "https://schemas.secapp.dev/v1/collector-definition.schema.json",
  collector_executions: "https://schemas.secapp.dev/v1/collector-execution.schema.json",
  observations: "https://schemas.secapp.dev/v1/observation.schema.json",
  evidence_references: "https://schemas.secapp.dev/v1/evidence-reference.schema.json",
  findings: "https://schemas.secapp.dev/v1/finding.schema.json",
  consent_receipts: "https://schemas.secapp.dev/v1/consent-receipt.schema.json",
  action_logs: "https://schemas.secapp.dev/v1/action-log.schema.json",
  audit_manifests: "https://schemas.secapp.dev/v1/audit-manifest.schema.json",
  export_manifests: "https://schemas.secapp.dev/v1/export-manifest.schema.json",
  redaction_profiles: "https://schemas.secapp.dev/v1/redaction-profile.schema.json",
  reboot_continuation_states: "https://schemas.secapp.dev/v1/reboot-continuation-state.schema.json",
  rule_definitions: "https://schemas.secapp.dev/v1/rule-definition.schema.json"
});

export const XOBJ_GRAPH_KEYS = Object.freeze([
  "graph_version",
  "test_only",
  "run_id",
  "validation_context",
  "collections",
  "loaded_digests",
  "replay_history",
  "manifest_membership_index",
  "redaction_field_registry",
  "capability_graph",
  "size_measurements"
]);

const MAX_GRAPH_BYTES = 4 * 1024 * 1024;
const MAX_MUTATIONS = 64;
const MAX_COLLECTION_ITEMS = 10000;
const ID_FIELDS = Object.freeze({
  audit_runs: "run_id",
  audit_passes: "pass_id",
  collector_definitions: "collector_id",
  collector_executions: "execution_id",
  observations: "observation_id",
  evidence_references: "evidence_id",
  findings: "finding_id",
  consent_receipts: "receipt_id",
  action_logs: "action_log_id",
  audit_manifests: "manifest_id",
  export_manifests: "export_id",
  redaction_profiles: "profile_id",
  reboot_continuation_states: "state_id",
  rule_definitions: "rule_id"
});

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function pointerTokens(pointer, allowAppend = false) {
  if (typeof pointer !== "string" || !pointer.startsWith("/") || pointer.length > 2048) throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
  const tokens = pointer.slice(1).split("/").map((token) => token.replace(/~1/g, "/").replace(/~0/g, "~"));
  if (tokens.some((token, index) => token === "" || token === "__proto__" || token === "prototype" || token === "constructor"
    || (token === "-" && (!allowAppend || index !== tokens.length - 1)))) throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
  return tokens;
}

function resolveParent(root, pointer, allowAppend = false) {
  const tokens = pointerTokens(pointer, allowAppend);
  const leaf = tokens.pop();
  let current = root;
  for (const token of tokens) {
    if ((Array.isArray(current) && !/^\d+$/.test(token)) || current === null || typeof current !== "object" || !Object.hasOwn(current, token)) {
      throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
    }
    current = current[token];
  }
  return { current, leaf };
}

function pointerGet(root, pointer) {
  let current = root;
  for (const token of pointerTokens(pointer)) {
    if ((Array.isArray(current) && !/^\d+$/.test(token)) || current === null || typeof current !== "object" || !Object.hasOwn(current, token)) {
      throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
    }
    current = current[token];
  }
  return current;
}

function applyMutation(graph, mutation) {
  if (!isPlainObject(mutation) || !["add", "copy", "remove", "replace"].includes(mutation.op)) throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
  const { current, leaf } = resolveParent(graph, mutation.path, mutation.op === "add" || mutation.op === "copy");
  if (mutation.op === "remove") {
    if (Array.isArray(current)) {
      if (!/^\d+$/.test(leaf) || Number(leaf) >= current.length) throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
      current.splice(Number(leaf), 1);
    } else {
      if (!isPlainObject(current) || !Object.hasOwn(current, leaf)) throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
      delete current[leaf];
    }
    return;
  }
  const value = structuredClone(mutation.op === "copy" ? pointerGet(graph, mutation.from) : mutation.value);
  if (Array.isArray(current)) {
    if (["add", "copy"].includes(mutation.op) && leaf === "-") current.push(value);
    else if (/^\d+$/.test(leaf) && Number(leaf) < current.length) current[Number(leaf)] = value;
    else throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
  } else {
    if (!isPlainObject(current) || (mutation.op === "replace" && !Object.hasOwn(current, leaf))) throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
    current[leaf] = value;
  }
}

function rejectAbsolutePaths(value, key = "", depth = 0) {
  if (depth > 80) throw new Error("XOBJ_GRAPH_BOUNDS_EXCEEDED");
  if (Array.isArray(value)) return value.forEach((item) => rejectAbsolutePaths(item, key, depth + 1));
  if (isPlainObject(value)) return Object.entries(value).forEach(([childKey, item]) => rejectAbsolutePaths(item, childKey, depth + 1));
  if (typeof value === "string" && (key.endsWith("path") || key.endsWith("_path"))
    && (path.win32.isAbsolute(value) || path.posix.isAbsolute(value))) throw new Error("XOBJ_GRAPH_ABSOLUTE_PATH_FORBIDDEN");
}

function compareIds(collection, left, right) {
  const field = ID_FIELDS[collection];
  return compareUnicodeCodeUnits(String(left?.[field] ?? ""), String(right?.[field] ?? ""));
}

function assertGraphShape(graph) {
  if (!isPlainObject(graph)) throw new Error("XOBJ_GRAPH_INPUT_MISSING");
  const keys = Object.keys(graph).sort(compareUnicodeCodeUnits);
  if (keys.length !== XOBJ_GRAPH_KEYS.length || XOBJ_GRAPH_KEYS.some((key) => !Object.hasOwn(graph, key))) throw new Error("XOBJ_GRAPH_INPUT_MISSING");
  if (keys.some((key) => !XOBJ_GRAPH_KEYS.includes(key))) throw new Error("XOBJ_GRAPH_UNKNOWN_OBJECT_KIND");
  if (graph.graph_version !== "1.0.0" || graph.test_only !== true || typeof graph.run_id !== "string") throw new Error("XOBJ_GRAPH_INPUT_MISSING");
  if (!isPlainObject(graph.collections)) throw new Error("XOBJ_GRAPH_INPUT_MISSING");
  const expectedCollections = Object.keys(XOBJ_COLLECTION_SCHEMAS).sort(compareUnicodeCodeUnits);
  const actualCollections = Object.keys(graph.collections).sort(compareUnicodeCodeUnits);
  if (actualCollections.some((key) => !expectedCollections.includes(key))) throw new Error("XOBJ_GRAPH_UNKNOWN_OBJECT_KIND");
  if (expectedCollections.some((key) => !actualCollections.includes(key))) throw new Error("XOBJ_GRAPH_INPUT_MISSING");
  for (const name of expectedCollections) {
    if (!Array.isArray(graph.collections[name])) throw new Error("XOBJ_GRAPH_INPUT_MISSING");
    if (graph.collections[name].length > MAX_COLLECTION_ITEMS) throw new Error("XOBJ_GRAPH_BOUNDS_EXCEEDED");
    graph.collections[name].sort((left, right) => compareIds(name, left, right));
  }
  for (const key of ["validation_context", "loaded_digests", "replay_history", "size_measurements"]) {
    if (!isPlainObject(graph[key])) throw new Error("XOBJ_GRAPH_INPUT_MISSING");
  }
  for (const key of ["manifest_membership_index", "redaction_field_registry", "capability_graph"]) {
    if (!Array.isArray(graph[key]) || graph[key].length > MAX_COLLECTION_ITEMS) throw new Error("XOBJ_GRAPH_INPUT_MISSING");
  }
  rejectAbsolutePaths(graph);
  if (Buffer.byteLength(JSON.stringify(graph), "utf8") > MAX_GRAPH_BYTES) throw new Error("XOBJ_GRAPH_BOUNDS_EXCEEDED");
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

export function materializeGraph(baseGraph, mutations = []) {
  if (!Array.isArray(mutations) || mutations.length > MAX_MUTATIONS) throw new Error("XOBJ_GRAPH_MUTATION_INVALID");
  const graph = structuredClone(baseGraph);
  for (const mutation of mutations) applyMutation(graph, mutation);
  assertGraphShape(graph);
  return deepFreeze(graph);
}

export function isXobjRecord(record) {
  const declared = record.fixture.rule_ids ?? (record.fixture.rule_id ? [record.fixture.rule_id] : []);
  return record.source.includes("/xobj/") || declared.some((rule) => rule.startsWith("XOBJ-"));
}

export function materializeXobjRecord(record) {
  if (!isXobjRecord(record) || !record.document.base_graph || typeof record.fixture.graph_ref !== "string") {
    throw new Error("XOBJ_GRAPH_INPUT_MISSING");
  }
  let setupMutations = [];
  if (record.fixture.graph_ref !== "/base_graph") {
    const match = /^\/consent_variant_graphs\/([A-Za-z][A-Za-z0-9]*)$/.exec(record.fixture.graph_ref);
    const graphVariant = match && record.document.consent_variant_graphs?.[match[1]];
    if (!Array.isArray(graphVariant)) throw new Error("XOBJ_GRAPH_INPUT_MISSING");
    setupMutations = graphVariant;
  }
  return materializeGraph(record.document.base_graph, [...setupMutations, ...(record.fixture.mutations ?? [])]);
}

export function xobjSchemaSubjects(graph) {
  return Object.entries(XOBJ_COLLECTION_SCHEMAS).flatMap(([collection, schemaId]) =>
    graph.collections[collection].map((instance) => ({ schemaId, instance })));
}

import crypto from "node:crypto";
import { types } from "node:util";
import { compareUnicodeCodeUnits, compareUtf8Bytes } from "./order.mjs";

export function clone(value) {
  return structuredClone(value);
}

export function deleteJsonPointer(value, pointer) {
  const tokens = pointer.split(".");
  const leaf = tokens.pop();
  let current = value;
  for (const token of tokens) {
    if (current === null || typeof current !== "object" || !Object.hasOwn(current, token)) {
      throw new Error(`Digest exclusion path does not exist: ${pointer}`);
    }
    current = current[token];
  }
  if (!Object.hasOwn(current, leaf)) throw new Error(`Digest exclusion path does not exist: ${pointer}`);
  delete current[leaf];
}

export class JcsInputError extends TypeError {
  constructor(message) {
    super(message);
    this.name = "JcsInputError";
    this.code = "JCS_INPUT_INVALID";
  }
}

function fail(message, pointer) {
  throw new JcsInputError(`${message} at ${pointer || "/"}`);
}

function assertUnicodeScalarString(value, pointer) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail("Unpaired surrogate", pointer);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail("Unpaired surrogate", pointer);
    }
  }
}

function pointerToken(value) {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function canonical(value, pointer, ancestors) {
  if (value === null) return "null";
  const kind = typeof value;
  if (kind === "boolean") return value ? "true" : "false";
  if (kind === "number") {
    if (!Number.isFinite(value)) fail("Non-finite number", pointer);
    return JSON.stringify(value);
  }
  if (kind === "string") {
    assertUnicodeScalarString(value, pointer);
    return JSON.stringify(value);
  }
  if (kind !== "object") fail(`Unsupported ${kind} value`, pointer);
  if (types.isProxy(value)) fail("Proxy object", pointer);
  if (ancestors.has(value)) fail("Cyclic object graph", pointer);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getOwnPropertySymbols(value).length !== 0) fail("Symbol-keyed array property", pointer);
      const names = Object.getOwnPropertyNames(value);
      if (names.length !== value.length + 1) fail("Sparse array or non-JSON array property", pointer);
      const items = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) fail("Sparse array", `${pointer}/${index}`);
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail("Unsafe array property descriptor", `${pointer}/${index}`);
        items.push(canonical(descriptor.value, `${pointer}/${index}`, ancestors));
      }
      return `[${items.join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail("Non-plain object", pointer);
    if (Object.getOwnPropertySymbols(value).length !== 0) fail("Symbol-keyed object property", pointer);
    const members = [];
    for (const key of Object.getOwnPropertyNames(value).sort(compareUnicodeCodeUnits)) {
      const memberPointer = `${pointer}/${pointerToken(key)}`;
      assertUnicodeScalarString(key, memberPointer);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail("Unsafe object property descriptor", memberPointer);
      members.push(`${JSON.stringify(key)}:${canonical(descriptor.value, memberPointer, ancestors)}`);
    }
    return `{${members.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function jcs(value) {
  return canonical(value, "", new Set());
}

export function sha256LowerHex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function jcsSha256(value) {
  return sha256LowerHex(Buffer.from(jcs(value), "utf8"));
}

function rejectDuplicates(items, key, label) {
  const seen = new Set();
  for (const item of items) {
    const value = key(item);
    if (seen.has(value)) throw new Error(`Duplicate ${label}: ${value}`);
    seen.add(value);
  }
}

export function normalizeAuditManifest(manifest) {
  const result = clone(manifest);
  rejectDuplicates(result.entries, (entry) => entry.member_id, "member_id");
  rejectDuplicates(result.entries, (entry) => entry.logical_path, "logical_path");
  result.entries.sort((left, right) => compareUtf8Bytes(left.logical_path, right.logical_path) || compareUtf8Bytes(left.member_id, right.member_id));
  return result;
}

export function normalizeExportManifest(manifest) {
  const result = clone(manifest);
  rejectDuplicates(result.entries, (entry) => entry.export_logical_path, "export_logical_path");
  rejectDuplicates(result.entries, (entry) => entry.source_member_id, "source_member_id");
  rejectDuplicates(result.omissions, (item) => item.omission_id, "omission_id");
  rejectDuplicates(result.warnings, (item) => `${item.warning_code}\u0000${item.subject_path}`, "warning tuple");
  result.entries.sort((left, right) => compareUtf8Bytes(left.export_logical_path, right.export_logical_path) || compareUtf8Bytes(left.source_member_id, right.source_member_id));
  result.omissions.sort((left, right) => compareUtf8Bytes(left.omission_id, right.omission_id) || compareUtf8Bytes(left.source_logical_path, right.source_logical_path));
  result.warnings.sort((left, right) => compareUtf8Bytes(left.warning_code, right.warning_code) || compareUtf8Bytes(left.subject_path, right.subject_path));
  return result;
}

export function normalizeRedactionProfile(profile) {
  const result = clone(profile);
  if (!Array.isArray(result.field_rules)) throw new Error("DIGEST_PROFILE_FIELD_INVALID");
  const fields = new Set();
  for (const rule of result.field_rules) {
    if (!rule || typeof rule !== "object" || typeof rule.field !== "string" || rule.field.length === 0) {
      throw new Error("DIGEST_PROFILE_FIELD_INVALID");
    }
    if (fields.has(rule.field)) throw new Error("DIGEST_PROFILE_DUPLICATE_FIELD");
    fields.add(rule.field);
  }
  result.field_rules.sort((left, right) => compareUtf8Bytes(left.field, right.field));
  return result;
}

export function profileDigest(profile) {
  return digestWithExclusion(profile, "profile_digest.digest", normalizeRedactionProfile);
}

export function materializeByteSource(source) {
  if (!source || typeof source !== "object" || typeof source.encoding !== "string" || typeof source.data !== "string") {
    throw new Error("DIGEST_BYTE_SOURCE_INVALID");
  }
  if (source.encoding === "Hex") {
    if (source.data.length % 2 !== 0 || !/^[0-9a-fA-F]*$/u.test(source.data)) throw new Error("DIGEST_BYTE_ENCODING_INVALID");
    return Buffer.from(source.data, "hex");
  }
  if (source.encoding === "Base64") {
    if (source.data.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(source.data)) {
      throw new Error("DIGEST_BYTE_ENCODING_INVALID");
    }
    const bytes = Buffer.from(source.data, "base64");
    if (bytes.toString("base64") !== source.data) throw new Error("DIGEST_BYTE_ENCODING_INVALID");
    return bytes;
  }
  throw new Error("DIGEST_BYTE_SOURCE_UNSUPPORTED");
}

export function canonicalizeContentBytes(bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error("DIGEST_CONTENT_UTF8_INVALID");
  }
  if (text.startsWith("\uFEFF")) text = text.slice(1);
  text = text.replace(/\r\n?/gu, "\n");
  if (!text.endsWith("\n")) text += "\n";
  return Buffer.from(text, "utf8");
}

export function contentDigestFromBytes(bytes) {
  return sha256LowerHex(canonicalizeContentBytes(bytes));
}

export function digestWithExclusion(value, exclusion, normalize = (item) => item) {
  const result = normalize(clone(value));
  deleteJsonPointer(result, exclusion);
  return jcsSha256(result);
}

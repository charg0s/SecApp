import path from "node:path";
import { reject } from "./import-errors.mjs";

export function assertLocalSourcePath(value, platform = process.platform) {
  if (typeof value !== "string") reject("IMPORT_SOURCE_PATH_INVALID", "Prepare", "sourcePath must be a local file path.");
  const windows = platform === "win32";
  const absolute = windows ? /^[A-Za-z]:[\\/]/u.test(value) : path.posix.isAbsolute(value);
  if (typeof value !== "string" || !absolute || /^[\\/]{2}/u.test(value) || /[\u0000-\u001F\u007F]/u.test(value)) {
    reject("IMPORT_SOURCE_PATH_INVALID", "Prepare", "sourcePath must be an absolute local non-device path.");
  }
  if (windows) {
    const tail = value.slice(3);
    if (tail.includes(":") || tail.split(/[\\/]/u).some((part) =>
      /^(?:con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3]|conin\$|conout\$)(?:\.|$)/iu.test(part)
      || (part !== "." && part !== ".." && /[. ]$/u.test(part)))) {
      reject("IMPORT_SOURCE_PATH_INVALID", "Prepare", "Alternate streams and device aliases are forbidden.");
    }
  }
  return value;
}

export const CANONICAL_LOGICAL_PATH = /^(?!\/)(?!.*\/\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*[\\:\u0000-\u001F\u007F])(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127})(?:\/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$/u;

const FORBIDDEN_EXTENSIONS = /\.(?:7z|bat|cmd|com|cpl|dll|exe|gz|hta|jar|js|lnk|msi|msp|pl|ps1|psm1|py|rar|rb|scr|sh|sys|tar|tgz|vbs|wsf|zip)$/iu;

function begins(bytes, signature) {
  return bytes.length >= signature.length && signature.every((value, index) => bytes[index] === value);
}

export function assertCanonicalLogicalPath(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 1024 || !CANONICAL_LOGICAL_PATH.test(value)) {
    reject("IMPORT_PATH_INVALID", "Container", "A non-canonical logical path was rejected.");
  }
  return value;
}

export function assertUniqueArchivePath(name, exact, folded) {
  assertCanonicalLogicalPath(name);
  if (exact.has(name)) reject("IMPORT_ZIP_DUPLICATE_PATH", "Container", "A duplicate archive path was rejected.");
  const collision = name.toLowerCase();
  if (folded.has(collision)) reject("IMPORT_ZIP_PATH_COLLISION", "Container", "A case-colliding archive path was rejected.");
  exact.add(name);
  folded.add(collision);
}

export function assertNonExecutableContent(name, bytes) {
  if (FORBIDDEN_EXTENSIONS.test(name)) {
    reject("IMPORT_EXECUTABLE_CONTENT_FORBIDDEN", "Container", "Executable or nested archive content is forbidden.");
  }
  const nestedArchive = begins(bytes, [0x50, 0x4b, 0x03, 0x04])
    || begins(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
    || begins(bytes, [0x52, 0x61, 0x72, 0x21])
    || begins(bytes, [0x1f, 0x8b])
    || (bytes.length >= 262 && bytes.subarray(257, 262).toString("ascii") === "ustar");
  if (nestedArchive) reject("IMPORT_ZIP_NESTED_ARCHIVE", "Container", "Nested archives are forbidden.");
  const executableMagic = begins(bytes, [0x4d, 0x5a])
    || begins(bytes, [0x7f, 0x45, 0x4c, 0x46])
    || begins(bytes, [0xcf, 0xfa, 0xed, 0xfe])
    || begins(bytes, [0xfe, 0xed, 0xfa, 0xcf]);
  if (executableMagic) {
    reject("IMPORT_EXECUTABLE_CONTENT_FORBIDDEN", "Container", "Executable content is forbidden.");
  }
}

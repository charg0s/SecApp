import path from "node:path";
import { readStrictJson } from "./strict-json.mjs";

const REQUIRED_SCRIPTS = Object.freeze([
  "validate:schemas",
  "validate:contracts",
  "validate:application",
  "validate:digests",
  "validate:all",
  "test"
]);
const LIFECYCLE_SCRIPTS = Object.freeze(["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"]);

export function validateSupplyChain(root) {
  const manifest = readStrictJson(path.join(root, "package.json"), "package.json");
  const lock = readStrictJson(path.join(root, "package-lock.json"), "package-lock.json");
  if (manifest.private !== true || manifest.type !== "module") throw new Error("package.json must be private and type=module");
  if (manifest.publishConfig !== undefined) throw new Error("package.json must not contain publishConfig");
  if (manifest.dependencies !== undefined && Object.keys(manifest.dependencies).length !== 0) throw new Error("runtime dependencies are forbidden");
  const expected = { ajv: "8.20.0", "ajv-formats": "3.0.1" };
  if (JSON.stringify(manifest.devDependencies) !== JSON.stringify(expected)) throw new Error("devDependencies must contain only exact pinned ajv versions");
  if (Object.values(manifest.devDependencies).some((version) => /[\^~*xX]|latest/u.test(version))) throw new Error("devDependency versions must be exact");
  for (const script of REQUIRED_SCRIPTS) if (typeof manifest.scripts?.[script] !== "string") throw new Error(`Missing required npm script: ${script}`);
  for (const script of LIFECYCLE_SCRIPTS) if (Object.hasOwn(manifest.scripts ?? {}, script)) throw new Error(`Lifecycle script is forbidden: ${script}`);
  if (lock.lockfileVersion !== 3) throw new Error(`Unsupported lockfileVersion: ${lock.lockfileVersion}`);
  if (JSON.stringify(lock.packages?.[""]?.devDependencies) !== JSON.stringify(expected)) throw new Error("lockfile root devDependencies mismatch");
  let resolvedPackages = 0;
  for (const [name, entry] of Object.entries(lock.packages ?? {})) {
    if (name === "") continue;
    resolvedPackages += 1;
    if (entry.dev !== true) throw new Error(`${name}: every installed package must be dev-only`);
    if (typeof entry.resolved !== "string" || !/^https:\/\/registry\.npmjs\.org\//u.test(entry.resolved)) throw new Error(`${name}: non-official or non-HTTPS resolved URL`);
    if (!/^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(entry.integrity ?? "")) throw new Error(`${name}: missing or invalid SHA-512 integrity`);
    if (entry.optional === true || entry.hasInstallScript === true || entry.link === true) throw new Error(`${name}: optional/native/install-script/link package is forbidden`);
  }
  return {
    lockfile_version: lock.lockfileVersion,
    resolved_package_count: resolvedPackages,
    locked_resolved_origin: "https://registry.npmjs.org/",
    integrity: "sha512 present for every resolved package",
    lifecycle_scripts: "none declared in root; no lock entry hasInstallScript",
    runtime_dependencies: 0
  };
}

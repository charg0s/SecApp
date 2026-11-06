import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runImportCommand } from "../../tools/lib/import-command.mjs";
import { referenceValidate } from "./reference-validator.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixture = "tests/import/fixtures/error-object.json";
const temporaryRoot = await mkdtemp(path.join(tmpdir(), "secapp-import-cli-test-"));
const options = { cwd: root, loadReferenceValidator: async () => referenceValidate };
after(async () => { await rm(temporaryRoot, { recursive: true, force: true }); });

test("CLI displays help without initializing validation", async () => {
  const result = await runImportCommand(["--help"], {
    loadReferenceValidator: () => { throw new Error("Must not load for help"); }
  });
  assert.equal(result.exitCode, 0);
  assert.match(result.output, /--source/);
});

test("CLI imports a relative path and emits one privacy-safe JSON result", async () => {
  const { exitCode, output } = await runImportCommand(["--source", fixture, "--json"], options);
  const result = JSON.parse(output);
  assert.equal(exitCode, 0);
  assert.equal(result.status, "Accepted");
  assert.equal(result.validation.reference_schema, "Passed");
  assert.equal(result.assessment_status, "NotPerformed");
  assert.equal(result.validation_scope, "ImportContractChecks");
  assert.equal(result.summary.provenance_claim, "NotEstablished");
  assert.equal(Object.hasOwn(result, "objects"), false);
  assert.equal(output.includes(root), false);
  const value = JSON.parse(await readFile(path.join(root, fixture), "utf8"));
  assert.equal(output.includes(value.error_id), false);
  assert.equal(output.includes(value.message), false);
});

test("CLI produces a readable summary", async () => {
  const { exitCode, output } = await runImportCommand(["--source", fixture], options);
  assert.equal(exitCode, 0);
  assert.match(output, /SecApp import: Accepted/);
  assert.match(output, /ErrorObject: 1/);
  assert.match(output, /Security assessment: not performed/);
});

test("CLI rejects ambiguous, unsupported, and weakened arguments before initialization", async () => {
  let loads = 0;
  const invalidArguments = [
    [], ["--source", fixture, "--source", fixture], ["--source", fixture, "--private"],
    ["--source", fixture, "--kind", "Unknown"], ["--source", fixture, "--max-source-bytes", "67108865"],
    ["--source", fixture, "--max-source-bytes", "1e6"], ["--source", fixture, "extra"],
    ["--source", fixture, "--help"], ["--source", "//synthetic.invalid/share/input.json"]
  ];
  for (const argv of invalidArguments) {
    const result = await runImportCommand([...argv, "--json"], {
      cwd: root,
      loadReferenceValidator: () => { loads += 1; return referenceValidate; }
    });
    assert.equal(result.exitCode, 64);
    assert.equal(JSON.parse(result.output).error.code, "IMPORT_CLI_ARGUMENTS_INVALID");
  }
  assert.equal(loads, 0);
});

test("CLI fails closed and redacts details when validator initialization fails", async () => {
  const { exitCode, output } = await runImportCommand(["--source", fixture, "--json"], {
    cwd: root,
    loadReferenceValidator: () => { throw new Error("synthetic-private-initialization-detail"); }
  });
  assert.equal(exitCode, 1);
  assert.equal(JSON.parse(output).error.code, "IMPORT_CLI_VALIDATOR_UNAVAILABLE");
  assert.equal(output.includes("synthetic-private-initialization-detail"), false);
});

test("CLI rejects invalid contracts through the real schema registry", async () => {
  const value = JSON.parse(await readFile(path.join(root, fixture), "utf8"));
  value.stage = "Unknown";
  const sourcePath = path.join(temporaryRoot, "invalid.json");
  await writeFile(sourcePath, JSON.stringify(value));
  const { exitCode, output } = await runImportCommand(["--source", sourcePath, "--json"], options);
  assert.equal(exitCode, 2);
  assert.equal(JSON.parse(output).error.code, "IMPORT_SCHEMA_VALIDATION_FAILED");
  assert.equal(output.includes(sourcePath), false);
});

test("CLI applies lowered limits, package-kind selection, and JSONL framing policy", async () => {
  const tooSmall = await runImportCommand(["--source", fixture, "--max-source-bytes", "1", "--json"], options);
  assert.equal(tooSmall.exitCode, 2);
  assert.equal(JSON.parse(tooSmall.output).error.code, "IMPORT_SOURCE_BYTES_EXCEEDED");
  const kind = await runImportCommand(["--source", fixture, "--kind", "JsonLines", "--json"], options);
  assert.equal(kind.exitCode, 2);
  assert.equal(JSON.parse(kind.output).error.code, "IMPORT_PACKAGE_KIND_MISMATCH");
  const sourcePath = path.join(temporaryRoot, "no-final-lf.jsonl");
  await writeFile(sourcePath, (await readFile(path.join(root, fixture), "utf8")).trim());
  // A JSONL record must occupy one line.
  await writeFile(sourcePath, JSON.stringify(JSON.parse(await readFile(sourcePath, "utf8"))));
  const framed = await runImportCommand(["--source", sourcePath, "--require-final-lf", "--json"], options);
  assert.equal(framed.exitCode, 2);
  assert.equal(JSON.parse(framed.output).error.code, "IMPORT_JSONL_FINAL_LF_REQUIRED");
});

test("CLI entrypoint works from another directory with literal file arguments", async () => {
  const value = JSON.parse(await readFile(path.join(root, fixture), "utf8"));
  const sourcePath = path.join(temporaryRoot, "synthetic space; literal.json");
  await writeFile(sourcePath, JSON.stringify(value));
  const result = spawnSync(process.execPath, [path.join(root, "tools/import-audit-package.mjs"), "--source", sourcePath, "--json"], {
    cwd: temporaryRoot, encoding: "utf8", shell: false, windowsHide: true, timeout: 15_000, maxBuffer: 64 * 1024
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  assert.equal(JSON.parse(result.stdout).status, "Accepted");
  assert.equal(result.stdout.includes(sourcePath), false);
});

test("CLI entrypoint uses nonzero exit status for a missing input", () => {
  const result = spawnSync(process.execPath, [path.join(root, "tools/import-audit-package.mjs"), "--source", path.join(temporaryRoot, "missing.json"), "--json"], {
    cwd: temporaryRoot, encoding: "utf8", shell: false, windowsHide: true, timeout: 15_000, maxBuffer: 64 * 1024
  });
  assert.equal(result.status, 2);
  assert.equal(result.stderr, "");
  assert.equal(JSON.parse(result.stdout).error.code, "IMPORT_SOURCE_READ_FAILED");
});

test("reference adapter binds the detected contract kind to its exact local schema", () => {
  assert.equal(referenceValidate({ contractKind: "AuditRun", schemaId: "https://schemas.secapp.dev/v1/error-object.schema.json", value: {} }), false);
});

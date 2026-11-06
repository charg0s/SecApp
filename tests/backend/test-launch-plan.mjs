import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { BACKEND_PIN, LAUNCH_BLOCKERS, LAUNCH_LIMITS, planBackendLaunch } from "../../src/backend/launch-plan.mjs";
import { runBackendPlanCommand } from "../../tools/lib/backend-plan-command.mjs";
import { digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { createSchemaRegistry } from "../../tools/lib/schema-registry.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const registry = createSchemaRegistry(root);
const schema = JSON.parse(await readFile(path.join(root, "schemas/backend/launch-plan.schema.json"), "utf8"));
assert.equal(registry.ajv.validateSchema(schema), true);
const validate = registry.ajv.compile(schema);
assert.deepEqual(registry.warnings, []);
const exactBlockerIds = [
  "TL-ADJACENT-DLL", "TL-LINKED-TOKEN", "TL-NON-ELEVATED-MECHANISM",
  "TL-REPARSE-REPLACEMENT", "TL-INITIAL-INVENTORY", "TL-PREVENTIVE-LOAD-POLICY",
  "TL-UNKNOWN-MODULES", "TL-IMAGE-BYTE-BINDING", "TL-PRODUCTION-LOAD-CONTEXT"
];

for (const operation of ["Version", "Help"]) {
  test(`${operation}: fixed, schema-valid, deterministic blocked plan`, () => {
    const plan = planBackendLaunch({ operation });
    assert.equal(validate(plan), true, JSON.stringify(validate.errors));
    assert.deepEqual(plan, planBackendLaunch({ operation }));
    assert.deepEqual(plan.command_template.argv, ["--nobanner", "--nocolor", operation === "Version" ? "version" : "--help"]);
    assert.equal(plan.execution_enabled, false);
    assert.equal(plan.development_authorized, true);
    assert.equal(plan.status, "Blocked");
    assert.equal(plan.binary_verification, "NotPerformed");
    assert.equal(plan.provenance_claim, "NotEstablished");
    assert.equal(plan.plan_digest, digestWithExclusion(plan, "plan_digest"));
    assert.deepEqual(plan.blockers.map((item) => item.id), exactBlockerIds);
    assert.ok(plan.blockers.every((item) => item.status === "Open"));
  });
}

test("historical backend identity and diagnostic argv agree with retained compatibility records", async () => {
  const compatibility = JSON.parse(await readFile(path.join(root, "tests/compatibility/expected/compatibility-contract.json"), "utf8"));
  const trust = JSON.parse(await readFile(path.join(root, "tests/compatibility/trust-launch/expected/trust-launch-contract.json"), "utf8"));
  for (const key of ["release", "source_commit", "asset_name", "sha256", "openpgp_fingerprint"]) assert.equal(BACKEND_PIN[key], trust.backend_pin[key]);
  assert.equal(BACKEND_PIN.size_bytes, compatibility.observed_backend_identity.file_size_bytes);
  assert.deepEqual(planBackendLaunch({ operation: "Version" }).command_template.argv, compatibility.invocations.version);
  assert.deepEqual(planBackendLaunch({ operation: "Help" }).command_template.argv, compatibility.invocations.help);
  assert.equal(trust.readiness.production_adapter_ready, false);
});

test("caller cannot mutate shared registry, returned plans, or limits", () => {
  const request = { operation: "Version", limits: { timeout_ms: 1 } };
  const plan = planBackendLaunch(request);
  request.limits.timeout_ms = 999999;
  assert.equal(plan.limits.timeout_ms, 1);
  for (const mutate of [
    () => { plan.execution_enabled = true; },
    () => { plan.command_template.argv.push("gui"); },
    () => { plan.blockers.pop(); },
    () => { LAUNCH_BLOCKERS[0].description = "approved"; },
    () => { BACKEND_PIN.sha256 = "synthetic-substitution"; },
    () => { LAUNCH_LIMITS.timeout_ms = 999999; }
  ]) assert.throws(mutate, TypeError);
});

test("rejects unknown commands, raw paths, force switches, and caller-supplied readiness", () => {
  for (const operation of [undefined, null, 1, "", "version", "Collect", "gui", "query", "__proto__", "constructor", "version; whoami"]) {
    assert.throws(() => planBackendLaunch({ operation }), { code: "LAUNCH_PLAN_INPUT_INVALID" });
  }
  for (const key of ["force", "execute", "execution_enabled", "readiness", "blockers", "backend_pin", "executable", "argv", "config", "artifact", "environment", "consent"]) {
    assert.throws(() => planBackendLaunch({ operation: "Version", [key]: "synthetic-private-canary" }), { code: "LAUNCH_PLAN_INPUT_INVALID" });
  }
});

test("rejects accessors, proxies, symbols, inherited and non-plain requests without reading getters", () => {
  let getterReads = 0;
  const accessor = { get operation() { getterReads++; return "Version"; } };
  const limitsAccessor = { operation: "Version", get limits() { getterReads++; return {}; } };
  for (const request of [null, [], "Version", new Date(), Object.create({ operation: "Version" }),
    new Proxy({ operation: "Version" }, { get() { throw new Error("must not read proxy"); } }),
    accessor, limitsAccessor, { operation: "Version", [Symbol("private")]: true }]) {
    assert.throws(() => planBackendLaunch(request), { code: "LAUNCH_PLAN_INPUT_INVALID" });
  }
  assert.equal(getterReads, 0);
});

for (const [field, maximum] of Object.entries(LAUNCH_LIMITS)) {
  test(`${field}: lowering-only limits reject unsafe numbers and types`, () => {
    for (const value of [1, maximum]) {
      const plan = planBackendLaunch({ operation: "Version", limits: { [field]: value } });
      assert.equal(plan.limits[field], value);
      assert.equal(validate(plan), true);
    }
    for (const value of [0, -1, 0.5, maximum + 1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "1", null]) {
      assert.throws(() => planBackendLaunch({ operation: "Version", limits: { [field]: value } }), { code: "LAUNCH_PLAN_INPUT_INVALID" });
    }
  });
}

test("schema rejects readiness promotion, omitted gates, command mismatch, and pin substitution", () => {
  for (const mutate of [
    (value) => { value.status = "Ready"; },
    (value) => { value.execution_enabled = true; },
    (value) => { value.binary_verification = "Verified"; },
    (value) => { value.blockers.pop(); },
    (value) => { value.blockers[0] = value.blockers[1]; },
    (value) => { value.blockers[0].status = "Pass"; },
    (value) => { value.required_before_launch.pop(); },
    (value) => { value.command_template.argv[2] = "--help"; },
    (value) => { value.command_template.shell = true; },
    (value) => { value.command_template.argv.push("--config=synthetic"); },
    (value) => { value.backend_pin.sha256 = "a".repeat(64); },
    (value) => { value.limits.timeout_ms = 10001; },
    (value) => { value.extra = "synthetic"; }
  ]) {
    const plan = structuredClone(planBackendLaunch({ operation: "Version" }));
    mutate(plan);
    assert.equal(validate(plan), false);
  }
});

test("CLI handles help, blocked plans, lowered limits, and redacted failures", () => {
  assert.equal(runBackendPlanCommand(["--help"]).exitCode, 0);
  const result = runBackendPlanCommand(["--operation", "Version", "--json", "--timeout-ms", "1"]);
  assert.equal(result.exitCode, 2);
  assert.equal(JSON.parse(result.output).limits.timeout_ms, 1);
  assert.match(runBackendPlanCommand(["--operation", "Help"]).output, /без выполнения/);
  for (const args of [[], ["--force"], ["--operation", "Version", "--execute"], ["--help", "--json"],
    ["--operation", "Version", "--operation", "Help"], ["--operation", "synthetic-private-canary"],
    ["--operation", "Version", "--timeout-ms", "10001"], ["--operation", "Version", "--timeout-ms", "1e2"],
    ["--operation", "Version", "--max-stdout-bytes", "01"], ["--operation", "Version", "--max-stderr-bytes", "-1"]]) {
    const rejected = runBackendPlanCommand([...args, ...(args.includes("--json") ? [] : ["--json"])]);
    assert.equal(rejected.exitCode, 64);
    assert.equal(JSON.parse(rejected.output).execution_enabled, false);
    assert.equal(rejected.output.includes("synthetic-private-canary"), false);
  }
});

test("actual CLI runs only the Node planner and returns blocked JSON", () => {
  const result = spawnSync(process.execPath, [path.join(root, "tools/plan-backend-launch.mjs"), "--operation", "Version", "--json"], {
    cwd: root, encoding: "utf8", shell: false, windowsHide: true, timeout: 5000, maxBuffer: 65536
  });
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.stderr, "");
  assert.equal(validate(JSON.parse(result.stdout)), true);
});

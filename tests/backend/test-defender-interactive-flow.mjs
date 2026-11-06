import test from "node:test";
import assert from "node:assert/strict";
import { DEFENDER_BUILD_PINS, decodeDefenderBuild, defenderConfirmation, runDefenderCheckCommand } from "../../src/backend/defender-interactive-flow.mjs";

const id = "0123456789abcdef0123456789abcdef";
const build = () => ({ kind: "SecAppDefenderBuildV1", run_id: id, executed: false, ...DEFENDER_BUILD_PINS, helper_sha256: "4".repeat(64) });
const receipt = () => ({ kind: "SecAppDefenderControlV1", run_id: id, outcome: "Completed", error: "NONE",
  backend_created: true, backend_resumed: true, backend_exit: 0, root_exited: true, job_empty: true, pipes_closed: true,
  elapsed_ms: 100, stdout_base64: Buffer.from('{"AMRunningMode":"Normal","RealTimeProtectionEnabled":true}\n').toString("base64") });
const envelope = () => ({ kind: "SecAppDefenderRunEnvelopeV1", run_id: id, helper_exit_confirmed: true, helper_exit_code: 0,
  data_files_removed: true, workspace_removed: false, result_json: JSON.stringify(receipt()) + "\n" });
const discarded = () => ({ kind: "SecAppDefenderDiscardV1", run_id: id, data_files_removed: true, workspace_removed: false });
function transport(row, fields = {}) { return { code: 0, closed: true, signal: null, overflow: false, timedOut: false,
  aborted: false, ioError: false, stdout: Buffer.from(JSON.stringify(row)), stderr: Buffer.alloc(0), ...fields }; }
function setup(overrides = {}) {
  const calls = [], output = [], errors = [];
  return { calls, output, errors, io: { platform: "win32", interactive: true,
    stdout: (text) => output.push(text), stderr: (text) => errors.push(text),
    prepare: async () => { calls.push("prepare"); return transport(build()); },
    prompt: async () => { calls.push("prompt"); return defenderConfirmation(build()); },
    run: async (value) => { calls.push("run"); assert.ok(Object.isFrozen(value)); assert.deepEqual(value, build()); return transport(envelope()); },
    discard: async (value) => { calls.push("discard"); assert.equal(value.run_id, id); return transport(discarded()); }, ...overrides } };
}
test("one explicit confirmation leads to exactly one run and a labelled result", async () => {
  const x = setup(); assert.equal(await runDefenderCheckCommand([], x.io), 0);
  assert.deepEqual(x.calls, ["prepare", "prompt", "run"]);
  const text = x.output.join("");
  for (const required of ["AMRunningMode", "RealTimeProtectionEnabled", "read-only sandbox", "журнале Windows",
    "не полный аудит", "controller.lock", "40 с", "180 с", "SHA-256", "СОБРАТЬ 01234567"]) assert.ok(text.includes(required), required);
  assert.equal(x.errors.length, 0);
});
for (const args of [["--yes"], ["--run"], ["--input", "PRIVATE"], ["--help", "--yes"], ["--query", "PRIVATE"]]) {
  test(`rejects flags before effects: ${args[0]}`, async () => { const x = setup(); assert.equal(await runDefenderCheckCommand(args, x.io), 1); assert.deepEqual(x.calls, []); assert.ok(!x.errors.join("").includes("PRIVATE")); });
}
for (const setting of [{ interactive: false }, { platform: "linux" }]) {
  test(`requires interactive Windows before prepare: ${JSON.stringify(setting)}`, async () => {
    const x = setup(setting); assert.equal(await runDefenderCheckCommand([], x.io), 1); assert.deepEqual(x.calls, []);
  });
}
test("help works without a terminal and has no effects", async () => {
  const x = setup({ interactive: false, platform: "linux" }); assert.equal(await runDefenderCheckCommand(["--help"], x.io), 0); assert.deepEqual(x.calls, []);
});
for (const answer of [null, "", "yes", "да", "СОБРАТЬ ffffffff", "СОБРАТЬ 01234567 ", "x".repeat(65)]) {
  test(`decline/EOF/invalid answer never runs: ${String(answer).slice(0, 24)}`, async () => {
    const x = setup({ prompt: async () => answer }); assert.equal(await runDefenderCheckCommand([], x.io), 3);
    assert.deepEqual(x.calls, ["prepare", "discard"]); assert.ok(x.output.join("").includes("Velociraptor не запускался"));
  });
}
for (const [key, value] of [["kind", "Other"], ["executed", true], ["run_id", "../PRIVATE"], ["helper_sha256", "no"],
  ["source_sha256", "0".repeat(64)], ["workspace_sha256", "0".repeat(64)], ["manifest_sha256", "0".repeat(64)], ["extra", true]]) {
  test(`rejects build ${key} before prompt or run`, async () => {
    const row = build(); row[key] = value;
    const x = setup({ prepare: async () => transport(row) }); assert.equal(await runDefenderCheckCommand([], x.io), 1); assert.deepEqual(x.calls, []);
  });
}
test("strict build JSON rejects duplicates, invalid UTF-8 and oversize", () => {
  for (const bytes of [Buffer.from(JSON.stringify(build()).replace('"executed":false', '"executed":true,"executed":false')),
    Buffer.from([0xff]), Buffer.alloc(2049)]) assert.throws(() => decodeDefenderBuild(transport(build(), { stdout: bytes })));
});
for (const fields of [{ closed: false }, { timedOut: true }, { aborted: true }, { ioError: true }, { overflow: true },
  { code: 1 }, { signal: "SIGTERM" }, { stderr: Buffer.from("PRIVATE ERROR") }]) {
  test(`bad preparation transport fails: ${Object.keys(fields)[0]}`, async () => {
    const x = setup({ prepare: async () => transport(build(), fields) }); assert.equal(await runDefenderCheckCommand([], x.io), 1);
    assert.deepEqual(x.calls, []); assert.ok(!x.errors.join("").includes("PRIVATE ERROR"));
  });
}
for (const [key, value] of [["run_id", "f".repeat(32)], ["outcome", "Failed"], ["error", "PRIVATE"], ["backend_exit", 1],
  ["root_exited", false], ["job_empty", false], ["pipes_closed", false], ["backend_created", false], ["backend_resumed", false], ["elapsed_ms", 40000]]) {
  test(`failed live receipt is not a report or cleanup authority: ${key}`, async () => {
    const row = receipt(); row[key] = value; const outer = envelope(); outer.result_json = JSON.stringify(row);
    let runs = 0; const x = setup({ run: async () => { runs++; return transport(outer); } });
    assert.equal(await runDefenderCheckCommand([], x.io), 1); assert.equal(runs, 1); assert.ok(!x.calls.includes("discard"));
    assert.ok(!x.output.join("").includes("Режим Defender: Активный")); assert.ok(!x.errors.join("").includes("PRIVATE"));
  });
}
for (const [key, value] of [["kind", "Other"], ["run_id", "f".repeat(32)], ["helper_exit_confirmed", false],
  ["workspace_removed", true], ["data_files_removed", "true"], ["result_json", {}], ["extra", "PRIVATE"]]) {
  test(`rejects envelope ${key}`, async () => {
    const row = envelope(); row[key] = value; const x = setup({ run: async () => transport(row) });
    assert.equal(await runDefenderCheckCommand([], x.io), 1); assert.ok(!x.calls.includes("discard"));
  });
}
test("cleanup failure is visible, not successful completion or a second cleanup", async () => {
  const row = envelope(); row.data_files_removed = false;
  const x = setup({ run: async () => transport(row, { code: 1 }) });
  assert.equal(await runDefenderCheckCommand([], x.io), 1);
  assert.ok(x.output.join("").includes("Режим Defender: Активный")); assert.ok(x.errors.join("").includes("Очистка данных не подтверждена"));
  assert.ok(!x.calls.includes("discard"));
});
test("nonzero actual helper exit cannot be relabelled as only a cleanup failure", async () => {
  for (const code of [1, 124, "0", null]) {
    const row = envelope(); row.helper_exit_code = code; row.data_files_removed = false;
    const x = setup({ run: async () => transport(row, { code: 1 }) });
    assert.equal(await runDefenderCheckCommand([], x.io), 1);
    assert.ok(!x.output.join("").includes("Режим Defender:"));
    assert.ok(!x.calls.includes("discard"));
  }
});
test("missing coverage stays NotTested even after completed lifecycle", async () => {
  const inner = receipt(); inner.stdout_base64 = ""; const row = envelope(); row.result_json = JSON.stringify(inner);
  const x = setup({ run: async () => transport(row) }); assert.equal(await runDefenderCheckCommand([], x.io), 2);
  assert.ok(x.output.join("").includes("проверка не засчитана"));
});
test("prompt exception discards only the prepared run and never exposes exception text", async () => {
  const x = setup({ prompt: async () => { throw new Error("PRIVATE EXCEPTION"); } });
  assert.equal(await runDefenderCheckCommand([], x.io), 1); assert.deepEqual(x.calls, ["prepare", "discard"]);
  assert.ok(!x.errors.join("").includes("PRIVATE EXCEPTION"));
});
test("run exception is not retried or cleaned as an unstarted run", async () => {
  let count = 0; const x = setup({ run: async () => { count++; throw new Error("PRIVATE EXCEPTION"); } });
  assert.equal(await runDefenderCheckCommand([], x.io), 1); assert.equal(count, 1); assert.ok(!x.calls.includes("discard"));
});
test("discard failure is not retried", async () => {
  let count = 0; const x = setup({ prompt: async () => null, discard: async () => { count++; return transport({ ...discarded(), run_id: "f".repeat(32) }); } });
  assert.equal(await runDefenderCheckCommand([], x.io), 1); assert.equal(count, 1); assert.ok(!x.calls.includes("run"));
});

import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { captureController, createDefenderControllerExecutor, verifyDefenderControlSources } from "../../tools/lib/defender-control-executor.mjs";
import { readDefenderConfirmation } from "../../tools/lib/defender-console.mjs";

function child() {
  const value = new EventEmitter(); value.stdout = new PassThrough(); value.stderr = new PassThrough(); value.kills = 0;
  value.kill = () => { value.kills++; return true; }; value.unref = () => {};
  return value;
}
test("reviewed source hashes match; verification only reads files", verifyDefenderControlSources);
test("executor fixes absolute program, script, arguments and environment", async () => {
  const calls = []; let verified = 0;
  const fake = (...args) => { calls.push(args); const c = child(); queueMicrotask(() => { c.stdout.write("{}"); c.emit("close", 0, null); }); return c; };
  const runner = createDefenderControllerExecutor({ spawnProcess: fake, verifySources: async () => { verified++; },
    environment: { SystemRoot: "C:\\Windows", USERPROFILE: "synthetic", PATH: "UNTRUSTED", NODE_OPTIONS: "UNTRUSTED", PSModulePath: "UNTRUSTED" } });
  const build = { run_id: "a".repeat(32), helper_sha256: "b".repeat(64) };
  await runner.prepare(); await runner.run(build); await runner.discard(build);
  assert.equal(verified, 3); assert.equal(calls.length, 3);
  for (const [exe, args, options] of calls) {
    assert.equal(exe, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.deepEqual(args.slice(0, 4), ["-NoLogo", "-NoProfile", "-NonInteractive", "-File"]);
    assert.ok(args[4].endsWith("Invoke-DefenderControl.ps1")); assert.equal(options.shell, false); assert.equal(options.windowsHide, true);
    assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe"]); assert.equal(options.env.PATH, undefined); assert.equal(options.env.NODE_OPTIONS, undefined);
    assert.notEqual(options.env.PSModulePath, "UNTRUSTED"); assert.ok(!args.includes("-ExecutionPolicy"));
  }
  assert.deepEqual(calls[0][1].slice(5), ["-CompileOnly"]);
  assert.deepEqual(calls[1][1].slice(5), ["-RunPrepared", build.run_id, "-ExpectedHelperSha256", build.helper_sha256, "-CleanupOnSuccess"]);
  assert.deepEqual(calls[2][1].slice(5), ["-DiscardPrepared", build.run_id, "-ExpectedHelperSha256", build.helper_sha256]);
});
test("changed source cannot spawn a controller", async () => {
  let called = false; const x = createDefenderControllerExecutor({ spawnProcess: () => { called = true; }, verifySources: async () => { throw new Error("changed"); } });
  await assert.rejects(x.prepare()); assert.equal(called, false);
});
test("environment cannot choose another PowerShell executable", async () => {
  for (const SystemRoot of ["C:\\Dev\\other", "\\\\host\\share", "D:\\Windows", "C:\\Windows\\..\\other", undefined]) {
    let called = false;
    const x = createDefenderControllerExecutor({ spawnProcess: () => { called = true; }, verifySources: async () => {}, environment: { SystemRoot } });
    await assert.rejects(x.prepare(), /^Error: CHECK_WINDOWS_PATH$/u);
    assert.equal(called, false);
  }
});
test("bounded stdout overflow requests only owned-child termination", async () => {
  const c = child(); const pending = captureController(() => c, "fixed", [], {}, { limit: 8, timeoutMs: 100, graceMs: 10 });
  c.stdout.write(Buffer.alloc(9)); c.emit("close", 1, null); const r = await pending;
  assert.equal(r.overflow, true); assert.equal(r.closed, true); assert.equal(r.stdout.length, 0); assert.equal(c.kills, 1);
});
test("timeout plus kill without close is unknown lifetime", async () => {
  const c = child(); const r = await captureController(() => c, "fixed", [], {}, { limit: 8, timeoutMs: 5, graceMs: 5 });
  assert.equal(c.kills, 1); assert.equal(r.timedOut, true); assert.equal(r.closed, false); assert.equal(r.code, null);
});
test("stderr is bounded and never treated as success", async () => {
  const c = child(); const p = captureController(() => c, "fixed", [], {}, { limit: 8, timeoutMs: 100, graceMs: 10 });
  c.stderr.write("synthetic-error"); c.emit("close", 0, null); const r = await p;
  assert.equal(c.kills, 1); assert.equal(r.stderr.toString(), "synthetic-error");
});
test("stream errors cannot become successful transport", async () => {
  const c = child(); const p = captureController(() => c, "fixed", [], {}, { limit: 8, timeoutMs: 100, graceMs: 10 });
  c.stdout.emit("error", new Error("synthetic")); c.emit("close", 0, null); assert.equal((await p).ioError, true);
});
test("already aborted request never spawns", async () => {
  const signal = AbortSignal.abort(); let called = false;
  const r = await captureController(() => { called = true; }, "fixed", [], {}, { limit: 8, timeoutMs: 5, signal });
  assert.equal(called, false); assert.equal(r.aborted, true); assert.equal(r.closed, false);
});
test("active abort is not an elevated-helper exit confirmation", async () => {
  const c = child(), a = new AbortController(); const p = captureController(() => c, "fixed", [], {}, { limit: 8, timeoutMs: 100, graceMs: 10, signal: a.signal });
  a.abort(); c.emit("close", null, "SIGTERM"); const r = await p;
  assert.equal(r.aborted, true); assert.equal(r.closed, true); assert.equal(r.signal, "SIGTERM"); assert.equal(c.kills, 1);
});
function terminal() {
  const input = new PassThrough(); input.isTTY = true; input.isRaw = false;
  input.setRawMode = (value) => { input.isRaw = value; };
  const text = []; const output = { isTTY: true, write: (s) => text.push(s) }; return { input, output, text };
}
test("keyboard UTF-8 chunks and backspace are bounded and raw mode restored", async () => {
  const x = terminal(); const p = readDefenderConfirmation(x.input, x.output, { timeoutMs: 500 });
  const bytes = Buffer.from("СОБРАТЬ a\b01234567\r");
  for (const byte of bytes) x.input.write(Buffer.from([byte]));
  assert.equal(await p, "СОБРАТЬ 01234567"); assert.equal(x.input.isRaw, false); assert.equal(x.input.listenerCount("data"), 0);
});
for (const text of ["x".repeat(65), "\x03", "\x04", "\x1b[31m", "\xff"]) {
  test(`keyboard cancels invalid input ${JSON.stringify(text).slice(0, 20)}`, async () => {
    const x = terminal(); const p = readDefenderConfirmation(x.input, x.output, { timeoutMs: 10 }); x.input.write(text); assert.equal(await p, null); assert.equal(x.input.isRaw, false);
  });
}
test("keyboard timeout cancels and restores raw mode", async () => {
  const x = terminal(); assert.equal(await readDefenderConfirmation(x.input, x.output, { timeoutMs: 5 }), null); assert.equal(x.input.isRaw, false);
});
test("oversized keyboard chunk is rejected before decoding or echo", async () => {
  const x = terminal(); const p = readDefenderConfirmation(x.input, x.output, { timeoutMs: 100 });
  x.input.write(Buffer.alloc(257, 97)); assert.equal(await p, null); assert.deepEqual(x.text, ["\n"]);
});
test("non-TTY is never accepted as interactive confirmation", async () => {
  const x = terminal(); x.input.isTTY = false; assert.equal(await readDefenderConfirmation(x.input, x.output), null);
});
test("real CLI help/invalid/noninteractive invocations use only Node", async () => {
  const invoke = promisify(execFile), script = new URL("../../tools/check-defender.mjs", import.meta.url);
  const help = await invoke(process.execPath, [fileURLToPath(script), "--help"]);
  assert.ok(help.stdout.includes("check:defender"));
  for (const args of [[], ["--yes"]]) await assert.rejects(invoke(process.execPath, [fileURLToPath(script), ...args]), (error) => error.code === 1 && !error.stderr.includes("Error:"));
});

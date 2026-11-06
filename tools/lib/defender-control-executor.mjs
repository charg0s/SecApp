import { spawn } from "node:child_process";
import { lstat, open, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DEFENDER_BUILD_PINS } from "../../src/backend/defender-interactive-flow.mjs";

export const CONTROLLER_SHA256 = "e3fe7413b0846db7dfe858ba7a72e8840ddb8daa0e14552e40c3479a43a61e95";
const controller = fileURLToPath(new URL("../backend/defender-control/Invoke-DefenderControl.ps1", import.meta.url));
const root = fileURLToPath(new URL("../../", import.meta.url));
const sourceNames = { source_sha256: "DefenderControl.cs", workspace_sha256: "Workspace.cs", manifest_sha256: "require-administrator.manifest" };
async function pinnedFile(file, expected) {
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 131072
      || (await realpath(file)).toLowerCase() !== path.resolve(file).toLowerCase()) throw new Error("CHECK_SOURCE_PATH");
  const input = await open(file, "r");
  const bytes = Buffer.alloc(131073);
  try {
    let length = 0;
    while (length < bytes.length) {
      const part = await input.read(bytes, length, bytes.length - length, length);
      if (part.bytesRead === 0) break;
      length += part.bytesRead;
    }
    if (length > 131072 || createHash("sha256").update(bytes.subarray(0, length)).digest("hex") !== expected) throw new Error("CHECK_SOURCE_CHANGED");
  } finally { bytes.fill(0); await input.close(); }
}
export async function verifyDefenderControlSources() {
  await pinnedFile(controller, CONTROLLER_SHA256);
  for (const [key, name] of Object.entries(sourceNames)) await pinnedFile(path.join(path.dirname(controller), name), DEFENDER_BUILD_PINS[key]);
}

// Captures bounded private transport. kill() requests termination of this one
// ordinary child; only 'close' establishes child closure, never helper lifetime.
export function captureController(spawnProcess, executable, args, options, { limit, timeoutMs, signal, graceMs = 5000 }) {
  return new Promise((resolve) => {
    let child, timer, grace, done = false, overflow = false, timedOut = false, aborted = false, ioError = false;
    let outSize = 0, errSize = 0;
    const out = [], err = [];
    const finish = (closed, code = null, childSignal = null) => {
      if (done) return;
      done = true; clearTimeout(timer); clearTimeout(grace);
      signal?.removeEventListener("abort", abort);
      const result = { closed, code, signal: childSignal, overflow, timedOut, aborted, ioError,
        stdout: Buffer.concat(out, outSize), stderr: Buffer.concat(err, errSize) };
      for (const buffer of [...out, ...err]) buffer.fill(0);
      if (!closed && child) { child.stdout?.destroy(); child.stderr?.destroy(); child.unref(); }
      resolve(result);
    };
    const stop = () => {
      if (done || grace) return;
      try { child?.kill(); } catch { /* Not an exit confirmation. */ }
      if (done) return;
      grace = setTimeout(() => finish(false), graceMs);
    };
    const abort = () => { aborted = true; stop(); };
    if (signal?.aborted) { aborted = true; finish(false); return; }
    try { child = spawnProcess(executable, args, options); }
    catch { finish(false); return; }
    const receive = (chunk, isError) => {
      if (done) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const available = (isError ? 4096 : limit) - (isError ? errSize : outSize);
      if (bytes.length > available) { overflow = true; stop(); return; }
      (isError ? err : out).push(Buffer.from(bytes));
      if (isError) { errSize += bytes.length; if (bytes.length) stop(); }
      else outSize += bytes.length;
    };
    child.stdout.on("data", (chunk) => receive(chunk, false));
    child.stderr.on("data", (chunk) => receive(chunk, true));
    const streamError = () => { ioError = true; stop(); };
    child.stdout.on("error", streamError); child.stderr.on("error", streamError);
    child.once("error", () => finish(false));
    child.once("close", (code, value) => finish(true, code, value));
    signal?.addEventListener("abort", abort, { once: true });
    timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
    if (signal?.aborted) abort();
  });
}

export function createDefenderControllerExecutor({ signal, spawnProcess = spawn, verifySources = verifyDefenderControlSources, environment = process.env } = {}) {
  async function invoke(mode, build) {
    await verifySources();
    if (signal?.aborted) throw new Error("CHECK_ABORTED");
    // This development route supports the checked host layout only. An inherited
    // environment variable must never select a different executable/interpreter.
    const windows = "C:\\Windows";
    if (typeof environment.SystemRoot !== "string" || environment.SystemRoot.toLowerCase() !== windows.toLowerCase()) throw new Error("CHECK_WINDOWS_PATH");
    const executable = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    const args = ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", controller];
    let limit, timeoutMs;
    if (mode === "prepare") { args.push("-CompileOnly"); limit = 2048; timeoutMs = 60000; }
    else {
      if (!build || !/^[0-9a-f]{32}$/u.test(build.run_id) || !/^[0-9a-f]{64}$/u.test(build.helper_sha256)) throw new Error("CHECK_BUILD_BINDING");
      args.push(mode === "run" ? "-RunPrepared" : "-DiscardPrepared", build.run_id, "-ExpectedHelperSha256", build.helper_sha256);
      if (mode === "run") args.push("-CleanupOnSuccess");
      limit = mode === "run" ? 16384 : 1024; timeoutMs = mode === "run" ? 180000 : 30000;
    }
    const env = { SystemRoot: windows, WINDIR: windows,
      PSModulePath: path.win32.join(windows, "System32", "WindowsPowerShell", "v1.0", "Modules") };
    for (const key of ["USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP"]) if (typeof environment[key] === "string") env[key] = environment[key];
    return captureController(spawnProcess, executable, args,
      { shell: false, windowsHide: true, cwd: root, stdio: ["ignore", "pipe", "pipe"], env },
      { limit, timeoutMs, signal });
  }
  return Object.freeze({ prepare: () => invoke("prepare"), run: (build) => invoke("run", build), discard: (build) => invoke("discard", build) });
}

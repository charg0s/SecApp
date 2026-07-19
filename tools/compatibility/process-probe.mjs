import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  mkdir,
  readFile,
  readdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, isAbsolute, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";

const MAX_FILE_BYTES = 1024 * 1024 * 1024;
const MAX_STREAM_LIMIT = 16 * 1024 * 1024;
const MAX_TIMEOUT_MS = 120_000;

function fail(message) {
  throw new Error(message);
}

function getSystemRoot() {
  const systemRoot = process.env.SystemRoot;
  if (!systemRoot || !isAbsolute(systemRoot)) fail("SystemRoot must be an absolute inherited path");
  return systemRoot;
}

function parseInteger(value, name, minimum, maximum) {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value ?? "")) fail(`${name} must be an unsigned decimal integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    fail(`${name} must be between ${minimum} and ${maximum}`);
  }
  return parsed;
}

function parseArguments(argv) {
  const separator = argv.indexOf("--");
  if (separator < 0) fail("A -- separator before the child argument array is required");
  const optionTokens = argv.slice(0, separator);
  const childArguments = argv.slice(separator + 1);
  if (optionTokens.length % 2 !== 0) fail("Every probe option requires one value");
  const options = new Map();
  for (let index = 0; index < optionTokens.length; index += 2) {
    const name = optionTokens[index];
    const value = optionTokens[index + 1];
    if (!name.startsWith("--") || options.has(name)) fail(`Invalid or duplicate option: ${name}`);
    options.set(name, value);
  }

  const required = [
    "--label",
    "--executable",
    "--expected-sha256",
    "--run-root",
    "--network-monitor-script",
    "--timeout-ms",
    "--stdout-limit-bytes",
    "--stderr-limit-bytes",
    "--mode",
    "--uac-mode",
  ];
  for (const name of required) {
    if (!options.has(name)) fail(`Missing option: ${name}`);
  }
  if (!["normal", "timeout", "cancel"].includes(options.get("--mode"))) fail("Invalid mode");
  if (!["default", "run-as-invoker"].includes(options.get("--uac-mode"))) fail("Invalid UAC mode");
  if (options.get("--mode") === "cancel" && !options.has("--cancel-after-ms")) {
    fail("cancel mode requires --cancel-after-ms");
  }
  return { options, childArguments };
}

async function hashFile(path) {
  const fileStat = await stat(path);
  if (!fileStat.isFile() || fileStat.size <= 0 || fileStat.size > MAX_FILE_BYTES) {
    fail("Executable is absent, empty, or over the probe file limit");
  }
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return {
    sha256: digest.digest("hex"),
    size: fileStat.size,
    mtime_ms: fileStat.mtimeMs,
    device: fileStat.dev,
    inode: fileStat.ino,
  };
}

function decodeUtf8(buffer) {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    return true;
  } catch {
    return false;
  }
}

function processExists(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function waitForClose(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({
      timedOut: false,
      code: child.exitCode,
      signal: child.signalCode,
    });
  }
  return new Promise((resolvePromise) => {
    let completed = false;
    const finish = (value) => {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      resolvePromise(value);
    };
    const timer = setTimeout(() => finish({ timedOut: true }), timeoutMs);
    child.once("close", (code, signal) => finish({ timedOut: false, code, signal }));
    child.once("error", (error) => finish({ timedOut: false, error }));
  });
}

async function terminateProcessTree(pid) {
  const taskkill = join(getSystemRoot(), "System32", "taskkill.exe");
  const child = spawn(taskkill, ["/PID", String(pid), "/T", "/F"], {
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  child.stdout.on("data", (chunk) => {
    if (stdoutBytes < 65_536) stdout.push(chunk.subarray(0, 65_536 - stdoutBytes));
    stdoutBytes += chunk.length;
  });
  child.stderr.on("data", (chunk) => {
    if (stderrBytes < 65_536) stderr.push(chunk.subarray(0, 65_536 - stderrBytes));
    stderrBytes += chunk.length;
  });
  const result = await waitForClose(child, 5_000);
  if (result.timedOut) child.kill();
  return {
    invoked: true,
    exit_code: result.code ?? null,
    signal: result.signal ?? null,
    timed_out: result.timedOut,
    stdout_bytes: stdoutBytes,
    stderr_bytes: stderrBytes,
  };
}

async function main() {
  const { options, childArguments } = parseArguments(process.argv.slice(2));
  const label = options.get("--label");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u.test(label)) fail("Invalid label");
  const executable = resolve(options.get("--executable"));
  const runRoot = resolve(options.get("--run-root"));
  const networkMonitorScript = resolve(options.get("--network-monitor-script"));
  if (!isAbsolute(executable) || !isAbsolute(runRoot) || !isAbsolute(networkMonitorScript)) {
    fail("Executable, run root, and monitor script must be absolute");
  }
  const expectedSha256 = options.get("--expected-sha256").toLowerCase();
  if (!/^[0-9a-f]{64}$/u.test(expectedSha256)) fail("Invalid expected SHA-256");
  const timeoutMs = parseInteger(options.get("--timeout-ms"), "timeout-ms", 1, MAX_TIMEOUT_MS);
  const stdoutLimit = parseInteger(options.get("--stdout-limit-bytes"), "stdout-limit-bytes", 1, MAX_STREAM_LIMIT);
  const stderrLimit = parseInteger(options.get("--stderr-limit-bytes"), "stderr-limit-bytes", 1, MAX_STREAM_LIMIT);
  const mode = options.get("--mode");
  const uacMode = options.get("--uac-mode");
  const cancelAfterMs = mode === "cancel"
    ? parseInteger(options.get("--cancel-after-ms"), "cancel-after-ms", 0, timeoutMs)
    : null;

  const identityBefore = await hashFile(executable);
  if (identityBefore.sha256 !== expectedSha256) fail("Executable digest mismatch before launch");

  await mkdir(runRoot, { recursive: false });
  const workingDirectory = join(runRoot, "cwd");
  const environmentRoot = join(runRoot, "environment");
  const resultDirectory = join(runRoot, "result");
  const tempDirectory = join(environmentRoot, "temp");
  const profileDirectory = join(environmentRoot, "profile");
  const appDataDirectory = join(environmentRoot, "appdata");
  const localAppDataDirectory = join(environmentRoot, "localappdata");
  await Promise.all([
    mkdir(workingDirectory),
    mkdir(resultDirectory),
    mkdir(tempDirectory, { recursive: true }),
    mkdir(profileDirectory, { recursive: true }),
    mkdir(appDataDirectory, { recursive: true }),
    mkdir(localAppDataDirectory, { recursive: true }),
  ]);
  if ((await readdir(workingDirectory)).length !== 0) fail("Dedicated working directory is not empty");

  const pidFile = join(resultDirectory, "target.pid");
  const stopFile = join(resultDirectory, "network-monitor.stop");
  const networkResultFile = join(resultDirectory, "network-observation.json");
  const powershell = join(
    getSystemRoot(),
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  const monitor = spawn(powershell, [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    networkMonitorScript,
    "-PidFile",
    pidFile,
    "-StopFile",
    stopFile,
    "-OutputFile",
    networkResultFile,
    "-PollMilliseconds",
    "25",
    "-MaximumDurationMilliseconds",
    String(Math.min(MAX_TIMEOUT_MS, timeoutMs + 10_000)),
  ], {
    shell: false,
    windowsHide: true,
    stdio: "ignore",
    env: {
      ...process.env,
      TEMP: tempDirectory,
      TMP: tempDirectory,
    },
  });

  const childEnvironment = {
    SystemRoot: getSystemRoot(),
    WINDIR: process.env.WINDIR ?? getSystemRoot(),
    TEMP: tempDirectory,
    TMP: tempDirectory,
    USERPROFILE: profileDirectory,
    HOME: profileDirectory,
    APPDATA: appDataDirectory,
    LOCALAPPDATA: localAppDataDirectory,
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
  };
  if (uacMode === "run-as-invoker") {
    childEnvironment.__COMPAT_LAYER = "RunAsInvoker";
  }

  const startedAt = new Date();
  const startedClock = performance.now();
  let terminationReason = null;
  let terminationRequestedAtMs = null;
  let taskkillResult = { invoked: false };
  let taskkillPromise = null;
  let directTerminationResult = { invoked: false, accepted: false };
  let spawnError = null;
  let exitCode = null;
  let exitSignal = null;
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let stdoutAfterTerminationBytes = 0;
  let stderrAfterTerminationBytes = 0;
  const stdoutChunks = [];
  const stderrChunks = [];

  const child = spawn(executable, childArguments, {
    cwd: workingDirectory,
    env: childEnvironment,
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const requestTermination = (reason) => {
    if (terminationReason !== null) return;
    terminationReason = reason;
    terminationRequestedAtMs = performance.now() - startedClock;
    if (Number.isInteger(child.pid) && child.pid > 0) {
      directTerminationResult = {
        invoked: true,
        accepted: child.kill(),
      };
      taskkillPromise = terminateProcessTree(child.pid).then((result) => {
        taskkillResult = result;
      });
    }
  };

  child.stdout.on("data", (chunk) => {
    if (terminationReason !== null) stdoutAfterTerminationBytes += chunk.length;
    const remaining = Math.max(0, stdoutLimit - stdoutBytes);
    if (remaining > 0) stdoutChunks.push(chunk.subarray(0, remaining));
    stdoutBytes += chunk.length;
    if (stdoutBytes > stdoutLimit) requestTermination("StdoutLimitExceeded");
  });
  child.stderr.on("data", (chunk) => {
    if (terminationReason !== null) stderrAfterTerminationBytes += chunk.length;
    const remaining = Math.max(0, stderrLimit - stderrBytes);
    if (remaining > 0) stderrChunks.push(chunk.subarray(0, remaining));
    stderrBytes += chunk.length;
    if (stderrBytes > stderrLimit) requestTermination("StderrLimitExceeded");
  });

  child.once("spawn", () => {
    writeFile(pidFile, String(child.pid), { encoding: "ascii", flag: "wx" }).catch(() => {
      requestTermination("PidCoordinationFailed");
    });
  });

  const closePromise = new Promise((resolvePromise) => {
    let resolved = false;
    const finish = () => {
      if (resolved) return;
      resolved = true;
      resolvePromise();
    };
    child.once("error", (error) => {
      spawnError = { code: error.code ?? "UNKNOWN", message: error.message };
      finish();
    });
    child.once("close", (code, signal) => {
      exitCode = code;
      exitSignal = signal;
      finish();
    });
  });

  const timeoutTimer = setTimeout(() => requestTermination("TimedOut"), timeoutMs);
  const cancelTimer = mode === "cancel"
    ? setTimeout(() => requestTermination("ExplicitCancellation"), cancelAfterMs)
    : null;
  await closePromise;
  clearTimeout(timeoutTimer);
  if (cancelTimer !== null) clearTimeout(cancelTimer);
  if (taskkillPromise !== null) await taskkillPromise;

  const endedAt = new Date();
  const durationMs = performance.now() - startedClock;
  await writeFile(stopFile, "stop\n", { encoding: "ascii", flag: "wx" }).catch(() => {});
  const monitorClose = await waitForClose(monitor, 5_000);
  if (monitorClose.timedOut) monitor.kill();

  const stdoutBuffer = Buffer.concat(stdoutChunks);
  const stderrBuffer = Buffer.concat(stderrChunks);
  await Promise.all([
    writeFile(join(resultDirectory, "stdout.bin"), stdoutBuffer, { flag: "wx" }),
    writeFile(join(resultDirectory, "stderr.bin"), stderrBuffer, { flag: "wx" }),
  ]);

  let networkObservation = {
    observer: "PowerShellNetTCPUDPPidPoll",
    result_available: false,
    limitation: "Polling observation can miss short-lived attempts and is not a network sandbox.",
  };
  try {
    const networkBytes = await readFile(networkResultFile);
    const networkText = new TextDecoder("utf-8", { fatal: true }).decode(networkBytes).replace(/^\uFEFF/u, "");
    networkObservation = { result_available: true, ...JSON.parse(networkText) };
  } catch {
    // The bounded summary records observer failure without importing raw errors.
  }

  const identityAfter = await hashFile(executable);
  const identityStable = JSON.stringify(identityBefore) === JSON.stringify(identityAfter);
  const childPid = child.pid ?? null;
  const summary = {
    contract_version: 1,
    label,
    executable: {
      file_name: basename(executable),
      expected_sha256: expectedSha256,
      identity_before: identityBefore,
      identity_after: identityAfter,
      identity_stable: identityStable,
    },
    invocation: {
      argument_array: childArguments,
      shell: false,
      windows_hide: true,
      stdin: "ignored",
      working_directory_policy: "FreshEmptyDedicatedDirectory",
      environment_keys: Object.keys(childEnvironment).sort(),
      locale_contract: { LANG: "C", LC_ALL: "C" },
      uac_mode: uacMode,
    },
    process: {
      spawned: spawnError === null,
      pid: childPid,
      started_at_utc: startedAt.toISOString(),
      ended_at_utc: endedAt.toISOString(),
      duration_ms: Number(durationMs.toFixed(3)),
      exit_code: exitCode,
      signal: exitSignal,
      spawn_error: spawnError,
      termination_reason: terminationReason,
      termination_requested_at_ms: terminationRequestedAtMs === null
        ? null
        : Number(terminationRequestedAtMs.toFixed(3)),
      direct_termination: directTerminationResult,
      taskkill: taskkillResult,
      target_pid_exists_after_close: processExists(childPid),
    },
    limits: {
      timeout_ms: timeoutMs,
      stdout_limit_bytes: stdoutLimit,
      stderr_limit_bytes: stderrLimit,
    },
    streams: {
      stdout: {
        observed_bytes: stdoutBytes,
        retained_bytes: stdoutBuffer.length,
        over_limit: stdoutBytes > stdoutLimit,
        bytes_after_termination_requested: stdoutAfterTerminationBytes,
        retained_sha256: createHash("sha256").update(stdoutBuffer).digest("hex"),
        retained_utf8_valid: decodeUtf8(stdoutBuffer),
      },
      stderr: {
        observed_bytes: stderrBytes,
        retained_bytes: stderrBuffer.length,
        over_limit: stderrBytes > stderrLimit,
        bytes_after_termination_requested: stderrAfterTerminationBytes,
        retained_sha256: createHash("sha256").update(stderrBuffer).digest("hex"),
        retained_utf8_valid: decodeUtf8(stderrBuffer),
      },
    },
    network_observation: networkObservation,
  };

  const serialized = `${JSON.stringify(summary, null, 2)}\n`;
  await writeFile(join(resultDirectory, "summary.json"), serialized, { encoding: "utf8", flag: "wx" });
  process.stdout.write(serialized);
}

main().catch((error) => {
  process.stderr.write(`process-probe: ${error.message}\n`);
  process.exitCode = 1;
});

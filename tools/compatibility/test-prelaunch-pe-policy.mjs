import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const inspectorPath = fileURLToPath(new URL("./inspect-authenticode.ps1", import.meta.url));

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function runInspector(path, expectedDigest) {
  if (!process.env.SystemRoot) throw new Error("SystemRoot is required");
  const powershell = join(
    process.env.SystemRoot,
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
  );
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(powershell, [
      "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
      "-File", inspectorPath,
      "-Path", path,
      "-ExpectedSha256", expectedDigest,
      "-ExpectedArchitecture", "AMD64",
    ], {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", rejectPromise);
    child.once("close", (code, signal) => resolvePromise({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
    }));
  });
}

async function main() {
  const root = await mkdtemp(join(tmpdir(), "secapp-pe-policy-"));
  const invalidPe = Buffer.from("not-a-pe-file", "ascii");
  const wrongArchitecture = Buffer.alloc(512);
  wrongArchitecture.writeUInt16LE(0x5a4d, 0);
  wrongArchitecture.writeUInt32LE(0x80, 0x3c);
  wrongArchitecture.writeUInt32LE(0x00004550, 0x80);
  wrongArchitecture.writeUInt16LE(0x014c, 0x84);
  const cases = [
    {
      name: "digest-mismatch",
      bytes: invalidPe,
      expectedDigest: "0".repeat(64),
      error: "SHA-256 does not match",
    },
    {
      name: "invalid-pe",
      bytes: invalidPe,
      expectedDigest: sha256(invalidPe),
      error: "Invalid DOS MZ signature",
    },
    {
      name: "wrong-architecture",
      bytes: wrongArchitecture,
      expectedDigest: sha256(wrongArchitecture),
      error: "PE architecture I386 does not match required AMD64",
    },
  ];
  const results = [];
  try {
    for (const testCase of cases) {
      const path = join(root, `${testCase.name}.bin`);
      await writeFile(path, testCase.bytes, { flag: "wx" });
      const observed = await runInspector(path, testCase.expectedDigest);
      if (observed.code === 0 || observed.signal !== null || !observed.stderr.includes(testCase.error)) {
        throw new Error(`${testCase.name}: expected rejection containing ${JSON.stringify(testCase.error)}`);
      }
      results.push({
        name: testCase.name,
        status: "PASS",
        exit_code: observed.code,
        rejection_class: testCase.error,
      });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  process.stdout.write(`${JSON.stringify({
    status: "PASS",
    cases: results.length,
    binary_execution_attempted: false,
    temporary_inputs_removed: true,
    results,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`test-prelaunch-pe-policy: ${error.message}\n`);
  process.exitCode = 1;
});

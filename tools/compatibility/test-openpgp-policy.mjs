import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const verifierPath = fileURLToPath(new URL("./verify-openpgp-detached.mjs", import.meta.url));

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  if (argv.length % 2 !== 0) fail("Every option requires one value");
  const options = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    if (!name.startsWith("--") || options.has(name)) fail(`Invalid or duplicate option: ${name}`);
    options.set(name, argv[index + 1]);
  }
  for (const required of ["--data", "--signature", "--keyring", "--expected-fingerprint", "--expected-sha256"]) {
    if (!options.has(required)) fail(`Missing ${required}`);
  }
  return options;
}

function runVerifier(options, overrides = {}) {
  const argumentsArray = [
    verifierPath,
    "--data", options.get("--data"),
    "--signature", overrides.signature ?? options.get("--signature"),
    "--keyring", options.get("--keyring"),
    "--expected-fingerprint", overrides.fingerprint ?? options.get("--expected-fingerprint"),
    "--expected-sha256", options.get("--expected-sha256"),
  ];
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, argumentsArray, {
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
  const options = parseArguments(process.argv.slice(2));
  const root = await mkdtemp(join(tmpdir(), "secapp-openpgp-policy-"));
  try {
    const valid = await runVerifier(options);
    if (valid.code !== 0 || valid.signal !== null || JSON.parse(valid.stdout).status !== "VALID") {
      fail("Valid detached signature did not verify");
    }

    const signatureBytes = await readFile(options.get("--signature"));
    if (signatureBytes.length < 16) fail("Signature fixture is unexpectedly short");
    const tamperedBytes = Buffer.from(signatureBytes);
    tamperedBytes[tamperedBytes.length - 1] ^= 0x01;
    const tamperedPath = join(root, "tampered.sig");
    await writeFile(tamperedPath, tamperedBytes, { flag: "wx" });
    const tampered = await runVerifier(options, { signature: tamperedPath });
    if (tampered.code === 0 || tampered.signal !== null) fail("Tampered detached signature was not rejected");

    const wrongFingerprint = await runVerifier(options, { fingerprint: "0".repeat(40) });
    if (wrongFingerprint.code === 0
      || wrongFingerprint.signal !== null
      || !wrongFingerprint.stderr.includes("Signature issuer fingerprint mismatch")) {
      fail("Wrong expected signing fingerprint was not rejected deterministically");
    }

    process.stdout.write(`${JSON.stringify({
      status: "PASS",
      cases: 3,
      valid_signature: "Accepted",
      tampered_signature: "Rejected",
      wrong_expected_fingerprint: "Rejected",
      binary_execution_attempted: false,
      temporary_inputs_removed: true,
    }, null, 2)}\n`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`test-openpgp-policy: ${error.message}\n`);
  process.exitCode = 1;
});

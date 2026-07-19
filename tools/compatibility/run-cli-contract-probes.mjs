import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseStrictJson } from "../lib/strict-json.mjs";

const processProbePath = fileURLToPath(new URL("./process-probe.mjs", import.meta.url));
const MAX_PROBE_OUTPUT_BYTES = 2 * 1024 * 1024;

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
  for (const required of [
    "--executable",
    "--expected-sha256",
    "--run-root",
    "--definitions",
    "--network-monitor-script",
  ]) {
    if (!options.has(required)) fail(`Missing ${required}`);
  }
  return options;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function runChild(executable, argumentArray, maximumBytes = MAX_PROBE_OUTPUT_BYTES) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(executable, argumentArray, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        SystemRoot: process.env.SystemRoot,
        WINDIR: process.env.WINDIR,
        TEMP: process.env.TEMP,
        TMP: process.env.TMP,
      },
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      const retained = stdout.reduce((total, item) => total + item.length, 0);
      if (retained < maximumBytes) stdout.push(chunk.subarray(0, maximumBytes - retained));
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      const retained = stderr.reduce((total, item) => total + item.length, 0);
      if (retained < maximumBytes) stderr.push(chunk.subarray(0, maximumBytes - retained));
    });
    child.once("error", rejectPromise);
    child.once("close", (code, signal) => resolvePromise({
      code,
      signal,
      stdout: Buffer.concat(stdout),
      stderr: Buffer.concat(stderr),
      stdoutBytes,
      stderrBytes,
    }));
  });
}

function classifyStderr(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  if (/panic:/iu.test(text)) return "ProcessPanic";
  if (/unknown flag|unknown long flag|expected command/iu.test(text)) return "InvalidArgument";
  if (/not found|unknown artifact|unable to find artifact/iu.test(text)) return "ArtifactNotFound";
  if (/yaml|vql|definition|artifact.*load|parse/iu.test(text)) return "DefinitionOrParseError";
  if (/permission|access|open|directory|file exists|cannot create/iu.test(text)) return "OutputUnavailable";
  return text.length === 0 ? "Empty" : "OtherDiagnostic";
}

function safeSummary(label, summary, rawStdout, rawStderr) {
  return {
    label,
    argument_array: summary.invocation.argument_array.map((argument) => {
      if (argument.startsWith("--tempdir=")) return "--tempdir=<fresh-run-temp>";
      if (argument.startsWith("--definitions=")) return "--definitions=<definitions-directory>";
      if (argument.startsWith("--output=")) return "--output=<external-output-path>";
      if (argument.includes("EchoValue=") && argument.length > 256) {
        return `--args=EchoValue=<long-${argument.length - "--args=EchoValue=".length}-character-value>`;
      }
      return argument;
    }),
    process: {
      spawned: summary.process.spawned,
      exit_code: summary.process.exit_code,
      signal: summary.process.signal,
      termination_reason: summary.process.termination_reason,
      duration_ms: summary.process.duration_ms,
      direct_termination_invoked: summary.process.direct_termination?.invoked ?? false,
      direct_termination_accepted: summary.process.direct_termination?.accepted ?? false,
      taskkill_invoked: summary.process.taskkill.invoked,
      target_pid_exists_after_close: summary.process.target_pid_exists_after_close,
    },
    streams: {
      stdout_bytes: summary.streams.stdout.observed_bytes,
      stdout_sha256: sha256(rawStdout),
      stdout_utf8_valid: summary.streams.stdout.retained_utf8_valid,
      stdout_over_limit: summary.streams.stdout.over_limit,
      stdout_bytes_after_termination_requested: summary.streams.stdout.bytes_after_termination_requested,
      stderr_bytes: summary.streams.stderr.observed_bytes,
      stderr_sha256: sha256(rawStderr),
      stderr_utf8_valid: summary.streams.stderr.retained_utf8_valid,
      stderr_over_limit: summary.streams.stderr.over_limit,
      stderr_bytes_after_termination_requested: summary.streams.stderr.bytes_after_termination_requested,
      stderr_class: classifyStderr(rawStderr),
    },
    network: {
      result_available: summary.network_observation.result_available,
      tcp_activity_observed: summary.network_observation.tcp_activity_observed ?? null,
      udp_activity_observed: summary.network_observation.udp_activity_observed ?? null,
      poll_count: summary.network_observation.poll_count ?? null,
      observer_error_count: summary.network_observation.observer_error_count ?? null,
    },
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const executable = resolve(options.get("--executable"));
  const expectedSha256 = options.get("--expected-sha256").toLowerCase();
  const root = resolve(options.get("--run-root"));
  const definitions = resolve(options.get("--definitions"));
  const networkMonitor = resolve(options.get("--network-monitor-script"));
  if (![executable, root, definitions, networkMonitor].every(isAbsolute)) fail("All paths must be absolute");
  if (!/^[a-f0-9]{64}$/u.test(expectedSha256)) fail("Invalid expected SHA-256");
  await access(executable);
  await access(definitions);
  await access(networkMonitor);
  await mkdir(root, { recursive: false });
  const runsRoot = join(root, "runs");
  const definitionsRoot = join(root, "temporary-definitions");
  const packagesRoot = join(root, "packages");
  await Promise.all([mkdir(runsRoot), mkdir(definitionsRoot), mkdir(packagesRoot)]);

  const validDefinition = await readFile(join(definitions, "synthetic-artifact.yaml"), "utf8");
  const malformedDefinitions = join(definitionsRoot, "malformed");
  const malformedVqlDefinitions = join(definitionsRoot, "malformed-vql");
  const duplicateDefinitions = join(definitionsRoot, "duplicate");
  const emptyDefinitions = join(definitionsRoot, "empty");
  await Promise.all([
    mkdir(malformedDefinitions),
    mkdir(malformedVqlDefinitions),
    mkdir(duplicateDefinitions),
    mkdir(emptyDefinitions),
  ]);
  await Promise.all([
    writeFile(join(malformedDefinitions, "malformed.yaml"), "name: [unterminated\n", { encoding: "utf8", flag: "wx" }),
    writeFile(join(malformedVqlDefinitions, "malformed-vql.yaml"), [
      "name: SecApp.Compatibility.MalformedVql",
      "description: Fully synthetic malformed-VQL negative fixture.",
      "type: CLIENT",
      "sources:",
      "  - name: Rows",
      "    query: |",
      "      SELECT FROM this is not valid VQL",
      "",
    ].join("\n"), { encoding: "utf8", flag: "wx" }),
    writeFile(join(duplicateDefinitions, "a.yaml"), validDefinition.replaceAll("SecApp.Compatibility.Synthetic", "SecApp.Compatibility.Duplicate").replace('SyntheticString="alpha"', 'SyntheticString="duplicate-a"'), { encoding: "utf8", flag: "wx" }),
    writeFile(join(duplicateDefinitions, "b.yaml"), validDefinition.replaceAll("SecApp.Compatibility.Synthetic", "SecApp.Compatibility.Duplicate").replace('SyntheticString="alpha"', 'SyntheticString="duplicate-b"'), { encoding: "utf8", flag: "wx" }),
    writeFile(join(emptyDefinitions, "empty.yaml"), [
      "name: SecApp.Compatibility.Empty",
      "description: Fully synthetic empty-result compatibility artifact.",
      "type: CLIENT",
      "sources:",
      "  - name: Rows",
      "    query: |",
      "      SELECT * FROM foreach(row=[])",
      "",
    ].join("\n"), { encoding: "utf8", flag: "wx" }),
  ]);

  let sequence = 0;
  const results = [];
  async function run(label, childArguments, configuration = {}) {
    sequence += 1;
    const runRoot = join(runsRoot, `${String(sequence).padStart(2, "0")}-${label}`);
    const resolvedChildArguments = childArguments.map((argument) => argument === "--tempdir=<probe-run-temp>"
      ? `--tempdir=${join(runRoot, "environment", "temp")}`
      : argument);
    const probeArguments = [
      processProbePath,
      "--label", label,
      "--executable", executable,
      "--expected-sha256", expectedSha256,
      "--run-root", runRoot,
      "--network-monitor-script", networkMonitor,
      "--timeout-ms", String(configuration.timeoutMs ?? 15_000),
      "--stdout-limit-bytes", String(configuration.stdoutLimit ?? 1024 * 1024),
      "--stderr-limit-bytes", String(configuration.stderrLimit ?? 1024 * 1024),
      "--mode", configuration.mode ?? "normal",
      "--uac-mode", "run-as-invoker",
    ];
    if ((configuration.mode ?? "normal") === "cancel") {
      probeArguments.push("--cancel-after-ms", String(configuration.cancelAfterMs ?? 0));
    }
    probeArguments.push("--", ...resolvedChildArguments);
    const probe = await runChild(process.execPath, probeArguments);
    if (probe.code !== 0 || probe.signal !== null) {
      fail(`${label}: process probe failed (${probe.code}/${probe.signal}): ${probe.stderr.toString("utf8")}`);
    }
    const summary = parseStrictJson(probe.stdout.toString("utf8"), `${label} process probe summary`);
    const rawStdout = await readFile(join(runRoot, "result", "stdout.bin"));
    const rawStderr = await readFile(join(runRoot, "result", "stderr.bin"));
    const sanitized = safeSummary(label, summary, rawStdout, rawStderr);
    results.push(sanitized);
    return { runRoot, summary, rawStdout, rawStderr, sanitized };
  }

  function globalArguments(runLabel, extra = []) {
    return ["--nobanner", "--nocolor", "--max_wait=1", "--tempdir=<probe-run-temp>", ...extra];
  }

  function syntheticCollect(runLabel, echoValue, extraCollectArguments = [], definitionsPath = definitions) {
    return [
      ...globalArguments(runLabel, [`--definitions=${definitionsPath}`]),
      "artifacts", "collect",
      "--timeout=10",
      "--progress_timeout=5",
      "--format=json",
      "--no-require_admin",
      ...extraCollectArguments,
      `--args=EchoValue=${echoValue}`,
      "SecApp.Compatibility.Synthetic",
    ];
  }

  await run("invalid-cli-argument", [...globalArguments("invalid-cli-argument"), "--definitely-invalid-option"]);
  await run("unknown-artifact", [
    ...globalArguments("unknown-artifact"),
    "artifacts", "collect", "--timeout=5", "--format=json", "--no-require_admin",
    "SecApp.Compatibility.DoesNotExist",
  ]);
  await run("unknown-artifact-show", [
    ...globalArguments("unknown-artifact-show"),
    "artifacts", "show", "SecApp.Compatibility.DoesNotExist",
  ]);
  const nonexistentDefinitions = join(definitionsRoot, "does-not-exist");
  await run("missing-definitions", [
    ...globalArguments("missing-definitions", [`--definitions=${nonexistentDefinitions}`]),
    "artifacts", "collect", "--timeout=5", "--format=json", "--no-require_admin",
    "SecApp.Compatibility.Synthetic",
  ]);
  await run("missing-definition-file-verify", [
    ...globalArguments("missing-definition-file-verify"),
    "artifacts", "verify", "--max_length=100000", join(definitionsRoot, "missing.yaml"),
  ]);
  await run("malformed-yaml-verify", [
    ...globalArguments("malformed-yaml-verify"),
    "artifacts", "verify", "--max_length=100000", join(malformedDefinitions, "malformed.yaml"),
  ]);
  await run("malformed-vql-verify", [
    ...globalArguments("malformed-vql-verify"),
    "artifacts", "verify", "--max_length=100000", join(malformedVqlDefinitions, "malformed-vql.yaml"),
  ]);
  await run("malformed-definitions", [
    ...globalArguments("malformed-definitions", [`--definitions=${malformedDefinitions}`]),
    "artifacts", "collect", "--timeout=5", "--format=json", "--no-require_admin",
    "SecApp.Compatibility.Malformed",
  ]);
  const duplicate = await run("duplicate-artifact-name", [
    ...globalArguments("duplicate-artifact-name", [`--definitions=${duplicateDefinitions}`]),
    "artifacts", "collect", "--timeout=5", "--format=json", "--no-require_admin",
    "SecApp.Compatibility.Duplicate",
  ]);
  let duplicateSelectedValue = null;
  if (duplicate.summary.process.exit_code === 0 && duplicate.rawStdout.length > 0) {
    const duplicateRows = parseStrictJson(duplicate.rawStdout.toString("utf8"), "duplicate artifact stdout");
    duplicateSelectedValue = duplicateRows[0]?.SyntheticString ?? null;
  }
  duplicate.sanitized.duplicate_resolution = duplicateSelectedValue === null
    ? "NoStructuredResult"
    : `CLISelected:${duplicateSelectedValue}`;
  await run("duplicate-artifact-verify", [
    ...globalArguments("duplicate-artifact-verify"),
    "artifacts", "verify", "--max_length=100000",
    join(duplicateDefinitions, "a.yaml"), join(duplicateDefinitions, "b.yaml"),
  ]);

  const empty = await run("collector-no-rows", [
    ...globalArguments("collector-no-rows", [`--definitions=${emptyDefinitions}`]),
    "artifacts", "collect", "--timeout=5", "--format=json", "--no-require_admin",
    "SecApp.Compatibility.Empty",
  ]);
  empty.sanitized.empty_output = empty.rawStdout.length === 0;

  await run("cpu-limit-alone", syntheticCollect("cpu-limit-alone", "synthetic-resource", ["--cpu_limit=20"]));
  await run("memory-limit-alone", syntheticCollect("memory-limit-alone", "synthetic-resource", ["--hard_memory_limit=536870912"]));

  const packagePath = join(packagesRoot, "synthetic-collection.zip");
  const packageRun = await run("package-output", syntheticCollect("package-output", "synthetic-package", [`--output=${packagePath}`]));
  let packageMetadata = { exists: false };
  try {
    const packageStat = await stat(packagePath);
    const packageBytes = await readFile(packagePath);
    packageMetadata = {
      exists: packageStat.isFile(),
      file_name: basename(packagePath),
      size: packageStat.size,
      sha256: sha256(packageBytes),
    };
  } catch {
    // The observed absence is represented without treating it as a harness error.
  }
  packageRun.sanitized.package = packageMetadata;

  const overwritePath = join(packagesRoot, "overwrite-existing.zip");
  const overwriteSentinel = Buffer.from("SECAPP-COMPATIBILITY-OVERWRITE-SENTINEL\n", "ascii");
  await writeFile(overwritePath, overwriteSentinel, { flag: "wx" });
  const overwrite = await run("package-overwrite-existing", syntheticCollect("package-overwrite-existing", "synthetic-overwrite", [`--output=${overwritePath}`]));
  const overwriteBytes = await readFile(overwritePath);
  overwrite.sanitized.overwrite = {
    initial_sha256: sha256(overwriteSentinel),
    final_sha256: sha256(overwriteBytes),
    changed: sha256(overwriteSentinel) !== sha256(overwriteBytes),
    final_size: overwriteBytes.length,
  };

  const unavailablePath = join(packagesRoot, "unavailable-output.zip");
  await mkdir(unavailablePath);
  await run("package-output-unavailable", syntheticCollect("package-output-unavailable", "synthetic-unavailable", [`--output=${unavailablePath}`]));

  const injectionValues = [
    ["spaces", "synthetic value with spaces"],
    ["quotes", 'synthetic"double\'single'],
    ["ampersand", "synthetic&and"],
    ["pipe", "synthetic|pipe"],
    ["semicolon", "synthetic:semicolon"],
    ["percent", "%TEMP%-synthetic"],
    ["powershell-metacharacters", "synthetic-$()@{}[]`"],
    ["unicode", "синтетика-漢字-🙂"],
    ["leading-dash", "-synthetic-leading"],
    ["path-traversal-text", "..\\..\\synthetic"],
    ["very-long", "x".repeat(8192)],
    ["newline", "synthetic-line-1\nsynthetic-line-2"],
    ["control-character", "synthetic-control-\u0001-end"],
  ];
  const injectionResults = [];
  for (const [name, value] of injectionValues) {
    const label = `argument-${name}`;
    const observed = await run(label, syntheticCollect(label, value));
    const workingDirectoryEntries = await readdir(join(observed.runRoot, "cwd"));
    if (workingDirectoryEntries.length !== 0) fail(`${label}: unexpected working-directory entry created`);
    if (observed.summary.process.exit_code === 0) {
      const rows = parseStrictJson(observed.rawStdout.toString("utf8"), `${label} stdout`);
      if (!Array.isArray(rows) || rows.length !== 2 || rows.some((row) => row.EchoValue !== value)) {
        fail(`${label}: parameter was not transmitted literally`);
      }
      injectionResults.push({
        name,
        status: "PassedLiterally",
        input_utf8_bytes: Buffer.byteLength(value, "utf8"),
        output_rows: rows.length,
        working_directory_entries_created: 0,
      });
    } else {
      injectionResults.push({
        name,
        status: "SafelyRejected",
        input_utf8_bytes: Buffer.byteLength(value, "utf8"),
        exit_code: observed.summary.process.exit_code,
        stderr_class: observed.sanitized.streams.stderr_class,
        working_directory_entries_created: 0,
      });
    }
  }

  await run("external-timeout", [...globalArguments("external-timeout"), "--help"], {
    mode: "timeout",
    timeoutMs: 1,
  });
  await run("explicit-cancellation", [...globalArguments("explicit-cancellation"), "--help"], {
    mode: "cancel",
    timeoutMs: 10_000,
    cancelAfterMs: 0,
  });
  await run("stdout-over-limit", syntheticCollect("stdout-over-limit", "synthetic-output-limit"), {
    stdoutLimit: 64,
  });

  const summary = {
    contract_version: 1,
    status: "COMPLETED",
    binary: { file_name: basename(executable), sha256: expectedSha256 },
    shell_used: false,
    uac_mode: "RunAsInvokerProcessEnvironmentOnly",
    result_count: results.length,
    results,
    command_injection: {
      status: "PASS",
      cases: injectionResults,
      second_process_requested_by_harness: false,
      unexpected_working_directory_files: false,
    },
    package_path_for_bounded_inspection: packageMetadata.exists ? packagePath : null,
    temporary_definitions_removed: true,
  };
  await rm(definitionsRoot, { recursive: true, force: true });
  const serialized = `${JSON.stringify(summary, null, 2)}\n`;
  await writeFile(join(root, "suite-summary.json"), serialized, { encoding: "utf8", flag: "wx" });
  process.stdout.write(serialized);
}

main().catch((error) => {
  process.stderr.write(`run-cli-contract-probes: ${error.message}\n`);
  process.exitCode = 1;
});

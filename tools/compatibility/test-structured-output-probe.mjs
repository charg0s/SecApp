import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

const probePath = fileURLToPath(new URL("./structured-output-probe.mjs", import.meta.url));

function fail(message) {
  throw new Error(message);
}

function runProbe(argumentsArray) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [probePath, ...argumentsArray], {
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
      if (stdoutBytes <= 1024 * 1024) stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= 1024 * 1024) stderr.push(chunk);
    });
    child.once("error", rejectPromise);
    child.once("close", (code, signal) => resolvePromise({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
      stdoutBytes,
      stderrBytes,
    }));
  });
}

async function main() {
  const root = await mkdtemp(join(tmpdir(), "secapp-structured-probe-"));
  const cases = [
    {
      name: "json-document",
      bytes: Buffer.from('[{"a":1},{"a":2}]', "utf8"),
      arguments: ["--mode", "json"],
      expect: { valid: true, framing: "JSONDocument", records: 2, finalLineTerminated: false },
    },
    {
      name: "jsonl-terminated",
      bytes: Buffer.from('{"a":1}\n{"a":2}\n', "utf8"),
      arguments: ["--mode", "jsonl"],
      expect: { valid: true, framing: "JSONLines", records: 2, finalLineTerminated: true },
    },
    {
      name: "jsonl-valid-final-line-without-lf",
      bytes: Buffer.from('{"a":1}\n{"a":2}', "utf8"),
      arguments: ["--mode", "jsonl"],
      expect: { valid: true, framing: "JSONLines", records: 2, finalLineTerminated: false },
    },
    {
      name: "concatenated-json-documents",
      bytes: Buffer.from('[{"a":1}][{"a":2}]', "utf8"),
      arguments: ["--mode", "auto"],
      expect: { valid: true, framing: "ConcatenatedJSONDocuments", records: 2, finalLineTerminated: false },
    },
    {
      name: "empty-jsonl",
      bytes: Buffer.alloc(0),
      arguments: ["--mode", "jsonl"],
      expect: { valid: true, framing: "JSONLines", records: 0, finalLineTerminated: true },
    },
    {
      name: "duplicate-key",
      bytes: Buffer.from('{"a":1,"a":2}', "utf8"),
      arguments: ["--mode", "json"],
      expect: { valid: false, error: "Duplicate object key" },
    },
    {
      name: "invalid-utf8",
      bytes: Buffer.from([0x5b, 0x22, 0xc3, 0x28, 0x22, 0x5d]),
      arguments: ["--mode", "json"],
      expect: { valid: false, error: "not valid UTF-8" },
    },
    {
      name: "utf8-bom",
      bytes: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("[]", "utf8")]),
      arguments: ["--mode", "json"],
      expect: { valid: false, error: "BOM is rejected" },
    },
    {
      name: "partial-final-concatenated-document",
      bytes: Buffer.from('[{"a":1}][{"a":', "utf8"),
      arguments: ["--mode", "auto"],
      expect: { valid: false, error: "Partial final concatenated JSON document is rejected" },
    },
    {
      name: "malformed-json",
      bytes: Buffer.from("[{]", "utf8"),
      arguments: ["--mode", "json"],
      expect: { valid: false, error: "Expected string" },
    },
    {
      name: "total-byte-limit",
      bytes: Buffer.from('[{"a":1}]', "utf8"),
      arguments: ["--mode", "json", "--max-total-bytes", "4"],
      expect: { valid: false, error: "exceeds total byte limit" },
    },
    {
      name: "jsonl-line-limit",
      bytes: Buffer.from('{"long":"1234567890"}\n', "utf8"),
      arguments: ["--mode", "jsonl", "--max-line-bytes", "8"],
      expect: { valid: false, error: "exceeds byte limit" },
    },
    {
      name: "record-limit",
      bytes: Buffer.from("[{},{},{}]", "utf8"),
      arguments: ["--mode", "json", "--max-records", "2"],
      expect: { valid: false, error: "record count exceeds limit" },
    },
    {
      name: "nesting-depth-limit",
      bytes: Buffer.from('{"a":{"b":{"c":1}}}', "utf8"),
      arguments: ["--mode", "json", "--max-depth", "2"],
      expect: { valid: false, error: "nesting depth exceeds limit" },
    },
  ];

  const results = [];
  try {
    for (const testCase of cases) {
      const inputPath = join(root, `${testCase.name}.bin`);
      await writeFile(inputPath, testCase.bytes, { flag: "wx" });
      const result = await runProbe(["--input", inputPath, ...testCase.arguments]);
      if (testCase.expect.valid) {
        if (result.code !== 0 || result.signal !== null) {
          fail(`${testCase.name}: expected success, received ${result.code}/${result.signal}: ${result.stderr}`);
        }
        const parsed = JSON.parse(result.stdout);
        if (parsed.framing !== testCase.expect.framing
          || parsed.record_count !== testCase.expect.records
          || parsed.final_line_terminated !== testCase.expect.finalLineTerminated) {
          fail(`${testCase.name}: structured result mismatch`);
        }
        results.push({
          name: testCase.name,
          status: "PASS",
          observed: {
            exit_code: result.code,
            framing: parsed.framing,
            record_count: parsed.record_count,
            final_line_terminated: parsed.final_line_terminated,
            empty_semantics: parsed.empty_semantics,
          },
        });
      } else {
        if (result.code === 0 || !result.stderr.includes(testCase.expect.error)) {
          fail(`${testCase.name}: expected rejection containing ${JSON.stringify(testCase.expect.error)}`);
        }
        results.push({
          name: testCase.name,
          status: "PASS",
          observed: {
            exit_code: result.code,
            error_class: testCase.expect.error,
          },
        });
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }

  process.stdout.write(`${JSON.stringify({
    status: "PASS",
    suite: basename(probePath),
    cases: results.length,
    temporary_inputs_removed: true,
    results,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`test-structured-output-probe: ${error.message}\n`);
  process.exitCode = 1;
});

import test, { after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, readdir, realpath, lstat, rm } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { createDefenderPreview, DEFENDER_QUERY_CANDIDATE } from "../../src/backend/direct-defender-output.mjs";
import { renderDefenderPreviewText, renderDefenderPreviewHtml } from "../../src/reporting/direct-defender-report.mjs";
import { runDefenderPreviewCommand } from "../../tools/lib/defender-preview-command.mjs";
import { digestWithExclusion } from "../../tools/lib/jcs.mjs";

const row = (mode = "Normal", enabled = true) => Buffer.from(`${JSON.stringify({ AMRunningMode: mode, RealTimeProtectionEnabled: enabled })}\n`);
const normal = row();
const tempBase = await realpath(tmpdir());
const temporary = await mkdtemp(path.join(tempBase, "secapp-defender-preview-test-"));
after(async () => {
  const resolved = await realpath(temporary);
  assert.equal(path.dirname(resolved), tempBase);
  assert.ok(path.basename(resolved).startsWith("secapp-defender-preview-test-"));
  assert.equal((await lstat(temporary)).isSymbolicLink(), false);
  await rm(resolved, { recursive: true, force: false });
});

test("normal Defender output assesses only the selected rule and never claims collection", () => {
  const report = createDefenderPreview(normal);
  assert.equal(report.checks[0].outcome, "NoConcernReported");
  assert.deepEqual(report.counts, { Concern: 0, NoConcernReported: 1, NotTested: 5 });
  assert.equal(report.assessment_status, "Partial");
  assert.equal(report.source_kind, "SuppliedBackendOutput");
  assert.equal(report.collection_claim, "NotEstablished");
  assert.equal(report.provenance_claim, "NotEstablished");
  assert.equal(report.freshness_claim, "NotEvaluated");
  assert.equal(report.privacy_class, "SensitiveSecurityData");
  assert.equal(report.checks[0].confidence, "Not detected");
  assert.equal(report.checks[0].status, "Requires review");
  assert.ok(report.checks.slice(1).every((item) => item.reason === "OutsideSelectedCheck"));
});

test("disabled realtime in Normal mode is a concern, not proof of compromise", () => {
  const result = createDefenderPreview(row("Normal", false)).checks[0];
  assert.equal(result.outcome, "Concern");
  assert.equal(result.severity, "Medium");
  assert.equal(result.confidence, "Possible");
  assert.equal(result.status, "Requires review");
});

for (const mode of ["Passive", "Passive Mode", "SxS Passive Mode", "EDR Block Mode", "Not running", "Future mode", "normal", "", null]) {
  test(`non-active/unknown mode ${JSON.stringify(mode)} is NotTested even with false realtime`, () => {
    const report = createDefenderPreview(row(mode, false));
    assert.equal(report.checks[0].outcome, "NotTested");
    assert.equal(report.counts.Concern, 0);
    assert.equal(report.counts.NoConcernReported, 0);
    assert.equal(report.assessment_status, "NotTested");
  });
}

for (const input of ["", "{}\n", '{"AMRunningMode":"Normal"}\n', '{"RealTimeProtectionEnabled":true}\n', '{"AMRunningMode":null,"RealTimeProtectionEnabled":null}\n']) {
  test(`missing/empty data never yields a positive: ${JSON.stringify(input)}`, () => {
    const report = createDefenderPreview(Buffer.from(input));
    assert.equal(report.checks[0].outcome, "NotTested");
    assert.equal(report.counts.NotTested, 6);
  });
}

const malformed = [
  ["duplicate", '{"AMRunningMode":"Normal","AMRunningMode":"Passive"}\n'],
  ["escaped duplicate", '{"AMRunningMode":"Normal","AMRunning\\u004dode":"Passive"}\n'],
  ["unknown field", '{"AMRunningMode":"Normal","ready":true}\n'],
  ["prototype field", '{"__proto__":{},"RealTimeProtectionEnabled":true}\n'],
  ["two rows", normal.toString() + normal.toString()],
  ["blank row", "\n"],
  ["blank prefix", "\n" + normal.toString()],
  ["log prefix", "Error: source registration failed\n" + normal.toString()],
  ["truncated", normal.toString().trimEnd()],
  ["trailing garbage", normal.toString().trimEnd() + " unexpected\n"],
  ["array root", "[]\n"],
  ["scalar root", "true\n"],
  ["null root", "null\n"],
  ["deep object", '{"AMRunningMode":' + "[".repeat(100) + "0" + "]".repeat(100) + "}\n"],
  ["array mode", '{"AMRunningMode":[]}\n'],
  ["number mode", '{"AMRunningMode":1}\n'],
  ["long mode", JSON.stringify({ AMRunningMode: "A".repeat(65) }) + "\n"],
  ["escaped control", '{"AMRunningMode":"\\u0000"}\n'],
  ["raw control", '{"AMRunningMode":"\u0000"}\n'],
  ["lone surrogate", '{"AMRunningMode":"\\ud800"}\n'],
  ["bool string", '{"AMRunningMode":"Normal","RealTimeProtectionEnabled":"True"}\n'],
  ["bool number", '{"AMRunningMode":"Normal","RealTimeProtectionEnabled":1}\n'],
  ["bool object", '{"AMRunningMode":"Normal","RealTimeProtectionEnabled":{}}\n'],
  ["infinite number", '{"RealTimeProtectionEnabled":1e999}\n'],
  ["oversize line", " ".repeat(1024) + "{}\n"]
];
for (const [name, input] of malformed) {
  test(`rejects ${name} without echoing input`, () => {
    assert.throws(() => createDefenderPreview(Buffer.from(input)), (error) => {
      assert.match(error.message, /^DEFENDER_OUTPUT_[A-Z_]+$/u);
      assert.equal(error.message.includes(input), false);
      return true;
    });
  });
}

test("byte limit and UTF-8 are enforced before parsing", () => {
  assert.throws(() => createDefenderPreview(Buffer.alloc(4097)), { code: "DEFENDER_OUTPUT_TOO_LARGE" });
  assert.throws(() => createDefenderPreview(Buffer.from([0xff, 0x0a])), { code: "DEFENDER_OUTPUT_INVALID" });
  assert.throws(() => createDefenderPreview(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), normal])), { code: "DEFENDER_OUTPUT_INVALID" });
  assert.throws(() => createDefenderPreview("{}\n"), { code: "DEFENDER_OUTPUT_BYTES_REQUIRED" });
});

test("one CRLF-terminated row is supported without losing byte identity", () => {
  const crlf = Buffer.from(normal.toString().replace(/\n$/u, "\r\n"));
  const report = createDefenderPreview(crlf);
  assert.deepEqual(report.normalized, createDefenderPreview(normal).normalized);
  assert.notEqual(report.source_sha256, createDefenderPreview(normal).source_sha256);
});

test("report is deterministic, deeply frozen and independent from input mutation", () => {
  const bytes = Buffer.from(normal);
  const report = createDefenderPreview(bytes);
  assert.deepEqual(report, createDefenderPreview(normal));
  bytes.fill(0);
  assert.deepEqual(report, createDefenderPreview(normal));
  assert.equal(report.report_digest, digestWithExclusion(report, "report_digest"));
  assert.throws(() => { report.checks[0].outcome = "NotTested"; }, TypeError);
  assert.throws(() => { report.normalized.mode = "Unknown"; }, TypeError);
  assert.throws(() => { report.limitations.push("fabricated"); }, TypeError);
  assert.equal(DEFENDER_QUERY_CANDIDATE.executionAdmission, "NotAccepted");
  assert.ok(Object.isFrozen(DEFENDER_QUERY_CANDIDATE));
});

test("renderers reject forged reports and never expose unknown raw strings", () => {
  const marker = '<script>alert("synthetic")</script>';
  const report = createDefenderPreview(row(marker, true));
  for (const render of [renderDefenderPreviewText, renderDefenderPreviewHtml]) {
    assert.throws(() => render({}), { code: "DEFENDER_REPORT_INVALID" });
    assert.throws(() => render(structuredClone(report)), { code: "DEFENDER_REPORT_INVALID" });
    const result = render(report);
    assert.equal(result.includes(marker), false);
    assert.match(result, /Не проверено/u);
    assert.match(result, /не подтверждены/u);
  }
  const html = renderDefenderPreviewHtml(report);
  assert.match(html, /default-src 'none'/u);
  assert.match(html, /base-uri 'none'; form-action 'none'/u);
  assert.doesNotMatch(html, /<script|<iframe|<form|\ssrc=|\shref=|\son[a-z]+=/iu);
  assert.match(html, /Проверка компьютера не выполнялась этим инструментом/u);
});

async function command(args) {
  let stdout = "", stderr = "";
  const code = await runDefenderPreviewCommand(args, { stdout: (s) => { stdout += s; }, stderr: (s) => { stderr += s; } });
  return { code, stdout, stderr };
}

test("file preview renders text/HTML without modifying source or saving a report", async () => {
  const file = path.join(temporary, "normal.jsonl");
  await writeFile(file, normal);
  const before = await readdir(temporary);
  for (const format of ["text", "html"]) {
    const result = await command(["--input", file, "--format", format]);
    assert.equal(result.code, 0);
    assert.equal(result.stderr, "");
    assert.match(result.stdout, /Замечание не выявлено/u);
    assert.match(result.stdout, /происхождение и актуальность данных не подтверждены/u);
    assert.equal(result.stdout.includes(file), false);
  }
  assert.deepEqual(await readFile(file), normal);
  assert.deepEqual(await readdir(temporary), before);
});

test("empty supplied output returns coverage exit 2, not success", async () => {
  const file = path.join(temporary, "empty.jsonl");
  await writeFile(file, "");
  const result = await command(["--input", file]);
  assert.equal(result.code, 2);
  assert.equal(result.stderr, "");
  assert.match(result.stdout, /Не проверено/u);
});

test("oversized and invalid files produce only controlled errors", async () => {
  for (const [name, bytes] of [["large.jsonl", Buffer.alloc(4097)], ["bad.jsonl", Buffer.from("synthetic-private-marker\n")]]) {
    const file = path.join(temporary, name);
    await writeFile(file, bytes);
    const result = await command(["--input", file]);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /^DEFENDER_OUTPUT_[A-Z_]+\n$/u);
    assert.equal(result.stderr.includes(file), false);
    assert.equal(result.stderr.includes("synthetic-private-marker"), false);
  }
});

test("missing file, directory and argument misuse cannot start collection", async () => {
  const badArguments = [[], ["--run"], ["--input"], ["--format", "json"],
    ["--input", "--help", "--input", "elsewhere"], ["--input", "\\\\synthetic-server\\share\\data"],
    ["--input", "//synthetic-server/share/data"], ["--input", "bad\u0000name"],
    ["--input", "file", "--format", "html", "--live"], ["--input", "x".repeat(4097)]];
  for (const args of badArguments) {
    const result = await command(args);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /^DEFENDER_ARGUMENTS\n$/u);
  }
  for (const file of [path.join(temporary, "missing-private-synthetic.jsonl"), temporary]) {
    const result = await command(["--input", file]);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr.includes(file), false);
  }
  const help = await command(["--help"]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /never runs Velociraptor/u);
});

test("committed fixture is synthetic and equals the defined Normal example", async () => {
  assert.deepEqual(await readFile(new URL("./fixtures/defender-normal.synthetic.jsonl", import.meta.url)), normal);
});

for (const broken of ["stdout", "stderr"]) {
  test("real Node CLI handles broken " + broken + " without an uncaught stack", async () => {
    const cli = fileURLToPath(new URL("../../tools/preview-defender-check.mjs", import.meta.url));
    const fixture = fileURLToPath(new URL("./fixtures/defender-normal.synthetic.jsonl", import.meta.url));
    const args = broken === "stdout" ? ["--input", fixture] : [];
    // Only this Node CLI, never a backend/helper/shell or arbitrary executable.
    const child = spawn(process.execPath, [cli, ...args], {
      shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], timeout: 5000
    });
    child[broken].destroy();
    const other = child[broken === "stdout" ? "stderr" : "stdout"];
    let captured = "";
    other.on("data", (chunk) => {
      captured += chunk.toString("utf8");
      if (captured.length > 8192) child.kill();
    });
    const exit = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    assert.equal(exit.signal, null);
    assert.equal(exit.code, 1);
    assert.equal(captured, "");
  });
}

import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { DEFENDER_BUILD_PINS, runDefenderCheckCommand } from "../../src/backend/defender-interactive-flow.mjs";
import { decodeDefenderControlResult } from "../../src/backend/defender-control-result.mjs";
import { createDefenderCheckReport, renderDefenderCheckText, renderDefenderCheckHtml } from "../../src/reporting/defender-check-report.mjs";
import { createDefenderDesktopSession, decodeDesktopCommand } from "../../src/ui/defender-desktop-session.mjs";
import { createDesktopCommandReader } from "../../tools/lib/defender-desktop-transport.mjs";

const id = "0123456789abcdef0123456789abcdef";
const build = { kind: "SecAppDefenderBuildV1", run_id: id, executed: false, ...DEFENDER_BUILD_PINS, helper_sha256: "4".repeat(64) };
const normal = '{"AMRunningMode":"Normal","RealTimeProtectionEnabled":true}\n';
const receipt = (raw = normal) => ({ kind: "SecAppDefenderControlV1", run_id: id, outcome: "Completed", error: "NONE",
  backend_created: true, backend_resumed: true, backend_exit: 0, root_exited: true, job_empty: true, pipes_closed: true,
  elapsed_ms: 100, stdout_base64: Buffer.from(raw).toString("base64") });
const envelope = (raw = normal) => ({ kind: "SecAppDefenderRunEnvelopeV1", run_id: id, helper_exit_confirmed: true, helper_exit_code: 0,
  data_files_removed: true, workspace_removed: false, result_json: JSON.stringify(receipt(raw)) });
const transport = (row, overrides = {}) => ({ code: 0, closed: true, signal: null, overflow: false, timedOut: false,
  aborted: false, ioError: false, stdout: Buffer.from(JSON.stringify(row)), stderr: Buffer.alloc(0), ...overrides });
const tick = () => new Promise((resolve) => setImmediate(resolve));
function setup(overrides = {}, options = {}) {
  const calls = [], messages = [];
  const executor = {
    prepare: async () => { calls.push("prepare"); return transport(build); },
    run: async (actual) => { assert.deepEqual(actual, build); calls.push("run"); return transport(envelope()); },
    discard: async () => { calls.push("discard"); return transport({ kind: "SecAppDefenderDiscardV1", run_id: id, data_files_removed: true, workspace_removed: false }); },
    ...overrides
  };
  const session = createDefenderDesktopSession({ executor, emit: (m) => messages.push(m), ...options });
  return { session, messages, calls, executor };
}
async function prepare(x) {
  x.session.command({ action: "ready" }); x.session.command({ action: "prepare" }); await tick();
  assert.equal(x.session.state(), "AwaitingConfirmation");
}

test("opening the desktop does not prepare, collect, export or create backend state", () => {
  const x = setup(); assert.equal(x.session.command({ action: "confirm", answer: "СОБРАТЬ 01234567" }), false);
  x.session.command({ action: "ready" });
  assert.equal(x.session.state(), "Ready"); assert.deepEqual(x.calls, []);
  assert.equal(x.messages.at(-1).reportHtml, null);
});
test("one prepare, one explicit phrase and one run; replay cannot collect again", async () => {
  const x = setup(); await prepare(x);
  assert.equal(x.session.command({ action: "prepare" }), false);
  assert.equal(x.session.command({ action: "confirm", answer: "СОБРАТЬ 01234567" }), true);
  assert.equal(x.session.command({ action: "confirm", answer: "СОБРАТЬ 01234567" }), false);
  await x.session.settled();
  assert.deepEqual(x.calls, ["prepare", "run"]);
  assert.equal(x.messages.at(-1).code, 0);
  assert.match(x.messages.at(-1).reportText, /Режим Defender: Активный/u);
  assert.match(x.messages.at(-1).reportHtml, /SensitiveSecurityData/u);
  for (const action of ["ready", "prepare", "cancel"]) assert.equal(x.session.command({ action }), false);
});
for (const command of [{ action: "cancel" }, { action: "confirm", answer: "yes" }, { action: "confirm", answer: "СОБРАТЬ ffffffff" }]) {
  test(`cancel or wrong phrase discards only prepared files: ${JSON.stringify(command)}`, async () => {
    const x = setup(); await prepare(x); x.session.command(command); await x.session.settled();
    assert.deepEqual(x.calls, ["prepare", "discard"]); assert.equal(x.messages.at(-1).code, 3);
    assert.equal(x.messages.at(-1).reportHtml, null);
  });
}
test("confirmation times out once and never runs", async () => {
  let timeout;
  const x = setup({}, { schedule: (callback, ms) => { assert.equal(ms, 120000); timeout = callback; return 1; }, unschedule: () => {} });
  await prepare(x); timeout(); timeout(); await x.session.settled();
  assert.deepEqual(x.calls, ["prepare", "discard"]);
});
test("window loss while awaiting input discards, without granting consent", async () => {
  const x = setup(); await prepare(x); x.session.disconnect(); await x.session.settled();
  assert.deepEqual(x.calls, ["prepare", "discard"]);
});
test("window loss during preparation waits for build, then discards", async () => {
  let finish;
  const x = setup({ prepare: () => new Promise((resolve) => { finish = resolve; }) });
  x.session.command({ action: "ready" }); x.session.command({ action: "prepare" }); x.session.disconnect();
  finish(transport(build)); await x.session.settled(); assert.deepEqual(x.calls, ["discard"]);
});
test("window loss after consent waits for the same run, without retry or unstarted discard", async () => {
  let finish, runs = 0;
  const x = setup({ run: () => { runs++; return new Promise((resolve) => { finish = resolve; }); } });
  await prepare(x); x.session.command({ action: "confirm", answer: "СОБРАТЬ 01234567" }); await tick();
  x.session.disconnect(); finish(transport(envelope())); await x.session.settled();
  assert.equal(runs, 1); assert.deepEqual(x.calls, ["prepare"]);
});
test("lost output channel during consent never leaves an input timer or starts a run", async () => {
  let broken = false;
  const x = setup({}, { emit: (m) => { if (m.state === "AwaitingConfirmation") { broken = true; throw new Error("PRIVATE"); } } });
  x.session.command({ action: "ready" }); x.session.command({ action: "prepare" });
  await x.session.settled(); assert.equal(broken, true); assert.deepEqual(x.calls, ["prepare", "discard"]);
});
for (const fields of [{ code: 1 }, { closed: false }, { aborted: true }, { timedOut: true }, { stderr: Buffer.from("PRIVATE") }]) {
  test(`failed execution is not a successful report: ${Object.keys(fields)[0]}`, async () => {
    const x = setup({ run: async () => transport(envelope(), fields) }); await prepare(x);
    x.session.command({ action: "confirm", answer: "СОБРАТЬ 01234567" }); await x.session.settled();
    const last = x.messages.at(-1); assert.equal(last.state, "Failed"); assert.equal(last.reportHtml, null);
    assert.ok(!last.text.includes("PRIVATE")); assert.deepEqual(x.calls, ["prepare"]);
  });
}
test("cleanup failure keeps an explicit warning in both report formats", async () => {
  const row = envelope(); row.data_files_removed = false;
  const x = setup({ run: async () => transport(row, { code: 1 }) }); await prepare(x);
  x.session.command({ action: "confirm", answer: "СОБРАТЬ 01234567" }); await x.session.settled();
  const last = x.messages.at(-1); assert.equal(last.code, 1);
  assert.match(last.reportText, /Очистка данных не подтверждена/u); assert.match(last.reportHtml, /Очистка данных не подтверждена/u);
});
test("missing data is NotTested, even after successful process completion", async () => {
  const x = setup({ run: async () => transport(envelope("")) }); await prepare(x);
  x.session.command({ action: "confirm", answer: "СОБРАТЬ 01234567" }); await x.session.settled();
  assert.equal(x.messages.at(-1).code, 2); assert.match(x.messages.at(-1).reportText, /проверка не засчитана/u);
});
test("CLI and GUI render exactly the same private result", async () => {
  const x = setup(); await prepare(x); x.session.command({ action: "confirm", answer: "СОБРАТЬ 01234567" }); await x.session.settled();
  const output = [];
  await runDefenderCheckCommand([], { ...x.executor, platform: "win32", interactive: true,
    stdout: (s) => output.push(s), stderr: (s) => output.push(s), prompt: async () => "СОБРАТЬ 01234567" });
  assert.ok(output.includes(x.messages.at(-1).reportText));
});
for (const [raw, outcome] of [[normal, "NoConcernReported"], ['{"AMRunningMode":"Normal","RealTimeProtectionEnabled":false}\n', "Concern"], ['{"AMRunningMode":"Passive","RealTimeProtectionEnabled":false}\n', "NotTested"], ["", "NotTested"], ['{"AMRunningMode":"<script>PRIVATE</script>","RealTimeProtectionEnabled":true}\n', "NotTested"]]) {
  test(`unified report: ${outcome} ${raw.length}`, () => {
    const reading = decodeDefenderControlResult(Buffer.from(JSON.stringify(receipt(raw))), id);
    const report = createDefenderCheckReport(reading, { dataFilesRemoved: true });
    assert.equal(report.outcome, outcome); assert.ok(Object.isFrozen(report.fields[0]));
    const html = renderDefenderCheckHtml(report); const text = renderDefenderCheckText(report);
    for (const s of [html, text]) { assert.ok(!s.includes("PRIVATE")); assert.ok(!s.includes(id)); assert.match(s, /не полный аудит/u); }
    assert.match(html, /default-src 'none'/u); assert.ok(!html.includes("<script"));
    assert.throws(() => renderDefenderCheckHtml({ ...report }));
    assert.throws(() => createDefenderCheckReport({ ...reading }, { dataFilesRemoved: true }));
    assert.throws(() => createDefenderCheckReport(reading, { dataFilesRemoved: "true" }));
  });
}
for (const raw of ['{"action":"run"}', '{"action":"prepare","path":"PRIVATE"}', '{"action":"confirm","answer":true}',
  '{"action":"confirm","answer":"' + "x".repeat(65) + '"}', '{"action":"ready","action":"prepare"}', '[]']) {
  test(`reject unsafe UI protocol ${raw.slice(0, 45)}`, () => assert.throws(() => decodeDesktopCommand(Buffer.from(raw))));
}
test("framing survives split UTF-8 and CRLF; oversized or invalid messages fail once", () => {
  const received = []; let failures = 0;
  const reader = createDesktopCommandReader((row) => received.push(row), () => failures++);
  const command = { action: "confirm", answer: "СОБРАТЬ 01234567" };
  for (const b of Buffer.from(JSON.stringify(command) + "\r\n")) reader.receive(Buffer.from([b]));
  assert.deepEqual(received, [command]); reader.receive(Buffer.alloc(257, 65)); reader.receive(Buffer.from('{}\n'));
  assert.equal(failures, 1); assert.equal(received.length, 1);
});
test("framing rejects truncated JSON, invalid UTF-8 and large chunks", () => {
  for (const bytes of [Buffer.from('{"action":"ready"}'), Buffer.from([0xff, 10]), Buffer.alloc(4097)]) {
    let failed = 0; const r = createDesktopCommandReader(() => assert.fail(), () => failed++);
    r.receive(bytes); r.end(); assert.equal(failed, 1);
  }
});
test("help and invalid options never open a window or start a check", () => {
  const file = new URL("../../tools/secapp.mjs", import.meta.url);
  assert.match(execFileSync(process.execPath, [file.pathname.replace(/^\/([A-Za-z]:)/u, "$1"), "--help"], { encoding: "utf8" }), /npm start/u);
  assert.throws(() => execFileSync(process.execPath, [file.pathname.replace(/^\/([A-Za-z]:)/u, "$1"), "--yes"], { stdio: "pipe" }));
});
test("desktop source has no elevation, policy bypass, network, automatic export or existing-file overwrite", async () => {
  const ps = await readFile(new URL("../../tools/ui/Show-DefenderWindow.ps1", import.meta.url), "utf8");
  const js = await readFile(new URL("../../tools/secapp.mjs", import.meta.url), "utf8");
  assert.equal(ps.charCodeAt(0), 0xfeff); // Required by Windows PowerShell 5.1 -File.
  for (const forbidden of [/Start-Process/iu, /-Verb\s+RunAs/iu, /Set-Acl/iu, /Set-ItemProperty/iu, /SetValue\(/u, /Invoke-WebRequest/iu, /FileMode\]::Create[,)]/u]) assert.doesNotMatch(ps, forbidden);
  assert.match(ps, /FileMode\]::CreateNew/u); assert.match(ps, /SaveFileDialog/u);
  assert.match(ps, /Test-ExistingEventSource/u); assert.match(ps, /OpenSubKey\([^\n]+, \$false\)/u);
  assert.doesNotMatch(js, /"-ExecutionPolicy"|"-Command"|createServer/u);
  assert.match(js, /windowsHide: false/u); // The UI host must not request hidden presentation.
});

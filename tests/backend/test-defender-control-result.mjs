import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { decodeDefenderControlResult as decode, renderDefenderControlReading as render } from "../../src/backend/defender-control-result.mjs";
import { DIRECT_DEFENDER_OPERATION } from "../../src/backend/direct-defender-operation.mjs";
const id = "1234567890abcdef1234567890abcdef";
const normal = '{"AMRunningMode":"Normal","RealTimeProtectionEnabled":true}\n';
const record = () => ({ kind: "SecAppDefenderControlV1", run_id: id, outcome: "Completed", error: "NONE",
  backend_created: true, backend_resumed: true, backend_exit: 0, root_exited: true, job_empty: true,
  pipes_closed: true, elapsed_ms: 1200, stdout_base64: Buffer.from(normal).toString("base64") });
const bytes = (row) => Buffer.from(JSON.stringify(row) + "\n");
test("valid synthetic receipt gives a narrowly labelled result, not attested collection", () => {
  const result = decode(bytes(record()), id);
  assert.equal(result.authority, "HelperReportedNotAttested");
  assert.equal(result.preview.collection_claim, "NotEstablished");
  assert.equal(result.preview.checks[0].outcome, "NoConcernReported");
  assert.ok(render(result).includes("Активный"));
  assert.ok(render(result).includes("не полный аудит"));
});
test("empty output does not invent useful coverage", () => {
  const row = record(); row.stdout_base64 = "";
  assert.equal(decode(bytes(row), id).preview.assessment_status, "NotTested");
});
test("rendering cannot relabel a caller-crafted result as a control receipt", () => {
  const reading = decode(bytes(record()), id);
  assert.throws(() => render({ ...reading }), /^Error: CONTROL_READING_INVALID$/u);
  assert.throws(() => render(JSON.parse(JSON.stringify(reading))), /^Error: CONTROL_READING_INVALID$/u);
});
for (const [key, value] of [["outcome", "Failed"], ["error", "CANCELLED"], ["backend_created", false],
  ["backend_resumed", false], ["backend_exit", 1], ["backend_exit", null], ["backend_exit", "0"],
  ["root_exited", false], ["job_empty", false], ["pipes_closed", false], ["elapsed_ms", 40000],
  ["elapsed_ms", -1], ["elapsed_ms", "1000"], ["job_empty", "true"], ["run_id", "a".repeat(32)],
  ["kind", "Other"], ["stdout_base64", "=bad"], ["stdout_base64", " "]]) {
  test(`rejects ${key}=${JSON.stringify(value)}`, () => {
    const row = record(); row[key] = value;
    assert.throws(() => decode(bytes(row), id), /^Error: CONTROL_/u);
  });
}
test("unknown keys, duplicate fields, invalid UTF-8 and oversized transport reject", () => {
  const row = record(); row.verified = true;
  for (const source of [bytes(row), Buffer.from(bytes(record()).toString().replace('"error":"NONE"', '"error":"NONE","error":"NONE"')),
    Buffer.from([0xff]), Buffer.alloc(8193)]) assert.throws(() => decode(source, id), /^Error: CONTROL_/u);
});
test("startup stdout prefix and invalid row are not filtered", () => {
  for (const text of ["Error: PRIVATE\n" + normal, normal + normal, normal.trimEnd()]) {
    const row = record(); row.stdout_base64 = Buffer.from(text).toString("base64");
    assert.throws(() => decode(bytes(row), id), /^Error: CONTROL_RESULT_OUTPUT$/u);
  }
});
test("native source pin/query/bounds stay aligned with the fixed candidate", async () => {
  const source = await readFile(new URL("../../tools/backend/defender-control/DefenderControl.cs", import.meta.url), "utf8");
  assert.ok(source.includes(DIRECT_DEFENDER_OPERATION.candidateAsset.sha256));
  const nativeQuery = source.match(/internal const string Query = ("(?:[^"\\]|\\.)*");/u);
  assert.ok(nativeQuery);
  assert.equal(JSON.parse(nativeQuery[1]), DIRECT_DEFENDER_OPERATION.arguments.at(-1));
  assert.ok(source.includes("536870912u"));
  assert.ok(source.includes("watch.ElapsedMilliseconds < 30000"));
  assert.ok(source.includes("Add(0x2000d"));
  for (const forbidden of ["CreateRestrictedToken", "CreateProcessAsUser", "SetAccessControl", "RegSetValue", "ShellExecute", "Process.Start"]) assert.equal(source.includes(forbidden), false);
});
test("private workspace creation has no existing-ACL setter or external bootstrap compiler", async () => {
  const controller = await readFile(new URL("../../tools/backend/defender-control/Invoke-DefenderControl.ps1", import.meta.url), "utf8");
  const workspace = await readFile(new URL("../../tools/backend/defender-control/Workspace.cs", import.meta.url), "utf8");
  assert.ok(controller.includes("$bridge::CreateDirectoryW($Path,$attributes)"));
  assert.ok(controller.includes("D:P(A;OICI;FA;;;"));
  assert.ok(controller.includes("SecApp-Control-"));
  assert.ok(controller.includes("PERSISTENT_ACLS_REQUIRED"));
  assert.ok(controller.includes("[Reflection.Emit.AssemblyBuilderAccess]::Run"));
  assert.equal(/^\s*(?:Add-Type|Set-Acl)\b/miu.test(controller), false);
  assert.equal(controller.includes("::SetAccessControl("), false);
  assert.equal(workspace.includes(".SetAccessControl("), false);
  assert.ok(workspace.includes("security.AreAccessRulesProtected"));
  assert.ok(workspace.includes("GetFinalPathNameByHandleW"));
  assert.ok(workspace.includes("GetVolumeInformationW"));
  assert.ok(controller.includes("CreateFileW($current, 0x81, 3,"));
  assert.ok(workspace.includes("CreateFileW(p, 0x81, 3,"));
  assert.ok(controller.includes("$source.CopyTo($copy,65536)"));
  assert.ok(controller.includes("[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None"));
  assert.ok(controller.includes("workspace_sha256"));
  assert.ok(controller.includes("$workspaceRoot = 'C:\\Dev'"));
  assert.ok(workspace.includes('const string root = @"C:\\Dev";'));
  assert.equal(controller.includes("Hold-DirectoryChain $acquisition"), false);
});

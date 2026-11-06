import test, { after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { syntheticObservations, sealObservation } from "./synthetic-observations.mjs";
import { createImportReferenceValidator } from "../../tools/lib/import-reference-validator.mjs";
import { createProtectionAssessment } from "../../tools/lib/protection-assessment.mjs";
import { createSchemaRegistry } from "../../tools/lib/schema-registry.mjs";
import { importAuditPackage } from "../../src/import/audit-package-importer.mjs";
import { assessWindowsProtection } from "../../src/assessment/windows-protection.mjs";
import { WINDOWS_PROTECTION_PROFILE as PROFILE } from "../../src/assessment/windows-protection-profile.mjs";
import { renderProtectionHtml } from "../../src/reporting/protection-report.mjs";
import { digestWithExclusion } from "../../tools/lib/jcs.mjs";
import { runImportCommand } from "../../tools/lib/import-command.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const temporaryRoot = await mkdtemp(path.join(tmpdir(), "secapp-assessment-test-"));
after(async () => { await rm(temporaryRoot, { recursive: true, force: true }); });
const referenceValidator = createImportReferenceValidator();
const assess = createProtectionAssessment(referenceValidator);
let sequence = 0;
async function importObjects(objects) {
  const sourcePath = path.join(temporaryRoot, `synthetic-${++sequence}.jsonl`);
  await writeFile(sourcePath, objects.map((value) => JSON.stringify(value)).join("\n") + "\n");
  return importAuditPackage({ sourcePath, privacyMode: "Private", referenceValidator });
}
async function evaluate(objects = syntheticObservations()) {
  const imported = await importObjects(objects);
  assert.equal(imported.status, "Accepted", JSON.stringify(imported.error));
  return assess(imported);
}

test("demo produces six deterministic checks with independent severity/confidence/status", async () => {
  const imported = await importObjects(syntheticObservations());
  const report = await assess(imported);
  assert.deepEqual(report, await assess(imported));
  assert.deepEqual(report.counts, { Concern: 2, NoConcernReported: 3, NotTested: 1 });
  assert.equal(report.assessment_status, "Partial");
  assert.equal(report.report_digest, digestWithExclusion(report, "report_digest"));
  assert.equal(report.checks.length, 6);
  assert.equal(report.checks[0].severity, "Medium");
  assert.equal(report.checks[0].confidence, "Possible");
  assert.equal(report.checks[0].status, "Requires review");
  assert.equal(report.provenance_claim, "NotEstablished");
  assert.equal(report.freshness_claim, "NotEvaluated");
});

test("committed synthetic demo exactly matches the digest-backed generator", async () => {
  const fixture = await readFile(path.join(root, "tests/assessment/fixtures/windows-protection.jsonl"), "utf8");
  assert.equal(fixture, syntheticObservations().map((value) => JSON.stringify(value)).join("\n") + "\n");
});

for (const rule of PROFILE.rules) {
  test(`${rule.id}: expected state is not a claim that the host is safe`, async () => {
    const observation = syntheticObservations().find((value) => value.area === rule.area);
    for (const check of rule.checks) observation.data[check.field] = check.expected;
    const report = await evaluate([sealObservation(observation)]);
    const result = report.checks.find((value) => value.rule_id === rule.id);
    assert.equal(result.outcome, "NoConcernReported");
    assert.equal(result.confidence, "Not detected");
    assert.equal(result.status, "Requires review");
    assert.equal(report.provenance_claim, "NotEstablished");
  });
  test(`${rule.id}: explicitly adverse state reports a concern`, async () => {
    const observation = syntheticObservations().find((value) => value.area === rule.area);
    for (const check of rule.checks) observation.data[check.field] = check.expected;
    const adverse = rule.checks.find((check) => check.known.some((value) => value !== check.expected));
    observation.data[adverse.field] = adverse.known.find((value) => value !== adverse.expected);
    const report = await evaluate([sealObservation(observation)]);
    const result = report.checks.find((value) => value.rule_id === rule.id);
    assert.equal(result.outcome, "Concern");
    assert.equal(result.severity, rule.severity);
    assert.equal(result.confidence, "Possible");
    assert.deepEqual(result.source.observation_id, observation.observation_id);
  });
}

for (const domain of PROFILE.domains) {
  test(`${domain.area}: domain schema rejects unknown fields, wrong types, versions, and enums`, async () => {
    const original = syntheticObservations().find((value) => value.area === domain.area);
    const field = Object.keys(original.data).find((key) => key !== "schema_version");
    const mutations = [
      (value) => { value.data.unreviewed_field = "synthetic"; },
      (value) => { value.data[field] = false; },
      (value) => { value.data[field] = null; },
      (value) => { value.data[field] = "Unexpected"; },
      (value) => { value.data.schema_version = "2.0.0"; },
      (value) => { delete value.data.schema_version; }
    ];
    for (const mutate of mutations) {
      const value = structuredClone(original);
      mutate(value);
      await assert.rejects(evaluate([sealObservation(value)]), { code: "ASSESSMENT_PAYLOAD_INVALID" });
    }
    assert.equal((await evaluate([original])).checks.length, 6);
  });
}

test("missing, unknown, and unsupported states always become coverage gaps", async () => {
  for (const replacement of [undefined, "Unknown", "Unsupported"]) {
    const observations = syntheticObservations();
    for (const observation of observations) {
      for (const key of Object.keys(observation.data)) {
        if (key === "schema_version") continue;
        if (replacement === undefined) delete observation.data[key];
        else observation.data[key] = replacement;
      }
      sealObservation(observation);
    }
    const report = await evaluate(observations);
    assert.equal(report.assessment_status, "NotTested");
    assert.equal(report.counts.NotTested, 6);
    assert.ok(report.checks.every((value) => value.severity === "Info" && value.confidence === "Not tested"));
  }
});

test("passive Defender mode does not invent a conclusion about another antivirus", async () => {
  const observation = syntheticObservations()[0];
  observation.data.mode = "Passive";
  const report = await evaluate([sealObservation(observation)]);
  assert.equal(report.checks[0].outcome, "NotTested");
});

test("unsupported domain schema version is not interpreted and leaks no input text", async () => {
  const observation = syntheticObservations()[0];
  observation.data_schema = "urn:secapp:observation:defender-protection:2";
  observation.data = { synthetic_private: "<script>synthetic-private</script>" };
  const report = await evaluate([sealObservation(observation)]);
  assert.equal(report.checks[0].reason, "UnsupportedSchema");
  assert.equal(report.checks[0].outcome, "NotTested");
  assert.equal(JSON.stringify(report).includes("synthetic-private"), false);
});

test("rejects payload bindings to the wrong area, subject, or privacy class", async () => {
  for (const mutate of [
    (value) => { value.area = "WindowsPlatform"; },
    (value) => { value.subject.key = "control:other"; },
    (value) => { value.privacy_class = "Public"; }
  ]) {
    const observation = syntheticObservations()[0];
    mutate(observation);
    await assert.rejects(evaluate([sealObservation(observation)]), { code: "ASSESSMENT_DOMAIN_MISMATCH" });
  }
});

test("rejects conflicting duplicate domains and mixed run IDs", async () => {
  const observations = syntheticObservations();
  const duplicate = structuredClone(observations[0]);
  duplicate.observation_id = "91000000-0000-4000-8000-000000000999";
  duplicate.data.real_time_protection = "Enabled";
  await assert.rejects(evaluate([...observations, sealObservation(duplicate)]), { code: "ASSESSMENT_DUPLICATE_DOMAIN" });
  observations[1].run_id = "92000000-0000-4000-8000-000000000999";
  await assert.rejects(evaluate(observations.map(sealObservation)), { code: "ASSESSMENT_RUN_MISMATCH" });
});

test("does not assess rejected inputs or bypass a missing domain validator", async () => {
  await assert.rejects(assessWindowsProtection({ status: "Rejected" }), { code: "ASSESSMENT_IMPORT_REQUIRED" });
  const imported = await importObjects(syntheticObservations());
  await assert.rejects(assessWindowsProtection(imported), { code: "ASSESSMENT_VALIDATOR_REQUIRED" });
  imported.objects[0].value.data.real_time_protection = "Enabled";
  await assert.rejects(assess(imported), { code: "IMPORT_DIGEST_MISMATCH" });
});

test("input without observations yields six NotTested results", async () => {
  const value = JSON.parse(await readFile(path.join(root, "tests/import/fixtures/error-object.json"), "utf8"));
  const report = await evaluate([value]);
  assert.equal(report.assessment_status, "NotTested");
  assert.equal(report.counts.NotTested, 6);
  assert.equal(report.run_id, null);
});

test("reported unsuccessful collection cannot yield a positive state assessment", async () => {
  const imported = await importObjects(syntheticObservations());
  const observation = imported.objects[0].value;
  // A direct boundary regression: this incomplete execution is not a package fixture.
  imported.objects.push({ contract_kind: "CollectorExecution", value: {
    execution_id: observation.execution_id, run_id: observation.run_id, state: "Failed", observation_ids: [observation.observation_id]
  } });
  const report = await assess(imported);
  assert.equal(report.checks[0].outcome, "NotTested");
  assert.equal(report.checks[0].reason, "CollectionNotSucceeded");
});

test("report schema rejects a NotTested result relabeled with confidence", async () => {
  const registry = createSchemaRegistry(root);
  const schema = JSON.parse(await readFile(path.join(root, "schemas/reports/windows-protection-report.schema.json"), "utf8"));
  const validate = registry.ajv.compile(schema);
  const report = await evaluate();
  assert.equal(validate(report), true);
  report.checks.at(-1).confidence = "Possible";
  assert.equal(validate(report), false);
});

test("HTML escapes hostile text and has no scripts, external assets, or links", async () => {
  const report = await evaluate();
  const attack = '<script>alert(1)</script><img src="https://synthetic.invalid/x" onerror="x">&';
  report.checks[0].title = attack;
  report.checks[0].explanation = attack;
  report.checks[0].limitation = attack;
  report.checks[0].source.observed_at = attack;
  report.limitations.push(attack);
  const html = renderProtectionHtml(report);
  assert.equal(html.includes(attack), false);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<(script|img|iframe|object|a|link)\b/iu);
  assert.match(html, /default-src 'none'/);
  assert.match(html, /form-action 'none'/);
  assert.match(html, /<html lang="ru">/);
});

test("CLI assessment returns a private report and leaves plain import unchanged", async () => {
  const sourcePath = path.join(root, "tests/assessment/fixtures/windows-protection.jsonl");
  const options = { cwd: root, loadReferenceValidator: async () => referenceValidator, loadAssessment: async () => assess };
  const plain = await runImportCommand(["--source", sourcePath, "--json"], options);
  assert.equal(plain.exitCode, 0);
  assert.equal(JSON.parse(plain.output).assessment_status, "NotPerformed");
  for (const format of [[], ["--json"], ["--html"]]) {
    const result = await runImportCommand(["--source", sourcePath, "--assess", PROFILE.id, ...format], options);
    assert.equal(result.exitCode, 0);
    if (format[0] === "--json") assert.equal(JSON.parse(result.output).privacy_class, "SensitiveSecurityData");
    else assert.match(result.output, /Требует внимания|требует внимания/);
    assert.equal(result.output.includes(sourcePath), false);
  }
});

test("CLI rejects invalid assessment flags and unavailable validators", async () => {
  const prefix = ["--source", "tests/assessment/fixtures/windows-protection.jsonl"];
  for (const args of [["--html"], ["--assess", "unknown"], ["--assess", PROFILE.id, "--html", "--json"]]) {
    assert.equal((await runImportCommand([...prefix, ...args], { cwd: root })).exitCode, 64);
  }
  const unavailable = await runImportCommand([...prefix, "--assess", PROFILE.id, "--json"], {
    cwd: root, loadReferenceValidator: async () => referenceValidator,
    loadAssessment: () => { throw new Error("synthetic-private-failure"); }
  });
  assert.equal(unavailable.exitCode, 1);
  assert.equal(JSON.parse(unavailable.output).error.code, "ASSESSMENT_VALIDATOR_UNAVAILABLE");
  assert.equal(unavailable.output.includes("synthetic-private-failure"), false);
});

test("actual CLI creates an HTML stream without writing files", async () => {
  const before = await readdir(temporaryRoot);
  const result = spawnSync(process.execPath, [path.join(root, "tools/import-audit-package.mjs"),
    "--source", path.join(root, "tests/assessment/fixtures/windows-protection.jsonl"), "--assess", PROFILE.id, "--html"], {
    cwd: temporaryRoot, encoding: "utf8", shell: false, windowsHide: true, timeout: 15000, maxBuffer: 256 * 1024
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.match(result.stdout, /^<!doctype html>/);
  assert.deepEqual(await readdir(temporaryRoot), before);
});

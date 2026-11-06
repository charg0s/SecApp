import { WINDOWS_PROTECTION_PROFILE as PROFILE } from "./windows-protection-profile.mjs";
import { digestWithExclusion, jcsSha256 } from "../../tools/lib/jcs.mjs";
import { verifyContractIntegrity } from "../import/import-normalization.mjs";
import { reject } from "../import/import-errors.mjs";

export async function assessWindowsProtection(importResult, { validateObservation, schemaDigests } = {}) {
  if (importResult?.status !== "Accepted" || !Array.isArray(importResult.objects)
    || importResult.summary?.privacy_mode !== "Private") {
    reject("ASSESSMENT_IMPORT_REQUIRED", "Assessment", "Assessment requires a validated private import.");
  }
  if (typeof validateObservation !== "function" || !schemaDigests
    || PROFILE.domains.some((domain) => !/^[a-f0-9]{64}$/u.test(schemaDigests[domain.schema_id] ?? ""))) {
    reject("ASSESSMENT_VALIDATOR_REQUIRED", "Assessment", "The local observation validation gate is required.");
  }
  const observations = importResult.objects.filter((object) => object.contract_kind === "Observation").map((object) => object.value);
  const runIds = new Set();
  const byArea = new Map();
  const executions = new Map(importResult.objects.filter((object) => object.contract_kind === "CollectorExecution").map((object) => [object.value.execution_id, object.value]));
  let ignoredCount = 0;
  for (const observation of observations) {
    runIds.add(observation.run_id);
    const domain = PROFILE.domains.find((item) => item.area === observation.area);
    const schemaDomain = PROFILE.domains.find((item) => item.schema_id === observation.data_schema);
    if (schemaDomain && schemaDomain !== domain) reject("ASSESSMENT_DOMAIN_MISMATCH", "Assessment", "Observation area does not match its payload schema.");
    if (!domain) { ignoredCount += 1; continue; }
    if (byArea.has(domain.area)) reject("ASSESSMENT_DUPLICATE_DOMAIN", "Assessment", "More than one observation describes the same assessment domain.");
    // Unknown payload versions remain coverage gaps; their content is never interpreted.
    if (observation.data_schema !== domain.schema_id) {
      byArea.set(domain.area, { reason: "UnsupportedSchema" });
      continue;
    }
    if (observation.subject?.kind !== "SecurityControl" || observation.subject.key !== domain.subject
      || observation.privacy_class !== "SensitiveSecurityData") {
      reject("ASSESSMENT_DOMAIN_MISMATCH", "Assessment", "Observation subject or privacy classification does not match the profile.");
    }
    let valid = false;
    try { valid = await validateObservation(structuredClone(observation)); } catch { /* fail closed */ }
    if (valid !== true) reject("ASSESSMENT_PAYLOAD_INVALID", "Assessment", "Observation failed the local domain schema.");
    verifyContractIntegrity("Observation", observation);
    const execution = executions.get(observation.execution_id);
    if (execution && (execution.run_id !== observation.run_id || !execution.observation_ids.includes(observation.observation_id))) {
      reject("ASSESSMENT_EXECUTION_MISMATCH", "Assessment", "Observation does not match its supplied execution.");
    }
    const failedCollection = (execution && !["Succeeded", "Partial"].includes(execution.state))
      || (importResult.package_kind === "AuditPackageZip" && !execution);
    byArea.set(domain.area, { observation, ...(failedCollection ? { reason: "CollectionNotSucceeded" } : {}) });
  }
  if (runIds.size > 1) reject("ASSESSMENT_RUN_MISMATCH", "Assessment", "Observations from different runs cannot be combined.");
  const rows = PROFILE.rules.map((rule) => {
    const selected = byArea.get(rule.area);
    const observation = selected?.observation;
    const known = observation && !selected.reason && rule.checks.every((check) => check.known.includes(observation.data[check.field]));
    const concern = known && rule.checks.some((check) => observation.data[check.field] !== check.expected);
    const outcome = !known ? "NotTested" : concern ? "Concern" : "NoConcernReported";
    return {
      rule_id: rule.id,
      title: rule.title,
      area: rule.area,
      outcome,
      severity: concern ? rule.severity : "Info",
      confidence: !known ? "Not tested" : concern ? "Possible" : "Not detected",
      status: "Requires review",
      reason: !known ? selected?.reason ?? (observation ? "MissingOrUnsupportedState" : "MissingObservation") : "ReportedState",
      explanation: !known ? "Недостаточно поддерживаемых данных для этой проверки." : concern ? rule.concern : rule.normal,
      limitation: rule.limitation,
      ...(observation ? { source: {
        observation_id: observation.observation_id,
        observed_at: observation.observed_at,
        object_digest: observation.integrity.object_digest
      } } : {})
    };
  });
  const counts = Object.fromEntries(["Concern", "NoConcernReported", "NotTested"].map((name) => [name, rows.filter((row) => row.outcome === name).length]));
  const report = {
    schema_version: "1.0.0",
    report_kind: "WindowsProtectionAssessment",
    profile_id: PROFILE.id,
    profile_version: PROFILE.version,
    profile_digest: jcsSha256(PROFILE),
    schema_digests: Object.fromEntries(PROFILE.domains.map((domain) => [domain.schema_id, schemaDigests[domain.schema_id]])),
    policy_review: "PendingIndependentReview",
    privacy_class: "SensitiveSecurityData",
    assessment_status: counts.NotTested === rows.length ? "NotTested" : counts.NotTested > 0 ? "Partial" : "Complete",
    run_id: [...runIds][0] ?? null,
    source_file_digest: importResult.summary.source_file_digest,
    provenance_claim: "NotEstablished",
    freshness_claim: "NotEvaluated",
    validation_scope: "ImportedObservationProfile",
    ignored_observation_count: ignoredCount,
    counts,
    checks: rows,
    limitations: [
      "Выводы относятся только к переданному снимку. Его актуальность и состояние компьютера сейчас не проверялись.",
      "Хеши обнаруживают изменение относительно предоставленных данных; происхождение и правдивость источника не подтверждены.",
      "Отсутствие замечания по правилу не означает, что компьютер безопасен. Полный аудит и независимая проверка правил ещё не выполнены.",
      "Это частный отчёт с данными о защите системы; он не является обезличенным публичным экспортом."
    ],
    report_digest: ""
  };
  report.report_digest = digestWithExclusion(report, "report_digest");
  return report;
}

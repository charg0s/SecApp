// Pure raw-output adapter. This module never starts a process or authenticates a source.
import { createHash } from "node:crypto";
import { parseJsonLinesBytes } from "../import/import-json.mjs";
import { WINDOWS_PROTECTION_PROFILE } from "../assessment/windows-protection-profile.mjs";
import { digestWithExclusion } from "../../tools/lib/jcs.mjs";

export const DEFENDER_OUTPUT_LIMITS = Object.freeze({
  maxSourceBytes: 4096, maxJsonlLineBytes: 1024, maxRecords: 1,
  maxJsonDepth: 2, jsonlFinalLf: "Required"
});

export const DEFENDER_QUERY_CANDIDATE = Object.freeze({
  id: "defender-realtime-standard-v1",
  sourceRevision: "7d287b0b988b35657e1b401f7b2ffebaf60dbcae",
  query: 'SELECT AMRunningMode, RealTimeProtectionEnabled FROM wmi(query="SELECT AMRunningMode, RealTimeProtectionEnabled FROM MSFT_MpComputerStatus", namespace="root/Microsoft/Windows/Defender") LIMIT 2',
  executionAdmission: "NotAccepted"
});

export class DefenderOutputError extends Error {
  constructor(code) {
    super(code); // Never carry parser diagnostics, source paths or raw backend values.
    this.name = "DefenderOutputError";
    this.code = code;
  }
}

const reports = new WeakSet();
const allowed = new Set(["AMRunningMode", "RealTimeProtectionEnabled"]);
const modeMap = new Map([
  ["Normal", "Active"], ["Passive", "Passive"],
  ["Passive Mode", "Passive"], ["SxS Passive Mode", "Passive"]
]);

function fail(code) { throw new DefenderOutputError(code); }
function freeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function normalize(bytes) {
  if (bytes.length === 0) return { mode: "Unknown", real_time_protection: "Unknown", empty: true };
  let row;
  try {
    row = parseJsonLinesBytes(bytes, DEFENDER_OUTPUT_LIMITS, "backend output").records[0].value;
  } catch { fail("DEFENDER_OUTPUT_INVALID"); }
  if (Object.keys(row).some((key) => !allowed.has(key))) fail("DEFENDER_OUTPUT_FIELDS");
  const mode = row.AMRunningMode;
  const realtime = row.RealTimeProtectionEnabled;
  if (mode !== undefined && mode !== null && (typeof mode !== "string" || mode.length > 64
      || /[\u0000-\u001f\u007f-\u009f]/u.test(mode))) fail("DEFENDER_OUTPUT_MODE");
  if (realtime !== undefined && realtime !== null && typeof realtime !== "boolean") {
    fail("DEFENDER_OUTPUT_BOOLEAN");
  }
  return {
    mode: modeMap.get(mode) ?? "Unknown",
    real_time_protection: realtime === true ? "Enabled" : realtime === false ? "Disabled" : "Unknown",
    empty: false
  };
}

export function createDefenderPreview(bytes) {
  if (!Buffer.isBuffer(bytes)) fail("DEFENDER_OUTPUT_BYTES_REQUIRED");
  if (bytes.length > DEFENDER_OUTPUT_LIMITS.maxSourceBytes) fail("DEFENDER_OUTPUT_TOO_LARGE");
  const snapshot = Buffer.from(bytes);
  const normalized = normalize(snapshot);
  const checks = WINDOWS_PROTECTION_PROFILE.rules.map((rule) => {
    const selected = rule.id === "rule:secapp.defender-realtime";
    const known = selected && rule.checks.every((check) => check.known.includes(normalized[check.field]));
    const concern = known && rule.checks.some((check) => normalized[check.field] !== check.expected);
    return {
      rule_id: rule.id, title: rule.title,
      outcome: !known ? "NotTested" : concern ? "Concern" : "NoConcernReported",
      severity: concern ? rule.severity : "Info",
      confidence: !known ? "Not tested" : concern ? "Possible" : "Not detected",
      status: "Requires review",
      reason: !selected ? "OutsideSelectedCheck" : normalized.empty ? "EmptyOutput"
        : !known ? "MissingOrUnsupportedState" : "ReportedState",
      explanation: !selected ? "Эта проверка не входит в выбранный минимальный сценарий."
        : !known ? "Недостаточно поддерживаемых данных для оценки защиты Defender."
          : concern ? rule.concern : rule.normal,
      limitation: rule.limitation
    };
  });
  const counts = Object.fromEntries(["Concern", "NoConcernReported", "NotTested"]
    .map((key) => [key, checks.filter((row) => row.outcome === key).length]));
  const report = {
    schema_version: "1.0.0",
    report_kind: "DefenderOutputPreview",
    profile_id: DEFENDER_QUERY_CANDIDATE.id,
    privacy_class: "SensitiveSecurityData",
    source_kind: "SuppliedBackendOutput",
    provenance_claim: "NotEstablished",
    freshness_claim: "NotEvaluated",
    collection_claim: "NotEstablished",
    policy_review: "ReferenceRuleNotProductionAccepted",
    assessment_status: counts.NotTested === checks.length ? "NotTested" : "Partial",
    source_sha256: createHash("sha256").update(snapshot).digest("hex"),
    normalized: { mode: normalized.mode, real_time_protection: normalized.real_time_protection },
    counts, checks,
    limitations: [
      "Это разбор предоставленного вывода, не выполненная SecApp проверка компьютера.",
      "Запуск, успешное завершение, происхождение и актуальность данных не подтверждены.",
      "Нет замечания по переданным значениям — не значит, что компьютер безопасен.",
      "Отчёт содержит частные сведения о защите. Автоматическое сохранение, шифрование и срок хранения не реализованы."
    ],
    report_digest: ""
  };
  report.report_digest = digestWithExclusion(report, "report_digest");
  freeze(report);
  reports.add(report);
  return report;
}

// Rendering accepts only the frozen product of this adapter, not caller-crafted JSON.
export function assertDefenderPreview(report) {
  if (!reports.has(report)) fail("DEFENDER_REPORT_INVALID");
  return report;
}

// One private presentation model for the CLI, desktop window and explicit HTML save.
// Not an AuditRun, a signed receipt, or an importable audit package.
import { assertDefenderControlReading } from "../backend/defender-control-result.mjs";

const reports = new WeakSet();
const mode = { Active: "Активный", Passive: "Пассивный", Unknown: "Неизвестен" };
const realtime = { Enabled: "Включена", Disabled: "Выключена", Unknown: "Неизвестно" };
const outcomes = { NoConcernReported: "По этим двум показателям замечание не выявлено.",
  Concern: "Выявлено состояние, требующее внимания.", NotTested: "Недостаточно данных: проверка не засчитана." };
const severities = { Info: "Информация", Low: "Низкая", Medium: "Средняя" };
const confidence = { Possible: "Возможно", "Not detected": "Не выявлено", "Not tested": "Не проверено" };
const escape = (text) => String(text).replace(/[&<>"']/gu, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export function createDefenderCheckReport(reading, { dataFilesRemoved } = {}) {
  assertDefenderControlReading(reading);
  if (typeof dataFilesRemoved !== "boolean") throw new Error("CHECK_REPORT_CLEANUP");
  const selected = reading.preview.checks.find((row) => row.rule_id === "rule:secapp.defender-realtime");
  const report = Object.freeze({
    kind: "SecAppDefenderCheckReportV1", privacy: "SensitiveSecurityData",
    authority: "HelperReportedNotAttested", outcome: selected.outcome,
    title: "SecApp — проверка Microsoft Defender",
    summary: outcomes[selected.outcome],
    fields: Object.freeze([
      Object.freeze({ title: "Режим Defender", value: mode[reading.preview.normalized.mode] }),
      Object.freeze({ title: "Защита в реальном времени", value: realtime[reading.preview.normalized.real_time_protection] })
    ]),
    severity: severities[selected.severity], confidence: confidence[selected.confidence],
    status: "Требует проверки", explanation: selected.explanation,
    cleanup: dataFilesRemoved
      ? "Временные данные удалены; закрытый каталог и пустой controller.lock сохранены."
      : "Очистка данных не подтверждена. Не удаляйте рабочий каталог без проверки завершения.",
    limitations: Object.freeze([
      "Это не полный аудит и не подтверждение безопасности компьютера.",
      selected.limitation,
      "Оценены только AMRunningMode и RealTimeProtectionEnabled из локального WMI Defender.",
      "Брандмауэр, BitLocker, Secure Boot и остальные области: не проверено.",
      "Помощник сообщил об успешном завершении. Происхождение данных криптографически не подтверждено.",
      "Проверка зависит от достоверности работающей Windows; скомпрометированная система может искажать сведения.",
      "Частный отчёт: SensitiveSecurityData. Не публикуйте без проверки; сохранённый HTML не зашифрован.",
      "Это локальный отчёт, не AuditRun и не пакет импорта."
    ])
  });
  reports.add(report);
  return report;
}

function checked(report) {
  if (!reports.has(report)) throw new Error("CHECK_REPORT_INVALID");
  return report;
}
export function renderDefenderCheckText(value) {
  const r = checked(value);
  return [r.title, "", r.summary, ...r.fields.map((f) => `${f.title}: ${f.value}.`), r.explanation,
    `Серьёзность: ${r.severity}; уверенность: ${r.confidence}; статус: ${r.status}.`,
    "", r.cleanup, "", ...r.limitations, ""].join("\n");
}
export function renderDefenderCheckHtml(value) {
  const r = checked(value);
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>${escape(r.title)}</title><style>
body{font:16px/1.6 system-ui,sans-serif;background:#eff3f7;color:#182c40;margin:0}main{max-width:850px;margin:auto;padding:32px 24px}h1{line-height:1.2}article,aside{background:white;padding:22px;border:1px solid #cbd8e4;border-radius:10px;margin:18px 0}h2{font-size:21px;margin:0}.label{color:#42596b;font-size:14px}dl{display:grid;grid-template-columns:1fr 1fr;gap:12px}dd{margin:0;font-weight:600}aside{border-left:5px solid #5f7890}footer{font-size:14px}@media print{body{background:white}article{break-inside:avoid}}
</style></head><body><main><p class="label">SECAPP · ЧАСТНЫЙ ОТЧЁТ · SensitiveSecurityData</p>
<h1>${escape(r.title)}</h1><article><h2>${escape(r.summary)}</h2>
<dl>${r.fields.map((f) => `<dt>${escape(f.title)}</dt><dd>${escape(f.value)}</dd>`).join("")}</dl>
<p>${escape(r.explanation)}</p><p>Серьёзность: ${escape(r.severity)}; уверенность: ${escape(r.confidence)}; статус: ${escape(r.status)}.</p></article>
<aside>${escape(r.cleanup)}</aside><section><h2>Границы проверки</h2><ul>${r.limitations.map((line) => `<li>${escape(line)}</li>`).join("")}</ul></section>
<footer>Velociraptor v0.77.3 · Локальный WMI · Повышение прав с подтверждением пользователя</footer>
</main></body></html>\n`;
}

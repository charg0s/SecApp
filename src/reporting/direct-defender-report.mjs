import { assertDefenderPreview } from "../backend/direct-defender-output.mjs";

const outcomes = Object.freeze({ Concern: "Требует внимания", NoConcernReported: "Замечание не выявлено", NotTested: "Не проверено" });
const severities = Object.freeze({ Info: "Информация", Low: "Низкая", Medium: "Средняя" });
const confidence = Object.freeze({ Possible: "Возможно", "Not detected": "Не выявлено", "Not tested": "Не проверено" });
const escape = (value) => String(value).replace(/[&<>"']/gu, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export function renderDefenderPreviewText(value) {
  const report = assertDefenderPreview(value);
  const lines = ["SecApp — разбор вывода Defender", ...report.limitations, ""];
  for (const row of report.checks) {
    lines.push(`${row.title}: ${outcomes[row.outcome]}`, row.explanation,
      `Серьёзность: ${severities[row.severity]}; уверенность: ${confidence[row.confidence]}; статус: требует проверки.`,
      `Ограничение: ${row.limitation}`, "");
  }
  lines.push(`SHA-256 переданных байтов: ${report.source_sha256}`,
    `SHA-256 отчёта: ${report.report_digest}`);
  return `${lines.join("\n")}\n`;
}

export function renderDefenderPreviewHtml(value) {
  const report = assertDefenderPreview(value);
  const rows = report.checks.map((row) => `<article><h2>${escape(row.title)}</h2>
<p class="status">${escape(outcomes[row.outcome])}</p><p>${escape(row.explanation)}</p>
<p>Серьёзность: ${escape(severities[row.severity])}; уверенность: ${escape(confidence[row.confidence])}; статус: требует проверки.</p>
<p class="muted">${escape(row.limitation)}</p></article>`).join("\n");
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>SecApp — разбор вывода Defender</title><style>
body{font:16px/1.6 system-ui,sans-serif;margin:0;color:#1d2e3b;background:#f2f5f7}main{max-width:900px;margin:auto;padding:32px 20px}h1{line-height:1.2}h2{font-size:19px;margin:0}article{background:white;padding:20px;margin:16px 0;border:1px solid #d5dfe7;border-radius:8px}.notice{border-left:4px solid #55758b;padding:12px 18px;background:#e4edf3}.status{font-weight:700}.muted,footer{font-size:14px;color:#485c6c}footer{overflow-wrap:anywhere}@media print{body{background:white}article{break-inside:avoid}}
</style></head><body><main><h1>Разбор вывода Defender</h1>
<div class="notice">Предварительный просмотр · SensitiveSecurityData. Проверка компьютера не выполнялась этим инструментом.</div>
${rows}<section><h2>Ограничения</h2><ul>${report.limitations.map((line) => `<li>${escape(line)}</li>`).join("")}</ul></section>
<footer>SHA-256 переданных байтов: ${escape(report.source_sha256)}<br>SHA-256 отчёта: ${escape(report.report_digest)}<br>Это частный предварительный отчёт, не AuditRun и не публичный экспорт.</footer>
</main></body></html>\n`;
}

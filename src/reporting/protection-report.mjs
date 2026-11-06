const OUTCOME_LABELS = Object.freeze({ Concern: "Требует внимания", NoConcernReported: "Замечание не выявлено", NotTested: "Не проверено" });
const COVERAGE_LABELS = Object.freeze({ Complete: "Все проверки имеют данные", Partial: "Неполное покрытие", NotTested: "Нет данных для оценки" });
const SEVERITY_LABELS = Object.freeze({ Info: "Информация", Low: "Низкая", Medium: "Средняя" });
const CONFIDENCE_LABELS = Object.freeze({ Possible: "Возможно", "Not detected": "Не выявлено", "Not tested": "Не проверено" });

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/gu, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}

export function renderProtectionText(report) {
  const lines = ["SecApp — защита Windows по импортированному снимку", COVERAGE_LABELS[report.assessment_status],
    `Требует внимания: ${report.counts.Concern}; без замечаний по правилу: ${report.counts.NoConcernReported}; не проверено: ${report.counts.NotTested}.`, ""];
  for (const check of report.checks) {
    lines.push(`${check.title}: ${OUTCOME_LABELS[check.outcome]}`, check.explanation,
      `Серьёзность: ${SEVERITY_LABELS[check.severity]}; уверенность: ${CONFIDENCE_LABELS[check.confidence]}; статус: требует проверки.`,
      `Ограничение: ${check.limitation}`);
    if (check.source) lines.push(`Наблюдение: ${check.source.observation_id}; время: ${check.source.observed_at}`);
    lines.push("");
  }
  lines.push(...report.limitations, `SHA-256 отчёта (JCS без report_digest): ${report.report_digest}`);
  return `${lines.join("\n")}\n`;
}

export function renderProtectionHtml(report) {
  const e = escapeHtml;
  const cards = report.checks.map((check) => {
    const tone = check.outcome === "Concern" ? "concern" : check.outcome === "NoConcernReported" ? "observed" : "unknown";
    return `<article class="check ${tone}"><div class="check-heading"><h2>${e(check.title)}</h2><span class="badge">${e(OUTCOME_LABELS[check.outcome])}</span></div>
<p>${e(check.explanation)}</p><dl><div><dt>Серьёзность</dt><dd>${e(SEVERITY_LABELS[check.severity])}</dd></div><div><dt>Уверенность</dt><dd>${e(CONFIDENCE_LABELS[check.confidence])}</dd></div><div><dt>Статус</dt><dd>Требует проверки</dd></div></dl>
<p class="muted">${e(check.limitation)}</p>${check.source ? `<details><summary>Источник наблюдения</summary><p>Время: <time>${e(check.source.observed_at)}</time></p><p>ID: <code>${e(check.source.observation_id)}</code></p><p>ObjectDigest: <code>${e(check.source.object_digest)}</code></p></details>` : ""}</article>`;
  }).join("\n");
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>SecApp — отчёт по защите Windows</title>
<style>
:root{color-scheme:light;--ink:#192936;--muted:#526675;--line:#dce3e8}*{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:var(--ink);font:16px/1.6 system-ui,sans-serif}main{max-width:1040px;margin:0 auto;padding:36px 24px 64px}.brand{font-size:13px;font-weight:700;letter-spacing:.14em;color:#33647c}h1{font-size:clamp(27px,4vw,40px);line-height:1.18;max-width:850px;margin:12px 0}h2{font-size:18px;margin:0}p{margin:12px 0}.muted{color:var(--muted);font-size:14px}.notice{border-left:4px solid #59788d;padding:12px 18px;background:#e8eff4;border-radius:0 8px 8px 0}.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:26px 0}.metric{padding:18px;background:#fff;border:1px solid var(--line);border-radius:12px}.metric strong{display:block;font-size:32px;line-height:1.3}.metric span{font-size:14px;color:var(--muted)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.check{padding:22px;background:white;border:1px solid var(--line);border-top:4px solid #8a9eaa;border-radius:12px}.check.concern{border-top-color:#bf7916}.check.observed{border-top-color:#4d7c9c}.check-heading{display:flex;gap:12px;align-items:flex-start;flex-wrap:wrap}.badge{font-size:12px;font-weight:600;padding:3px 8px;border-radius:5px;background:#eef2f5}.concern .badge{background:#fff0d8;color:#764700}dl{display:flex;flex-wrap:wrap;gap:12px 20px;margin:16px 0}dt{font-size:12px;color:var(--muted)}dd{font-size:14px;margin:0;font-weight:600}details{font-size:13px;border-top:1px solid var(--line);padding-top:12px}summary{cursor:pointer;color:#315d79}code{overflow-wrap:anywhere;font-size:12px}.limitations{margin-top:30px;border-top:1px solid var(--line);padding-top:20px}.limitations li{margin:8px 0}footer{margin-top:25px;color:var(--muted);font-size:12px;overflow-wrap:anywhere}@media(max-width:700px){.grid,.summary{grid-template-columns:1fr}main{padding:24px 16px}.summary{gap:8px}.metric{padding:12px 18px}.metric strong{display:inline;margin-right:12px}}@media print{body{background:#fff}main{padding:0}.grid{display:block}.check{break-inside:avoid;margin-bottom:12px}details{display:block}footer{font-size:10px}}
</style></head><body><main><header><div class="brand">SECAPP / IMPORT-ONLY</div><h1>Защита Windows<br>по переданному снимку</h1><p class="muted">${e(COVERAGE_LABELS[report.assessment_status])} · профиль ${e(report.profile_id)} · версия ${e(report.profile_version)}</p>
<div class="notice">Частный отчёт · SensitiveSecurityData. SecApp оценивает переданные значения; компьютер не сканировался. Происхождение и актуальность снимка не подтверждены.</div></header>
<section class="summary" aria-label="Сводка"><div class="metric"><strong>${e(report.counts.Concern)}</strong><span>требует внимания</span></div><div class="metric"><strong>${e(report.counts.NoConcernReported)}</strong><span>без замечаний по правилу</span></div><div class="metric"><strong>${e(report.counts.NotTested)}</strong><span>не проверено</span></div></section>
<section class="grid" aria-label="Результаты проверок">${cards}</section><section class="limitations"><h2>Границы выводов</h2><ul>${report.limitations.map((value) => `<li>${e(value)}</li>`).join("")}</ul><p class="muted">Наблюдений вне профиля: ${e(report.ignored_observation_count)}. Правила ожидают независимой проверки.</p></section>
<footer>SHA-256 исходного файла: <code>${e(report.source_file_digest)}</code><br>SHA-256 отчёта (JCS без report_digest): <code>${e(report.report_digest)}</code><br>Это представление отдельного отчёта; оно не является AuditRun или публичным ExportManifest.</footer></main></body></html>\n`;
}

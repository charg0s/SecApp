// Pure command flow. Effects are supplied by the local CLI, never by CLI flags.
import { parseJsonObjectBytes } from "../import/import-json.mjs";
import { decodeDefenderControlResult } from "./defender-control-result.mjs";
import { createDefenderCheckReport, renderDefenderCheckText } from "../reporting/defender-check-report.mjs";

export const DEFENDER_BUILD_PINS = Object.freeze({
  source_sha256: "bbb16bf75a7bbc58db76d13df4ee5f68f304ad4d4935577fb59d5b85554bdc9e",
  workspace_sha256: "72775e4575cc0a530fa212647496992569ac5f420a32567e866b78cfa35842ff",
  manifest_sha256: "aca109275c7ac2ffca0f83f986685c172c4c46f50e3a45d2d8fdd1b3827191af"
});
export const DEFENDER_CHECK_USAGE = "SecApp: npm run check:defender\n"
  + "Интерактивная проверка двух полей Microsoft Defender через Velociraptor.\n"
  + "Нужны обычный терминал Windows, подтверждение сбора и затем UAC.\n"
  + "--help ничего не собирает. Автоматическое подтверждение не поддерживается.\n";
const buildKeys = ["kind", "run_id", "executed", "source_sha256", "workspace_sha256", "manifest_sha256", "helper_sha256"];
const runKeys = ["kind", "run_id", "helper_exit_confirmed", "helper_exit_code", "data_files_removed", "workspace_removed", "result_json"];
const discardKeys = ["kind", "run_id", "data_files_removed", "workspace_removed"];
const sameKeys = (row, keys) => JSON.stringify(Object.keys(row).sort()) === JSON.stringify([...keys].sort());
const fail = () => { throw new Error("DEFENDER_CHECK_FAILED"); };

function payload(transport, limit, codes = [0]) {
  if (!transport || transport.closed !== true || transport.overflow !== false
      || transport.timedOut !== false || transport.aborted !== false || transport.ioError !== false || transport.signal !== null
      || !codes.includes(transport.code) || !Buffer.isBuffer(transport.stdout)
      || !Buffer.isBuffer(transport.stderr) || transport.stderr.length !== 0 || transport.stdout.length > limit) fail();
  return parseJsonObjectBytes(transport.stdout, { maxJsonBytes: limit, maxJsonDepth: 2 }).records[0].value;
}
export function decodeDefenderBuild(transport) {
  const row = payload(transport, 2048);
  if (!sameKeys(row, buildKeys) || row.kind !== "SecAppDefenderBuildV1" || row.executed !== false
      || typeof row.run_id !== "string" || !/^[0-9a-f]{32}$/u.test(row.run_id)
      || typeof row.helper_sha256 !== "string" || !/^[0-9a-f]{64}$/u.test(row.helper_sha256)
      || Object.entries(DEFENDER_BUILD_PINS).some(([key, value]) => row[key] !== value)) fail();
  return Object.freeze({ ...row });
}
export function decodeDefenderRunEnvelope(transport, build) {
  const row = payload(transport, 16384, [0, 1]);
  if (!sameKeys(row, runKeys) || row.kind !== "SecAppDefenderRunEnvelopeV1" || row.run_id !== build.run_id
      || row.helper_exit_confirmed !== true || row.helper_exit_code !== 0 || typeof row.data_files_removed !== "boolean"
      || row.workspace_removed !== false || typeof row.result_json !== "string"
      || Buffer.byteLength(row.result_json, "utf8") > 8192
      || (row.data_files_removed ? transport.code !== 0 : transport.code !== 1)) fail();
  return Object.freeze({ reading: decodeDefenderControlResult(Buffer.from(row.result_json, "utf8"), build.run_id),
    dataFilesRemoved: row.data_files_removed, workspaceRemoved: false });
}
function acceptedDiscard(transport, build) {
  const row = payload(transport, 1024);
  return sameKeys(row, discardKeys) && row.kind === "SecAppDefenderDiscardV1" && row.run_id === build.run_id
    && row.data_files_removed === true && row.workspace_removed === false;
}
export function defenderConfirmation(build) {
  return `СОБРАТЬ ${build.run_id.slice(0, 8)}`;
}
function directory(build) { return `C:\\Dev\\SecApp-Control-${build.run_id}`; }
function offer(build, desktop) {
  return ["\nСостав проверки:",
    "  AMRunningMode — режим Microsoft Defender.",
    "  RealTimeProtectionEnabled — включена ли защита в реальном времени.",
    "Источник: только локальный WMI Microsoft Defender. Полный аудит не выполняется.",
    "Повышение прав: только локальный помощник SecApp и Velociraptor v0.77.3.",
    "UAC может показать неизвестного издателя у локально собранного помощника.",
    "Административные права технически шире чтения; это не read-only sandbox.",
    desktop ? "Источник Velociraptor в журнале Windows должен уже существовать; окно его не регистрирует."
      : "Разрешённый побочный эффект: регистрация источника Velociraptor в журнале Windows",
    "Обычная стартовая запись остаётся побочным эффектом (включая возможный источник .NET Runtime).",
    "Системные настройки защиты не меняются; службы, исправления, перезагрузка",
    "и сетевая коллекция не выполняются. Политику пересылки журналов Windows не меняем.",
    "Лимит helper: 30 с, аварийный watchdog: 40 с; stdout: 4096 байт, Job: 512 MiB.",
    "Общий таймер CLI для ожидания UAC/контроллера: 180 с; это не гарантия остановки kernel I/O.",
    `Новый закрытый каталог: ${directory(build)}`,
    `SHA-256 помощника: ${build.helper_sha256}`,
    desktop ? "Результат показывается в окне; HTML сохраняется только по отдельному нажатию. Автоэкспорта нет."
      : "Результат выводится в этот терминал (он может сохранять scrollback). Автоэкспорта нет.",
    "После подтверждённого успеха удаляются файлы данных; каталог и пустой controller.lock остаются.",
    `Для ОДНОГО сбора этих двух полей введите: ${defenderConfirmation(build)}`,
    "Любой другой ответ, EOF или 120 с без подтверждения — отмена. Затем потребуется UAC.", ""].join("\n");
}

export async function runDefenderCheckCommand(args, io) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) return 1;
  if (args.length === 1 && args[0] === "--help") { io.stdout(DEFENDER_CHECK_USAGE); return 0; }
  if (args.length !== 0) { io.stderr("DEFENDER_CHECK_ARGUMENTS\n" + DEFENDER_CHECK_USAGE); return 1; }
  if (io.platform !== "win32" || io.interactive !== true) {
    io.stderr("Нужен обычный интерактивный терминал Windows; перенаправленный ввод не считается согласием.\n");
    return 1;
  }
  return runDefenderCheckSession(io);
}

// Shared single-operation workflow. The desktop owns its own explicit input gate;
// it does not spoof the CLI's TTY check or pass an automatic confirmation flag.
export async function runDefenderCheckSession(io) {
  let build, runStarted = false, discardAttempted = false;
  const say = (text) => io.stdout(text);
  const warn = (text) => { try { io.stderr(text); } catch { /* Broken terminal: no raw exception. */ } };
  async function discard() {
    discardAttempted = true;
    io.phase?.("Discarding");
    if (!acceptedDiscard(await io.discard(build), build)) fail();
    say(`Подготовленные данные удалены. Служебный каталог и пустой lock сохранены: ${directory(build)}\n`);
  }
  try {
    io.phase?.("Preparing");
    say("SecApp: подготовка одной проверки Defender. Пока сбор не запускается.\n"
      + "Будут созданы новая закрытая папка C:\\Dev\\SecApp-Control-<id>, локальная сборка\n"
      + "помощника и проверенная копия уже полученного Velociraptor. Скачивания нет.\n");
    build = decodeDefenderBuild(await io.prepare());
    io.phase?.("AwaitingConfirmation");
    say(offer(build, io.presentation === "desktop"));
    const answer = await io.prompt();
    if (typeof answer !== "string" || answer.length > 64 || answer !== defenderConfirmation(build)) {
      await discard();
      say("Отменено: Velociraptor не запускался.\n");
      return 3;
    }
    runStarted = true; // No subsequent code path can retry or discard-as-unstarted.
    io.phase?.("Running");
    say("Подтвердите UAC для SecAppDefenderControl.exe. Ожидание результата…\n");
    const result = decodeDefenderRunEnvelope(await io.run(build), build);
    const report = createDefenderCheckReport(result.reading, { dataFilesRemoved: result.dataFilesRemoved });
    io.report?.(report);
    say(renderDefenderCheckText(report));
    if (!result.dataFilesRemoved) {
      warn(`Очистка данных не подтверждена; проверьте закрытый каталог: ${directory(build)}\n`);
      return 1;
    }
    say(`Временные данные удалены. Каталог и пустой controller.lock сохранены: ${directory(build)}\n`);
    return result.reading.preview.checks[0].outcome === "NotTested" ? 2 : 0;
  } catch {
    if (build && !runStarted && !discardAttempted) {
      try { await discard(); } catch { /* Never retry a failed discard. */ }
    }
    warn("DEFENDER_CHECK_FAILED: успешная проверка не подтверждена; повторного запуска нет.\n");
    warn(build ? `Очистку/завершение процессов не предполагайте. Рабочий каталог: ${directory(build)}\n`
      : "Подготовка не подтверждена; её новый закрытый каталог мог сохраниться.\n");
    return 1;
  }
}

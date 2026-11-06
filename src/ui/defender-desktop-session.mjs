import { parseJsonObjectBytes } from "../import/import-json.mjs";
import { runDefenderCheckSession } from "../backend/defender-interactive-flow.mjs";
import { renderDefenderCheckHtml, renderDefenderCheckText } from "../reporting/defender-check-report.mjs";

export const DESKTOP_INTRO = [
  "Одна проверка Microsoft Defender через Velociraptor v0.77.3.",
  "Только AMRunningMode и RealTimeProtectionEnabled. Это не поиск всех угроз.",
  "1. Подготовить — создать новую закрытую рабочую папку, собрать помощник и проверить копию backend.",
  "2. Прочитать точный состав и ввести одноразовую фразу. Затем лично подтвердить UAC.",
  "3. Посмотреть результат; при желании отдельно сохранить частный HTML-отчёт.",
  "Никаких скачиваний, фонового сбора или изменения настроек защиты.",
  "Требуется уже зарегистрированный источник журнала Velociraptor; окно не создаёт и не исправляет его.",
  "Рабочая Windows считается доверенной. Внешний носитель не делает её ответы независимыми.",
  "Во время подготовки/сбора/очистки дождитесь завершения. Повторного запуска в этом окне нет."
].join("\n\n");

export function decodeDesktopCommand(bytes) {
  const row = parseJsonObjectBytes(bytes, { maxJsonBytes: 256, maxJsonDepth: 2 }).records[0].value;
  const expected = row.action === "confirm" ? ["action", "answer"] : ["action"];
  if (JSON.stringify(Object.keys(row).sort()) !== JSON.stringify(expected)
      || !["ready", "prepare", "confirm", "cancel"].includes(row.action)
      || (row.action === "confirm" && (typeof row.answer !== "string" || row.answer.length > 64))) {
    throw new Error("DESKTOP_COMMAND_INVALID");
  }
  return row;
}

// No handles, arbitrary queries, paths or executable arguments cross this boundary.
// Commands are state-bound, single-use and never queued as a later consent.
export function createDefenderDesktopSession({ executor, emit, schedule = setTimeout, unschedule = clearTimeout }) {
  let state = "Connecting", connected = true, resolvePrompt, timer, task = Promise.resolve(), result;
  let log = "", code = null;
  const publish = () => {
    if (!connected) return;
    try {
      emit({ kind: "SecAppDesktopStateV1", state, text: log, code,
        reportText: result ? renderDefenderCheckText(result) : null,
        reportHtml: result ? renderDefenderCheckHtml(result) : null });
    } catch { connected = false; finishPrompt(null); }
  };
  const append = (text) => {
    if (typeof text !== "string" || log.length + text.length > 18000) throw new Error("DESKTOP_OUTPUT_LIMIT");
    log += text; publish();
  };
  const finishPrompt = (answer) => {
    if (!resolvePrompt) return;
    const resolve = resolvePrompt; resolvePrompt = undefined;
    unschedule(timer); timer = undefined;
    // Disable the consent controls synchronously, before the workflow continues.
    state = "Submitting"; publish(); resolve(answer);
  };
  const start = () => {
    log = "";
    task = runDefenderCheckSession({ ...executor, presentation: "desktop", stdout: append, stderr: append,
      phase: (value) => { state = value; publish(); },
      report: (report) => { result = report; },
      prompt: () => new Promise((resolve) => {
        resolvePrompt = resolve;
        timer = schedule(() => finishPrompt(null), 120000);
        if (!connected) finishPrompt(null);
      })
    }).then((exitCode) => { code = exitCode; state = exitCode === 1 ? "Failed" : "Finished"; publish(); });
  };
  return Object.freeze({
    command(command) {
      // Revalidate even internal callers; external JSON is decoded before this.
      const row = decodeDesktopCommand(Buffer.from(JSON.stringify(command)));
      if (!connected) return false;
      if (row.action === "ready" && state === "Connecting") {
        state = "Ready"; log = DESKTOP_INTRO; publish(); return true;
      }
      if (row.action === "prepare" && state === "Ready") { start(); return true; }
      if (state === "AwaitingConfirmation" && resolvePrompt && ["confirm", "cancel"].includes(row.action)) {
        finishPrompt(row.action === "confirm" ? row.answer : null); return true;
      }
      return false;
    },
    disconnect() {
      connected = false;
      // Before run: finish preparation and discard. After run: retain the owner
      // until its existing bounded completion, never kill an elevated tree here.
      finishPrompt(null);
    },
    settled: () => task,
    exitCode: () => code,
    state: () => state
  });
}

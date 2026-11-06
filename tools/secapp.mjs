import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createDefenderControllerExecutor } from "./lib/defender-control-executor.mjs";
import { createDefenderDesktopSession } from "../src/ui/defender-desktop-session.mjs";
import { createDesktopCommandReader } from "./lib/defender-desktop-transport.mjs";

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "--help") {
  console.log("SecApp: npm start\nЛокальное окно проверки Defender. Подготовка по кнопке; сбор только после фразы и UAC.\nСохранение HTML — отдельное действие. Открытие окна ничего не собирает.");
} else if (args.length || process.platform !== "win32" || process.env.SystemRoot?.toLowerCase() !== "c:\\windows") {
  console.error("SECAPP_DESKTOP_ARGUMENTS_OR_PLATFORM: нужен поддерживаемый Windows; параметры запуска не принимаются.");
  process.exitCode = 1;
} else {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const windowScript = fileURLToPath(new URL("ui/Show-DefenderWindow.ps1", import.meta.url));
  const env = { SystemRoot: "C:\\Windows", WINDIR: "C:\\Windows",
    PSModulePath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules" };
  for (const key of ["USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP"]) if (typeof process.env[key] === "string") env[key] = process.env[key];
  // No shell, ExecutionPolicy bypass, runas, TCP listener or automatic backend run.
  const child = spawn("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-File", windowScript],
    // This child is the user-facing window, not a hidden background helper.
    { cwd: root, env, windowsHide: false, shell: false, stdio: ["pipe", "pipe", "pipe"] });
  let broken = false, ended = false;
  const session = createDefenderDesktopSession({ executor: createDefenderControllerExecutor(), emit(message) {
    if (broken) return;
    const line = Buffer.from(JSON.stringify(message) + "\n", "utf8");
    if (line.length > 65536 || child.stdin.writableLength + line.length > 262144) { disconnect(); return; }
    child.stdin.write(line);
  } });
  function disconnect() {
    if (broken) return;
    broken = true; session.disconnect(); child.stdin.destroy();
    // Closing this pipe makes the ordinary window fail closed. The existing
    // controller owns any consented operation and is allowed to finish cleanup.
  }
  const reader = createDesktopCommandReader((command) => session.command(command), disconnect);
  child.stdout.on("data", reader.receive);
  child.stdout.on("error", disconnect); child.stdin.on("error", disconnect);
  child.stderr.on("data", disconnect); child.stderr.on("error", disconnect);
  child.on("error", disconnect);
  const interrupt = () => disconnect();
  process.on("SIGINT", interrupt); process.on("SIGTERM", interrupt);
  child.once("close", async (code) => {
    if (ended) return;
    ended = true; reader.end(); const wasBroken = broken; disconnect();
    await session.settled();
    process.removeListener("SIGINT", interrupt); process.removeListener("SIGTERM", interrupt);
    process.exitCode = wasBroken || code !== 0 ? 1 : (session.exitCode() ?? 0);
    if (wasBroken || code !== 0) console.error("SECAPP_DESKTOP_CLOSED: окно/канал завершились с ошибкой; автоматического повтора нет.");
  });
}

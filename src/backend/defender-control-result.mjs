// Pure decoder of the helper's bounded local transport, not an execution authority.
import { parseJsonObjectBytes } from "../import/import-json.mjs";
import { createDefenderPreview } from "./direct-defender-output.mjs";

const keys = ["kind", "run_id", "outcome", "error", "backend_created", "backend_resumed", "backend_exit",
  "root_exited", "job_empty", "pipes_closed", "elapsed_ms", "stdout_base64"].sort();
const flags = ["backend_created", "backend_resumed", "root_exited", "job_empty", "pipes_closed"];
const readings = new WeakSet();
const fail = (code) => { throw new Error(code); };
export function decodeDefenderControlResult(bytes, expectedRunId) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 8192 || typeof expectedRunId !== "string"
      || !/^[0-9a-f]{32}$/u.test(expectedRunId)) fail("CONTROL_RESULT_INPUT");
  let row;
  try { row = parseJsonObjectBytes(bytes, { maxJsonBytes: 8192, maxJsonDepth: 2 }).records[0].value; }
  catch { fail("CONTROL_RESULT_JSON"); }
  if (JSON.stringify(Object.keys(row).sort()) !== JSON.stringify(keys)
      || row.kind !== "SecAppDefenderControlV1" || row.run_id !== expectedRunId) fail("CONTROL_RESULT_BINDING");
  if (flags.some((key) => typeof row[key] !== "boolean") || !Number.isSafeInteger(row.elapsed_ms)
      || row.elapsed_ms < 0 || row.elapsed_ms >= 40000 || typeof row.stdout_base64 !== "string"
      || row.stdout_base64.length > 5464) fail("CONTROL_RESULT_SHAPE");
  if (row.outcome !== "Completed" || row.error !== "NONE" || row.backend_exit !== 0
      || flags.some((key) => row[key] !== true)) fail("CONTROL_EXECUTION_NOT_COMPLETED");
  // Node's base64 decoder is permissive: require exact canonical encoding as well.
  const raw = Buffer.from(row.stdout_base64, "base64");
  if (raw.length > 4096 || raw.toString("base64") !== row.stdout_base64) { raw.fill(0); fail("CONTROL_RESULT_BASE64"); }
  let preview;
  try { preview = createDefenderPreview(raw); }
  catch { fail("CONTROL_RESULT_OUTPUT"); }
  finally { raw.fill(0); }
  const reading = Object.freeze({
    kind: "DefenderControlResultReading",
    authority: "HelperReportedNotAttested",
    run_id: expectedRunId,
    elapsed_ms: row.elapsed_ms,
    execution_context: "ExplicitlyConfirmedElevatedControl",
    preview
  });
  readings.add(reading);
  return reading;
}

export function assertDefenderControlReading(reading) {
  if (!readings.has(reading)) fail("CONTROL_READING_INVALID");
  return reading;
}

export function renderDefenderControlReading(reading) {
  // No caller-defined report/strings enter output. The preview renderer is not
  // relabelled as an accepted AuditRun or cryptographically attested collection.
  if (!readings.has(reading)) fail("CONTROL_READING_INVALID");
  const mode = { Active: "Активный", Passive: "Пассивный", Unknown: "Неизвестен" };
  const realtime = { Enabled: "Включена", Disabled: "Выключена", Unknown: "Неизвестно" };
  const finding = { NoConcernReported: "По этим двум показателям замечание не выявлено.",
    Concern: "Выявлено состояние, требующее внимания.", NotTested: "Недостаточно данных: проверка не засчитана." };
  const report = reading.preview;
  const outcome = report.checks[0].outcome;
  if (!Object.hasOwn(mode, report.normalized.mode) || !Object.hasOwn(realtime, report.normalized.real_time_protection)
      || !Object.hasOwn(finding, outcome)) fail("CONTROL_READING_INVALID");
  return ["SecApp — результат контрольного запуска Velociraptor",
    "Помощник сообщил об успешном завершении и остановке собственного процесса.",
    "Этот разбор файла сам по себе не подтверждает происхождение результата.",
    `Режим Defender: ${mode[report.normalized.mode]}.`,
    `Защита в реальном времени: ${realtime[report.normalized.real_time_protection]}.`,
    finding[outcome], "Это не полный аудит и не подтверждение безопасности компьютера.", ""].join("\n");
}

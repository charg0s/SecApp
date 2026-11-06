import { parseArgs } from "node:util";
import { planBackendLaunch, LaunchPlanInputError } from "../../src/backend/launch-plan.mjs";

const HELP = `SecApp backend launch planner (NO EXECUTION)

Usage:
  node tools/plan-backend-launch.mjs --operation <Version|Help> [options]

Options:
  --timeout-ms <integer>         Lower the 10000 ms ceiling
  --max-stdout-bytes <integer>   Lower the 65536 byte ceiling
  --max-stderr-bytes <integer>   Lower the 65536 byte ceiling
  --json                        Emit one JSON plan
  --help                        Show this help

No binary is opened, verified, or executed. No host data is collected.
The historical v0.77.1 pin is not a current file trust decision.
This plan is not an execution authority. Technical launch gates remain open.
No --force, executable path, custom arguments, VQL, config, or artifact input.
Exit codes: 0 help; 2 valid but blocked plan; 64 invalid arguments; 1 internal error.
`;

export function runBackendPlanCommand(argv) {
  let json = Array.isArray(argv) && argv.includes("--json");
  try {
    const { values, tokens } = parseArgs({
      args: argv, strict: true, allowPositionals: false, tokens: true,
      options: {
        operation: { type: "string" }, "timeout-ms": { type: "string" },
        "max-stdout-bytes": { type: "string" }, "max-stderr-bytes": { type: "string" },
        json: { type: "boolean" }, help: { type: "boolean" }
      }
    });
    json = values.json === true;
    const names = tokens.filter((token) => token.kind === "option").map((token) => token.name);
    if (new Set(names).size !== names.length || (values.help && names.length !== 1)) throw new LaunchPlanInputError();
    if (values.help) return { exitCode: 0, output: HELP };
    const limits = {};
    for (const [flag, field] of [["timeout-ms", "timeout_ms"], ["max-stdout-bytes", "stdout_limit_bytes"], ["max-stderr-bytes", "stderr_limit_bytes"]]) {
      if (values[flag] !== undefined) {
        if (!/^[1-9][0-9]*$/u.test(values[flag])) throw new LaunchPlanInputError();
        limits[field] = Number(values[flag]);
      }
    }
    const plan = planBackendLaunch({ operation: values.operation, limits });
    const output = json ? `${JSON.stringify(plan)}\n` : [
      "SecApp: план запуска Velociraptor (без выполнения)",
      `Операция: ${plan.operation}; release: ${plan.backend_pin.release}`,
      `Аргументы: ${JSON.stringify(plan.command_template.argv)}`,
      `Лимиты: ${plan.limits.timeout_ms} ms; stdout ${plan.limits.stdout_limit_bytes} B; stderr ${plan.limits.stderr_limit_bytes} B`,
      "Разработка разрешена; выполнение заблокировано техническими требованиями.",
      "Бинарник не открывался, не проверялся и не запускался.",
      ...plan.blockers.map((item) => `${item.id}: ${item.description}`),
      `Дополнительные обязательные условия: ${plan.required_before_launch.join(", ")}`,
      `SHA-256 плана (JCS без plan_digest): ${plan.plan_digest}`, ""
    ].join("\n");
    return { exitCode: 2, output };
  } catch (error) {
    const inputError = error instanceof LaunchPlanInputError || error?.code?.startsWith("ERR_PARSE_ARGS_");
    const code = inputError ? "LAUNCH_PLAN_INPUT_INVALID" : "LAUNCH_PLAN_INTERNAL_ERROR";
    const message = inputError ? "Invalid launch-plan arguments. Use --help." : "Launch planning failed without exposing request details.";
    return { exitCode: inputError ? 64 : 1, output: json ? `${JSON.stringify({ status: "Rejected", error: { code, message }, execution_enabled: false })}\n` : `${code}: ${message}\n` };
  }
}

import { runBackendPlanCommand } from "./lib/backend-plan-command.mjs";

const result = runBackendPlanCommand(process.argv.slice(2));
process.stdout.write(result.output);
process.exitCode = result.exitCode;

import { runDefenderCheckCommand } from "../src/backend/defender-interactive-flow.mjs";
import { createDefenderControllerExecutor } from "./lib/defender-control-executor.mjs";
import { readDefenderConfirmation } from "./lib/defender-console.mjs";

const cancellation = new AbortController();
let streamFailed = false;
const abort = () => cancellation.abort();
process.on("SIGINT", abort); process.on("SIGTERM", abort);
process.stdin.on("error", abort);
for (const stream of [process.stdout, process.stderr]) stream.on("error", () => { streamFailed = true; abort(); });
const executor = createDefenderControllerExecutor({ signal: cancellation.signal });
try {
  const code = await runDefenderCheckCommand(process.argv.slice(2), {
    platform: process.platform,
    interactive: process.stdin.isTTY === true && process.stdout.isTTY === true && process.stderr.isTTY === true,
    stdout: (text) => { if (streamFailed) throw new Error("TERMINAL_CLOSED"); process.stdout.write(text); },
    stderr: (text) => { if (!process.stderr.destroyed) process.stderr.write(text); },
    prompt: () => readDefenderConfirmation(process.stdin, process.stdout, { signal: cancellation.signal }),
    ...executor
  });
  process.exitCode = streamFailed ? 1 : code;
} catch { process.exitCode = 1; }
finally { process.removeListener("SIGINT", abort); process.removeListener("SIGTERM", abort); process.stdin.removeListener("error", abort); }

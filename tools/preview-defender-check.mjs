import { runDefenderPreviewCommand } from "./lib/defender-preview-command.mjs";

let streamFailed = false;
const failStream = () => { streamFailed = true; process.exitCode = 1; };
// Pipe failures are asynchronous: do not emit a raw Node stack or retry a broken stream.
process.stdout.on("error", failStream);
process.stderr.on("error", failStream);
try {
  const code = await runDefenderPreviewCommand(process.argv.slice(2), {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text)
  });
  process.exitCode = streamFailed ? 1 : code;
} catch {
  process.exitCode = 1;
  if (!process.stderr.destroyed) process.stderr.write("DEFENDER_PREVIEW_FAILED\n");
}

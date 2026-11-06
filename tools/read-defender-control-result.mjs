// Local result reader only. Never starts a helper/backend or requests elevation.
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { decodeDefenderControlResult, renderDefenderControlReading } from "../src/backend/defender-control-result.mjs";
let streamFailed = false;
for (const stream of [process.stdout, process.stderr]) stream.on("error", () => { streamFailed = true; process.exitCode = 1; });
try {
  if (process.platform !== "win32" || process.argv.length !== 4 || process.argv[2] !== "--run-id"
      || !/^[0-9a-f]{32}$/u.test(process.argv[3])) throw new Error("CONTROL_READER_ARGUMENTS");
  const root = "C:\\Dev"; // Fixed development workspace, not an input-controlled path.
  const source = path.join(root, `SecApp-Control-${process.argv[3]}`, "result.json");
  for (let current = source; ; current = path.dirname(current)) {
    const stat = await lstat(current);
    if (stat.isSymbolicLink() || (current === source ? !stat.isFile() : !stat.isDirectory())) throw new Error("CONTROL_READER_PATH");
    if (path.dirname(current) === current) break;
  }
  const file = await open(source, "r");
  let reading;
  try {
    if ((await file.stat()).size > 8192) throw new Error("CONTROL_RESULT_INPUT");
    const buffer = Buffer.alloc(8193); let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (!bytesRead) break; length += bytesRead;
    }
    reading = decodeDefenderControlResult(buffer.subarray(0, length), process.argv[3]);
    buffer.fill(0);
  } finally { await file.close(); }
  process.stdout.write(renderDefenderControlReading(reading));
  if (!streamFailed) process.exitCode = reading.preview.checks[0].outcome === "NotTested" ? 2 : 0;
} catch {
  if (!process.stderr.destroyed) process.stderr.write("CONTROL_RESULT_REJECTED\n");
  process.exitCode = 1;
}

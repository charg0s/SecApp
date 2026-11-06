import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { assertLocalSourcePath } from "../../src/import/import-path-policy.mjs";
import { createDefenderPreview, DefenderOutputError, DEFENDER_OUTPUT_LIMITS } from "../../src/backend/direct-defender-output.mjs";
import { renderDefenderPreviewHtml, renderDefenderPreviewText } from "../../src/reporting/direct-defender-report.mjs";

const USAGE = "Usage: node tools/preview-defender-check.mjs --input <local-file> [--format text|html]\nThis reads supplied output only; it never runs Velociraptor.\n";
const fail = (code) => { throw new DefenderOutputError(code); };

async function readBoundedLocalFile(selected) {
  const source = path.resolve(selected);
  try { assertLocalSourcePath(source); } catch { fail("DEFENDER_SOURCE_PATH"); }
  // Check every existing ancestor, not only the leaf. This is not a same-user race proof.
  let cursor = source;
  for (;;) {
    const info = await lstat(cursor);
    if (info.isSymbolicLink()) fail("DEFENDER_SOURCE_LINK");
    if (cursor === source ? !info.isFile() : !info.isDirectory()) fail("DEFENDER_SOURCE_TYPE");
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  const canonical = await realpath(source);
  try { assertLocalSourcePath(canonical); } catch { fail("DEFENDER_SOURCE_PATH"); }
  const file = await open(canonical, constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW));
  try {
    const info = await file.stat();
    if (!info.isFile()) fail("DEFENDER_SOURCE_TYPE");
    if (info.size > DEFENDER_OUTPUT_LIMITS.maxSourceBytes) fail("DEFENDER_OUTPUT_TOO_LARGE");
    const buffer = Buffer.alloc(DEFENDER_OUTPUT_LIMITS.maxSourceBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > DEFENDER_OUTPUT_LIMITS.maxSourceBytes) fail("DEFENDER_OUTPUT_TOO_LARGE");
    return buffer.subarray(0, length);
  } finally { await file.close(); }
}

export async function runDefenderPreviewCommand(args, io) {
  try {
    if (!Array.isArray(args) || args.length > 4 || args.some((arg) => typeof arg !== "string" || arg.length > 4096)) fail("DEFENDER_ARGUMENTS");
    if (args.length === 1 && args[0] === "--help") { io.stdout(USAGE); return 0; }
    let input, format = "text", formatSeen = false;
    for (let i = 0; i < args.length; i += 2) {
      if (args[i] === "--input" && input === undefined && args[i + 1]) input = args[i + 1];
      else if (args[i] === "--format" && !formatSeen && ["text", "html"].includes(args[i + 1])) { format = args[i + 1]; formatSeen = true; }
      else fail("DEFENDER_ARGUMENTS");
    }
    if (!input || /[\u0000-\u001f\u007f]/u.test(input) || /^[\\/]{2}/u.test(input)
      || (process.platform === "win32" && /^(?:[A-Za-z]:(?![\\/])|[\\/](?![\\/]))/u.test(input))) fail("DEFENDER_ARGUMENTS");
    const report = createDefenderPreview(await readBoundedLocalFile(input));
    const rendered = format === "html" ? renderDefenderPreviewHtml(report) : renderDefenderPreviewText(report);
    io.stdout(rendered);
    return report.checks[0].outcome === "NotTested" ? 2 : 0;
  } catch (error) {
    io.stderr(`${error instanceof DefenderOutputError ? error.code : "DEFENDER_PREVIEW_FAILED"}\n`);
    return 1;
  }
}

import { runImportCommand } from "./lib/import-command.mjs";

process.stdout.on("error", () => { process.exitCode = 1; });
try {
  const { exitCode, output } = await runImportCommand(process.argv.slice(2));
  process.exitCode = exitCode;
  process.stdout.write(output);
} catch {
  process.exitCode = 1;
  process.stderr.write("IMPORT_CLI_INTERNAL_ERROR: import command failed.\n");
}

import path from "node:path";
import { parseArgs } from "node:util";
import { importAuditPackage } from "../../src/import/audit-package-importer.mjs";
import { assertLocalSourcePath } from "../../src/import/import-path-policy.mjs";
import { resolveImportLimits } from "../../src/import/import-limits.mjs";
import { isImportError } from "../../src/import/import-errors.mjs";
import { renderProtectionText, renderProtectionHtml } from "../../src/reporting/protection-report.mjs";

const HELP = `SecApp reference import CLI

Usage:
  node tools/import-audit-package.mjs --source <local-file> [options]

Options:
  --kind <Auto|JsonObject|JsonLines|AuditPackageZip>  Default: Auto
  --max-source-bytes <positive-integer>             Lower the 64 MiB limit
  --require-final-lf                              Require final LF in JSONL
  --json                                          Emit one JSON result
  --assess windows-protection-v1                   Evaluate supplied observations
  --html                                          Emit a private HTML assessment
  --help                                          Show this help

Input: SecApp v1 contracts or a restricted manifest-based audit ZIP.
Default output: summary only; no source paths or imported field values.
Exit codes: 0 accepted/help, 2 rejected/unsupported, 64 invalid arguments,
            1 unavailable validation infrastructure or internal error.
Plain import checks contracts without assessment. --assess evaluates only
the supplied snapshot; its text/JSON/HTML output is SensitiveSecurityData,
not a public export. --html requires --assess and excludes --json.
No files are written by this command. Origin/freshness are not established.
Automatic backend execution remains disabled.
`;

async function defaultValidatorLoader() {
  const { createImportReferenceValidator } = await import("./import-reference-validator.mjs");
  return createImportReferenceValidator();
}

async function defaultAssessmentLoader(referenceValidator) {
  const { createProtectionAssessment } = await import("./protection-assessment.mjs");
  return createProtectionAssessment(referenceValidator);
}

function parseCommand(argv, cwd) {
  const { values, tokens } = parseArgs({
    args: argv,
    strict: true,
    allowPositionals: false,
    tokens: true,
    options: {
      source: { type: "string" },
      kind: { type: "string" },
      "max-source-bytes": { type: "string" },
      "require-final-lf": { type: "boolean" },
      json: { type: "boolean" },
      assess: { type: "string" },
      html: { type: "boolean" },
      help: { type: "boolean" }
    }
  });
  const names = tokens.filter((token) => token.kind === "option").map((token) => token.name);
  if (new Set(names).size !== names.length) throw new Error("Duplicate option.");
  if (values.help) {
    if (names.length !== 1) throw new Error("Help cannot be combined with an import.");
    return { help: true };
  }
  if (!values.source || /^[\\/]{2}/u.test(values.source)
    || (process.platform === "win32" && /^[A-Za-z]:(?![\\/])/u.test(values.source))) {
    throw new Error("Explicit local source required.");
  }
  if ((values.assess !== undefined && values.assess !== "windows-protection-v1")
    || (values.html && (!values.assess || values.json))) throw new Error("Invalid assessment format or profile.");
  const sourcePath = path.resolve(cwd, values.source);
  assertLocalSourcePath(sourcePath);
  const expectedPackageKind = values.kind ?? "Auto";
  if (!["Auto", "JsonObject", "JsonLines", "AuditPackageZip"].includes(expectedPackageKind)) throw new Error("Unknown package kind.");
  const limits = {};
  if (values["max-source-bytes"] !== undefined) {
    if (!/^[1-9][0-9]*$/u.test(values["max-source-bytes"])) throw new Error("Invalid byte limit.");
    limits.maxSourceBytes = Number(values["max-source-bytes"]);
  }
  if (values["require-final-lf"]) limits.jsonlFinalLf = "Required";
  resolveImportLimits(limits);
  return { sourcePath, expectedPackageKind, limits, json: values.json === true, assess: values.assess, html: values.html === true };
}

function failure(code, stage, message) {
  return {
    import_result_version: 1,
    status: "Rejected",
    error: { code, stage, message },
    summary: { integrity_claim: "NotEstablished", provenance_claim: "NotEstablished" }
  };
}

function render(result, json) {
  const report = { ...result, validation_scope: "ImportContractChecks", assessment_status: "NotPerformed" };
  if (json) return `${JSON.stringify(report)}\n`;
  const lines = [`SecApp import: ${result.status}`];
  if (result.status === "Accepted") {
    lines.push(`Format: ${result.package_kind}`, `Objects: ${result.summary.imported_object_count}`);
    for (const [kind, count] of Object.entries(result.summary.contract_counts)) lines.push(`  ${kind}: ${count}`);
    lines.push(`Integrity: ${result.summary.integrity_claim}`);
  } else lines.push(`Error: ${result.error.code}`, result.error.message);
  lines.push("Scope: import contract checks", "Security assessment: not performed", "Provenance: not established");
  return `${lines.join("\n")}\n`;
}

export async function runImportCommand(argv, { cwd = process.cwd(), loadReferenceValidator = defaultValidatorLoader, loadAssessment = defaultAssessmentLoader } = {}) {
  let command;
  try {
    command = parseCommand(argv, cwd);
  } catch {
    const result = failure("IMPORT_CLI_ARGUMENTS_INVALID", "Prepare", "Invalid command arguments. Use --help for supported options.");
    return { exitCode: 64, output: render(result, argv.includes("--json")) };
  }
  if (command.help) return { exitCode: 0, output: HELP };
  let referenceValidator;
  try {
    referenceValidator = await loadReferenceValidator();
    if (typeof referenceValidator !== "function") throw new Error("Missing validation function.");
  } catch {
    const result = failure("IMPORT_CLI_VALIDATOR_UNAVAILABLE", "Schema", "The pinned local reference validator could not be initialized.");
    return { exitCode: 1, output: render(result, command.json) };
  }
  let assess;
  if (command.assess) {
    try {
      assess = await loadAssessment(referenceValidator);
      if (typeof assess !== "function") throw new Error("Missing assessment function.");
    } catch {
      return { exitCode: 1, output: render(failure("ASSESSMENT_VALIDATOR_UNAVAILABLE", "Schema", "The local assessment schemas could not be initialized."), command.json) };
    }
  }
  const result = await importAuditPackage({ ...command, privacyMode: command.assess ? "Private" : "SummaryOnly", referenceValidator });
  if (result.status === "Accepted" && assess) {
    try {
      const report = await assess(result);
      return { exitCode: 0, output: command.json ? `${JSON.stringify(report)}\n` : command.html ? renderProtectionHtml(report) : renderProtectionText(report) };
    } catch (error) {
      const controlled = isImportError(error) ? failure(error.code, error.stage, error.message)
        : failure("ASSESSMENT_INTERNAL_ERROR", "Assessment", "Assessment failed without exposing source details.");
      return { exitCode: isImportError(error) ? 2 : 1, output: render(controlled, command.json) };
    }
  }
  return { exitCode: result.status === "Accepted" ? 0 : 2, output: render(result, command.json) };
}

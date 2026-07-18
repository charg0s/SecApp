import { dependencyVersions } from "./schema-registry.mjs";
import { FIXTURE_KINDS, TOOL_VERSION } from "./constants.mjs";
import { compareUnicodeCodeUnits } from "./order.mjs";

export function createResult(tool) {
  return {
    tool,
    tool_version: TOOL_VERSION,
    node_version: process.version,
    dependency_versions: dependencyVersions(),
    schema_count: 0,
    vector_count: 0,
    passed: 0,
    failed: 0,
    skipped_by_fixture_kind: Object.fromEntries(FIXTURE_KINDS.map((kind) => [kind, 0])),
    errors: []
  };
}

export function finish(result, details = {}) {
  Object.assign(result, details);
  result.errors.sort((left, right) => compareUnicodeCodeUnits(JSON.stringify(left), JSON.stringify(right)));
  return result;
}

export function emit(result) {
  if (process.argv.includes("--json")) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write(`${result.tool}: ${result.failed === 0 ? "PASS" : "FAIL"}; schemas=${result.schema_count}; vectors=${result.vector_count}; passed=${result.passed}; failed=${result.failed}\n`);
    for (const error of result.errors) {
      const subject = error.vector_id ?? error.schema_id ?? "gate";
      process.stderr.write(`- ${error.error_code}: ${subject}: ${error.message}\n`);
    }
  }
  process.exitCode = result.failed === 0 ? 0 : 1;
}

import { types } from "node:util";
import { digestWithExclusion } from "../../tools/lib/jcs.mjs";

function freeze(value) {
  if (value && typeof value === "object") {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

// Historical compatibility identity, not verification of any currently installed file.
export const BACKEND_PIN = freeze({
  release: "v0.77.1",
  source_commit: "3137c7f714ab344dd37d0df1d5393573e41b30a5",
  asset_name: "velociraptor-v0.77.1-windows-amd64.exe",
  sha256: "c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e",
  size_bytes: 70375416,
  openpgp_fingerprint: "0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1"
});

export const LAUNCH_BLOCKERS = freeze([
  { id: "TL-ADJACENT-DLL", description: "Adjacent DLL placement remains possible in the execution directory." },
  { id: "TL-LINKED-TOKEN", description: "The restricted child retains linked-token metadata." },
  { id: "TL-NON-ELEVATED-MECHANISM", description: "An acceptable production non-elevated launch mechanism is not selected." },
  { id: "TL-REPARSE-REPLACEMENT", description: "Protection against reparse replacement is not proven." },
  { id: "TL-INITIAL-INVENTORY", description: "Initial module inventory before resume is not completed." },
  { id: "TL-PREVENTIVE-LOAD-POLICY", description: "Runtime module observation is not a preventive loader policy." },
  { id: "TL-UNKNOWN-MODULES", description: "Four historical runtime modules remain Unknown." },
  { id: "TL-IMAGE-BYTE-BINDING", description: "Verified source bytes are not proven to be the mapped process image." },
  { id: "TL-PRODUCTION-LOAD-CONTEXT", description: "A production-safe DLL/image-load context is not implemented." }
]);

const OPERATIONS = freeze({
  Version: ["--nobanner", "--nocolor", "version"],
  Help: ["--nobanner", "--nocolor", "--help"]
});
export const LAUNCH_LIMITS = freeze({ timeout_ms: 10000, stdout_limit_bytes: 65536, stderr_limit_bytes: 65536 });

export class LaunchPlanInputError extends Error {
  constructor() {
    super("Invalid launch-plan request; only registered diagnostics and lowering-only limits are accepted.");
    this.name = "LaunchPlanInputError";
    this.code = "LAUNCH_PLAN_INPUT_INVALID";
  }
}

function invalid() { throw new LaunchPlanInputError(); }

function assertDataObject(value, allowedKeys) {
  if (!value || typeof value !== "object" || types.isProxy(value) || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== "string" || !allowedKeys.includes(key) || !descriptor.enumerable || !("value" in descriptor)) invalid();
  }
}

// This complete planning function deliberately has no executor, path input, IO,
// readiness callback, or authority token. Its output can never authorize resume.
export function planBackendLaunch(request) {
  assertDataObject(request, ["operation", "limits"]);
  if (!Object.hasOwn(request, "operation") || typeof request.operation !== "string"
    || !Object.hasOwn(OPERATIONS, request.operation)) invalid();
  const limits = { ...LAUNCH_LIMITS };
  if (Object.hasOwn(request, "limits")) {
    assertDataObject(request.limits, Object.keys(LAUNCH_LIMITS));
    for (const [key, value] of Object.entries(request.limits)) {
      if (!Number.isSafeInteger(value) || value < 1 || value > LAUNCH_LIMITS[key]) invalid();
      limits[key] = value;
    }
  }
  const plan = {
    schema_version: "1.0.0",
    plan_kind: "BackendLaunchPlan",
    privacy_class: "Public",
    status: "Blocked",
    reason: "LAUNCH_PREREQUISITES_UNRESOLVED",
    development_authorized: true,
    execution_enabled: false,
    production_launcher: "NotImplemented",
    operation: request.operation,
    backend_pin: { ...BACKEND_PIN },
    binary_verification: "NotPerformed",
    provenance_claim: "NotEstablished",
    command_template: {
      argv: [...OPERATIONS[request.operation]],
      shell: false,
      stdin: "Closed",
      working_directory: "PrivateRunDirectory",
      environment: "ReviewedAllowlistOnly",
      elevation: "Forbidden"
    },
    limits,
    blockers: LAUNCH_BLOCKERS.map((item) => ({ ...item, status: "Open" })),
    required_before_launch: [
      "ReviewedNativeSupervisor",
      "CurrentBinaryTrustVerification",
      "PrivateRunStoragePolicy",
      "ReviewedOfflineEnforcement",
      "BoundedOutputAndTreeCleanup",
      "ExactActionAuthorization",
      "IndependentLaunchReview"
    ],
    plan_digest: ""
  };
  plan.plan_digest = digestWithExclusion(plan, "plan_digest");
  return freeze(plan);
}

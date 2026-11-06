// Pure integration policy and bounded output gate. NO process creation or admission.
import { createDefenderPreview, DEFENDER_QUERY_CANDIDATE, DEFENDER_OUTPUT_LIMITS } from "./direct-defender-output.mjs";

const freeze = (value) => {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
};

// Fixed private working-file name, never a user-selected config. A future host must
// create/lock these exact bytes before launch and bind its verified working dir.
// FileLoader precedes Embedded/EnvLiteral/NullLoader in the pinned main.go chain.
// An empty environment variable alone does NOT override an embedded config.
export const DIRECT_DEFENDER_OPERATION = freeze({
  id: DEFENDER_QUERY_CANDIDATE.id,
  sourceRevision: DEFENDER_QUERY_CANDIDATE.sourceRevision,
  executionAdmission: "NotAccepted",
  candidateAsset: {
    release: "v0.77.3",
    platform: "windows-amd64",
    size: 73422840,
    sha256: "3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32",
    manifest: "highestAvailable"
  },
  applicationName: "ExplicitAuthenticatedAbsolutePathRequired",
  argv0: "velociraptor",
  arguments: [
    "--config", "secapp-empty.config.yaml", "--nocolor",
    "query", "--format", "jsonl", "--timeout", "15", DEFENDER_QUERY_CANDIDATE.query
  ],
  workingConfig: { name: "secapp-empty.config.yaml", utf8: "{}\n" },
  environment: {
    strategy: "ConstructFromEmpty",
    allowedNames: ["SystemRoot", "WINDIR", "TEMP", "TMP"],
    values: "NativeResolvedWindowsDirectoryAndOwnedPrivateWorkingDirectoryRequired"
  },
  limits: {
    stdoutBytes: DEFENDER_OUTPUT_LIMITS.maxSourceBytes,
    stderrBytesAccepted: 0,
    wallTimeMs: 30000,
    cleanupGraceMs: 3000,
    activeBackendProcesses: 1,
    jobMemoryBytes: 536870912
  },
  effects: {
    collection: "TwoLocalDefenderStateFieldsOnly",
    configuration: "OwnedEmptyWorkingFileOnly",
    eventLog: "StartupArgvEventAttempt",
    // D-063: only the pinned startup source/values; no repair or elevated retry.
    eventSourceRegistration: "AllowedPinnedStartupAttempt",
    network: "NotAuthorized",
    elevation: "Forbidden",
    protectionSettings: "NoChanges"
  },
  unresolved: [
    "ActualStandardCreationAndHighestAvailableCompatibility",
    "RemainingStartupEffectsBeyondAllowedEventLogging",
    "FixedConfigAndOfflineComposition",
    "OwnedCreationTimeJobAndCancellation",
    "AuthenticatedPrivateImageAndWorkingContext"
  ]
});

export class DirectDefenderOperationError extends Error {
  constructor(code) {
    super(code);
    this.name = "DirectDefenderOperationError";
    this.code = code;
  }
}

const abortCodes = new Map([
  ["Cancelled", "DIRECT_CANCELLED"],
  ["TimedOut", "DIRECT_TIMED_OUT"],
  ["LaunchFailed", "DIRECT_LAUNCH_FAILED"],
  ["CleanupFailed", "DIRECT_CLEANUP_FAILED"],
  ["TransportFailed", "DIRECT_TRANSPORT_FAILED"]
]);

// Caller events are NOT trusted native evidence. Even a successful sequence only
// returns the existing supplied-output preview, never a live/verified report.
// A future owner must enforce OS limits, kill/settle the job, authenticate the
// source and independently bind confirmation. This gate cannot authorize launch.
export function createDirectDefenderOutputGate() {
  let storage = Buffer.alloc(DEFENDER_OUTPUT_LIMITS.maxSourceBytes);
  let length = 0, stdoutEnded = false, stderrEnded = false, completed = false;
  let firstFailure = null;
  const clear = () => { storage.fill(0); storage = Buffer.alloc(0); length = 0; };
  const reject = (code) => {
    firstFailure ??= code;
    clear();
    throw new DirectDefenderOperationError(firstFailure);
  };
  const active = () => {
    if (firstFailure) reject(firstFailure);
    if (completed) reject("DIRECT_ALREADY_COMPLETED");
  };
  const bytes = (chunk) => {
    if (!Buffer.isBuffer(chunk)) reject("DIRECT_CHUNK_INVALID");
  };
  return Object.freeze({
    stdout(chunk) {
      active(); bytes(chunk);
      if (stdoutEnded) reject("DIRECT_STDOUT_AFTER_END");
      if (chunk.length > storage.length - length) reject("DIRECT_STDOUT_LIMIT");
      chunk.copy(storage, length);
      length += chunk.length;
    },
    stderr(chunk) {
      active(); bytes(chunk);
      if (stderrEnded) reject("DIRECT_STDERR_AFTER_END");
      // Do not retain, display, sanitize, or whitelist arbitrary backend messages.
      if (chunk.length !== 0) reject("DIRECT_STDERR_PRESENT");
    },
    endStdout() {
      active();
      if (stdoutEnded) reject("DIRECT_STDOUT_DUPLICATE_END");
      stdoutEnded = true;
    },
    endStderr() {
      active();
      if (stderrEnded) reject("DIRECT_STDERR_DUPLICATE_END");
      stderrEnded = true;
    },
    abort(reason) {
      active();
      reject(abortCodes.get(reason) ?? "DIRECT_ABORT_REASON_INVALID");
    },
    complete(exitCode) {
      active();
      if (!Number.isInteger(exitCode) || exitCode < 0 || exitCode > 0xffffffff) {
        reject("DIRECT_EXIT_INVALID");
      }
      if (exitCode !== 0) reject("DIRECT_EXIT_NONZERO");
      if (!stdoutEnded || !stderrEnded) reject("DIRECT_STREAMS_INCOMPLETE");
      completed = true;
      try {
        const preview = createDefenderPreview(storage.subarray(0, length));
        return Object.freeze({ disposition: "SuppliedOutputOnly", preview });
      } catch {
        reject("DIRECT_OUTPUT_INVALID");
      } finally {
        clear();
      }
    }
  });
}

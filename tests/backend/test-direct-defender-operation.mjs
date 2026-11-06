import test from "node:test";
import assert from "node:assert/strict";
import { createDirectDefenderOutputGate, DIRECT_DEFENDER_OPERATION as operation } from "../../src/backend/direct-defender-operation.mjs";
import { DEFENDER_QUERY_CANDIDATE } from "../../src/backend/direct-defender-output.mjs";

const normal = Buffer.from('{"AMRunningMode":"Normal","RealTimeProtectionEnabled":true}\n');
const errorCode = (code) => (error) => error.code === code && error.message === code;
const close = (gate) => { gate.endStdout(); gate.endStderr(); return gate.complete(0); };

test("fixed operation is deeply immutable and has no runtime admission", () => {
  const check = (value) => {
    if (value && typeof value === "object") {
      assert.ok(Object.isFrozen(value));
      Object.values(value).forEach(check);
    }
  };
  check(operation);
  assert.equal(operation.executionAdmission, "NotAccepted");
  assert.equal(operation.candidateAsset.size, 73422840);
  assert.equal(operation.candidateAsset.sha256, "3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32");
  assert.equal(operation.candidateAsset.manifest, "highestAvailable");
  assert.deepEqual(operation.arguments, ["--config", "secapp-empty.config.yaml", "--nocolor", "query", "--format", "jsonl", "--timeout", "15", DEFENDER_QUERY_CANDIDATE.query]);
  assert.deepEqual(operation.workingConfig, { name: "secapp-empty.config.yaml", utf8: "{}\n" });
  assert.deepEqual(operation.environment.allowedNames, ["SystemRoot", "WINDIR", "TEMP", "TMP"]);
  assert.equal(operation.environment.strategy, "ConstructFromEmpty");
  assert.equal(operation.argv0, "velociraptor");
  assert.ok(operation.unresolved.length > 0);
  assert.throws(() => operation.arguments.push("--api_config"), TypeError);
});

test("candidate limits and effects are fixed, not OS enforcement claims", () => {
  assert.deepEqual(operation.limits, { stdoutBytes: 4096, stderrBytesAccepted: 0, wallTimeMs: 30000,
    cleanupGraceMs: 3000, activeBackendProcesses: 1, jobMemoryBytes: 536870912 });
  assert.equal(operation.effects.network, "NotAuthorized");
  assert.equal(operation.effects.elevation, "Forbidden");
  assert.equal(operation.effects.protectionSettings, "NoChanges");
  assert.equal(operation.effects.eventSourceRegistration, "AllowedPinnedStartupAttempt");
});

test("D-063 logging consent is not broader effects or runtime admission", () => {
  assert.equal(operation.executionAdmission, "NotAccepted");
  assert.equal(operation.effects.elevation, "Forbidden");
  assert.equal(operation.effects.network, "NotAuthorized");
  assert.equal(operation.effects.protectionSettings, "NoChanges");
  assert.ok(operation.unresolved.includes("RemainingStartupEffectsBeyondAllowedEventLogging"));
  assert.ok(operation.unresolved.includes("ActualStandardCreationAndHighestAvailableCompatibility"));
  assert.ok(operation.unresolved.includes("FixedConfigAndOfflineComposition"));
  assert.throws(() => { operation.effects.elevation = "Allowed"; }, TypeError);
  assert.throws(() => { operation.executionAdmission = "Accepted"; }, TypeError);
});

test("successful byte-by-byte sequence remains an unverified supplied preview", () => {
  const gate = createDirectDefenderOutputGate();
  for (const byte of normal) gate.stdout(Buffer.from([byte]));
  gate.stderr(Buffer.alloc(0));
  const result = close(gate);
  assert.ok(Object.isFrozen(result));
  assert.equal(result.disposition, "SuppliedOutputOnly");
  assert.equal(result.preview.collection_claim, "NotEstablished");
  assert.equal(result.preview.provenance_claim, "NotEstablished");
  assert.equal(result.preview.freshness_claim, "NotEvaluated");
  assert.equal(result.preview.checks[0].outcome, "NoConcernReported");
  assert.throws(() => gate.complete(0), errorCode("DIRECT_ALREADY_COMPLETED"));
});

test("chunks are copied, not retained as caller-mutable views", () => {
  const gate = createDirectDefenderOutputGate();
  const chunk = Buffer.from(normal);
  gate.stdout(chunk); chunk.fill(0);
  assert.equal(close(gate).preview.normalized.mode, "Active");
});

test("empty output after exit zero is NotTested", () => {
  const result = close(createDirectDefenderOutputGate());
  assert.equal(result.preview.assessment_status, "NotTested");
});

test("disabled protection remains a concern, not an execution error", () => {
  const gate = createDirectDefenderOutputGate();
  gate.stdout(Buffer.from(normal.toString().replace("true", "false")));
  assert.equal(close(gate).preview.checks[0].outcome, "Concern");
});

for (const [reason, code] of [["Cancelled", "DIRECT_CANCELLED"], ["TimedOut", "DIRECT_TIMED_OUT"],
  ["LaunchFailed", "DIRECT_LAUNCH_FAILED"], ["CleanupFailed", "DIRECT_CLEANUP_FAILED"],
  ["TransportFailed", "DIRECT_TRANSPORT_FAILED"], ["arbitrary private detail", "DIRECT_ABORT_REASON_INVALID"]]) {
  test(`${reason} cannot be hidden by valid stdout/exit zero`, () => {
    const gate = createDirectDefenderOutputGate(); gate.stdout(normal);
    assert.throws(() => gate.abort(reason), errorCode(code));
    assert.throws(() => gate.complete(0), errorCode(code));
    assert.throws(() => gate.stdout(normal), errorCode(code));
  });
}

for (const code of [1, 740, 1314, 0xffffffff]) {
  test(`nonzero exit ${code} rejects a normal row`, () => {
    const gate = createDirectDefenderOutputGate(); gate.stdout(normal); gate.endStdout(); gate.endStderr();
    assert.throws(() => gate.complete(code), errorCode("DIRECT_EXIT_NONZERO"));
    assert.throws(() => gate.complete(0), errorCode("DIRECT_EXIT_NONZERO"));
  });
}

for (const value of [undefined, null, "0", false, NaN, Infinity, -1, 0.5, 0x100000000]) {
  test(`invalid exit ${String(value)} is not success`, () => {
    const gate = createDirectDefenderOutputGate();
    assert.throws(() => gate.complete(value), errorCode("DIRECT_EXIT_INVALID"));
  });
}

for (const ends of [[], ["endStdout"], ["endStderr"]]) {
  test(`exit without both EOF events rejects (${ends.join(",")})`, () => {
    const gate = createDirectDefenderOutputGate(); gate.stdout(normal);
    for (const end of ends) gate[end]();
    assert.throws(() => gate.complete(0), errorCode("DIRECT_STREAMS_INCOMPLETE"));
  });
}

test("any stderr is fatal without echoing or storing its contents", () => {
  const gate = createDirectDefenderOutputGate(); gate.stdout(normal);
  assert.throws(() => gate.stderr(Buffer.from("PRIVATE diagnostic")), errorCode("DIRECT_STDERR_PRESENT"));
  assert.throws(() => gate.complete(0), errorCode("DIRECT_STDERR_PRESENT"));
});

for (const sizes of [[4097], [4096, 1], [1024, 1024, 1024, 1025]]) {
  test(`cumulative output bound rejects ${sizes.join("+")} before copying excess`, () => {
    const gate = createDirectDefenderOutputGate();
    assert.throws(() => sizes.forEach((size) => gate.stdout(Buffer.alloc(size))), errorCode("DIRECT_STDOUT_LIMIT"));
    assert.throws(() => gate.complete(0), errorCode("DIRECT_STDOUT_LIMIT"));
  });
}

test("exact buffer capacity is allowed but still needs valid bounded JSONL", () => {
  const gate = createDirectDefenderOutputGate(); gate.stdout(Buffer.alloc(4096, 32));
  assert.throws(() => close(gate), errorCode("DIRECT_OUTPUT_INVALID"));
});

for (const [append, end, lateCode, duplicateCode] of [
  ["stdout", "endStdout", "DIRECT_STDOUT_AFTER_END", "DIRECT_STDOUT_DUPLICATE_END"],
  ["stderr", "endStderr", "DIRECT_STDERR_AFTER_END", "DIRECT_STDERR_DUPLICATE_END"]
]) {
  test(`${append} after EOF rejects even an empty chunk`, () => {
    const gate = createDirectDefenderOutputGate(); gate[end]();
    assert.throws(() => gate[append](Buffer.alloc(0)), errorCode(lateCode));
  });
  test(`${append} duplicate EOF rejects`, () => {
    const gate = createDirectDefenderOutputGate(); gate[end]();
    assert.throws(() => gate[end](), errorCode(duplicateCode));
  });
  test(`${append} refuses string or typed-array coercion`, () => {
    for (const value of ["PRIVATE", new Uint8Array(1), null, undefined]) {
      const gate = createDirectDefenderOutputGate();
      assert.throws(() => gate[append](value), errorCode("DIRECT_CHUNK_INVALID"));
    }
  });
}

for (const [name, output] of [
  ["startup log prefix", Buffer.concat([Buffer.from("Error sending to the event log: PRIVATE\n"), normal])],
  ["truncated row", normal.subarray(0, -1)],
  ["extra row", Buffer.concat([normal, normal])],
  ["duplicate field", Buffer.from('{"AMRunningMode":"Normal","AMRunningMode":"Normal"}\n')],
  ["BOM", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), normal])]
]) {
  test(`${name} rejects; no filtering or recovery of a normal-looking row`, () => {
    const gate = createDirectDefenderOutputGate(); gate.stdout(output);
    assert.throws(() => close(gate), errorCode("DIRECT_OUTPUT_INVALID"));
  });
}

test("one gate failure does not contaminate a separate attempt", () => {
  const failed = createDirectDefenderOutputGate();
  assert.throws(() => failed.abort("Cancelled"), errorCode("DIRECT_CANCELLED"));
  const other = createDirectDefenderOutputGate(); other.stdout(normal);
  assert.equal(close(other).preview.checks[0].outcome, "NoConcernReported");
});

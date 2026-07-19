# Velociraptor compatibility probes

Status: development-only compatibility evidence; this directory does not
authorize or implement a production adapter.

The committed YAML and JSON files are deterministic and fully synthetic. No
Velociraptor executable, collection ZIP, raw stdout/stderr, certificate, host
identity, username, SID, address, process list, or other machine evidence may
be placed here.

`synthetic-artifact.yaml` returns exactly two constant rows and echoes one
string parameter. It does not read the filesystem, registry, network, process
list, or system identity and does not execute a process. The expected fixture
is the normalized result for `EchoValue=synthetic-echo`.

The dependency-free parser safety suites can be run without a Velociraptor
binary:

```text
node tools/compatibility/test-structured-output-probe.mjs
node tools/compatibility/test-zip-package-probe.mjs
node tools/compatibility/test-prelaunch-pe-policy.mjs
```

The binary-backed probe is intentionally not part of `npm test` or
`validate:all`. Run it only after separately approving official acquisition,
verifying the exact binary identity, and choosing a new output directory
outside the repository:

```text
node tools/compatibility/run-cli-contract-probes.mjs \
  --executable <absolute-verified-binary> \
  --expected-sha256 <approved-lowercase-sha256> \
  --run-root <new-external-directory> \
  --definitions <absolute-tests-compatibility-directory> \
  --network-monitor-script <absolute-observe-network-script>
```

The detached-signature accept/reject policy can be rechecked without executing
the binary:

```text
node tools/compatibility/test-openpgp-policy.mjs \
  --data <absolute-verified-binary> \
  --signature <absolute-detached-signature> \
  --keyring <absolute-fingerprint-selected-public-key> \
  --expected-fingerprint <40-hex-fingerprint> \
  --expected-sha256 <approved-lowercase-sha256>
```

The harness always uses `shell: false`, an argument array, fresh process-local
profile/temp directories, bounded streams, an external timeout, explicit
cancellation, and PID-scoped read-only network observation. Its
`RunAsInvoker` process environment is an observed v0.77.1 compatibility
workaround, not an accepted production elevation design.

See [the compatibility report](../../docs/velociraptor-adapter-compatibility.md)
for trust requirements, exact invocations, limitations, cleanup, and blockers.

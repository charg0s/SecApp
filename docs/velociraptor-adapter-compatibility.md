# Velociraptor CLI adapter compatibility experiment

Experiment: `VELOCIRAPTOR-ADAPTER-COMPAT1`

Status: `compatibility_partial_blockers_remain`

Date: 2026-07-19

This document records a development-only compatibility spike against one
verified Velociraptor release asset. It is not a production adapter, runtime
readiness declaration, updater policy, server design, or authorization to run
additional collectors. The required next gate is a separate
`VELOCIRAPTOR-ADAPTER-COMPAT-REVIEW1`.

## 1. Preflight

The experiment began offline at the accepted repository baseline:

| Check | Result |
|---|---|
| Branch | `main` |
| `HEAD` | `283da2e85dbdd7802308632aae29e4c2eea45400` |
| `origin/main` | `283da2e85dbdd7802308632aae29e4c2eea45400` |
| Initial working tree | Clean, including untracked files |
| `git diff --check` | Pass |
| Schemas | 21/21 |
| Contracts | 171/171 |
| Application rules | 178/178 |
| Digests | 123/123 |
| `npm.cmd ls --all` | No missing or extraneous dependency |

The baseline commit records that ARCH-REVIEW6 completed without blockers and
authorizes only this separate compatibility experiment. It does not authorize
full SecApp runtime implementation.

The experiment read `AGENTS.md`, `docs/velociraptor-integration.md`,
`docs/audit-parity-matrix.md`, `docs/architecture.md`,
`docs/threat-model.md`, `docs/integrity-model.md`, and
`docs/decision-log.md` before network or executable work.

The existing project pins remain distinct:

| Identity kind | Pin or observation | Meaning |
|---|---|---|
| Source/research pin | `3137c7f714ab344dd37d0df1d5393573e41b30a5` | Architecture/capability research only |
| Release tag | `v0.77.1` | Exact compatibility release; no “latest” claim |
| Windows runtime asset | `velociraptor-v0.77.1-windows-amd64.exe` | Selected official release asset |
| Observed runtime identity | version `0.77.1`, commit `3137c7f71`, Windows/amd64 | Output of the verified executable |
| Runtime file digest | `c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e` | Exact bytes tested |
| Authenticode identity | Rapid7 LLC; cache-only WinVerifyTrust success | Additional observed signer identity |

The research pin was confirmed in project files and independently resolved by
the official tag API. It was not assumed to authenticate a runtime binary.

## 2. Network authorization and pre-network plan

Before network use, the plan limited acquisition to official Velociraptor
project release metadata, one Windows AMD64 executable, and its official
verification artifacts. Storage was outside the repository under the current
user's local application-data compatibility cache. Planned reads were limited
to CLI help/version, the reviewed listening-port artifact, and constant
synthetic rows. Planned outputs were bounded stdout/stderr, one synthetic ZIP,
and dev-only metadata; raw machine output was scheduled for deletion. No step
required or requested administrative privileges.

The user separately authorized:

1. official release metadata reads;
2. download of exactly one official Windows binary and its verification
   artifact;
3. no other network actions.

The official project did not host a retrievable first-party copy of the
release signing key. Official documentation pinned its fingerprint but linked
to `keys.openpgp.org`. After the first-party repository, documentation tree,
and WKD checks did not yield a usable key, the user explicitly authorized one
exception: retrieving exactly that fingerprint from `keys.openpgp.org`. No
other network request was made under that exception.

## 3. Sources and acquisition record

Official project sources used:

- release API:
  `https://api.github.com/repos/Velocidex/velociraptor/releases/tags/v0.77.1`;
- tag-ref API:
  `https://api.github.com/repos/Velocidex/velociraptor/git/ref/tags/v0.77.1`;
- release asset API IDs `455074922` (executable) and `455074195`
  (detached signature);
- [official v0.77.1 release](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.1);
- [official downloads page](https://docs.velociraptor.app/downloads/), which
  pins the release signing fingerprint;
- [official source revision](https://github.com/Velocidex/velociraptor/tree/3137c7f714ab344dd37d0df1d5393573e41b30a5).

The separately authorized key retrieval was:

`https://keys.openpgp.org/vks/v1/by-fingerprint/0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1`

Acquisition metadata:

| Item | Recorded value |
|---|---|
| Release ID | `343212309` |
| Tag | `v0.77.1` |
| Target branch label | `v0.77-release` |
| Resolved source commit | `3137c7f714ab344dd37d0df1d5393573e41b30a5` |
| Published UTC | `2026-06-23T00:01:42Z` |
| Executable asset | `velociraptor-v0.77.1-windows-amd64.exe` |
| Executable asset ID | `455074922` |
| Executable size | 70,375,416 bytes |
| Published executable digest | `sha256:c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e` |
| Signature asset | `velociraptor-v0.77.1-windows-amd64.exe.sig` |
| Signature asset ID | `455074195` |
| Signature size | 438 bytes |
| Published signature digest | `sha256:378c07d0fa58b822869e02124e99a38ddaafd5eda69f7ba16b8e4be8737fa5b0` |
| Retrieval date | 2026-07-19 |

The release and tag API calls returned HTTP 200. Each GitHub asset request
returned HTTP 302 then 200 from `release-assets.githubusercontent.com`; the
recorded redirect paths were the GitHub production-release-asset paths, with
signed query values deliberately omitted. The downloads page and authorized
key request returned HTTP 200. No mirror, package manager, fork, cached binary,
or forum attachment was used.

## 4. Release, source, and runtime identity

The tag ref pointed directly to commit
`3137c7f714ab344dd37d0df1d5393573e41b30a5`. The verified runtime reported:

```text
name: velociraptor
version: 0.77.1
commit: 3137c7f71
build_time: "2026-06-22T15:35:00Z"
compiler: go1.25.3
system: windows
architecture: amd64
```

The release/source association, official asset digest, valid detached
signature over the exact executable, runtime version, and reported commit
prefix agree. This authenticates the tested official release asset; it is not
a reproducible-build proof.

## 5. Binary trust model and SHA-256

The executable was not run until all mandatory trust checks passed:

- exact file size: 70,375,416 bytes;
- SHA-256:
  `c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e`;
- exact match to the digest published in official GitHub release metadata;
- detached RSA/SHA-512 signature valid over all executable bytes;
- signature creation time `2026-06-22T16:12:51Z`;
- issuer fingerprint exactly
  `0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1`;
- the official downloads page pins that fingerprint to the Velociraptor Team
  release key;
- PE32+ AMD64 (`Machine=0x8664`), 12 sections;
- exact digest rechecked before and after every harness launch;
- only the ordinary `:$DATA` stream was present; there was no
  `Zone.Identifier` and none was manually removed or altered;
- no adjacent DLL was present, so the tested directory supplied no local DLL
  side-loading candidate.

A GitHub uploader key set for `scudette` was independently rejected because
its fingerprints did not equal the official documentation pin. The failed WKD
attempts were not bypassed: the dedicated WKD host did not resolve, and the
direct host presented a wrong TLS principal.

A post-cleanup offline policy suite accepted the original signature, rejected
a one-byte-mutated detached signature, and rejected a wrong expected
fingerprint. The executable was read but not executed by these negative tests.

Fail-closed rule: any absent official digest, digest mismatch, signature
mismatch, fingerprint mismatch, PE mismatch, or ambiguous source produces
`binary_trust_verification_failed` and forbids process creation.

## 6. Signature and Authenticode result

The detached OpenPGP result was `VALID`. The Authenticode result was
`VALID_OFFLINE_CACHE_ONLY_NO_REVOCATION`, with WinVerifyTrust result
`0x00000000`.

Primary signer:

- subject: `CN=Rapid7 LLC, O=Rapid7 LLC, L=Boston, S=Massachusetts, C=US`;
- SHA-1 certificate thumbprint:
  `8dd67269b148092ac5a14a4982c920c9fdca3b91`;
- offline chain: Rapid7 LLC → DigiCert Trusted G4 Code Signing RSA4096 SHA384
  2021 CA1 → DigiCert Trusted Root G4 → DigiCert Assured ID Root CA;
- chain built successfully with certificate downloads disabled and revocation
  mode `NoCheck`.

Timestamp:

- valid legacy counter-signature;
- time: `2026-06-22T15:37:08.0000000Z`;
- signer: DigiCert SHA256 RSA4096 Timestamp Responder 2025 1;
- timestamp signer SHA-1 thumbprint:
  `dd6230ac860a2d306bda38b16879523007fb417e`;
- timestamp chain built successfully offline.

No online revocation-status claim is made. Trust does not depend on
Authenticode alone: the official release digest and detached release signature
are mandatory independent checks.

## 7. Exact process and argument contract

Every binary launch used an absolute executable path, `shell: false`, ignored
stdin, a fresh empty working directory, hidden window, and a separate argument
array. No `cmd /c`, PowerShell expression evaluation, string-built command, or
shell interpolation was used.

The child environment was limited to `SystemRoot`, `WINDIR`, `TEMP`, `TMP`,
`USERPROFILE`, `HOME`, `APPDATA`, `LOCALAPPDATA`, `LANG=C`, `LC_ALL=C`,
`NO_COLOR=1`, and process-local `__COMPAT_LAYER=RunAsInvoker`. Profile, appdata,
local-appdata, and temp paths were fresh per run and outside the repository.

The executable manifest requests `highestAvailable`. On this admin-capable but
non-elevated token, default process creation failed before spawn with Node
`EACCES`/`-4092` from both LocalAppData and Temp. No elevation was requested.
Setting `__COMPAT_LAYER=RunAsInvoker` only in the child environment preserved
the current standard-user token and allowed launch. This compatibility shim is
an observed requirement, not an accepted production design.

Representative exact argument arrays, using path placeholders only:

```json
["--nobanner", "--nocolor", "--help"]
```

```json
["--nobanner", "--nocolor", "version"]
```

```json
["--nobanner", "--nocolor", "artifacts", "show", "Windows.Network.ListeningPorts"]
```

```json
[
  "--nobanner", "--nocolor", "--max_wait=1",
  "--tempdir=<fresh-run-temp>",
  "artifacts", "collect",
  "--timeout=10", "--progress_timeout=5", "--format=json",
  "--no-require_admin",
  "Windows.Network.ListeningPorts"
]
```

```json
[
  "--nobanner", "--nocolor", "--max_wait=1",
  "--tempdir=<fresh-run-temp>",
  "--definitions=<verified-definitions-directory>",
  "artifacts", "collect",
  "--timeout=10", "--progress_timeout=5", "--format=json",
  "--no-require_admin", "--args=EchoValue=synthetic-echo",
  "SecApp.Compatibility.Synthetic"
]
```

Global options precede the subcommand. Collection options precede the artifact
name. Each user value remains one process argument; no additional quoting layer
is accepted. Definitions and output paths must be absolute, digest-checked,
outside the binary directory, and prevalidated before launch.

## 8. CLI version and help contract

`--help` exited 0, emitted 3,624 valid UTF-8 bytes to stderr, and emitted no
stdout. `version` exited 0, emitted 143 valid UTF-8 bytes to stdout, and emitted
no stderr.

The actual command surface includes:

- `artifacts list`;
- `artifacts show`;
- `artifacts collect`;
- `artifacts verify`;
- `version`;
- global `--definitions`, `--nobanner`, `--nocolor`, `--tempdir`, and
  `--max_wait`;
- collection `--output`, `--timeout`, `--progress_timeout`, `--cpu_limit`,
  `--hard_memory_limit`, `--format`, `--args`, and
  `--[no-]require_admin`.

`--format` advertised `csv`, `json`, and `csv_only`. `--output` advertised a
ZIP container. No CLI cancellation switch was discovered; explicit
cancellation is an orchestrator process action.

Overwrite and postcondition rules are not safe by default: an existing ZIP was
silently replaced with exit 0, while an output path that was a directory
produced exit 0, empty stdout/stderr, and no package. The adapter contract must
create a new output path atomically and verify file type, existence, size,
digest, and ownership after process exit.

## 9. Built-in artifact result

The selected built-in was `Windows.Network.ListeningPorts`, which is present in
the accepted parity matrix. Before collection, `artifacts show` returned the
embedded definition with SHA-256
`977716dc186be67f503b69c93ba8617d52486123d10b4e9aa6059432fa793a16`.

Independent review confirmed that this pinned definition:

- uses `pslist()` and `netstat()`;
- filters `Status = 'LISTEN'`;
- joins process name/PID to address, family, port, and protocol;
- contains no artifact import/call, network plugin, EXECVE, registry access, or
  filesystem write;
- has no parameter or branch that expands scope;
- agrees with the definition assessed by the parity matrix.

The run used the standard-user token, a ten-second backend timeout, a
five-second progress timeout, a one-MiB stdout limit, a one-MiB stderr limit,
and a 1,024-record import limit. It completed in 288.891 ms with exit 0,
7,576 stdout bytes, empty stderr, and 43 rows. Raw values were treated as real
machine evidence and were never copied to Git.

The first attempt also supplied `--hard_memory_limit=536870912` and
`--cpu_limit=20`; it crashed before collection with exit 2 and a Go panic in
`NannyService.RegisterOnWarnings`. Isolation tests showed that
`--cpu_limit=20` succeeds, while `--hard_memory_limit=536870912` alone
reproduces the panic. The memory flag is therefore prohibited for this pin.

## 10. Custom artifact through `--definitions`

`tests/compatibility/synthetic-artifact.yaml` is a CLIENT artifact containing
only two constant dictionary rows and one echoed string parameter. It reads no
filesystem, registry, process, network, user identity, or system identity and
invokes no process. Its SHA-256 is
`0b93d5929c8612f60324e6ca41f4b4e4ef05053c5814ba33094d294192acf464`.

`artifacts verify --max_length=100000` succeeded, and `artifacts list` resolved
exactly `SecApp.Compatibility.Synthetic`. Two independent collections with
`EchoValue=synthetic-echo` each exited 0, emitted 441 stdout bytes, emitted no
stderr, and produced two rows in deterministic order.

Negative semantics observed:

| Case | Observed result |
|---|---|
| Missing definitions directory during collect | exit 1; stderr diagnostic |
| Missing file passed to `artifacts verify` | exit 0; no output |
| Malformed YAML passed to `artifacts verify` | exit 1; stdout and stderr diagnostic |
| Malformed VQL passed to `artifacts verify` | exit 1; stdout and stderr diagnostic |
| Malformed definitions directory during collect | exit 0; no rows or diagnostic |
| Unknown artifact during collect | exit 0; no rows or diagnostic |
| Unknown artifact through `artifacts show` | exit 1; stderr diagnostic |
| Duplicate names passed to `artifacts verify` | exit 0; no diagnostic |
| Duplicate names during collect | exit 0; later `b.yaml` definition selected |
| Known synthetic empty artifact | exit 0; empty stdout/stderr |

Consequently, file-existence checks, strict YAML/VQL verification, duplicate
name rejection, an exact `artifacts show` identity check, and expected-source
postconditions are mandatory. Exit code and empty stdout alone cannot
distinguish an unknown/malformed artifact from a valid zero-row collection.

## 11. Structured JSON import contract

The observed `--format=json` framing is not uniformly JSONL:

- the two-row custom run is one JSON array document with no final LF;
- the built-in run is five concatenated JSON array documents with no delimiter
  other than JSON document boundaries and no final LF;
- the result entry inside the ZIP is UTF-8 JSONL with a final LF;
- stdout contains data only for direct collection; ZIP mode stdout instead
  contains a small JSON status object naming the container;
- diagnostics remain on stderr for ordinary failures, but help text itself is
  written to stderr.

The dev-only bounded parser accepts a strict JSON document, strict JSONL, or a
sequence of complete object/array JSON documents. It rejects duplicate keys,
invalid UTF-8, BOM, malformed JSON, a partial final sequence document, excess
total/document/line bytes, excess records, and excess nesting. Fourteen
positive/negative parser cases pass. A syntactically complete JSONL final line
without LF is accepted but recorded as `final_line_terminated=false`; a source
truncation signal still controls whether lifecycle state is `Partial`.

Direct stdout normalization:

| Velociraptor field | Raw type | SecApp normalized field/type | Required / nullable | Privacy | Error behavior |
|---|---|---|---|---|---|
| `SchemaVersion` | string | `schema_version`: semantic-version string | required / non-null | Synthetic | mismatch → `ValidationError` |
| `SyntheticString` | string | `synthetic_string`: string | required / non-null | Synthetic | type/value mismatch → `ValidationError` |
| `SyntheticInteger` | number | `synthetic_integer`: safe integer | required / non-null | Synthetic | non-integer/out-of-range → `ValidationError` |
| `SyntheticBoolean` | boolean | `synthetic_boolean`: boolean | required / non-null | Synthetic | type mismatch → `ValidationError` |
| `RowOrder` | number | `row_order`: safe integer | required / non-null | Synthetic | missing/duplicate/order mismatch → `ValidationError` |
| `EchoValue` | string | `echo_value`: string | required / non-null | Synthetic | not exact parameter value → `ValidationError` |
| `_Source` | string | validated source identity | direct stdout required; absent in ZIP | OperationalMetadata | mismatch → `ValidationError`; ZIP derives it only from the validated entry name |

The built-in result's observed fields were all present and non-null in the test:

| Field | Raw/normalized type | Privacy class | Error behavior |
|---|---|---|---|
| `Address` | string | NetworkMetadata | invalid/missing → row rejection |
| `Family` | string | NetworkMetadata | unknown value → row rejection |
| `Name` | string | SystemMetadata | invalid/missing → row rejection |
| `Pid` | safe integer | SystemMetadata | non-integer/out-of-range → row rejection |
| `Port` | safe integer | NetworkMetadata | outside 0..65535 → row rejection |
| `Protocol` | string | NetworkMetadata | unknown value → row rejection |
| `_Source` | string | OperationalMetadata | exact artifact/source mismatch → collection rejection |

No production importer was written.

## 12. ZIP/package result

The pin supports ZIP output through `--output=<external-path>`. The synthetic
package run exited 0 and created a 2,718-byte ZIP. That individual run's raw
archive SHA-256 was
`3e99ccdcd6dad3a55aba14967e4b8ab550a920bd28a70552e896e2e3192f47f6`;
the archive is not a committed fixture and no byte determinism is claimed.

The bounded central-directory reader performed no filesystem extraction. It
validated local/central headers, bounds, methods, CRCs, names, duplicates,
case collisions, traversal, absolute/drive paths, backslashes, Unix symlink
metadata, entry count, individual/total expanded sizes, and compression ratio.
It found seven entries and 3,195 expanded bytes:

- `results/SecApp.Compatibility.Synthetic%2FRows.json.index`;
- `results/SecApp.Compatibility.Synthetic%2FRows.json`;
- `log.json.index`;
- `log.json`;
- `collection_context.json`;
- `requests.json`;
- `client_info.json`.

The result entry was two terminating-LF JSONL records. In-memory import
validated all six synthetic fields, derived source identity from the validated
entry name because package rows omit `_Source`, and produced normalized
SHA-256 `3de82c3b5dade1c41723f1a38a86f15e31e5986c39cfd54a326f16079ddc26cb`.

`client_info.json` contains host/FQDN/path/platform field names even for a
constant artifact. Therefore a real package is machine evidence and must use
private retention/cleanup rules; it is never a wholly synthetic fixture.

Fourteen synthetic archive safety cases pass, including duplicate/case-colliding
paths, absolute and traversal paths, backslashes, symlink metadata, count and
size limits, compression bomb ratio, bad CRC, and truncation.

## 13. Exit-code and CollectorExecution matrix

This mapping uses only existing `CollectorExecution` states and existing
`ErrorObject.code` values. Expected identity remains pinned by the command
contract. `backend_process` is absent in pre-execution states and required in
terminal states.

Identity representation is deterministic for every row: `BackendNotFound`
stores `expected_backend` and has no observed process; `PolicyRejected` stores
neither identity field because the accepted schema forbids them there, while
the expected identity remains available from the immutable collector/command
contract; every terminal state stores the exact tested identity in
`backend_process` and the schema forbids `expected_backend`. No rejected or
unspawned file is promoted to an observed backend identity.

| Scenario | State | Error code | `backend_process` | Retention | Retry |
|---|---|---|---:|---|---|
| Binary absent | `BackendNotFound` | `BackendNotFound` | no | none | after approved restore |
| Access denied before spawn | `PolicyRejected` | `PermissionDenied` | no | none | after launch-policy correction |
| Invalid PE | `PolicyRejected` | `BackendRejected` | no | none | no |
| Wrong architecture | `PolicyRejected` | `Unsupported` | no | none | approved compatible asset only |
| Version mismatch | `PolicyRejected` | `BackendRejected` | no | none | contract review only |
| Checksum/signature mismatch | `PolicyRejected` | `IntegrityError` | no | none | no |
| Invalid CLI argument | `Failed` | `ValidationError` | yes | bounded diagnostic | corrected contract only |
| Unknown artifact | `PolicyRejected` | `ValidationError` | no collection process | none | reviewed definition only |
| Malformed/duplicate definitions | `PolicyRejected` | `ValidationError` | no collection process | none | corrected definition only |
| Known collector returns no rows | `Succeeded` | none | yes | digests plus zero records | unnecessary |
| Malformed output | `Failed` | `ParseError` | yes | bounded private diagnostic if allowed | corrected bytes/contract only |
| Timeout | `TimedOut` | `Timeout` | yes | bounded diagnostic | policy-limited |
| Explicit cancellation | `Cancelled` | `Cancelled` | yes | bounded diagnostic | user/orchestrator decision |
| Process crash | `Failed` | `Internal` | yes | bounded diagnostic | no same-invocation retry |
| Unclassified nonzero exit | `Failed` | `Internal` | yes | bounded diagnostic | after classification |
| Valid complete prefix with known truncation | `Partial` | `ResourceLimit` | yes | complete validated records plus truncation marker | policy-limited |
| Invalid UTF-8 | `Failed` | `ParseError` | yes | digest/bounded private diagnostic | no for same bytes |
| Output over limit without complete prefix | `Failed` | `ResourceLimit` | yes | digest/bounded private diagnostic | policy-limited |
| Output destination unavailable | `Failed` | `ImportError` | yes | none | new destination only |

Prelaunch synthetic tests prove digest mismatch, invalid PE, and I386 mismatch
are rejected without attempting execution. CLI observations prove invalid
argument, silent unknown artifact, malformed definitions, empty rows, panic,
nonzero exit, timeout, cancellation, output limit, and unavailable output
semantics. Parser tests cover malformed bytes and valid/invalid partial framing.

## 14. Timeout and cancellation

Every collection carried backend `--timeout`, but no unreviewed sleep primitive
was used; expiration of Velociraptor's internal timer was therefore not tested.
The adapter contract must always enforce an independent external timeout.

The final harness behavior is:

- timeout and explicit cancellation are distinct reasons;
- immediate `child.kill()` was accepted and produced `SIGTERM`;
- bounded `taskkill /PID <pid> /T /F` was also invoked as a tree fallback;
- the target PID did not exist after close;
- stdout/stderr bytes after the termination request were both zero;
- cleanup waits are bounded;
- no Velociraptor orphan was observed.

The tested commands do not create descendants. A kill-on-close Windows Job
Object for arbitrary descendants was not implemented or proven and remains a
production blocker.

## 15. Command-injection result

Thirteen values were passed as the value portion of one `--args=EchoValue=...`
argument: spaces, single/double quotes, ampersand, pipe, semicolon, percent
syntax, PowerShell metacharacters, Unicode, leading dash, traversal text, 8,192
characters, newline, and a control character.

All thirteen exited 0 and were returned literally in both synthetic rows. No
working-directory file appeared, no shell was involved, and the harness
requested no second process. This proves literal argument transport for the
tested array-based path; it does not authorize arbitrary artifact names or
flags.

## 16. Network-activity observation

PID-scoped `Get-NetTCPConnection`/`Get-NetUDPEndpoint` polling ran during help,
version, built-in definition/collection, both deterministic custom runs, and
the later synthetic/error suite. The observer used no driver, firewall change,
administrator right, address capture, or unrelated-traffic capture.

Result: `NoNetworkActivityObservedDuringTest`.

Each short run had at least one 25 ms sample, both TCP/UDP observers were
available, and observer error count was zero. Polling can miss short-lived
attempts and is not a sandbox; `NetworkImpossible` is explicitly not claimed.

## 17. Determinism

| Item | SHA-256 / result |
|---|---|
| Binary | `c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e` |
| Definitions input | `0b93d5929c8612f60324e6ca41f4b4e4ef05053c5814ba33094d294192acf464` |
| Custom raw stdout run 1 | `e9c99221272bf4c9a41f255554c2279f4e4e090995f548a216fb7c812dc7504a` |
| Custom raw stdout run 2 | `e9c99221272bf4c9a41f255554c2279f4e4e090995f548a216fb7c812dc7504a` |
| Normalized stdout run 1 | `b06facbec0e35560648b6069d88e2948832a9d5bb4ce06b5cdc851aadca49c76` |
| Normalized stdout run 2 | `b06facbec0e35560648b6069d88e2948832a9d5bb4ce06b5cdc851aadca49c76` |
| Normalized package result | `3de82c3b5dade1c41723f1a38a86f15e31e5986c39cfd54a326f16079ddc26cb` |
| Compatibility contract fixture | `2fcc093c7270b299855007c147eaddf461f329bd332c19b0f7d631e4fa7bf1eb` |

Both direct runs had identical row count, order, schema/type mapping, values,
exit semantics, raw bytes, and normalized bytes. Package-level logs/context
contain volatile times and runtime metadata; raw ZIP byte identity is not
claimed.

## 18. Dev-only repository files

The experiment adds only:

- this report;
- `tests/compatibility/README.md`;
- `tests/compatibility/synthetic-artifact.yaml`;
- synthetic expected contract/normalization JSON;
- dependency-free compatibility probes under `tools/compatibility/`;
- minimal roadmap and decision-log status updates.

No binary, raw machine output, package, certificate, absolute local path,
hostname, username, token, dependency, production adapter, GUI, service,
agent, installer, updater, server, gRPC component, or remediation code is
added.

## 19. Cache, temporary locations, and cleanup

The retained local compatibility cache is represented as:

`%LOCALAPPDATA%\SecApp\compat\velociraptor\v0.77.1\`

It is outside Git and outside PATH. The verified executable may remain there
as an explicitly local compatibility cache. The detached signature and the
fingerprint-selected public key may remain beside verification metadata.

Cleanup removed all 459 files under the execution `%TEMP%` tree, including raw
runs, real built-in stdout, package ZIPs, malformed/duplicate definitions,
normalization rechecks, compiler scratch data, and the temporary executable
copy. Empty parent directories through `%TEMP%\SecApp` were also removed. Raw
HTTP headers/API pages, including signed redirect queries, all cache run/work
directories, and the rejected unrelated GitHub key were removed.

No Velociraptor process existed before or after cleanup. The retained cache now
contains exactly three files:

| Relative cache entry | Size | SHA-256 |
|---|---:|---|
| `bin\velociraptor-v0.77.1-windows-amd64.exe` | 70,375,416 | `c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e` |
| `verification\velociraptor-v0.77.1-windows-amd64.exe.sig` | 438 | `378c07d0fa58b822869e02124e99a38ddaafd5eda69f7ba16b8e4be8737fa5b0` |
| `verification\velociraptor-release-signing-key.asc` | 2,658 | `71f37f19312f543534f2eaadde63d1afe28ed2140c16fec85885f92597bbbee6` |

Cleanup made no ACL, registry, PATH, service, scheduled-task, firewall, or
system-setting change.

## 20. Existing validation result

After repository changes, the required commands are:

```text
npm.cmd test
npm.cmd run validate:all
npm.cmd ls --all
git diff --check
```

All four commands passed after cleanup. Both `npm.cmd test` and the separately
required `npm.cmd run validate:all` produced exactly 21/21 schemas, 171/171
contracts, 178/178 application rules, and 123/123 digests. `npm.cmd ls --all`
returned exit 0 with no missing/extraneous package, and `git diff --check`
passed.

The separate dev-only suites also passed: structured output 14/14, ZIP safety
14/14, prelaunch PE policy 3/3, and OpenPGP accept/tamper/fingerprint policy
3/3. The committed normalized fixture was re-derived from actual synthetic
stdout and matched byte-for-byte. These suites do not emit runtime-readiness
claims.

## 21. Compatibility blockers

1. `VR-COMPAT-001-HIGHESTAVAILABLE-LAUNCH-POLICY`: the official executable's
   `highestAvailable` manifest causes default non-elevated spawn to fail for an
   admin-capable user. The process-local `RunAsInvoker` shim worked but is not
   yet an accepted production launch boundary.
2. `VR-COMPAT-002-HARD-MEMORY-LIMIT-PANIC`: the v0.77.1
   `--hard_memory_limit` path reproducibly panics. A reviewed OS-level memory
   limit or upstream-fixed pin is required.
3. `VR-COMPAT-003-WINDOWS-JOB-OBJECT-NOT-PROVEN`: main-process termination and
   `/T` fallback leave no observed orphan, but kill-on-close Job Object
   containment for descendants is not proven.
4. `VR-COMPAT-004-SILENT-SUCCESS-REQUIRES-ADAPTER-PREFLIGHT-AND-POSTCONDITIONS`:
   collect/verify/output cases can return exit 0 with no diagnostic. A
   production adapter must implement strict definition uniqueness, artifact
   identity, and output postconditions before this can be accepted.

The OpenPGP key retrieval also depended on a separately authorized third-party
keyserver because the official project published the fingerprint but not a
retrievable first-party key. A production acquisition procedure should retain
or publish a reviewed key copy by fingerprint.

## 22. Proven and not proven

Proven for the exact tested bytes and environment:

- independent official digest, detached-signature, PE, and Authenticode trust
  checks can bind the tested executable to v0.77.1;
- exact help/version/artifact command syntax;
- safe standard-user built-in collection for the reviewed artifact;
- deterministic fully synthetic custom definition loading and parameter
  transport;
- bounded direct structured import and bounded ZIP result import;
- observed exit/error anomalies and mandatory fail-closed compensating checks;
- distinct external timeout/cancellation with no late bytes or observed orphan;
- literal transport of the tested metacharacter corpus;
- no network activity observed during the sampled runs.

Not proven:

- compatibility with another release, architecture, Windows version, or token
  configuration;
- reproducible build equivalence, current online certificate revocation, or
  network impossibility;
- safety of any other built-in/custom artifact or deep audit;
- reliable Velociraptor internal timeout expiration;
- descendant containment without a Job Object;
- safe use of the crashing memory-limit option;
- production storage, retention, elevation, updater, or rollback behavior;
- production adapter readiness.

## 23. Git status

After cleanup and validation, `git status --short --untracked-files=all` is:

```text
 M docs/decision-log.md
 M docs/roadmap.md
?? docs/velociraptor-adapter-compatibility.md
?? tests/compatibility/README.md
?? tests/compatibility/expected/compatibility-contract.json
?? tests/compatibility/expected/synthetic-normalized.json
?? tests/compatibility/synthetic-artifact.yaml
?? tools/compatibility/inspect-authenticode.ps1
?? tools/compatibility/normalize-synthetic-output.mjs
?? tools/compatibility/observe-network.ps1
?? tools/compatibility/process-probe.mjs
?? tools/compatibility/run-cli-contract-probes.mjs
?? tools/compatibility/structured-output-probe.mjs
?? tools/compatibility/test-openpgp-policy.mjs
?? tools/compatibility/test-prelaunch-pe-policy.mjs
?? tools/compatibility/test-structured-output-probe.mjs
?? tools/compatibility/test-zip-package-probe.mjs
?? tools/compatibility/verify-openpgp-detached.mjs
?? tools/compatibility/zip-package-probe.mjs
```

All changes remain uncommitted and limited to allowed dev-only compatibility
paths plus minimal roadmap and decision-log updates.

## 24. Scope confirmation and decision

No commit or push was performed. No worktree was created. No production
runtime implementation, GUI, service, agent, installer, updater, persistent
server, gRPC integration, remediation, reboot, elevation request, security-tool
disablement, system configuration change, or unapproved network action was
performed.

Decision: the spike establishes a concrete v0.77.1 contract suitable for
independent review, but the contract is not yet ready to authorize a production
adapter. Final status is `compatibility_partial_blockers_remain`.

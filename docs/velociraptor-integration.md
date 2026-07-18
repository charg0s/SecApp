# Velociraptor Integration Study

Status: recommendation for architecture review
Research date: 2026-07-18
Capability source pin: release [v0.77.1](https://github.com/Velocidex/velociraptor/tree/v0.77.1), resolved commit [3137c7f714ab344dd37d0df1d5393573e41b30a5](https://github.com/Velocidex/velociraptor/tree/3137c7f714ab344dd37d0df1d5393573e41b30a5)

This is a source/research pin. It is distinct from the future runtime binary version, digest, signer/trust decision, and acquisition record.

## Confirmed architecture

### Binary, client, frontend, and GUI

Velociraptor ships one binary per operating-system and architecture combination; commands select client, frontend, GUI, or utility behavior ([deployment overview](https://docs.velociraptor.app/docs/deployment/); [`bin/client.go`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/bin/client.go), [`bin/frontend.go`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/bin/frontend.go), [`bin/gui.go`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/bin/gui.go)). The normal client/server deployment keeps clients connected to a frontend and exposes a web Admin GUI ([overview](https://docs.velociraptor.app/docs/overview/), [GUI](https://docs.velociraptor.app/docs/gui/)).

Instant mode starts a server and one client in a single process on loopback, creates a datastore, creates a default administrator, and opens a browser. It is officially positioned for evaluation, testing, and local investigation, not as a production Windows server ([Instant mode](https://docs.velociraptor.app/docs/deployment/)).

### Datastore and filestore

Velociraptor stores small metadata such as clients, flows, and collections in the datastore and large result sets/uploads in the filestore ([storage architecture](https://docs.velociraptor.app/docs/deployment/server/multifrontend/)). The distinction is useful when importing Velociraptor data but SecApp should not expose upstream storage layout as its own public contract.

### Artifacts and VQL

VQL is the query engine. Artifacts package VQL queries, parameters, sources, and preconditions in YAML. Built-in artifacts are compiled into the binary; custom artifacts can be loaded from reviewed directories using `--definitions` ([artifact model](https://docs.velociraptor.app/docs/vql/artifacts/), [CLI artifact commands](https://docs.velociraptor.app/docs/cli/commands/artifacts/)).

The CLI can run local VQL with `query` or local artifacts with `artifacts collect`. Without a server config, artifact commands use the built-in repository plus explicitly supplied definitions. The official documentation describes `artifacts collect` as suitable for server-less triage and documents time, progress, CPU, memory, admin, format, output, and argument controls ([artifact CLI](https://docs.velociraptor.app/docs/cli/commands/artifacts/); source: [`bin/artifacts.go`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/bin/artifacts.go)).

### Flows, hunts, and monitoring

A flow is one artifact collection on one client; a hunt groups flows across clients ([server automation](https://docs.velociraptor.app/docs/server_automation/), [hunting](https://docs.velociraptor.app/docs/hunting/)). These server concepts are useful for fleet operations but are unnecessary for the first single-machine SecApp slice.

Client monitoring consists of long-running event artifacts, local writeback state, buffering, and later synchronization with the server ([client monitoring](https://docs.velociraptor.app/docs/clients/monitoring/)). SecApp's first slice is a bounded point-in-time audit, so monitoring is deferred.

### Offline collectors

Offline collectors execute preselected artifacts without client/server connectivity and write a portable collection container. The normal collector is a standard Velociraptor binary repacked with embedded configuration and may bundle external tools; the official GUI-built collector normally requires elevation ([offline collections](https://docs.velociraptor.app/docs/deployment/offline_collections/), [running collectors](https://docs.velociraptor.app/docs/deployment/offline_collections/running/)). Containers may be encrypted, but fixed passwords are embedded and extractable; certificate-based protection is preferred ([collection security](https://docs.velociraptor.app/docs/deployment/offline_collections/)).

Because SecApp intends to use an externally supplied, unmodified backend binary and needs separate standard/elevated passes, a repacked offline collector is not the baseline.

### API

The supported external API is streaming gRPC with mutual certificate authentication. It exposes a powerful `Query` method capable of server administration, scheduling, and result retrieval. The internal REST API is explicitly not considered public or stable ([server API](https://docs.velociraptor.app/docs/server_automation/server_api/); [`api/proto/api.proto`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/api/proto/api.proto)). API credentials and broad VQL power increase attack surface, so API mode is not required for the first local slice.

## Integration options

Ratings are relative to one offline Windows machine. "Local" means no intentional external network during the audit.

| Option | Complexity | OS privilege | Network | Fully local | Storage | Read-only fit | One-machine fit | Reboot continuation | Testability | Main security risk | Upstream maintenance |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. Separate local process | Medium | Per collector; multiple passes possible | None | Yes | SecApp-owned staging and normalized store | Strong with allowlist | Strong | SecApp-owned | Strong process-boundary tests | Binary/argument/artifact substitution | Low-medium |
| B. Local frontend + client | High | Client often elevated | Loopback required | Yes | Velociraptor datastore/filestore | Mixed; broad client capability | Moderate | Velociraptor writeback plus SecApp state | High integration cost | Powerful local server, browser, credentials | Medium |
| C. Standalone/offline collector | Medium | GUI-built collector normally elevated | None during collection | Yes | Collection ZIP | Mixed; packed spec may include broad actions | Good for one-shot triage | Re-run or external state | Good container tests | Repacked binary, embedded configuration/passwords | Medium |
| D. gRPC API | High | Depends on server/client roles | Loopback or network | Yes on loopback | Velociraptor datastore/filestore | Possible with wrapper artifacts | Moderate | Server/client state | Good protocol tests | API certificate theft and arbitrary VQL | Medium-high |
| E. CLI invocation | Medium | Per command | None unless selected VQL uses network | Yes | stdout or collection ZIP | Strong if fixed arguments | Strong | SecApp-owned | Strong | Command/VQL injection, output framing | Low-medium |
| F. Result import | Medium | None after collection | None | Yes | Private raw input plus normalized objects | Strong | Strong | Independent | Strong fixture tests | Parser bugs, zip/path traversal | Medium |
| G. VQL/artifacts without persistent server | Medium | Per VQL capability | None by policy | Yes | SecApp-owned | Strong with reviewed definitions | Strong | SecApp-owned | Strong artifact tests | Malicious VQL or unsafe plugin | Low-medium |

### A. Separate local process

**Proposed use:** one fresh backend process per `CollectorExecution`, or one tightly bounded group only after output-framing tests.

- Complexity: process lifecycle, timeouts, cancellation, output limits, and exit-code handling.
- Privilege: standard and elevated process launches are separate consent scopes.
- Network: forbidden by SecApp policy; any collector declaring `NETWORK` is rejected.
- Storage: backend output enters a private staging area and is treated as untrusted.
- Read-only: reject `EXECVE`, write, remediation, upload, memory, and network capabilities by default.
- Reboot: SecApp persists authenticated `RebootContinuationState`; the backend does not own workflow continuation.
- Testing: replace the backend with a deterministic fake process only in adapter unit tests; do not present it as product functionality.
- Maintenance: pin supported upstream versions and contract-test actual CLI output.
- Limitation: a process boundary is not a sandbox. An elevated malicious artifact still has elevated host access.

### B. Local frontend + client

Instant mode confirms that a local server and client can share one process and loopback connection ([deployment overview](https://docs.velociraptor.app/docs/deployment/)). It provides GUI, flows, notebooks, datastore, and API, but also writes a datastore, creates credentials, and launches a browser. It duplicates SecApp's UI and storage responsibilities and enlarges the attack surface. Keep it as an analyst/test environment or future fallback, not the first embedded architecture.

### C. Standalone/offline collectors

Offline collectors are proven for no-network collection and standardized containers ([offline collections](https://docs.velociraptor.app/docs/deployment/offline_collections/)). They are less suitable for SecApp because the common build flow repacks the binary with configuration, multi-artifact packs obscure per-collector consent, and GUI-built collectors generally demand elevation. A Generic Collector may reduce repacking, but still needs a separately managed executable plus collector data and does not eliminate trust-policy work.

### D. API integration

The public gRPC API is appropriate when a real Velociraptor server is already part of the deployment. It is overpowered for a first single-machine offline audit: it requires server lifecycle, API certificates, role design, and a datastore. If introduced later, bind to loopback, use a narrowly authorized API identity, never use the internal REST API, and expose only fixed wrapper operations.

### E. CLI invocation

This is the primary interface for option A. Use an argument array, never a shell command string. Permit only exact reviewed subcommands, artifact names, flags, and value types. Velociraptor documents that artifact arguments are strings and that shell escaping is tricky; this reinforces structured process creation rather than interpolation ([artifact CLI](https://docs.velociraptor.app/docs/cli/commands/artifacts/)).

Open compatibility question: the documentation confirms stdout output and standardized ZIP output, but SecApp must experimentally verify framing, source identity, log separation, encoding, and exit behavior for every supported upstream version before freezing an adapter contract.

### F. Result import

Import is always separated from execution. The importer:

1. enforces byte, row, nesting, and file-count limits;
2. rejects absolute paths, backslashes, traversal segments, links, and reparse points in containers;
3. verifies the raw digest before parsing;
4. preserves source/artifact identity;
5. validates normalized observations;
6. records parse failures instead of inferring absence.

Standardized collection containers are documented as importable and contain query results and optional uploads ([offline data](https://docs.velociraptor.app/docs/deployment/offline_collections/collection_data/)). Direct ZIP parsing creates an upstream-format dependency; prefer documented exports and pin compatibility tests.

### G. VQL/artifacts without a persistent server

Use built-in artifacts only when release-specific source, dependencies, VQL functions, optional branches, and pinned parameters meet the capability contract. Declared or implied permissions are not a sandbox. Load SecApp custom artifacts from a read-only, digest-checked definition directory using `--definitions`. Do not override built-in names. Run `artifacts verify` in development/CI; it is necessary static validation, not proof of safe runtime behavior ([artifact verification](https://docs.velociraptor.app/docs/cli/commands/artifacts/), [artifact security](https://docs.velociraptor.app/docs/artifacts/security/)).

## Recommendation

Adopt **A + E + F + G**:

- unmodified Velociraptor as a separately supplied local binary;
- one bounded CLI invocation per approved collector;
- no frontend, client service, GUI, API credentials, or persistent Velociraptor server;
- built-in artifacts only where the v0.77.1 transitive review and pinned parameters are safe and adequate;
- reviewed custom artifacts for missing coverage;
- SecApp-owned normalization, rules, findings, reporting, consent, audit log, and continuation;
- private raw output with hashes, followed by typed import.

Use **B or D** only if a controlled prototype proves that the CLI cannot supply a stable, source-identifiable result contract. Use **C** only for an explicitly separate out-of-band collection workflow.

This is a recommendation, not a proven runtime decision. A binary-backed compatibility spike is required before implementation is declared ready.

## Proposed invocation contract

The adapter accepts only:

- separately verified runtime binary identity: version, file digest, signer/trust decision, acquisition record, and source-release mapping;
- collector ID and version;
- collector-definition digest and complete transitive capability set;
- exact artifact or VQL source name from a reviewed definition;
- typed parameters serialized as individual process arguments;
- standard or elevated context already approved by the orchestrator;
- offline policy;
- command-contract identifier plus timeout, progress timeout, CPU, memory, stdout, stderr, record-count, and output-size limits;
- a newly created private logical output target.

It records exit status when present, raw stdout/stderr and optional collection-ZIP file digests, observed backend version/revision, parser/import status, record count, truncation, timeout/cancellation source, and applied limits. Raw streams are not required inside CollectorExecution. It never returns a claim that the system is safe.

## Confirmed built-in capabilities useful to SecApp

At release v0.77.1:

- system metadata is exposed by [`Generic.Client.Info`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/artifacts/definitions/Generic/Client/Info.yaml), but whole-artifact collection is UnsafeForDefault because its Users source calls Windows.Sys.Users;
- [`Windows.Sys.Users`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/artifacts/definitions/Windows/Sys/Users.yaml) declares FILESYSTEM_WRITE and is UnsafeForDefault;
- firewall rules: [`Windows.Sys.FirewallRules`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/artifacts/definitions/Windows/Sys/FirewallRules.yaml);
- listeners/connections: [`Windows.Network.ListeningPorts`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/artifacts/definitions/Windows/Network/ListeningPorts.yaml) and [`Windows.Network.Netstat`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/artifacts/definitions/Windows/Network/Netstat.yaml);
- startup items, services, tasks, WMI persistence, drivers, signatures, installed programs, DNS cache, hosts, PowerShell logs, and generic EVTX parsing: see the pinned paths in [the audit parity matrix](audit-parity-matrix.md).

The built-in [`Windows.System.LocalAdmins`](https://github.com/Velocidex/velociraptor/blob/3137c7f714ab344dd37d0df1d5393573e41b30a5/artifacts/definitions/Windows/System/LocalAdmins.yaml) requires `EXECVE` and launches PowerShell with an unrestricted execution-policy argument. Windows.Registry.RDP is also UnsafeForDefault because Windows.Registry.NTUser calls Windows.Sys.Users transitively. Safe VQL-native alternatives are proposed compatibility experiments, not confirmed collectors.

## Required custom artifacts

Names are proposed, not implemented:

- `SecApp.Windows.PlatformAndUpdates`;
- `SecApp.Windows.UsersReadOnly`;
- `SecApp.Windows.PendingReboot`;
- `SecApp.Windows.DefenderStatus`;
- `SecApp.Windows.FirewallProfiles`;
- `SecApp.Windows.SecurePlatform` for Secure Boot, TPM, UAC, and VBS;
- `SecApp.Windows.BitLockerStatus`;
- `SecApp.Windows.LocalAdministrators` without `execve`;
- `SecApp.Windows.PasswordPolicyAndGuest`;
- `SecApp.Windows.RemoteManagement`;
- `SecApp.Windows.PowerShellPolicy`;
- `SecApp.Windows.NameResolutionPolicy`;
- `SecApp.Windows.RecoveryStatus`;
- `SecApp.Windows.DefenderOfflineDiagnostics`;
- narrow wrappers/normalizers where a built-in artifact exposes optional upload, execution, or overly broad output.

Each custom artifact must declare permissions, have a Windows precondition, use only allowlisted read operations, include no tool downloads, and pass `artifacts verify` plus synthetic positive/negative tests.

## Blockers and experiments

1. Verify actual stdout/ZIP schema, source identity, logs, exit codes, cancellation, and encoding for supported Velociraptor versions.
2. Prove that custom local-administrator and password-policy collectors work without `execve`.
3. Establish exact standard-versus-elevated coverage across supported Windows versions.
4. Define backend binary acquisition, Authenticode/hash validation, pinning, and update rollback.
5. Select a narrow Windows elevation mechanism and prove that untrusted parameters cannot cross it.
6. Select encrypted storage/key management for private raw output.
7. Validate reboot continuation without a persistent service or auto-run command.
8. Confirm that all selected built-ins and dependencies stay within the explicit capability set under pinned parameters.
9. Resolve retention, temporary-file, ACL, encryption/key, backup, deletion, and composition policies.
10. Add a full Draft 2020-12 validator and cross-object negative-test harness before baseline acceptance.

## Fork decision

A fork is **not justified now**. Official modes already provide local CLI queries, local artifact collection, custom definitions, standardized containers, Instant mode, and a public gRPC API. Current gaps are collector coverage and adapter policy, both addressable outside upstream source.

Reconsider a fork only after a reproducible, version-pinned experiment demonstrates one of these blockers:

- no viable single-machine local workflow;
- no safe privilege separation possible through an external orchestrator;
- no usable documented CLI or public API result contract;
- no external reboot-continuation design;
- irreconcilable storage semantics;
- a required GUI capability cannot be supplied as an external layer;
- a security defect cannot be mitigated externally and upstream cannot accept a fix.

Convenience, branding, or avoiding an adapter is not sufficient.

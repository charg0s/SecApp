# Synthetic Windows protection assessment tests

Run `npm run test:assessment` or the complete `npm test` gate. No backend,
native helper, machine collection, network, elevation, or Windows setting
change is part of this suite.

`fixtures/windows-protection.jsonl` contains four synthetic
`FullContractInstance` Observation objects with real computed digests. The
matching generator is `synthetic-observations.mjs`; a test checks exact bytes.
These objects satisfy the Observation contract, not a complete application
graph, and are not evidence of any machine's state or successful collection.
The demo has two concerns, three expected reported states, and one NotTested
result. All identifiers, provenance markers, and values are synthetic.

The unsuccessful-execution boundary test uses a deliberately incomplete
`ShapeOnly` execution object injected after import. It is not an application-
valid positive fixture, nor evidence that a complete ZIP graph was validated.
Other mutations are targeted negative inputs, never accepted full fixtures.

Tests use unique temporary directories for generated synthetic files and
remove them afterward. The actual CLI subprocess test executes only the Node
reference command, with no shell and no native helper. It checks that HTML is
returned on stdout and no report files appear in the working directory.

HTML tests inject hostile synthetic text into renderer inputs to check escaping
and forbid active/resource tags. This is not a substitute for independent
security review or a complete browser matrix. Rules, limitations, privacy
classification, and digest semantics are documented in
[the profile contract](../../docs/windows-protection-import.md).

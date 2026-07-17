# Repository Guidance

These instructions apply to the entire repository.

- Keep SecApp an independent, fully open project.
- Treat Velociraptor as a separate, unmodified backend; do not vendor its binaries or create a fork here.
- Keep collection, risk assessment, and user-interface concerns separated.
- Preserve read-only checks as the default.
- Require separate, explicit consent for network access, administrative operations, rebooting, memory scanning, and remediation.
- Never commit real audit results, generated evidence, personal or system data, secrets, tokens, or credentials.
- Use only synthetic, non-sensitive test data.
- The project is currently in the design stage. Do not add executable application code or placeholder implementations unless a later task explicitly authorizes that work.
- Keep text files in UTF-8 with LF line endings and a final newline.

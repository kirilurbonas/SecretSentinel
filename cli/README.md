## SecretSentinel CLI (`sentineld`)

The SecretSentinel CLI provides a Git pre-commit integration and local scanning workflow to prevent secrets from being committed to source control.

### Commands

- `sentineld init`
  - Installs a `.git/hooks/pre-commit` hook into the current repository.
  - The hook runs `sentineld scan --staged` on every commit attempt.

- `sentineld scan --staged`
  - Scans only staged changes using `git diff --cached --unified=0`.
  - Runs local detection (regex + Shannon entropy) against new/changed lines.
  - Optionally calls the detection engine service for deeper analysis.
  - Blocks the commit (exit code 1) when a secret is detected.

Implementation details and tests live under `cmd/` and `internal/`.

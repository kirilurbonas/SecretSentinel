## SecretSentinel

SecretSentinel is a developer-first secrets security platform designed to prevent credentials (API keys, tokens, passwords, database URLs, and private keys) from leaking into source code and version control.

The core of the system is a pre-commit hook CLI (`sentineld`) and a detection engine that together provide an airtight developer protection layer. Future components (Vault service, rotation worker, API gateway, and dashboard) build on this foundation to manage and rotate secrets centrally.

### Monorepo structure

- `cli/` – Go 1.22 CLI (`sentineld`) providing:
  - `sentineld init` to install a Git pre-commit hook.
  - `sentineld scan --staged` to scan staged changes for secrets before each commit.
- `detection/` – Python 3.12 FastAPI detection microservice combining regex rules, Shannon entropy, and context-aware scoring.
- `vault/` – Node.js 22 HashiCorp Vault wrapper service (stubbed for now).
- `rotation/` – Node.js 22 rotation worker using AWS SQS (stubbed for now).
- `api/` – Apollo GraphQL + REST gateway (stubbed for now).
- `dashboard/` – React 19 + TypeScript + Tailwind CSS frontend (stubbed for now).
- `shared/` – Shared types and protocol definitions.
- `infra/` – Local Docker Compose and Terraform stubs for AWS ECS Fargate deployments.

### CLI pre-commit workflow

1. Run `sentineld init` once in a Git repository to install a `.git/hooks/pre-commit` hook.
2. On every `git commit`, the hook runs `sentineld scan --staged`.
3. The CLI:
   - Collects the staged diff (`git diff --cached --unified=0`).
   - Scans only added/modified lines for secrets using:
     - Local regex-based detectors (AWS keys, GitHub PATs, Stripe keys, DB URLs, `.env` patterns, private keys, and high-entropy strings).
     - A local `.sentinelignore` allow-list file and inline `# sentineld:ignore` comments.
     - The detection service (`/detection`) as a secondary, richer detection layer when available.
4. If any secrets are found, the commit is blocked with a clear report including:
   - File path and line number.
   - Secret type and the detected value.
   - A remediation hint that points to the SecretSentinel vault workflow.

### Production mode (ASAP)

```bash
# One-command: build detection image and run in production mode
make prod

# Or step by step:
make build-detection   # Build Docker image
make up-prod          # Run detection on port 8000 (4 workers, health checks)

# Build CLI static binary for distribution
make build-cli        # Output: bin/sentineld
```

The detection service exposes `GET /health` for load balancers and orchestrators. Set `SENTINEL_DETECTION_URL=http://your-host:8000` for the CLI to use it.

### Running the detection service locally

- The detection microservice lives under `detection/` and is implemented with FastAPI.
- It exposes:
  - `POST /scan` for scanning a single file.
  - `POST /scan/batch` for scanning multiple files in one request.
- The service combines:
  - A library of regex-based rules (50+ providers and secret formats).
  - A Shannon entropy model to flag generic high-entropy strings.
  - Simple context analysis to adjust confidence (e.g., lower scores in tests or examples).

When running locally (for example via Docker Compose), the CLI will default to calling the detection service at `http://localhost:8000` and merge remote findings with its own local detections.

### Future components (not implemented yet)

- `vault/` – Multi-tenant Vault-backed secrets API and an accompanying `@sentineldev/sdk` npm package for fetching, caching, and injecting secrets into `process.env`.
- `rotation/` – Rotation worker listening to AWS SQS events to rotate secrets and update Vault.
- `api/` – GraphQL and REST gateway that exposes a unified API across detection, vault, and rotation.
- `dashboard/` – Web dashboard for visualizing secret usage, rotation status, and policy enforcement.

These components will be implemented after the CLI and detection engine are stable and battle-tested.

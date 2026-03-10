## SecretSentinel

SecretSentinel is a developer-first secrets security platform designed to prevent credentials (API keys, tokens, passwords, database URLs, and private keys) from leaking into source code and version control.

The core of the system is a pre-commit hook CLI (`sentineld`) and a detection engine that together provide an airtight developer protection layer. Future components (Vault service, rotation worker, API gateway, and dashboard) build on this foundation to manage and rotate secrets centrally.

### Monorepo structure

- `cli/` – Go 1.22 CLI (`sentineld`) providing:
  - `sentineld init` to install a Git pre-commit hook.
  - `sentineld scan --staged` to scan staged changes for secrets before each commit.
  - `sentineld scan --path <dir>` to scan all files under a directory (e.g. for CI).
  - `sentineld scan --json` for machine-readable findings. Use `SENTINEL_DETECTION_URL` (e.g. `http://localhost:8000`) to enable the detection service.
- `detection/` – Python 3.12 FastAPI detection microservice combining regex rules, Shannon entropy, and context-aware scoring.
- `vault/` – Node.js 22 Vault HTTP API (in-memory or HashiCorp Vault) and `@sentineldev/sdk`.
- `rotation/` – Node.js 22 rotation worker (polls AWS SQS, calls Vault rotate).
- `api/` – API gateway (GraphQL + REST proxy to detection and vault, JWT-friendly).
- `dashboard/` – React 19 + TypeScript + Tailwind dashboard (login, secrets list/add/rotate).
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

### Vault service and SDK

- **Vault** (`vault/`) – Node.js 22 HTTP API wrapping HashiCorp Vault (or in-memory store for local dev): `GET/POST /secrets/:env/:key`, `GET /secrets/:env` (list keys), `PUT .../rotate`.
- **SDK** (`vault/sdk/`) – `@sentineldev/sdk`: `get(key, { env })`, `inject(keys, { env })`, cache (default 5 min), `SentinelSecretNotFoundError` when missing.

### Full stack (Docker Compose)

From repo root, run `cd infra && docker compose up -d` to start:

- **detection** (8000), **vault** (3000), **api** (4000), **rotation** (worker), **dashboard** (8080), **db** (5432).

Set `SQS_ROTATION_QUEUE_URL` for the rotation worker to poll AWS SQS. The dashboard proxies `/api` and `/graphql` to the API gateway when using `npm run dev` (see dashboard `vite.config.ts`); in production, point the dashboard at the API URL.

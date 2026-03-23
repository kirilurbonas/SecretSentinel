## SecretSentinel

SecretSentinel is a developer-first secrets security platform designed to prevent credentials (API keys, tokens, passwords, database URLs, and private keys) from leaking into source code and version control.

The system combines a pre-commit hook CLI (`sentineld`), a detection engine, a secrets vault, an automated rotation worker, and an API gateway — all production-hardened and ready to deploy.

---

### Monorepo structure

| Directory | Description |
|-----------|-------------|
| `cli/` | Go 1.22 CLI (`sentineld`) — pre-commit hook, path scanning, JSON output |
| `detection/` | Python 3.12 FastAPI detection microservice — regex, entropy, context scoring |
| `vault/` | Node.js 22 Vault HTTP API + `@sentineldev/sdk` — AES-256-GCM encrypted, Postgres-backed |
| `rotation/` | Node.js 22 rotation worker — polls AWS SQS, rotates secrets via Vault |
| `api/` | API gateway — GraphQL + REST proxy, HMAC-SHA256 JWT auth, CORS |
| `dashboard/` | React 19 + TypeScript + Tailwind — login, secrets list, add/rotate UI |
| `shared/` | Shared types and protocol definitions |
| `infra/` | Docker Compose (full stack) and Terraform stubs for AWS ECS Fargate |

---

### Quick start (full stack)

```bash
# 1. Copy and fill in required secrets
cp .env.example .env

# 2. Start all services
cd infra && docker compose up -d
```

Services started: **detection** (8000) · **vault** (3000) · **api** (4000) · **rotation** (worker) · **dashboard** (8080) · **db** (5432)

All containers include health checks and start in dependency order. The dashboard proxies `/api` and `/graphql` to the API gateway (`vite.config.ts`); in production, set the dashboard's `VITE_API_URL` to your API gateway host.

---

### Required environment variables

See `.env.example` for the full list. Key variables:

| Variable | Used by | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | db, vault | Postgres root password |
| `VAULT_AUTH_SECRET` | vault, rotation | HMAC secret for signing vault auth tokens |
| `VAULT_ENCRYPTION_KEY` | vault | Key for AES-256-GCM secret encryption at rest |
| `JWT_SECRET` | api | HMAC-SHA256 JWT verification secret |
| `ALLOWED_ORIGINS` | api | Comma-separated CORS origin allowlist |
| `SENTINEL_CLI_TOKEN` | cli | Bearer token for authenticated API calls |
| `SQS_ROTATION_QUEUE_URL` | rotation | AWS SQS queue for rotation jobs |

---

### CLI

```bash
# Install pre-commit hook in a repo
sentineld init

# Scan staged changes (runs automatically on git commit)
sentineld scan --staged

# Scan a directory (CI usage)
sentineld scan --path ./src

# Machine-readable output
sentineld scan --path ./src --json

# Authenticated scan via API gateway
sentineld scan --staged --auth-token $SENTINEL_CLI_TOKEN
# or set SENTINEL_CLI_TOKEN env var
```

Set `SENTINEL_DETECTION_URL` (e.g. `http://localhost:8000`) to route scans through the detection service. Set `SENTINEL_REMOTE_TIMEOUT_SECONDS` (default 30, max 300) to control request timeout.

#### Build the CLI

```bash
make build-cli    # outputs bin/sentineld
```

---

### Detection service

`POST /scan` · `POST /scan/batch` · `POST /validate` · `GET /health` · `GET /metrics`

The service combines:
- **50+ regex rules** covering AWS, GitHub, Stripe, Slack, GCP, Azure, Kubernetes, and more
- **Shannon entropy** scoring to catch generic high-entropy strings
- **Context-aware scoring** — confidence is reduced for values found in test files, example files, or comment lines
- **Filename-filtered rules** — e.g. the Kubernetes Secret rule only fires on `.yaml`/`.yml` files
- **Confidence threshold** — findings below `SENTINEL_MIN_CONFIDENCE` (default `0.5`) are suppressed
- **Secret liveness validation** — `POST /validate` checks if a detected credential is still active (AWS via STS `GetCallerIdentity`, GitHub via `/user` API)
- **Prometheus metrics** at `/metrics` — request counts, latency histograms, per-rule detection counters

---

### Vault service & SDK

**Vault** (`vault/`) is a Node.js 22 HTTP API providing encrypted secret storage:

- Secrets are encrypted with **AES-256-GCM** before being written to Postgres (key derived via `scrypt`)
- Auth tokens are **HMAC-SHA256 signed** and verified with constant-time comparison
- Supports **per-tenant secret namespacing**
- Routes: `GET/POST /secrets/:env/:key` · `GET /secrets/:env` · `PUT /secrets/:env/:key/rotate`

**SDK** (`vault/sdk/`) — `@sentineldev/sdk`:

```ts
import { SentinelClient } from "@sentineldev/sdk";
const client = new SentinelClient({ env: "production" });
const secret = await client.get("DATABASE_URL");
const injected = await client.inject(["DB_PASS", "API_KEY"]);
```

Features: 5-minute local cache, `SentinelSecretNotFoundError` on missing keys.

---

### Rotation worker

The rotation worker (`rotation/`) polls an AWS SQS queue for rotation jobs and calls the Vault API to rotate secrets. Production features:

- **Exponential backoff** — failed messages are delayed `2^attempt` seconds (up to `MAX_ROTATION_RETRIES`, default 5) before being dead-lettered
- **AWS IAM key rotation** — creates a new IAM access key, then deletes the old one
- **Generic rotation** — generates a cryptographically random 48-byte base64url secret for non-IAM keys
- **Health file** — writes `/tmp/sentinel-alive` on every successful SQS poll (used by Docker health check)
- **Vault auth** — generates signed vault tokens using `VAULT_AUTH_SECRET`

---

### API gateway

The API gateway (`api/`) is a Fastify service providing:

- **HMAC-SHA256 JWT verification** — validates tokens using `JWT_SECRET`, rejects tampered JWTs with 401
- **CORS restriction** — only origins listed in `ALLOWED_ORIGINS` are allowed
- **GraphQL API** — `query { secrets }`, `mutation { storeSecret }`, `mutation { rotateSecret }`, `mutation { validateSecret(type, value) }`
- **REST proxy** — `/api/scan` and `/api/validate` forwarded to the detection service
- **Structured JSON logging** on every request

---

### CI/CD pipeline

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | What it does |
|-----|-------------|
| `test-go` | `go test ./... -race -coverprofile=coverage.out` |
| `test-python` | `pytest tests/ -v` (104 parametrized rule tests + context tests) |
| `vault-test` | `npm test` (crypto + auth unit tests via Vitest) |
| `api-test` | `npm test` (middleware JWT tests via Vitest + Supertest) |
| `build` | Builds Docker images for detection and vault |
| `security` | Trivy container scanning (SARIF upload), gitleaks secret scanning, SBOM generation via Syft |

---

### Production deployment

```bash
# Build detection image
make build-detection

# Run detection in production mode (4 Gunicorn workers)
make up-prod

# Or bring up the full stack
cd infra && docker compose up -d
```

All Docker Compose services include:
- `healthcheck` blocks (HTTP probe or file existence)
- `depends_on: condition: service_healthy` — services wait for dependencies to be ready before starting
- No hardcoded credentials — all secrets injected via environment variables

For cloud deployment, Terraform stubs for AWS ECS Fargate are in `infra/terraform/`.

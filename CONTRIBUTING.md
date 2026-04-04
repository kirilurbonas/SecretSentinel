# Contributing to SecretSentinel

## Development Setup

### Prerequisites

- Go 1.22+
- Python 3.12+
- Node.js 22+
- Docker + Docker Compose

### Clone and configure

```bash
git clone https://github.com/kirilurbonas/SecretSentinel.git
cd SecretSentinel
cp .env.example .env
# Edit .env and fill in all required secrets
```

### Start the full dev stack

```bash
cd infra && docker compose up -d
```

## Running Tests

```bash
# Go CLI
cd cli && go test -cover ./...

# Python detection (requires virtualenv or uv)
cd detection && pip install -e ".[dev]"
ruff check app/ && mypy app/ && pytest tests/ -v

# Vault (Node 22)
cd vault && npm install && npm test

# API Gateway
cd api && npm install && npm test

# Rotation Worker
cd rotation && npm install && npm test

# Dashboard
cd dashboard && npm install && npm test

# Full lint pass
make lint
```

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready, protected — merge via PR only |
| `feat/<name>` | New features |
| `fix/<name>` | Bug fixes |
| `chore/<name>` | Maintenance, deps, config |

## Pull Request Process

1. Create a branch from `main` using the naming convention above.
2. Ensure all CI jobs pass before requesting review (`cli`, `detection`, `vault-test`, `api-test`, `rotation-test`, `dashboard-build`, `security`).
3. Include tests for any new behaviour.
4. Update documentation (inline comments, README, or this file) for user-visible changes.
5. Keep PRs focused — one logical change per PR.
6. Request at least one review.

## Coding Standards

### Go (CLI)

- `gofmt` formatting enforced; run `gofmt -w ./...`
- Linted with `golangci-lint` (config at `cli/.golangci.yml`)
- All exported functions must have doc comments
- Use stdlib (`strings`, `bytes`, `net/http`) — avoid adding third-party dependencies

### Python (Detection)

- Formatted and linted with `ruff` (line length 100)
- Type-checked with `mypy` (strict mode)
- All public functions must have type annotations
- Tests in `tests/` using `pytest`; maintain coverage above 60%

### TypeScript (Vault, API, Rotation, SDK)

- Strict TypeScript (`strict: true` in all `tsconfig.json`)
- `noUnusedLocals` and `noUnusedParameters` enforced in dashboard
- Tests with `vitest`
- No `any` casts unless unavoidable; prefer typed assertions

### React (Dashboard)

- Functional components only (no class components)
- Props typed with TypeScript interfaces
- Tests with Vitest + React Testing Library

## Adding a New Detection Rule

1. Open `detection/app/detectors/regex_rules.py`
2. Add a `RegexRule(id="...", type="...", pattern=..., base_confidence=...)` entry to `ALL_RULES`
3. Add a corresponding pattern in `cli/internal/detect/patterns.go` for CLI-local detection
4. Add test cases in `detection/tests/test_rules.py` (positive and negative)
5. Add test cases in `cli/internal/detect/patterns_test.go`

## Security Policy

If you discover a security vulnerability, **do not open a public issue**. Email the maintainers directly. For secret detection test strings, always split them to avoid triggering scanners, e.g., `"AKIA" + "1234567890ABCDEF"`.

## Commit Message Convention

```
<type>(<scope>): <short summary>

type: feat | fix | chore | docs | test | refactor | ci | perf
scope: cli | detection | vault | api | rotation | dashboard | infra | deps
```

Examples:
- `feat(vault): add secret version history endpoint`
- `fix(detection): correct entropy threshold for short tokens`
- `chore(deps): update fastapi to 0.115.2`
- `ci: add rotation worker test job`

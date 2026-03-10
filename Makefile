.PHONY: build-cli build-detection lint test up up-prod down help

# Build the Go CLI as a static binary (no CGO, works in minimal containers)
build-cli:
	cd cli && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../bin/sentineld ./cmd/sentineld

# Build detection Docker image
build-detection:
	docker build -t secretsentinel-detection:latest ./detection

# Run full stack (detection + db) for local dev
up:
	cd infra && docker compose up -d

# Run production-style stack (detection only, optimized)
up-prod:
	cd infra && docker compose -f docker-compose.prod.yml up -d

# Stop all services
down:
	cd infra && docker compose down; docker compose -f docker-compose.prod.yml down 2>/dev/null || true

# One-command production deploy: build and run detection
prod: build-detection up-prod

# Run Go tests
test-cli:
	cd cli && go test -cover ./...

# Run Go linter (golangci-lint)
lint-cli:
	cd cli && golangci-lint run ./...

# Run detection tests and lint (pytest, ruff, mypy)
test-detection:
	cd detection && pip install -e ".[dev]" -q && pytest tests/ -v
lint-detection:
	cd detection && pip install -e ".[dev]" -q && ruff check app/ && mypy app/

# All tests and lints
test: test-cli test-detection
lint: lint-cli lint-detection

build-vault:
	docker build -t secretsentinel-vault:latest ./vault
build-api:
	docker build -t secretsentinel-api:latest ./api
build-rotation:
	docker build -t secretsentinel-rotation:latest ./rotation
build-dashboard:
	docker build -t secretsentinel-dashboard:latest ./dashboard

up-full:
	cd infra && docker compose up -d

help:
	@echo "SecretSentinel targets:"
	@echo "  make build-cli        - Build sentineld static binary to bin/"
	@echo "  make build-detection  - Build detection Docker image"
	@echo "  make build-vault      - Build vault Docker image"
	@echo "  make build-api        - Build API gateway Docker image"
	@echo "  make build-rotation   - Build rotation worker Docker image"
	@echo "  make build-dashboard  - Build dashboard Docker image"
	@echo "  make up               - Start dev stack (detection + postgres)"
	@echo "  make up-full          - Start full stack (detection, vault, api, rotation, dashboard, db)"
	@echo "  make up-prod          - Start production detection service only"
	@echo "  make prod             - Build detection image + run in prod mode"
	@echo "  make down             - Stop all services"

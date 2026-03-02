.PHONY: build-cli build-detection up up-prod down help

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

help:
	@echo "SecretSentinel production targets:"
	@echo "  make build-cli      - Build sentineld static binary to bin/"
	@echo "  make build-detection - Build detection Docker image"
	@echo "  make up             - Start dev stack (detection + postgres)"
	@echo "  make up-prod        - Start production detection service only"
	@echo "  make prod           - Build detection image + run in prod mode"
	@echo "  make down           - Stop all services"

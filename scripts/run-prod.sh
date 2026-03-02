#!/bin/sh
# Fastest path to production: build and run detection service
set -e
cd "$(dirname "$0")/.."
docker build -t secretsentinel-detection:latest ./detection
cd infra && docker compose -f docker-compose.prod.yml up -d
echo ""
echo "SecretSentinel detection is running at http://localhost:8000"
echo "Health: curl http://localhost:8000/health"
echo "CLI: set SENTINEL_DETECTION_URL=http://localhost:8000"

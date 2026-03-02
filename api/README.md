## SecretSentinel API Gateway (stub)

This directory will contain the Apollo Server–based GraphQL and REST API gateway for SecretSentinel.

Planned responsibilities:

- Expose a unified API across:
  - Detection service.
  - Vault service.
  - Rotation worker.
- Handle authentication and authorization using JWTs.
- Provide query and mutation endpoints for managing secrets, policies, projects, and integrations.

Implementation will be added after the core CLI and detection engine are complete.

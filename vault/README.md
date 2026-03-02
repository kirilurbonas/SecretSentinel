## SecretSentinel Vault Service (stub)

This directory will contain the Node.js 22 HashiCorp Vault wrapper service that exposes a multi-tenant HTTP API for managing secrets.

Planned responsibilities:

- Wrap HashiCorp Vault with a tenant-aware API:
  - `GET  /secrets/:env/:key` – fetch secret values (returns dynamic tokens).
  - `POST /secrets/:env` – store new secrets.
  - `PUT  /secrets/:env/:key/rotate` – trigger rotation.
  - `GET  /secrets/:env` – list secret keys (never values) for an environment.
- Provide an npm SDK (`@sentineldev/sdk`) for applications to consume secrets with local caching and `process.env` injection.

Implementation will be added after the core CLI and detection engine are complete.

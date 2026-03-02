## SecretSentinel Rotation Worker (stub)

This directory will contain the Node.js 22 rotation worker that processes rotation requests and coordinates with the Vault service.

Planned responsibilities:

- Listen to AWS SQS queues for rotation events.
- Perform provider-specific rotation workflows (e.g., database passwords, API keys).
- Update HashiCorp Vault with new secret values.
- Emit audit events for the API gateway and dashboard.

Implementation will be added after the CLI and detection engine are complete.

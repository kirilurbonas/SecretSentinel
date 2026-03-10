## SecretSentinel Rotation Worker

Node.js 22 worker that polls an AWS SQS queue for rotation events and triggers the Vault service to rotate secrets.

### Behaviour

- Polls `SQS_ROTATION_QUEUE_URL` (long polling). If unset, runs in stub mode (idle).
- Each message body must be JSON: `{ "env": "dev", "key": "DATABASE_URL", "tenant": "optional" }`.
- For each message, calls `PUT VAULT_URL/secrets/:env/:key/rotate` with optional auth, then deletes the message on success.

### Env

- `SQS_ROTATION_QUEUE_URL` – SQS queue URL (optional; if missing, worker does nothing).
- `VAULT_URL` – Vault API base (default `http://localhost:3000`).
- `SENTINEL_TOKEN` – Optional Bearer token for Vault.
- `AWS_REGION` – AWS region for SQS (default `us-east-1`).
- `POLL_INTERVAL_MS` – Delay between poll cycles (default 20000).

### Run

```bash
npm install && npm run build && npm start
```

Or use the Dockerfile; ensure `VAULT_URL` points at the Vault service.

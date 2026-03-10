## SecretSentinel API Gateway

Node.js 22 gateway exposing GraphQL (Apollo Server 4) and REST proxies to the detection and vault services.

### Endpoints

- `GET /health` – Health check.
- `POST /graphql` – GraphQL (queries: `secretKeys(env)`, `secret(env, key)`; mutations: `scan(content, filename)`, `setSecret(env, key, value)`, `rotateSecret(env, key)`).
- `POST /api/scan/scan`, `POST /api/scan/scan/batch` – Proxied to detection service.
- `GET/POST /api/vault/secrets/:env`, `GET /api/vault/secrets/:env/:key`, `PUT .../rotate` – Proxied to vault.

Auth: `Authorization: Bearer <token>` or `X-Sentinel-Token`; token is parsed and attached to the request (JWT optional).

### Env

- `PORT` – Default 4000.
- `DETECTION_URL` – Detection service base (default `http://localhost:8000`).
- `VAULT_URL` – Vault service base (default `http://localhost:3000`).
- `SENTINEL_TOKEN` – Optional token for server-to-server calls to detection/vault.

### Run

```bash
npm install && npm run build && npm start
```

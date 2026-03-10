## SecretSentinel Dashboard

React 19 + TypeScript + Tailwind CSS dashboard for viewing and managing secrets.

### Features

- **Login** – Token-based (dev: any non-empty token; store in localStorage).
- **Secrets** – List secret keys per environment (dev/staging/prod), add a secret (key + value), trigger rotate.

API calls go to the same origin in dev (Vite proxies `/api` and `/graphql` to the API gateway). For production, set `VITE_API_URL` at build time to the API base URL.

### Run

```bash
npm install && npm run dev
```

Open http://localhost:5173. Ensure the API gateway is running on port 4000 (or set the proxy in `vite.config.ts`).

### Build

```bash
npm run build
```

Output in `dist/`. For production, set `VITE_API_URL` before building, e.g.:

```bash
VITE_API_URL=https://api.example.com npm run build
```

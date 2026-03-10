# @sentineldev/sdk

SecretSentinel client SDK: fetch secrets from the Vault API with optional caching and inject them into `process.env`.

## Install

```bash
npm install @sentineldev/sdk
```

## Usage

```ts
import { SecretSentinel, SentinelSecretNotFoundError } from "@sentineldev/sdk";

const ss = new SecretSentinel({
  token: process.env.SENTINEL_TOKEN,
  baseUrl: "http://localhost:3000", // optional, default from SENTINEL_VAULT_URL
  ttl: 5 * 60 * 1000,               // optional, cache TTL in ms (default 5 min)
});

// Get a single secret (cached for ttl)
const dbUrl = await ss.get("DATABASE_URL", { env: "prod" });

// Inject multiple secrets into process.env
await ss.inject(["DATABASE_URL", "STRIPE_KEY"], { env: "prod" });
// then use process.env.DATABASE_URL, process.env.STRIPE_KEY
```

If a secret is missing, `get()` throws `SentinelSecretNotFoundError` with a helpful message.

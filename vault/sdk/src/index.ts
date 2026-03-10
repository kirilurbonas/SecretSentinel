export class SentinelSecretNotFoundError extends Error {
  constructor(
    public readonly key: string,
    public readonly env?: string,
    message?: string
  ) {
    super(
      message ??
        `Secret "${key}"${env ? ` for env "${env}"` : ""} not found. Check your vault or SENTINEL_TOKEN.`
    );
    this.name = "SentinelSecretNotFoundError";
    Object.setPrototypeOf(this, SentinelSecretNotFoundError.prototype);
  }
}

const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_BASE_URL = "http://localhost:3000";

export interface SecretSentinelOptions {
  token?: string;
  baseUrl?: string;
  ttl?: number;
}

interface CacheEntry {
  value: string;
  expiresAt: number;
}

export class SecretSentinel {
  private readonly token: string;
  private readonly baseUrl: string;
  private readonly ttlMs: number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(options: SecretSentinelOptions = {}) {
    this.token = options.token ?? process.env.SENTINEL_TOKEN ?? "";
    this.baseUrl = (options.baseUrl ?? process.env.SENTINEL_VAULT_URL ?? DEFAULT_BASE_URL).replace(
      /\/$/,
      ""
    );
    this.ttlMs = options.ttl ?? DEFAULT_TTL_MS;
  }

  private cacheKey(env: string, key: string): string {
    return `${env}:${key}`;
  }

  private getCached(env: string, key: string): string | undefined {
    const entry = this.cache.get(this.cacheKey(env, key));
    if (!entry || Date.now() >= entry.expiresAt) return undefined;
    return entry.value;
  }

  private setCached(env: string, key: string, value: string): void {
    this.cache.set(this.cacheKey(env, key), {
      value,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /**
   * Fetch a secret by key and env. Throws SentinelSecretNotFoundError if missing.
   */
  async get(key: string, options: { env?: string } = {}): Promise<string> {
    const env = options.env ?? "dev";
    const cached = this.getCached(env, key);
    if (cached !== undefined) return cached;
    const url = `${this.baseUrl}/secrets/${encodeURIComponent(env)}/${encodeURIComponent(key)}`;
    const res = await fetch(url, {
      headers: this.token ? { Authorization: `Bearer ${this.token}` } : {},
    });
    if (res.status === 404) {
      throw new SentinelSecretNotFoundError(key, env);
    }
    if (!res.ok) {
      throw new Error(`Vault returned ${res.status} for ${key}`);
    }
    const body = (await res.json()) as { value?: string };
    const value = body?.value;
    if (typeof value !== "string") {
      throw new SentinelSecretNotFoundError(key, env, "Invalid response: missing value");
    }
    this.setCached(env, key, value);
    return value;
  }

  /**
   * Fetch multiple keys and set them on process.env.
   */
  async inject(keys: string[], options: { env?: string } = {}): Promise<void> {
    const env = options.env ?? "dev";
    await Promise.all(
      keys.map(async (key) => {
        const value = await this.get(key, { env });
        process.env[key] = value;
      })
    );
  }
}

const DETECTION_URL = process.env.DETECTION_URL ?? "http://localhost:8000";
const VAULT_URL = process.env.VAULT_URL ?? "http://localhost:3000";
const SENTINEL_TOKEN = process.env.SENTINEL_TOKEN ?? "";

const headers: Record<string, string> = {
  "Content-Type": "application/json",
  ...(SENTINEL_TOKEN ? { Authorization: `Bearer ${SENTINEL_TOKEN}` } : {}),
};

async function detectionFetch(path: string, body?: object): Promise<unknown> {
  const url = `${DETECTION_URL.replace(/\/$/, "")}${path}`;
  const res = await fetch(url, {
    method: body ? "POST" : "GET",
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`Detection: ${res.status}`);
  return res.json();
}

async function vaultFetch(path: string, opts?: { method?: string; body?: object }): Promise<unknown> {
  const url = `${VAULT_URL.replace(/\/$/, "")}${path}`;
  const res = await fetch(url, {
    method: opts?.method ?? "GET",
    headers,
    body: opts?.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) throw new Error(`Vault: ${res.status}`);
  return res.json();
}

export const resolvers = {
  Query: {
    health: () => "ok",
    async secretKeys(_: unknown, { env }: { env: string }) {
      const r = await vaultFetch(`/secrets/${encodeURIComponent(env)}`) as { keys?: string[] };
      return { keys: r?.keys ?? [] };
    },
    async secret(_: unknown, { env, key }: { env: string; key: string }) {
      const r = await vaultFetch(`/secrets/${encodeURIComponent(env)}/${encodeURIComponent(key)}`) as { value?: string };
      return { value: r?.value ?? "" };
    },
  },
  Mutation: {
    async scan(_: unknown, { content, filename }: { content: string; filename?: string }) {
      const r = await detectionFetch("/scan", { content, filename: filename ?? "unknown" }) as { findings?: Array<{ line: number; type: string; value: string; confidence?: number }> };
      return { findings: r?.findings ?? [] };
    },
    async setSecret(_: unknown, { env, key, value }: { env: string; key: string; value: string }) {
      await vaultFetch(`/secrets/${encodeURIComponent(env)}`, { method: "POST", body: { key, value } });
      return key;
    },
    async rotateSecret(_: unknown, { env, key }: { env: string; key: string }) {
      await vaultFetch(`/secrets/${encodeURIComponent(env)}/${encodeURIComponent(key)}/rotate`, { method: "PUT" });
      return key;
    },
  },
};

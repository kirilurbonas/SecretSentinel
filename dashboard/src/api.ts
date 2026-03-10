const API_BASE = typeof import.meta.env.VITE_API_URL === "string" ? import.meta.env.VITE_API_URL : "";

function getHeaders(): HeadersInit {
  const token = localStorage.getItem("sentinel_token");
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export async function listSecretKeys(env: string): Promise<string[]> {
  const r = await fetch(`${API_BASE}/api/vault/secrets/${encodeURIComponent(env)}`, {
    headers: getHeaders(),
  });
  if (!r.ok) throw new Error(await r.text());
  const data = (await r.json()) as { keys?: string[] };
  return data.keys ?? [];
}

export async function setSecret(env: string, key: string, value: string): Promise<void> {
  const r = await fetch(`${API_BASE}/api/vault/secrets/${encodeURIComponent(env)}`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ key, value }),
  });
  if (!r.ok) throw new Error(await r.text());
}

export async function rotateSecret(env: string, key: string): Promise<void> {
  const r = await fetch(
    `${API_BASE}/api/vault/secrets/${encodeURIComponent(env)}/${encodeURIComponent(key)}/rotate`,
    { method: "PUT", headers: getHeaders() }
  );
  if (!r.ok) throw new Error(await r.text());
}

/**
 * In-memory store for local dev when Vault is not configured.
 * Keys are "tenant/env/key".
 */
const memory = new Map<string, string>();

export function memoryGet(tenant: string, env: string, key: string): string | undefined {
  return memory.get(`${tenant}/${env}/${key}`);
}

export function memorySet(tenant: string, env: string, key: string, value: string): void {
  memory.set(`${tenant}/${env}/${key}`, value);
}

export function memoryListKeys(tenant: string, env: string): string[] {
  const prefix = `${tenant}/${env}/`;
  const keys: string[] = [];
  for (const k of memory.keys()) {
    if (k.startsWith(prefix)) keys.push(k.slice(prefix.length));
  }
  return keys.sort();
}

export function memoryDelete(tenant: string, env: string, key: string): void {
  memory.delete(`${tenant}/${env}/${key}`);
}

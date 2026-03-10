import vault from "node-vault";
import {
  memoryGet,
  memoryListKeys,
  memorySet,
} from "./store.js";

const useVault = Boolean(process.env.VAULT_ADDR);
let vaultClient: ReturnType<typeof vault> | null = null;

function getClient(): ReturnType<typeof vault> | null {
  if (!useVault) return null;
  if (!vaultClient) {
    vaultClient = vault({
      endpoint: process.env.VAULT_ADDR ?? "http://127.0.0.1:8200",
      token: process.env.VAULT_TOKEN,
    });
  }
  return vaultClient;
}

function secretPath(tenant: string, env: string, key: string): string {
  return `secret/data/${tenant}/${env}/${key}`;
}

export async function getSecret(
  tenant: string,
  env: string,
  key: string
): Promise<string | undefined> {
  const client = getClient();
  if (client) {
    try {
      const r = await client.read(secretPath(tenant, env, key));
      const data = (r as { data?: { data?: { value?: string } } })?.data?.data;
      return typeof data?.value === "string" ? data.value : undefined;
    } catch {
      return undefined;
    }
  }
  return memoryGet(tenant, env, key);
}

export async function setSecret(
  tenant: string,
  env: string,
  key: string,
  value: string
): Promise<void> {
  const client = getClient();
  if (client) {
    await client.write(secretPath(tenant, env, key), { data: { value } });
    return;
  }
  memorySet(tenant, env, key, value);
}

export async function listKeys(tenant: string, env: string): Promise<string[]> {
  const client = getClient();
  if (client) {
    try {
      const path = `secret/metadata/${tenant}/${env}`;
      const r = await (client as { list: (p: string) => Promise<{ data?: { keys?: string[] } }> }).list(path);
      const keys = r?.data?.keys ?? [];
      return keys.sort();
    } catch {
      return [];
    }
  }
  return memoryListKeys(tenant, env);
}

export async function triggerRotate(
  _tenant: string,
  _env: string,
  _key: string
): Promise<void> {
  // Stub: in production would enqueue to SQS or call rotation worker
  return;
}

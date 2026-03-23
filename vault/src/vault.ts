import vault from "node-vault";
import { memoryGet, memoryListKeys, memorySet } from "./store.js";
import { log } from "./logger.js";

let vaultClient: ReturnType<typeof vault> | null = null;

function getClient(): ReturnType<typeof vault> | null {
  if (!process.env.VAULT_ADDR) return null;
  if (!vaultClient) {
    vaultClient = vault({
      endpoint: process.env.VAULT_ADDR,
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
  key: string,
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
  value: string,
): Promise<void> {
  const client = getClient();
  if (client) {
    await client.write(secretPath(tenant, env, key), { data: { value } });
    return;
  }
  await memorySet(tenant, env, key, value);
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

/**
 * Rotates a secret using the appropriate provider based on key naming convention.
 * - Keys prefixed with "aws_iam_" use the AWS IAM provider.
 * - All other keys use the generic random-bytes provider.
 */
export async function triggerRotate(tenant: string, env: string, key: string): Promise<string> {
  const currentValue = await getSecret(tenant, env, key);
  if (currentValue === undefined) {
    throw new Error(`Secret not found: ${tenant}/${env}/${key}`);
  }

  let newValue: string;

  if (key.startsWith("aws_iam_")) {
    const { rotate } = await import("./providers/aws.js");
    newValue = await rotate(tenant, env, key, currentValue);
  } else {
    const { rotate } = await import("./providers/generic.js");
    newValue = await rotate(tenant, env, key, currentValue);
  }

  await setSecret(tenant, env, key, newValue);
  log.info("secret rotated", { tenant, env, key });
  return newValue;
}

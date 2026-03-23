import { Pool } from "pg";
import { encrypt, decrypt } from "./crypto.js";

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error("DATABASE_URL environment variable must be set");

const pool = new Pool({ connectionString: DATABASE_URL });
let ready = false;

async function ensureReady(): Promise<void> {
  if (ready) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vault_secrets (
      tenant TEXT NOT NULL,
      env    TEXT NOT NULL,
      key    TEXT NOT NULL,
      value  TEXT NOT NULL,
      PRIMARY KEY (tenant, env, key)
    )
  `);
  ready = true;
}

export async function memoryGet(tenant: string, env: string, key: string): Promise<string | undefined> {
  await ensureReady();
  const r = await pool.query<{ value: string }>(
    "SELECT value FROM vault_secrets WHERE tenant=$1 AND env=$2 AND key=$3",
    [tenant, env, key],
  );
  const row = r.rows[0];
  if (!row) return undefined;
  return decrypt(row.value);
}

export async function memorySet(tenant: string, env: string, key: string, value: string): Promise<void> {
  await ensureReady();
  await pool.query(
    `INSERT INTO vault_secrets (tenant, env, key, value)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (tenant, env, key) DO UPDATE SET value = EXCLUDED.value`,
    [tenant, env, key, encrypt(value)],
  );
}

export async function memoryListKeys(tenant: string, env: string): Promise<string[]> {
  await ensureReady();
  const r = await pool.query<{ key: string }>(
    "SELECT key FROM vault_secrets WHERE tenant=$1 AND env=$2 ORDER BY key",
    [tenant, env],
  );
  return r.rows.map((row) => row.key);
}

export async function memoryDelete(tenant: string, env: string, key: string): Promise<void> {
  await ensureReady();
  await pool.query(
    "DELETE FROM vault_secrets WHERE tenant=$1 AND env=$2 AND key=$3",
    [tenant, env, key],
  );
}

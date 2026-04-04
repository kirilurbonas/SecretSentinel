import { readFileSync, readdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

import { Pool } from "pg";

import { decrypt, encrypt } from "./crypto.js";
import { log } from "./logger.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error("DATABASE_URL environment variable must be set");

export const pool = new Pool({ connectionString: DATABASE_URL });

// ── Migrations ────────────────────────────────────────────────────────────────

export async function runMigrations(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const migrationsDir = join(__dirname, "..", "migrations");
  let files: string[];
  try {
    files = readdirSync(migrationsDir)
      .filter((f) => f.endsWith(".sql"))
      .sort();
  } catch {
    log.warn("migrations directory not found; skipping");
    return;
  }

  for (const file of files) {
    const version = file.replace(".sql", "");
    const existing = await pool.query(
      "SELECT 1 FROM schema_migrations WHERE version = $1",
      [version],
    );
    if ((existing.rowCount ?? 0) > 0) continue;

    const sql = readFileSync(join(migrationsDir, file), "utf8");
    await pool.query(sql);
    await pool.query("INSERT INTO schema_migrations (version) VALUES ($1)", [version]);
    log.info("migration applied", { version });
  }
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

export async function addAuditEntry(
  tenant: string,
  action: string,
  env: string,
  key: string,
  ip?: string,
): Promise<void> {
  try {
    await pool.query(
      "INSERT INTO audit_log (tenant, action, env, key, ip) VALUES ($1, $2, $3, $4, $5)",
      [tenant, action, env, key, ip ?? null],
    );
  } catch (err) {
    log.error("audit log write failed", { error: String(err) });
  }
}

export async function getAuditLog(
  tenant: string,
  env: string,
  limit = 100,
): Promise<Array<{ action: string; key: string; ip: string | null; created_at: string }>> {
  const r = await pool.query<{
    action: string;
    key: string;
    ip: string | null;
    created_at: Date;
  }>(
    `SELECT action, key, ip, created_at
     FROM audit_log
     WHERE tenant = $1 AND env = $2
     ORDER BY created_at DESC
     LIMIT $3`,
    [tenant, env, limit],
  );
  return r.rows.map((row) => ({ ...row, created_at: row.created_at.toISOString() }));
}

// ── Secret Versions ───────────────────────────────────────────────────────────

export async function getSecretVersions(
  tenant: string,
  env: string,
  key: string,
): Promise<Array<{ version: number; created_at: string }>> {
  const r = await pool.query<{ version: number; created_at: Date }>(
    `SELECT version, created_at
     FROM vault_secret_versions
     WHERE tenant = $1 AND env = $2 AND key = $3
     ORDER BY version DESC`,
    [tenant, env, key],
  );
  return r.rows.map((row) => ({ version: row.version, created_at: row.created_at.toISOString() }));
}

// ── Secrets CRUD ──────────────────────────────────────────────────────────────

export async function memoryGet(
  tenant: string,
  env: string,
  key: string,
): Promise<string | undefined> {
  const r = await pool.query<{ value: string }>(
    "SELECT value FROM vault_secrets WHERE tenant = $1 AND env = $2 AND key = $3",
    [tenant, env, key],
  );
  const row = r.rows[0];
  if (!row) return undefined;
  return decrypt(row.value);
}

export async function memorySet(
  tenant: string,
  env: string,
  key: string,
  value: string,
): Promise<void> {
  const encrypted = encrypt(value);

  // Determine next version number before upserting
  const versionResult = await pool.query<{ max: number | null }>(
    "SELECT MAX(version) AS max FROM vault_secret_versions WHERE tenant = $1 AND env = $2 AND key = $3",
    [tenant, env, key],
  );
  const nextVersion = (versionResult.rows[0]?.max ?? 0) + 1;

  await pool.query(
    "INSERT INTO vault_secret_versions (tenant, env, key, version, value) VALUES ($1, $2, $3, $4, $5)",
    [tenant, env, key, nextVersion, encrypted],
  );

  await pool.query(
    `INSERT INTO vault_secrets (tenant, env, key, value)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (tenant, env, key) DO UPDATE SET value = EXCLUDED.value`,
    [tenant, env, key, encrypted],
  );
}

export async function memoryListKeys(tenant: string, env: string): Promise<string[]> {
  const r = await pool.query<{ key: string }>(
    "SELECT key FROM vault_secrets WHERE tenant = $1 AND env = $2 ORDER BY key",
    [tenant, env],
  );
  return r.rows.map((row) => row.key);
}

export async function memoryDelete(tenant: string, env: string, key: string): Promise<void> {
  await pool.query(
    "DELETE FROM vault_secrets WHERE tenant = $1 AND env = $2 AND key = $3",
    [tenant, env, key],
  );
}

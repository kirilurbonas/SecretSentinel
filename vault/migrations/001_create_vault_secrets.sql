CREATE TABLE IF NOT EXISTS vault_secrets (
  tenant TEXT NOT NULL,
  env    TEXT NOT NULL,
  key    TEXT NOT NULL,
  value  TEXT NOT NULL,
  PRIMARY KEY (tenant, env, key)
);

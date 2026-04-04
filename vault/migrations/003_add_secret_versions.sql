CREATE TABLE IF NOT EXISTS vault_secret_versions (
  id         BIGSERIAL   PRIMARY KEY,
  tenant     TEXT        NOT NULL,
  env        TEXT        NOT NULL,
  key        TEXT        NOT NULL,
  version    INTEGER     NOT NULL,
  value      TEXT        NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secret_versions
  ON vault_secret_versions (tenant, env, key, version DESC);

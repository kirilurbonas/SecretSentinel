CREATE TABLE IF NOT EXISTS audit_log (
  id         BIGSERIAL PRIMARY KEY,
  tenant     TEXT        NOT NULL,
  action     TEXT        NOT NULL,
  env        TEXT        NOT NULL,
  key        TEXT        NOT NULL,
  ip         TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_env
  ON audit_log (tenant, env, created_at DESC);

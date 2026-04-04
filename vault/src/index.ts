import { randomUUID } from "crypto";

import express from "express";
import rateLimit from "express-rate-limit";

import { getTenantFromAuth } from "./auth.js";
import { log } from "./logger.js";
import { metricsHandler, metricsMiddleware } from "./metrics.js";
import { auditRouter } from "./routes/audit.js";
import { secretsRouter } from "./routes/secrets.js";
import { pool, runMigrations } from "./store.js";

const app = express();
app.use(express.json({ limit: "64kb" }));

// ── Prometheus metrics ────────────────────────────────────────────────────────
app.use(metricsMiddleware);

// ── Rate limiting ─────────────────────────────────────────────────────────────
app.use(
  rateLimit({
    windowMs: 60_000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests" },
  }),
);

// ── Request logging with request ID ──────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  const requestId = (req.headers["x-request-id"] as string | undefined) ?? randomUUID();
  res.set("X-Request-ID", requestId);
  res.on("finish", () => {
    log.info("request", {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      latencyMs: Date.now() - start,
      requestId,
    });
  });
  next();
});

// ── Health / readiness ────────────────────────────────────────────────────────
app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", db: "connected" });
  } catch (err) {
    log.error("health check db error", { error: String(err) });
    res.status(503).json({ status: "error", db: "disconnected" });
  }
});

app.get("/ready", (_req, res) => {
  res.json({ status: "ready" });
});

// ── Metrics ───────────────────────────────────────────────────────────────────
app.get("/metrics", metricsHandler);

// ── Auth middleware ───────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const tenant = getTenantFromAuth(req.get("Authorization") ?? req.get("X-Sentinel-Token"));
  if (!tenant) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  (req as express.Request & { tenant?: string }).tenant = tenant;
  next();
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.use("/secrets", secretsRouter);
app.use("/audit", auditRouter);

// ── Start ─────────────────────────────────────────────────────────────────────
const port = Number(process.env.PORT) || 3000;

await runMigrations();

const server = app.listen(port, "0.0.0.0", () => {
  log.info("SecretSentinel Vault started", { port });
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
let shuttingDown = false;

function shutdown(signal: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  log.info("shutting down", { signal });
  server.close(async () => {
    await pool.end().catch(() => undefined);
    process.exit(0);
  });
  // Force-kill after 10 s if drain takes too long
  setTimeout(() => {
    log.error("graceful shutdown timed out; forcing exit");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

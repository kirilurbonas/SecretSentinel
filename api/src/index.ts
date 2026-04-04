import { ApolloServer } from "@apollo/server";
import { expressMiddleware } from "@apollo/server/express4";
import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";

import { typeDefs } from "./graphql/schema.js";
import { resolvers } from "./graphql/resolvers.js";
import { log } from "./logger.js";
import { metricsHandler, metricsMiddleware } from "./metrics.js";
import {
  authMiddleware,
  proxyToDetection,
  proxyToVault,
  requestIdMiddleware,
} from "./middleware.js";

const DETECTION_URL = process.env.DETECTION_URL ?? "http://localhost:8000";
const VAULT_URL = process.env.VAULT_URL ?? "http://localhost:3000";
const PORT = Number(process.env.PORT) || 4000;

const app = express();

app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(",").map((s) => s.trim()) ?? [],
    credentials: true,
  }),
);
app.use(express.json({ limit: "1mb" }));

// ── Prometheus metrics ────────────────────────────────────────────────────────
app.use(metricsMiddleware);

// ── Rate limiting ─────────────────────────────────────────────────────────────
app.use(
  rateLimit({
    windowMs: 60_000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests" },
  }),
);

// ── Request ID propagation ────────────────────────────────────────────────────
app.use(requestIdMiddleware);

// ── Request logging ───────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    log.info("request", {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      latencyMs: Date.now() - start,
      requestId: res.getHeader("X-Request-ID"),
    });
  });
  next();
});

// ── Health / readiness ────────────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/ready", (_req, res) => {
  res.json({ status: "ready" });
});

// ── Metrics ───────────────────────────────────────────────────────────────────
app.get("/metrics", metricsHandler);

// ── Auth ──────────────────────────────────────────────────────────────────────
app.use(authMiddleware);

// ── Proxy routes ──────────────────────────────────────────────────────────────
app.use("/api/scan", proxyToDetection(DETECTION_URL));
app.use("/api/validate", proxyToDetection(DETECTION_URL));
app.use("/api/vault", proxyToVault(VAULT_URL));

// ── GraphQL ───────────────────────────────────────────────────────────────────
const server = new ApolloServer({ typeDefs, resolvers });
await server.start();
app.use("/graphql", expressMiddleware(server));

// ── Start ─────────────────────────────────────────────────────────────────────
const httpServer = app.listen(PORT, "0.0.0.0", () => {
  log.info("SecretSentinel API gateway started", { port: PORT });
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
let shuttingDown = false;

function shutdown(signal: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  log.info("shutting down", { signal });
  httpServer.close(async () => {
    await server.stop();
    process.exit(0);
  });
  setTimeout(() => {
    log.error("graceful shutdown timed out; forcing exit");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

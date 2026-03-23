import express from "express";
import { secretsRouter } from "./routes/secrets.js";
import { getTenantFromAuth } from "./auth.js";
import { log } from "./logger.js";

const app = express();
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    log.info("request", {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      latencyMs: Date.now() - start,
    });
  });
  next();
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use((req, res, next) => {
  const tenant = getTenantFromAuth(req.get("Authorization") ?? req.get("X-Sentinel-Token"));
  if (!tenant) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  (req as express.Request & { tenant?: string }).tenant = tenant;
  next();
});

app.use("/secrets", secretsRouter);

const port = Number(process.env.PORT) || 3000;
app.listen(port, "0.0.0.0", () => {
  log.info("SecretSentinel Vault started", { port });
});

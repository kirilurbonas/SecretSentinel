import express from "express";
import { secretsRouter } from "./routes/secrets.js";
import { getTenantFromAuth } from "./auth.js";

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  const tenant = getTenantFromAuth(req.get("Authorization") ?? req.get("X-Sentinel-Token"));
  if (!tenant && (req.path.startsWith("/secrets") || req.path === "/health")) {
    (req as express.Request & { tenant?: string }).tenant = "default";
  } else {
    (req as express.Request & { tenant?: string }).tenant = tenant ?? "default";
  }
  next();
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/secrets", secretsRouter);

const port = Number(process.env.PORT) || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log(`SecretSentinel Vault listening on ${port}`);
});

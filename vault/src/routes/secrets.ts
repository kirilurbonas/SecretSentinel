import type { Request, Response } from "express";
import { Router } from "express";

import {
  addAuditEntry,
  getSecretVersions,
  memoryDelete,
  memoryListKeys,
} from "../store.js";
import * as vault from "../vault.js";
import { secretOperations } from "../metrics.js";

export const secretsRouter = Router();

type ReqWithTenant = Request & { tenant?: string };

function tenant(req: ReqWithTenant): string {
  return req.tenant ?? "default";
}

function clientIP(req: Request): string {
  return (
    (req.headers["x-forwarded-for"] as string | undefined)?.split(",")[0]?.trim() ??
    req.socket.remoteAddress ??
    "unknown"
  );
}

// GET /secrets/:env/:key
secretsRouter.get("/:env/:key", async (req: ReqWithTenant, res: Response) => {
  const { env, key } = req.params;
  if (!env || !key) {
    res.status(400).json({ error: "env and key required" });
    return;
  }
  const t = tenant(req);
  const value = await vault.getSecret(t, env, key);
  if (value === undefined) {
    res.status(404).json({ error: "Secret not found", key });
    return;
  }
  await addAuditEntry(t, "read", env, key, clientIP(req));
  secretOperations.inc({ operation: "read" });
  res.json({ value });
});

// GET /secrets/:env/:key/versions
secretsRouter.get("/:env/:key/versions", async (req: ReqWithTenant, res: Response) => {
  const { env, key } = req.params;
  if (!env || !key) {
    res.status(400).json({ error: "env and key required" });
    return;
  }
  const versions = await getSecretVersions(tenant(req), env, key);
  res.json({ versions });
});

// GET /secrets/:env - list keys only
secretsRouter.get("/:env", async (req: ReqWithTenant, res: Response) => {
  const { env } = req.params;
  if (!env) {
    res.status(400).json({ error: "env required" });
    return;
  }
  const keys = await vault.listKeys(tenant(req), env);
  res.json({ keys });
});

// POST /secrets/:env - body: { key, value } or { secrets: [{ key, value }] }
secretsRouter.post("/:env", async (req: ReqWithTenant, res: Response) => {
  const { env } = req.params;
  if (!env) {
    res.status(400).json({ error: "env required" });
    return;
  }
  const body = req.body as {
    key?: string;
    value?: string;
    secrets?: Array<{ key: string; value: string }>;
  };
  const t = tenant(req);
  const ip = clientIP(req);

  if (body.key != null && body.value != null) {
    await vault.setSecret(t, env, body.key, body.value);
    await addAuditEntry(t, "write", env, body.key, ip);
    secretOperations.inc({ operation: "write" });
    res.status(201).json({ key: body.key });
    return;
  }
  if (Array.isArray(body.secrets)) {
    for (const s of body.secrets) {
      if (s?.key && typeof s.value === "string") {
        await vault.setSecret(t, env, s.key, s.value);
        await addAuditEntry(t, "write", env, s.key, ip);
      }
    }
    secretOperations.inc({ operation: "write" });
    res.status(201).json({ keys: body.secrets.map((s) => s.key) });
    return;
  }
  res.status(400).json({ error: "body must contain key and value, or secrets array" });
});

// DELETE /secrets/:env/:key
secretsRouter.delete("/:env/:key", async (req: ReqWithTenant, res: Response) => {
  const { env, key } = req.params;
  if (!env || !key) {
    res.status(400).json({ error: "env and key required" });
    return;
  }
  const t = tenant(req);
  await memoryDelete(t, env, key);
  await addAuditEntry(t, "delete", env, key, clientIP(req));
  secretOperations.inc({ operation: "delete" });
  res.json({ ok: true, key });
});

// PUT /secrets/:env/:key/rotate
secretsRouter.put("/:env/:key/rotate", async (req: ReqWithTenant, res: Response) => {
  const { env, key } = req.params;
  if (!env || !key) {
    res.status(400).json({ error: "env and key required" });
    return;
  }
  const t = tenant(req);
  try {
    await vault.triggerRotate(t, env, key);
    await addAuditEntry(t, "rotate", env, key, clientIP(req));
    secretOperations.inc({ operation: "rotate" });
    res.json({ ok: true, rotated: true, key });
  } catch (err) {
    res.status(500).json({ error: "Rotation failed", detail: String(err) });
  }
});

// GET /secrets/:env (list) duplicates handled; alias for listKeys covered above.
// Add bulk-list for all envs
secretsRouter.get("/", async (req: ReqWithTenant, res: Response) => {
  const keys = await memoryListKeys(tenant(req), "");
  res.json({ keys });
});

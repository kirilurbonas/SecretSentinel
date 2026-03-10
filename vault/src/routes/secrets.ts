import { Router, Request, Response } from "express";
import * as vault from "../vault.js";

export const secretsRouter = Router();

type ReqWithTenant = Request & { tenant?: string };

function tenant(req: ReqWithTenant): string {
  return req.tenant ?? "default";
}

// GET /secrets/:env/:key
secretsRouter.get("/:env/:key", async (req: ReqWithTenant, res: Response) => {
  const env = req.params.env;
  const key = req.params.key;
  if (!env || !key) {
    res.status(400).json({ error: "env and key required" });
    return;
  }
  const value = await vault.getSecret(tenant(req), env, key);
  if (value === undefined) {
    res.status(404).json({ error: "Secret not found", key });
    return;
  }
  res.json({ value });
});

// GET /secrets/:env - list keys only
secretsRouter.get("/:env", async (req: ReqWithTenant, res: Response) => {
  const env = req.params.env;
  if (!env) {
    res.status(400).json({ error: "env required" });
    return;
  }
  const keys = await vault.listKeys(tenant(req), env);
  res.json({ keys });
});

// POST /secrets/:env - body: { key, value } or { secrets: [{ key, value }] }
secretsRouter.post("/:env", async (req: ReqWithTenant, res: Response) => {
  const env = req.params.env;
  if (!env) {
    res.status(400).json({ error: "env required" });
    return;
  }
  const body = req.body as { key?: string; value?: string; secrets?: Array<{ key: string; value: string }> };
  const t = tenant(req);
  if (body.key != null && body.value != null) {
    await vault.setSecret(t, env, body.key, body.value);
    res.status(201).json({ key: body.key });
    return;
  }
  if (Array.isArray(body.secrets)) {
    for (const s of body.secrets) {
      if (s?.key && typeof s.value === "string") {
        await vault.setSecret(t, env, s.key, s.value);
      }
    }
    res.status(201).json({ keys: body.secrets.map((s) => s.key) });
    return;
  }
  res.status(400).json({ error: "body must contain key and value, or secrets array" });
});

// PUT /secrets/:env/:key/rotate
secretsRouter.put("/:env/:key/rotate", async (req: ReqWithTenant, res: Response) => {
  const env = req.params.env;
  const key = req.params.key;
  if (!env || !key) {
    res.status(400).json({ error: "env and key required" });
    return;
  }
  await vault.triggerRotate(tenant(req), env, key);
  res.json({ ok: true, message: "Rotation triggered" });
});

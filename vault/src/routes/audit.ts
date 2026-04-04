import type { Request, Response } from "express";
import { Router } from "express";

import { getAuditLog } from "../store.js";

export const auditRouter = Router();

type ReqWithTenant = Request & { tenant?: string };

function tenant(req: ReqWithTenant): string {
  return req.tenant ?? "default";
}

// GET /audit/:env[?limit=N]
auditRouter.get("/:env", async (req: ReqWithTenant, res: Response) => {
  const { env } = req.params;
  if (!env) {
    res.status(400).json({ error: "env required" });
    return;
  }
  const limit = Math.min(Number(req.query.limit) || 100, 1000);
  const entries = await getAuditLog(tenant(req), env, limit);
  res.json({ entries });
});

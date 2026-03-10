import type { Request, Response, NextFunction } from "express";

export type AuthContext = { userId?: string; token?: string };

export function authMiddleware(req: Request, _res: Response, next: NextFunction): void {
  const auth = req.get("Authorization");
  const token = auth?.startsWith("Bearer ") ? auth.slice(7).trim() : req.get("X-Sentinel-Token") ?? "";
  (req as Request & AuthContext).token = token || undefined;
  if (token) {
    try {
      const parts = token.split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString()) as { sub?: string };
        (req as Request & AuthContext).userId = payload.sub ?? "anonymous";
      } else {
        (req as Request & AuthContext).userId = "bearer";
      }
    } catch {
      (req as Request & AuthContext).userId = "bearer";
    }
  }
  next();
}

function forwardHeaders(req: Request): Record<string, string> {
  const h: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const auth = req.get("Authorization");
  if (auth) h["Authorization"] = auth;
  const token = req.get("X-Sentinel-Token");
  if (token) h["X-Sentinel-Token"] = token;
  return h;
}

export function proxyToDetection(baseUrl: string) {
  const url = baseUrl.replace(/\/$/, "");
  return async (req: Request, res: Response): Promise<void> => {
    const path = (req as Request & { params?: { "0"?: string } }).params?.["0"] ?? req.path;
    const target = `${url}${path.replace(/^\/api\/scan/, "")}`;
    try {
      const body = req.method !== "GET" && req.body ? JSON.stringify(req.body) : undefined;
      const r = await fetch(target, {
        method: req.method,
        headers: forwardHeaders(req),
        body,
      });
      const text = await r.text();
      res.status(r.status).set("Content-Type", r.headers.get("Content-Type") ?? "application/json").send(text);
    } catch (e) {
      res.status(502).json({ error: "Detection service unavailable", detail: String(e) });
    }
  };
}

export function proxyToVault(baseUrl: string) {
  const url = baseUrl.replace(/\/$/, "");
  return async (req: Request, res: Response): Promise<void> => {
    const path = req.path.replace(/^\/api\/vault/, "") || "/secrets";
    const target = `${url}${path}`;
    try {
      const body = req.method !== "GET" && req.body && Object.keys(req.body).length > 0 ? JSON.stringify(req.body) : undefined;
      const r = await fetch(target, {
        method: req.method,
        headers: forwardHeaders(req),
        body,
      });
      const text = await r.text();
      res.status(r.status).set("Content-Type", r.headers.get("Content-Type") ?? "application/json").send(text);
    } catch (e) {
      res.status(502).json({ error: "Vault service unavailable", detail: String(e) });
    }
  };
}

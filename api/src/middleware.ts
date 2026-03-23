import { createHmac, timingSafeEqual } from "crypto";
import type { Request, Response, NextFunction } from "express";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("JWT_SECRET environment variable must be set");

export type AuthContext = { userId?: string; token?: string };

function verifyHmacJwt(headerB64: string, payloadB64: string, signatureB64: string): boolean {
  const expected = createHmac("sha256", JWT_SECRET!)
    .update(`${headerB64}.${payloadB64}`)
    .digest("base64url");
  try {
    return timingSafeEqual(Buffer.from(expected), Buffer.from(signatureB64));
  } catch {
    return false;
  }
}

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const auth = req.get("Authorization");
  const token = auth?.startsWith("Bearer ") ? auth.slice(7).trim() : req.get("X-Sentinel-Token") ?? "";
  (req as Request & AuthContext).token = token || undefined;
  if (token) {
    const parts = token.split(".");
    if (parts.length === 3) {
      const [header, payload, signature] = parts;
      if (!verifyHmacJwt(header!, payload!, signature!)) {
        res.status(401).json({ error: "invalid token" });
        return;
      }
      try {
        const parsed = JSON.parse(Buffer.from(payload!, "base64url").toString()) as { sub?: string };
        (req as Request & AuthContext).userId = parsed.sub ?? "anonymous";
      } catch {
        res.status(401).json({ error: "invalid token" });
        return;
      }
    } else {
      // Non-JWT opaque token — accept but no userId
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
    const normalised = path.replace(/^\/api\/(scan|validate)/, "/$1");
    const target = `${url}${normalised}`;
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

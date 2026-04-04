import { createHmac, randomUUID, timingSafeEqual } from "crypto";
import type { NextFunction, Request, Response } from "express";

import { log } from "./logger.js";
import { proxyErrors } from "./metrics.js";

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
  const token =
    auth?.startsWith("Bearer ") ? auth.slice(7).trim() : (req.get("X-Sentinel-Token") ?? "");
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
        const parsed = JSON.parse(
          Buffer.from(payload!, "base64url").toString(),
        ) as { sub?: string };
        (req as Request & AuthContext).userId = parsed.sub ?? "anonymous";
      } catch {
        res.status(401).json({ error: "invalid token" });
        return;
      }
    } else {
      // Non-JWT opaque token — reject for security
      res.status(401).json({ error: "invalid token format" });
      return;
    }
  }
  next();
}

// ── Request ID propagation ─────────────────────────────────────────────────────

export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const requestId =
    (req.headers["x-request-id"] as string | undefined) ?? randomUUID();
  req.headers["x-request-id"] = requestId;
  res.set("X-Request-ID", requestId);
  next();
}

// ── Circuit Breaker ────────────────────────────────────────────────────────────

type CircuitState = "closed" | "open" | "half-open";

interface CircuitBreaker {
  state: CircuitState;
  failures: number;
  lastFailure: number;
}

const FAILURE_THRESHOLD = 5;
const RESET_TIMEOUT_MS = 30_000;

function createBreaker(): CircuitBreaker {
  return { state: "closed", failures: 0, lastFailure: 0 };
}

function isAllowed(cb: CircuitBreaker): boolean {
  if (cb.state === "closed") return true;
  if (cb.state === "open") {
    if (Date.now() - cb.lastFailure >= RESET_TIMEOUT_MS) {
      cb.state = "half-open";
      return true;
    }
    return false;
  }
  return true; // half-open: allow one probe
}

function recordSuccess(cb: CircuitBreaker): void {
  cb.failures = 0;
  cb.state = "closed";
}

function recordFailure(cb: CircuitBreaker, upstream: string): void {
  cb.failures++;
  cb.lastFailure = Date.now();
  if (cb.failures >= FAILURE_THRESHOLD) {
    cb.state = "open";
    log.warn("circuit breaker opened", { upstream, failures: cb.failures });
  }
}

// ── Proxy helpers ──────────────────────────────────────────────────────────────

function forwardHeaders(req: Request): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  const auth = req.get("Authorization");
  if (auth) h["Authorization"] = auth;
  const token = req.get("X-Sentinel-Token");
  if (token) h["X-Sentinel-Token"] = token;
  const requestId = req.get("X-Request-ID");
  if (requestId) h["X-Request-ID"] = requestId;
  return h;
}

const detectionBreaker = createBreaker();
const vaultBreaker = createBreaker();

export function proxyToDetection(baseUrl: string) {
  const url = baseUrl.replace(/\/$/, "");
  return async (req: Request, res: Response): Promise<void> => {
    if (!isAllowed(detectionBreaker)) {
      proxyErrors.inc({ upstream: "detection" });
      res.status(503).json({ error: "Detection service circuit open; retry later" });
      return;
    }
    const path = (req as Request & { params?: { "0"?: string } }).params?.["0"] ?? req.path;
    const normalised = path.replace(/^\/api\/(scan|validate)/, "/$1");
    const target = `${url}${normalised}`;
    try {
      const body =
        req.method !== "GET" && req.body ? JSON.stringify(req.body) : undefined;
      const r = await fetch(target, {
        method: req.method,
        headers: forwardHeaders(req),
        body,
      });
      recordSuccess(detectionBreaker);
      const text = await r.text();
      res
        .status(r.status)
        .set("Content-Type", r.headers.get("Content-Type") ?? "application/json")
        .send(text);
    } catch (e) {
      recordFailure(detectionBreaker, "detection");
      proxyErrors.inc({ upstream: "detection" });
      res.status(502).json({ error: "Detection service unavailable", detail: String(e) });
    }
  };
}

export function proxyToVault(baseUrl: string) {
  const url = baseUrl.replace(/\/$/, "");
  return async (req: Request, res: Response): Promise<void> => {
    if (!isAllowed(vaultBreaker)) {
      proxyErrors.inc({ upstream: "vault" });
      res.status(503).json({ error: "Vault service circuit open; retry later" });
      return;
    }
    const path = req.path.replace(/^\/api\/vault/, "") || "/secrets";
    const target = `${url}${path}`;
    try {
      const body =
        req.method !== "GET" && req.body && Object.keys(req.body).length > 0
          ? JSON.stringify(req.body)
          : undefined;
      const r = await fetch(target, {
        method: req.method,
        headers: forwardHeaders(req),
        body,
      });
      recordSuccess(vaultBreaker);
      const text = await r.text();
      res
        .status(r.status)
        .set("Content-Type", r.headers.get("Content-Type") ?? "application/json")
        .send(text);
    } catch (e) {
      recordFailure(vaultBreaker, "vault");
      proxyErrors.inc({ upstream: "vault" });
      res.status(502).json({ error: "Vault service unavailable", detail: String(e) });
    }
  };
}

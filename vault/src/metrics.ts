import type { NextFunction, Request, Response } from "express";
import { Counter, Histogram, Registry, collectDefaultMetrics } from "prom-client";

export const register = new Registry();
collectDefaultMetrics({ register });

export const httpRequestDuration = new Histogram({
  name: "vault_http_request_duration_seconds",
  help: "Duration of vault HTTP requests in seconds",
  labelNames: ["method", "route", "status_code"],
  buckets: [0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
  registers: [register],
});

export const secretOperations = new Counter({
  name: "vault_secret_operations_total",
  help: "Total number of vault secret operations",
  labelNames: ["operation"],
  registers: [register],
});

export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    httpRequestDuration.observe(
      {
        method: req.method,
        route: (req.route as { path?: string } | undefined)?.path ?? req.path,
        status_code: String(res.statusCode),
      },
      durationMs / 1000,
    );
  });
  next();
}

export async function metricsHandler(_req: Request, res: Response): Promise<void> {
  res.set("Content-Type", register.contentType);
  res.send(await register.metrics());
}

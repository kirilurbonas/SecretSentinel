import { Counter, Gauge, Registry, collectDefaultMetrics } from "prom-client";

export const register = new Registry();
collectDefaultMetrics({ register });

export const rotationSuccesses = new Counter({
  name: "rotation_successes_total",
  help: "Total successful secret rotations",
  registers: [register],
});

export const rotationFailures = new Counter({
  name: "rotation_failures_total",
  help: "Total failed secret rotation attempts",
  registers: [register],
});

export const rotationDeadLettered = new Counter({
  name: "rotation_dead_lettered_total",
  help: "Total rotation events dead-lettered after max retries",
  registers: [register],
});

export const activeRetries = new Gauge({
  name: "rotation_active_retries",
  help: "Number of messages currently being retried",
  registers: [register],
});

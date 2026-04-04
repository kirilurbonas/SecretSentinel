import { createHmac } from "crypto";
import { writeFileSync } from "fs";

import {
  ChangeMessageVisibilityCommand,
  DeleteMessageCommand,
  ReceiveMessageCommand,
  SQSClient,
} from "@aws-sdk/client-sqs";

import { log } from "./logger.js";
import {
  activeRetries,
  register,
  rotationDeadLettered,
  rotationFailures,
  rotationSuccesses,
} from "./metrics.js";

const VAULT_URL = (process.env.VAULT_URL ?? "http://localhost:3000").replace(/\/$/, "");
const SQS_QUEUE_URL = process.env.SQS_ROTATION_QUEUE_URL;
const SQS_REGION = process.env.AWS_REGION ?? "us-east-1";
const VAULT_AUTH_SECRET = process.env.VAULT_AUTH_SECRET ?? "";
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS) || 20_000;
const MAX_RETRIES = Number(process.env.MAX_ROTATION_RETRIES) || 5;
const HEALTH_FILE = "/tmp/sentinel-alive";
const METRICS_PORT = Number(process.env.METRICS_PORT) || 9090;

// Per-message retry tracking: messageId → retry count
export const retryCount = new Map<string, number>();

let isShuttingDown = false;

function generateVaultToken(tenantId: string): string {
  const sig = createHmac("sha256", VAULT_AUTH_SECRET).update(tenantId).digest("base64url");
  return `${tenantId}.${sig}`;
}

export interface RotationEvent {
  env: string;
  key: string;
  tenant?: string;
}

export function parseBody(body: string): RotationEvent | null {
  try {
    const o = JSON.parse(body) as unknown;
    if (o && typeof o === "object" && "env" in o && "key" in o) {
      const env = String((o as { env: unknown }).env);
      const key = String((o as { key: unknown }).key);
      const raw = o as Record<string, unknown>;
      const tenant =
        raw["tenant"] != null ? String(raw["tenant"]) : undefined;
      if (env && key) return { env, key, tenant };
    }
  } catch {
    // ignore parse errors
  }
  return null;
}

export async function triggerVaultRotate(ev: RotationEvent): Promise<void> {
  const tenantId = ev.tenant ?? "default";
  const url = `${VAULT_URL}/secrets/${encodeURIComponent(ev.env)}/${encodeURIComponent(ev.key)}/rotate`;
  const token = generateVaultToken(tenantId);
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  });
  if (!res.ok) {
    throw new Error(`Vault rotate returned ${res.status}: ${await res.text()}`);
  }
}

export async function poll(client: SQSClient): Promise<void> {
  if (!SQS_QUEUE_URL) {
    log.warn("SQS_ROTATION_QUEUE_URL not set; rotation worker idle (stub mode)");
    return;
  }
  const result = await client.send(
    new ReceiveMessageCommand({
      QueueUrl: SQS_QUEUE_URL,
      MaxNumberOfMessages: 10,
      WaitTimeSeconds: 15,
      VisibilityTimeout: 60,
    }),
  );
  const messages = result.Messages ?? [];
  for (const msg of messages) {
    if (!msg.ReceiptHandle || !msg.MessageId) continue;

    const ev = msg.Body ? parseBody(msg.Body) : null;
    if (!ev) {
      log.error("invalid rotation event body", { body: msg.Body });
      await client.send(
        new DeleteMessageCommand({ QueueUrl: SQS_QUEUE_URL, ReceiptHandle: msg.ReceiptHandle }),
      );
      continue;
    }

    const attempts = retryCount.get(msg.MessageId) ?? 0;

    if (attempts >= MAX_RETRIES) {
      log.error("rotation dead-lettered after max retries", {
        env: ev.env,
        key: ev.key,
        tenant: ev.tenant,
        attempts,
      });
      retryCount.delete(msg.MessageId);
      activeRetries.set(retryCount.size);
      rotationDeadLettered.inc();
      await client.send(
        new DeleteMessageCommand({ QueueUrl: SQS_QUEUE_URL, ReceiptHandle: msg.ReceiptHandle }),
      );
      continue;
    }

    try {
      await triggerVaultRotate(ev);
      log.info("rotation triggered", { env: ev.env, key: ev.key, tenant: ev.tenant });
      retryCount.delete(msg.MessageId);
      activeRetries.set(retryCount.size);
      rotationSuccesses.inc();
      await client.send(
        new DeleteMessageCommand({ QueueUrl: SQS_QUEUE_URL, ReceiptHandle: msg.ReceiptHandle }),
      );
    } catch (err) {
      const nextAttempt = attempts + 1;
      retryCount.set(msg.MessageId, nextAttempt);
      activeRetries.set(retryCount.size);
      rotationFailures.inc();
      const backoffSeconds = Math.min(Math.pow(2, nextAttempt), 43200);
      log.error("rotation failed", {
        env: ev.env,
        key: ev.key,
        tenant: ev.tenant,
        attempt: nextAttempt,
        backoffSeconds,
        error: String(err),
      });
      await client.send(
        new ChangeMessageVisibilityCommand({
          QueueUrl: SQS_QUEUE_URL,
          ReceiptHandle: msg.ReceiptHandle,
          VisibilityTimeout: backoffSeconds,
        }),
      );
    }
  }
}

async function startMetricsServer(): Promise<void> {
  // Minimal HTTP server for Prometheus scraping
  const { createServer } = await import("http");
  const metricsServer = createServer(async (req, res) => {
    if (req.url === "/metrics" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": register.contentType });
      res.end(await register.metrics());
    } else {
      res.writeHead(404);
      res.end("Not found");
    }
  });
  metricsServer.listen(METRICS_PORT, "0.0.0.0", () => {
    log.info("rotation metrics server started", { port: METRICS_PORT });
  });
}

async function run(): Promise<void> {
  log.info("SecretSentinel rotation worker started");
  if (SQS_QUEUE_URL) {
    log.info("polling SQS", { queue: SQS_QUEUE_URL });
  }

  await startMetricsServer();

  const client = new SQSClient({ region: SQS_REGION });

  // Graceful shutdown
  function shutdown(signal: string): void {
    if (isShuttingDown) return;
    isShuttingDown = true;
    log.info("shutting down", { signal });
    // Allow current poll to complete
    setTimeout(() => process.exit(0), 5_000).unref();
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  for (;;) {
    if (isShuttingDown) break;
    try {
      await poll(client);
      writeFileSync(HEALTH_FILE, String(Date.now()));
    } catch (err) {
      log.error("poll error", { error: String(err) });
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

run();

import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from "@aws-sdk/client-sqs";

const VAULT_URL = (process.env.VAULT_URL ?? "http://localhost:3000").replace(/\/$/, "");
const SQS_QUEUE_URL = process.env.SQS_ROTATION_QUEUE_URL;
const SQS_REGION = process.env.AWS_REGION ?? "us-east-1";
const SENTINEL_TOKEN = process.env.SENTINEL_TOKEN ?? "";
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS) || 20_000;

interface RotationEvent {
  env: string;
  key: string;
  tenant?: string;
}

function parseBody(body: string): RotationEvent | null {
  try {
    const o = JSON.parse(body) as unknown;
    if (o && typeof o === "object" && "env" in o && "key" in o) {
      const env = String((o as { env: unknown }).env);
      const key = String((o as { key: unknown }).key);
      const tenant = (o as { tenant?: unknown }).tenant != null ? String((o as { tenant: unknown }).tenant) : undefined;
      if (env && key) return { env, key, tenant };
    }
  } catch {
    // ignore
  }
  return null;
}

async function triggerVaultRotate(ev: RotationEvent): Promise<void> {
  const tenant = ev.tenant ?? "default";
  const url = `${VAULT_URL}/secrets/${encodeURIComponent(ev.env)}/${encodeURIComponent(ev.key)}/rotate`;
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      ...(SENTINEL_TOKEN ? { Authorization: `Bearer ${SENTINEL_TOKEN}` } : {}),
      ...(tenant !== "default" ? { "X-Sentinel-Tenant": tenant } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Vault rotate returned ${res.status}: ${await res.text()}`);
  }
}

async function poll(): Promise<void> {
  if (!SQS_QUEUE_URL) {
    console.warn("SQS_ROTATION_QUEUE_URL not set; rotation worker idle (stub mode).");
    return;
  }
  const client = new SQSClient({ region: SQS_REGION });
  const result = await client.send(
    new ReceiveMessageCommand({
      QueueUrl: SQS_QUEUE_URL,
      MaxNumberOfMessages: 10,
      WaitTimeSeconds: 15,
      VisibilityTimeout: 60,
    })
  );
  const messages = result.Messages ?? [];
  for (const msg of messages) {
    if (!msg.ReceiptHandle) continue;
    const ev = msg.Body ? parseBody(msg.Body) : null;
    if (!ev) {
      console.error("Invalid rotation event body:", msg.Body);
      await client.send(new DeleteMessageCommand({ QueueUrl: SQS_QUEUE_URL, ReceiptHandle: msg.ReceiptHandle }));
      continue;
    }
    try {
      await triggerVaultRotate(ev);
      console.log("Rotation triggered:", ev.env, ev.key);
      await client.send(new DeleteMessageCommand({ QueueUrl: SQS_QUEUE_URL, ReceiptHandle: msg.ReceiptHandle }));
    } catch (err) {
      console.error("Rotation failed:", ev, err);
      // Do not delete message so it can be retried
    }
  }
}

async function run(): Promise<void> {
  console.log("SecretSentinel rotation worker started.");
  if (SQS_QUEUE_URL) {
    console.log("Polling SQS:", SQS_QUEUE_URL);
  }
  for (;;) {
    try {
      await poll();
    } catch (err) {
      console.error("Poll error:", err);
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

run();

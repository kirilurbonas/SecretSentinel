import { describe, it, expect, vi, beforeEach } from "vitest";

// Set required env vars before importing the module
process.env.VAULT_AUTH_SECRET = "test-secret";
process.env.SQS_ROTATION_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789/test-queue";

import { parseBody, retryCount, type RotationEvent } from "./index.js";

describe("parseBody", () => {
  it("parses a valid rotation event with tenant", () => {
    const body = JSON.stringify({ env: "prod", key: "API_KEY", tenant: "acme" });
    const result = parseBody(body);
    expect(result).toEqual({ env: "prod", key: "API_KEY", tenant: "acme" });
  });

  it("parses a rotation event without tenant", () => {
    const body = JSON.stringify({ env: "dev", key: "DB_PASS" });
    const result = parseBody(body);
    expect(result).toEqual({ env: "dev", key: "DB_PASS", tenant: undefined });
  });

  it("returns null for missing env", () => {
    const body = JSON.stringify({ key: "API_KEY" });
    expect(parseBody(body)).toBeNull();
  });

  it("returns null for missing key", () => {
    const body = JSON.stringify({ env: "prod" });
    expect(parseBody(body)).toBeNull();
  });

  it("returns null for invalid JSON", () => {
    expect(parseBody("not-json")).toBeNull();
    expect(parseBody("{broken")).toBeNull();
  });

  it("returns null for an empty string", () => {
    expect(parseBody("")).toBeNull();
  });

  it("returns null for empty env value", () => {
    const body = JSON.stringify({ env: "", key: "API_KEY" });
    expect(parseBody(body)).toBeNull();
  });

  it("returns null for empty key value", () => {
    const body = JSON.stringify({ env: "prod", key: "" });
    expect(parseBody(body)).toBeNull();
  });

  it("coerces numeric env and key to strings", () => {
    const body = JSON.stringify({ env: 42, key: 100 });
    const result = parseBody(body);
    expect(result?.env).toBe("42");
    expect(result?.key).toBe("100");
  });
});

describe("retryCount", () => {
  beforeEach(() => {
    retryCount.clear();
  });

  it("starts empty", () => {
    expect(retryCount.size).toBe(0);
  });

  it("tracks retries per message ID", () => {
    retryCount.set("msg-1", 1);
    retryCount.set("msg-2", 3);
    expect(retryCount.get("msg-1")).toBe(1);
    expect(retryCount.get("msg-2")).toBe(3);
    expect(retryCount.get("msg-3")).toBeUndefined();
  });

  it("clears individual messages on success", () => {
    retryCount.set("msg-1", 2);
    retryCount.delete("msg-1");
    expect(retryCount.has("msg-1")).toBe(false);
  });
});

describe("triggerVaultRotate", () => {
  it("calls vault rotate endpoint with correct URL and auth", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);

    const { triggerVaultRotate } = await import("./index.js");
    const ev: RotationEvent = { env: "prod", key: "API_KEY", tenant: "acme" };
    await triggerVaultRotate(ev);

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/secrets/prod/API_KEY/rotate");
    expect((options.headers as Record<string, string>)["Authorization"]).toMatch(/^Bearer acme\./);
    expect(options.method).toBe("PUT");

    vi.unstubAllGlobals();
  });

  it("throws when vault returns non-OK status", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => "internal error",
    });
    vi.stubGlobal("fetch", fetchMock);

    const { triggerVaultRotate } = await import("./index.js");
    await expect(
      triggerVaultRotate({ env: "dev", key: "SECRET", tenant: "test" }),
    ).rejects.toThrow("500");

    vi.unstubAllGlobals();
  });

  it("uses 'default' tenant when tenant is undefined", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);

    const { triggerVaultRotate } = await import("./index.js");
    await triggerVaultRotate({ env: "dev", key: "KEY" });

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((options.headers as Record<string, string>)["Authorization"]).toMatch(/^Bearer default\./);

    vi.unstubAllGlobals();
  });
});

import { describe, it, expect } from "vitest";
import { createHmac } from "crypto";

const TEST_AUTH_SECRET = "test-vault-auth-secret";
process.env.VAULT_AUTH_SECRET = TEST_AUTH_SECRET;

const { getTenantFromAuth, generateVaultToken } = await import("./auth.js");

function makeToken(tenantId: string, secret = TEST_AUTH_SECRET): string {
  const sig = createHmac("sha256", secret).update(tenantId).digest("base64url");
  return `${tenantId}.${sig}`;
}

describe("generateVaultToken", () => {
  it("generates a token that verifies correctly", () => {
    const token = generateVaultToken("acme");
    expect(getTenantFromAuth(`Bearer ${token}`)).toBe("acme");
  });
});

describe("getTenantFromAuth", () => {
  it("returns the tenant ID for a valid Bearer token", () => {
    const token = makeToken("tenant-abc");
    expect(getTenantFromAuth(`Bearer ${token}`)).toBe("tenant-abc");
  });

  it("returns the tenant ID for a raw token (no Bearer prefix)", () => {
    const token = makeToken("tenant-xyz");
    expect(getTenantFromAuth(token)).toBe("tenant-xyz");
  });

  it("returns undefined for a missing auth header", () => {
    expect(getTenantFromAuth(undefined)).toBeUndefined();
    expect(getTenantFromAuth("")).toBeUndefined();
    expect(getTenantFromAuth("   ")).toBeUndefined();
  });

  it("returns undefined when the signature is wrong", () => {
    const token = makeToken("tenant-abc", "wrong-secret");
    expect(getTenantFromAuth(`Bearer ${token}`)).toBeUndefined();
  });

  it("returns undefined for a tampered tenant ID", () => {
    const token = makeToken("tenant-abc");
    // Replace tenant ID, keep signature
    const parts = token.split(".");
    const tampered = `evil-tenant.${parts[1]}`;
    expect(getTenantFromAuth(`Bearer ${tampered}`)).toBeUndefined();
  });

  it("returns undefined if there is no dot separator", () => {
    expect(getTenantFromAuth("Bearer nodot")).toBeUndefined();
  });

  it("returns undefined if tenant ID is empty", () => {
    const sig = createHmac("sha256", TEST_AUTH_SECRET).update("").digest("base64url");
    expect(getTenantFromAuth(`Bearer .${sig}`)).toBeUndefined();
  });
});

import { createHmac, timingSafeEqual } from "crypto";

const VAULT_AUTH_SECRET = process.env.VAULT_AUTH_SECRET;
if (!VAULT_AUTH_SECRET) throw new Error("VAULT_AUTH_SECRET environment variable must be set");

/**
 * Generates a signed vault auth token for a given tenant.
 * Format: "<tenantId>.<base64url-HMAC-SHA256(tenantId, VAULT_AUTH_SECRET)>"
 */
export function generateVaultToken(tenantId: string): string {
  const sig = createHmac("sha256", VAULT_AUTH_SECRET!)
    .update(tenantId)
    .digest("base64url");
  return `${tenantId}.${sig}`;
}

/**
 * Verifies a vault auth token and returns the tenant ID, or undefined if invalid.
 */
export function getTenantFromAuth(auth: string | undefined): string | undefined {
  if (!auth?.trim()) return undefined;
  const raw = auth.startsWith("Bearer ") ? auth.slice(7).trim() : auth.trim();

  const dotIdx = raw.lastIndexOf(".");
  if (dotIdx === -1) return undefined;

  const tenantId = raw.slice(0, dotIdx);
  const providedSig = raw.slice(dotIdx + 1);

  if (!tenantId) return undefined;

  const expectedSig = createHmac("sha256", VAULT_AUTH_SECRET!)
    .update(tenantId)
    .digest("base64url");

  try {
    if (!timingSafeEqual(Buffer.from(expectedSig), Buffer.from(providedSig))) {
      return undefined;
    }
  } catch {
    return undefined;
  }

  return tenantId;
}

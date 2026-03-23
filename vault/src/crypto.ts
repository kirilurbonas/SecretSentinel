import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "crypto";

const VAULT_ENCRYPTION_KEY = process.env.VAULT_ENCRYPTION_KEY;
if (!VAULT_ENCRYPTION_KEY) throw new Error("VAULT_ENCRYPTION_KEY environment variable must be set");

// Fixed application-specific salt — the actual secret is VAULT_ENCRYPTION_KEY.
const SALT = Buffer.from("secretsentinel-vault-v1");
const KEY = scryptSync(VAULT_ENCRYPTION_KEY, SALT, 32) as Buffer;

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Returns "<iv_hex>:<authTag_hex>:<ciphertext_hex>".
 */
export function encrypt(plaintext: string): string {
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv("aes-256-gcm", KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted.toString("hex")}`;
}

/**
 * Decrypts a ciphertext string produced by encrypt().
 * Returns undefined if the format is invalid or decryption fails (tampered data).
 */
export function decrypt(ciphertext: string): string | undefined {
  try {
    const parts = ciphertext.split(":");
    if (parts.length !== 3) return undefined;
    const [ivHex, authTagHex, encryptedHex] = parts;
    const iv = Buffer.from(ivHex!, "hex");
    const authTag = Buffer.from(authTagHex!, "hex");
    const encrypted = Buffer.from(encryptedHex!, "hex");
    const decipher = createDecipheriv("aes-256-gcm", KEY, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(encrypted).toString("utf8") + decipher.final("utf8");
  } catch {
    return undefined;
  }
}

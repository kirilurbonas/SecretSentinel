import { describe, it, expect, beforeAll } from "vitest";

process.env.VAULT_ENCRYPTION_KEY = "test-encryption-key-for-unit-tests";

const { encrypt, decrypt } = await import("./crypto.js");

describe("encrypt / decrypt", () => {
  it("roundtrip: decrypt(encrypt(x)) === x", () => {
    const plain = "super-secret-value";
    expect(decrypt(encrypt(plain))).toBe(plain);
  });

  it("produces different ciphertext on each call (unique IV)", () => {
    const plain = "same-value";
    const c1 = encrypt(plain);
    const c2 = encrypt(plain);
    expect(c1).not.toBe(c2);
    // Both still decrypt correctly
    expect(decrypt(c1)).toBe(plain);
    expect(decrypt(c2)).toBe(plain);
  });

  it("returns undefined for tampered ciphertext", () => {
    const ct = encrypt("value");
    const parts = ct.split(":");
    // Flip a byte in the ciphertext portion
    parts[2] = parts[2]!.slice(0, -2) + "00";
    expect(decrypt(parts.join(":"))).toBeUndefined();
  });

  it("returns undefined for malformed input", () => {
    expect(decrypt("not-valid")).toBeUndefined();
    expect(decrypt("a:b")).toBeUndefined();
    expect(decrypt("")).toBeUndefined();
  });

  it("handles empty string plaintext", () => {
    expect(decrypt(encrypt(""))).toBe("");
  });

  it("handles unicode plaintext", () => {
    const plain = "🔑 секрет";
    expect(decrypt(encrypt(plain))).toBe(plain);
  });
});

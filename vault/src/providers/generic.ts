import { randomBytes } from "crypto";

/**
 * Generic rotation provider: generates a cryptographically random 48-byte value.
 */
export async function rotate(
  _tenant: string,
  _env: string,
  _key: string,
  _currentValue: string,
): Promise<string> {
  return randomBytes(48).toString("base64url");
}

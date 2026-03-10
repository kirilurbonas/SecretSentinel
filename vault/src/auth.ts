/**
 * Derives tenant ID from Authorization header (Bearer token) or X-Sentinel-Token.
 * For now we use a simple convention: token format "tenant:<id>" or just use "default".
 */
export function getTenantFromAuth(auth: string | undefined): string | undefined {
  if (!auth?.trim()) return undefined;
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : auth.trim();
  if (token.startsWith("tenant:")) return token.slice(7).trim() || undefined;
  return undefined;
}

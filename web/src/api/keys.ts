import { queryOptions } from "@tanstack/react-query";
import { api, unwrap } from "./client";
import type { components } from "./schema";
import type { Membership } from "./tokens";

export type SigningKey = components["schemas"]["SigningKey"];

/** The tenant's signing keys (ADR-0026), newest first: one page of up to 200, which holds them all in practice. */
export const signingKeysQuery = (tenant: string) =>
  queryOptions({
    queryKey: ["signing-keys", tenant],
    queryFn: async () => unwrap(await api.GET("/tenants/{tenant}/signing-keys", { params: { path: { tenant }, query: { limit: 200 } } })),
  });

export async function createSigningKey(tenant: string): Promise<SigningKey> {
  return unwrap(await api.POST("/tenants/{tenant}/signing-keys", { params: { path: { tenant } } }));
}

export async function promoteSigningKey(tenant: string, kid: string): Promise<SigningKey> {
  return unwrap(await api.POST("/tenants/{tenant}/signing-keys/{kid}/promote", { params: { path: { tenant, kid } } }));
}

export async function discardSigningKey(tenant: string, kid: string): Promise<SigningKey> {
  return unwrap(await api.POST("/tenants/{tenant}/signing-keys/{kid}/discard", { params: { path: { tenant, kid } } }));
}

/** key:read on every product: every role has it, but only tenant-wide. */
export const canReadKeys = (m: Membership | undefined) => !!m && m.scope.all;
/** key:write: owners only. Only to hide controls; the API is the real check. */
export const canManageKeys = (m: Membership | undefined) => !!m && m.role === "owner" && m.scope.all;

/**
 * The trusted key set builds embed (License File Format): every key that is
 * pending (so builds trust it before it's promoted), active, or retired after
 * signing (offline files it signed stay valid). A discarded key, retired
 * without ever being active, signed nothing and is left out.
 */
export function trustedKeySet(keys: SigningKey[]) {
  return keys.filter((k) => k.status !== "retired" || k.activated_at != null).map(({ kid, alg, public_key }) => ({ kid, alg, public_key }));
}

/** A public key's bytes (base64url without padding, RFC 4648 §5). */
export function keyBytes(publicKey: string): Uint8Array {
  // atob is forgiving base64 (WHATWG): no padding needed, only the standard alphabet.
  return Uint8Array.from(atob(publicKey.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
}

/** The trusted key set as Go source for the SDK (licensefile.KeySet): keys as byte literals, nothing to decode. */
export function goKeySet(keys: { kid: string; alg: string; public_key: string }[]) {
  const lines = keys.map((k) => {
    const bytes = Array.from(keyBytes(k.public_key), (b) => "0x" + b.toString(16).padStart(2, "0")).join(", ");
    return `\t{KID: ${JSON.stringify(k.kid)}, Alg: ${JSON.stringify(k.alg)}, Key: []byte{${bytes}}},`;
  });
  return ["var trustedKeys = licensefile.KeySet{", ...lines, "}"].join("\n");
}

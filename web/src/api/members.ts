import { infiniteQueryOptions } from "@tanstack/react-query";
import { api, check, unwrap } from "./client";
import type { components } from "./schema";
import type { ApiToken, Membership, Role } from "./tokens";

export type Member = components["schemas"]["Member"];
export type MemberRole = components["schemas"]["MemberRole"];
export type MemberUpdated = components["schemas"]["MemberUpdated"];
export type Invitation = components["schemas"]["Invitation"];
export type InvitationCreate = components["schemas"]["InvitationCreate"];
export type InvitationCreated = components["schemas"]["InvitationCreated"];

/** What a member change also revokes (ADR-0035); both default to true on the server. */
export type RevokeOptions = { tokens: boolean; invitations: boolean };
export type Revoked = { tokens: string[]; invitations: string[] };

const page = <T>(key: string, tenant: string, get: (cursor?: string) => Promise<{ items: T[]; next_cursor?: string }>) =>
  infiniteQueryOptions({
    queryKey: [key, tenant],
    queryFn: ({ pageParam }) => get(pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor,
  });

export const membersQuery = (tenant: string) =>
  page("members", tenant, async (cursor) =>
    unwrap(await api.GET("/tenants/{tenant}/members", { params: { path: { tenant }, query: { cursor } } })),
  );

/** Never holds a link token: the list has none, and a create's result stays in its dialog. */
export const invitationsQuery = (tenant: string) =>
  page("invitations", tenant, async (cursor) =>
    unwrap(await api.GET("/tenants/{tenant}/invitations", { params: { path: { tenant }, query: { cursor } } })),
  );

// The server's defaults are true: send a flag only to turn it off.
const revokeQuery = (o: RevokeOptions) => ({
  ...(o.tokens ? {} : { revoke_tokens: false }),
  ...(o.invitations ? {} : { revoke_invitations: false }),
});

/** Changes a member's role with a JSON Merge Patch (RFC 7396): only the role, the scope stays. */
export async function changeRole(tenant: string, id: string, role: MemberRole, o: RevokeOptions): Promise<MemberUpdated> {
  return unwrap(
    await api.PATCH("/tenants/{tenant}/members/{id}", {
      params: { path: { tenant, id }, query: revokeQuery(o) },
      body: { role },
      headers: { "Content-Type": "application/merge-patch+json" },
    }),
  );
}

const ids = (h: string | null) => (h ? h.split(",").filter(Boolean) : []);

/** Removes a member. 204: what it revoked comes in headers (ADR-0032). */
export async function removeMember(tenant: string, id: string, o: RevokeOptions): Promise<Revoked> {
  const res = check(await api.DELETE("/tenants/{tenant}/members/{id}", { params: { path: { tenant, id }, query: revokeQuery(o) } }));
  return { tokens: ids(res.headers.get("X-Revoked-Token-Ids")), invitations: ids(res.headers.get("X-Revoked-Invitation-Ids")) };
}

/** Creates an invitation. The result holds the link token: keep it in component state only. */
export async function createInvitation(tenant: string, body: InvitationCreate): Promise<InvitationCreated> {
  return unwrap(await api.POST("/tenants/{tenant}/invitations", { params: { path: { tenant } }, body }));
}

export async function revokeInvitation(tenant: string, id: string): Promise<Invitation> {
  return unwrap(await api.POST("/tenants/{tenant}/invitations/{id}/revoke", { params: { path: { tenant, id } } }));
}

/** Accepts an invitation as the signed-in user. The token goes in the body, never in a URL. */
export async function acceptInvitation(token: string) {
  return unwrap(await api.POST("/invitations/accept", { body: { token } }));
}

/** The invite link: the token in the fragment, which browsers never send to the server. */
export const inviteLink = (token: string) => `${window.location.origin}/invite#token=${encodeURIComponent(token)}`;

/** Every page of a list, for previews, bounded at maxPages: complete is false if it stopped there. */
export async function everyPage<T>(
  get: (cursor?: string) => Promise<{ items: T[]; next_cursor?: string }>,
  maxPages = 50,
): Promise<{ items: T[]; complete: boolean }> {
  const items: T[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < maxPages; i++) {
    const p = await get(cursor);
    items.push(...p.items);
    if (!(cursor = p.next_cursor)) return { items, complete: true };
  }
  return { items, complete: false };
}

export const allTokens = (tenant: string) =>
  everyPage(async (cursor) =>
    unwrap(await api.GET("/tenants/{tenant}/api-tokens", { params: { path: { tenant }, query: { cursor, limit: 200 } } })),
  );
export const allInvitations = (tenant: string) =>
  everyPage(async (cursor) =>
    unwrap(await api.GET("/tenants/{tenant}/invitations", { params: { path: { tenant }, query: { cursor, limit: 200 } } })),
  );

// The previews mirror internal/members (exceeds, canInvite); the server decides.
const ranked: Role[] = ["owner", "admin", "manager", "support", "viewer"];
/** Whether role r has no permission g lacks (never sdk, which stands alone). */
export const within = (r: Role, g: Role) => r !== "sdk" && ranked.indexOf(r) >= ranked.indexOf(g);

/** Whether grant g goes beyond to: a role above it (never sdk) or a product outside its scope. */
export function exceeds(g: Membership, to: Membership): boolean {
  if (g.role !== "sdk" && !within(g.role, to.role)) return true;
  if (to.scope.all) return false;
  return g.scope.all || g.scope.products.some((p) => !to.scope.products.includes(p));
}

/** Whether inviter could have sent an invitation with grant g (member:write on every product, role within its own). */
export const canInvite = (inviter: Membership, g: Membership) =>
  (inviter.role === "owner" || inviter.role === "admin") && inviter.scope.all && within(g.role, inviter.role);

export const grantOf = (x: { role: Role; all_products: boolean; product_ids: string[] }): Membership => ({
  role: x.role,
  scope: { all: x.all_products, products: x.product_ids },
});

const activeTokensOf = (m: Member, tokens: ApiToken[], now: Date) =>
  tokens.filter((tok) => tok.created_by === m.user_id && !tok.revoked_at && new Date(tok.expires_at) > now);
const pendingInvitationsOf = (m: Member, invs: Invitation[]) =>
  invs.filter((i) => i.invited_by === m.user_id && i.status === "pending");

/** What changing m's role to role would revoke: tokens it newly exceeds, invitations it newly couldn't send. */
export function previewRoleChange(m: Member, role: MemberRole, tokens: ApiToken[], invs: Invitation[], now = new Date()): { tokens: ApiToken[]; invitations: Invitation[] } {
  const from = grantOf(m);
  const to = { ...from, role };
  return {
    tokens: activeTokensOf(m, tokens, now).filter((tok) => exceeds(grantOf(tok), to) && !exceeds(grantOf(tok), from)),
    invitations: pendingInvitationsOf(m, invs).filter((i) => !canInvite(to, grantOf(i)) && canInvite(from, grantOf(i))),
  };
}

/** What removing m would revoke: every active token they created, every pending invitation they sent. */
export const previewRemoval = (m: Member, tokens: ApiToken[], invs: Invitation[], now = new Date()) => ({
  tokens: activeTokensOf(m, tokens, now),
  invitations: pendingInvitationsOf(m, invs),
});

/** Whether the caller may change members and invite (member:write on every product). */
export const canManageMembers = (m: Membership) => (m.role === "owner" || m.role === "admin") && m.scope.all;

/** Roles the caller may give or take away: its own and below (authz.CanAssign); the API is the real check. */
export const assignableMemberRoles = (m: Membership): MemberRole[] =>
  canManageMembers(m) ? (ranked.slice(ranked.indexOf(m.role)) as MemberRole[]) : [];

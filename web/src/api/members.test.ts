import { afterEach, describe, expect, it, vi } from "vitest";
import { setCsrfToken } from "./client";
import {
  acceptInvitation,
  assignableMemberRoles,
  changeRole,
  everyPage,
  exceeds,
  type Invitation,
  inviteLink,
  type Member,
  previewRemoval,
  previewRoleChange,
  removeMember,
} from "./members";
import type { ApiToken } from "./tokens";

function serve(status: number, body: unknown, headers: Record<string, string> = {}) {
  const f = vi.fn<(req: Request) => Promise<Response>>(async () =>
    new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } }),
  );
  vi.stubGlobal("fetch", f);
  return f;
}
const sent = (f: ReturnType<typeof serve>) => f.mock.calls[0]![0];
const base = `${window.location.origin}/api/v1/tenants/acme`;

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken("");
});

const member: Member = {
  id: "mem_1", user_id: "usr_m", email: "m@example.com", name: "M", role: "admin",
  all_products: true, product_ids: [], created_at: "2026-11-01T00:00:00Z",
};

describe("member calls", () => {
  it("changes a role with a JSON Merge Patch and the CSRF token", async () => {
    setCsrfToken("csrf-1");
    const f = serve(200, { ...member, role: "viewer", revoked_token_ids: ["tok_1"], revoked_invitation_ids: [] });
    const u = await changeRole("acme", "mem_1", "viewer", { tokens: true, invitations: true });
    const req = sent(f);
    expect(req.method).toBe("PATCH");
    expect(req.url).toBe(`${base}/members/mem_1`); // defaults (true) are not sent
    expect(req.headers.get("Content-Type")).toBe("application/merge-patch+json");
    expect(req.headers.get("X-CSRF-Token")).toBe("csrf-1");
    expect(await req.text()).toBe('{"role":"viewer"}');
    expect(u.revoked_token_ids).toEqual(["tok_1"]);
  });

  it("sends only the toggles turned off", async () => {
    const f = serve(200, { ...member, revoked_token_ids: [], revoked_invitation_ids: [] });
    await changeRole("acme", "mem_1", "viewer", { tokens: false, invitations: true });
    expect(sent(f).url).toBe(`${base}/members/mem_1?revoke_tokens=false`);
  });

  it("removes a member and reads what it revoked from the headers", async () => {
    const f = serve(204, null, { "X-Revoked-Token-Ids": "tok_1,tok_2" });
    const r = await removeMember("acme", "mem_1", { tokens: true, invitations: false });
    expect(sent(f).method).toBe("DELETE");
    expect(sent(f).url).toBe(`${base}/members/mem_1?revoke_invitations=false`);
    expect(r).toEqual({ tokens: ["tok_1", "tok_2"], invitations: [] });
  });

  it("parses a refusal as a problem", async () => {
    serve(409, { type: "about:blank", title: "Conflict", status: 409, code: "last_owner", request_id: "r" });
    await expect(removeMember("acme", "mem_1", { tokens: true, invitations: true })).rejects.toMatchObject({ code: "last_owner" });
  });

  it("accepts with the token in the body, never in the URL", async () => {
    setCsrfToken("csrf-1");
    const f = serve(200, { membership_id: "mem_9", tenant_id: "tnt_1", role: "viewer", all_products: true });
    await acceptInvitation("SECRET-TOKEN");
    const req = sent(f);
    expect(req.url).toBe(`${window.location.origin}/api/v1/invitations/accept`);
    expect(req.headers.get("X-CSRF-Token")).toBe("csrf-1");
    expect(await req.text()).toBe('{"token":"SECRET-TOKEN"}');
  });

  it("puts the link token in the fragment", () => {
    expect(inviteLink("a b")).toBe(`${window.location.origin}/invite#token=a%20b`);
  });
});

const now = new Date("2026-11-05T00:00:00Z");
const tok = (id: string, o: Partial<ApiToken>): ApiToken => ({
  id, name: id, role: "admin", all_products: true, product_ids: [], display: "lf_live_x", created_by: "usr_m",
  created_at: "2026-11-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z", last_used_at: null, revoked_at: null, ...o,
});
const inv = (id: string, o: Partial<Invitation>): Invitation => ({
  id, email: `${id}@example.com`, role: "viewer", all_products: true, product_ids: [], status: "pending", invited_by: "usr_m",
  created_at: "2026-11-01T00:00:00Z", expires_at: "2026-11-08T00:00:00Z", accepted_at: null, accepted_by: null, revoked_at: null, ...o,
});

describe("revocation previews (mirror internal/members)", () => {
  const tokens = [
    tok("admin", {}),
    tok("manager", { role: "manager" }),
    tok("sdk", { role: "sdk" }),
    tok("other-creator", { created_by: "usr_x" }),
    tok("revoked", { revoked_at: "2026-11-02T00:00:00Z" }),
    tok("expired", { expires_at: "2026-11-02T00:00:00Z" }),
  ];
  const invs = [inv("pending", {}), inv("accepted", { status: "accepted" }), inv("other", { invited_by: "usr_x" })];

  it("a demotion revokes the member's active tokens above the new role, never sdk", () => {
    const p = previewRoleChange(member, "manager", tokens, invs, now);
    expect(p.tokens.map((x) => x.id)).toEqual(["admin"]);
    // a manager can't invite at all: their pending invitations go
    expect(p.invitations.map((x) => x.id)).toEqual(["pending"]);
  });

  it("a token that already exceeded the old grant stays (an earlier opt-out)", () => {
    const owner = previewRoleChange({ ...member, role: "manager" }, "viewer", [tok("admin", {}), tok("manager", { role: "manager" })], [], now);
    expect(owner.tokens.map((x) => x.id)).toEqual(["manager"]);
  });

  it("a promotion revokes nothing", () => {
    expect(previewRoleChange(member, "owner", tokens, invs, now)).toEqual({ tokens: [], invitations: [] });
  });

  it("owner to admin revokes only the pending owner invitations", () => {
    const owner = { ...member, role: "owner" as const };
    const p = previewRoleChange(owner, "admin", [], [inv("owner-inv", { role: "owner" }), inv("admin-inv", { role: "admin" })], now);
    expect(p.invitations.map((x) => x.id)).toEqual(["owner-inv"]);
  });

  it("a product-scoped admin couldn't invite before, so a demotion revokes no invitation", () => {
    const scoped = { ...member, all_products: false, product_ids: ["prd_1"] };
    expect(previewRoleChange(scoped, "manager", [], [inv("viewer-inv", {})], now).invitations).toEqual([]);
  });

  it("an invitation already outside the old grant stays (an earlier opt-out)", () => {
    // an admin with a pending owner invitation: the old grant couldn't send it either
    expect(previewRoleChange(member, "manager", [], [inv("owner-inv", { role: "owner" })], now).invitations).toEqual([]);
  });

  it("a removal revokes every active token and pending invitation of the member", () => {
    const p = previewRemoval(member, tokens, invs, now);
    expect(p.tokens.map((x) => x.id)).toEqual(["admin", "manager", "sdk"]);
    expect(p.invitations.map((x) => x.id)).toEqual(["pending"]);
  });
});

describe("exceeds", () => {
  const g = (role: ApiToken["role"], all = true, products: string[] = []) => ({ role, scope: { all, products } });
  it("an sdk token never exceeds by role", () => {
    expect(exceeds(g("sdk"), g("viewer"))).toBe(false);
  });
  it("a role above, or a product outside the scope, exceeds", () => {
    expect(exceeds(g("admin"), g("manager"))).toBe(true);
    expect(exceeds(g("viewer"), g("viewer", false, ["prd_1"]))).toBe(true); // all products vs one
    expect(exceeds(g("viewer", false, ["prd_2"]), g("viewer", false, ["prd_1"]))).toBe(true);
    expect(exceeds(g("viewer", false, ["prd_1"]), g("admin", false, ["prd_1", "prd_2"]))).toBe(false);
  });
});

describe("assignableMemberRoles", () => {
  const all = { all: true, products: [] };
  it("offers the caller's role and below, never sdk", () => {
    expect(assignableMemberRoles({ role: "owner", scope: all })).toEqual(["owner", "admin", "manager", "support", "viewer"]);
    expect(assignableMemberRoles({ role: "admin", scope: all })).toEqual(["admin", "manager", "support", "viewer"]);
  });
  it("offers nothing without member:write on every product", () => {
    expect(assignableMemberRoles({ role: "manager", scope: all })).toEqual([]);
    expect(assignableMemberRoles({ role: "owner", scope: { all: false, products: ["prd_1"] } })).toEqual([]);
  });
});

describe("everyPage", () => {
  it("says whether it saw every page", async () => {
    const endless = async (c?: string) => ({ items: [c ?? "first"], next_cursor: "more" });
    expect(await everyPage(endless, 2)).toEqual({ items: ["first", "more"], complete: false });
    const two = async (c?: string) => (c ? { items: [2] } : { items: [1], next_cursor: "c" });
    expect(await everyPage(two, 2)).toEqual({ items: [1, 2], complete: true });
  });
});

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { goKeySet, keyBytes, trustedKeySet, type SigningKey } from "./api/keys";
import { createAppRouter } from "./router";


beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.open = true;
  };
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.open = false;
  };
});
let root: Root | undefined;
afterEach(() => {
  act(() => root?.unmount());
  root = undefined;
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
});

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const key = (over: Record<string, unknown> = {}) => ({
  kid: "sk_active", alg: "ed25519", public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", status: "active",
  created_at: "2026-11-01T00:00:00Z", activated_at: "2026-11-01T00:00:00Z", retired_at: null, ...over,
});
const pendingKey = key({ kid: "sk_pending", public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI", status: "pending", activated_at: null });
const oldKey = key({ kid: "sk_old", public_key: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM", status: "retired", retired_at: "2026-11-01T00:00:00Z", activated_at: "2026-10-01T00:00:00Z" });
const discarded = key({ kid: "sk_discarded", public_key: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ", status: "retired", activated_at: null, retired_at: "2026-11-02T00:00:00Z" });

type Sent = { method: string; path: string; body: unknown; type: string | null };

async function open(role: string, hooks: unknown[], extra?: (req: Request, u: URL) => Response | undefined, all = true, test = false) {
  const sent: Sent[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const u = new URL(req.url);
      const body = req.method === "GET" || req.method === "DELETE" ? undefined : await req.clone().text().then((t) => (t ? JSON.parse(t) : undefined));
      if (u.pathname.startsWith("/api/v1/tenants/")) sent.push({ method: req.method, path: u.pathname, body, type: req.headers.get("Content-Type") });
      if (u.pathname === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
      if (u.pathname === "/api/v1/me/tenants")
        return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role, all_products: all, product_ids: all ? [] : ["prd_1"], mfa_policy: "none", accessible: true, test }] });
      const r = extra?.(req, u);
      if (r) return r;
      if (u.pathname === "/api/v1/tenants/acme/signing-keys" && req.method === "GET") return json({ items: hooks });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient();
  const el = document.createElement("div");
  document.body.append(el);
  root = createRoot(el);
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: ["/t/acme/settings/signing-keys"] }));
  await act(async () =>
    root!.render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    ),
  );
  await vi.waitFor(() => expect(el.querySelector("h1")?.textContent).toBe("Signing keys"));
  return { el, qc, sent };
}

const button = (el: HTMLElement, text: string) => [...el.querySelectorAll("button")].find((b) => b.textContent === text);


it("trusts pending, active and retired-after-signing keys, never a discarded one", () => {
  expect(trustedKeySet([pendingKey, key(), oldKey, discarded] as SigningKey[]).map((k) => k.kid)).toEqual(["sk_pending", "sk_active", "sk_old"]);
  expect(trustedKeySet([key()] as SigningKey[])).toEqual([{ kid: "sk_active", alg: "ed25519", public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" }]);
});

it("shows viewers the keys and the trusted key set, without controls", async () => {
  const { el } = await open("viewer", [pendingKey, key(), oldKey, discarded]);
  await vi.waitFor(() => expect(el.querySelectorAll("tbody tr").length).toBe(4));
  const row = (kid: string) => [...el.querySelectorAll("tbody tr")].find((r) => r.textContent!.includes(kid))!;
  expect(row("sk_discarded").textContent).toContain("never signed");
  expect(row("sk_old").textContent).not.toContain("never signed");
  expect(el.textContent).toContain("when it's the active key, first generate a new key and promote it");
  const set = JSON.parse(el.querySelector("pre#json")!.textContent!);
  expect(set.map((k: { kid: string }) => k.kid)).toEqual(["sk_pending", "sk_active", "sk_old"]);
  for (const b of ["Generate key", "Promote", "Discard"]) expect(button(el, b)).toBeUndefined();
  expect([...el.querySelectorAll("nav a")].some((a) => a.textContent === "Signing keys")).toBe(true);
});

it("tells a product-scoped member keys are tenant-wide, without asking for them or a nav link", async () => {
  const { el, sent } = await open("owner", [key()], undefined, false);
  await vi.waitFor(() => expect(el.textContent).toContain("Signing keys belong to the whole tenant"));
  expect(sent.some((s) => s.path.endsWith("/signing-keys"))).toBe(false);
  expect([...el.querySelectorAll("nav a")].some((a) => a.textContent === "Signing keys")).toBe(false);
  expect(button(el, "Generate key")).toBeUndefined();
});

it("generates the first key after saying it signs at once; a rotation key after saying it waits", async () => {
  let keys: unknown[] = [];
  const { el, sent } = await open("owner", [], (req, u) => {
    if (req.method === "POST" && u.pathname.endsWith("/signing-keys")) {
      keys = [key()];
      return json(key(), 201);
    }
    if (req.method === "GET" && u.pathname.endsWith("/signing-keys")) return json({ items: keys });
    return undefined;
  });
  await vi.waitFor(() => expect(button(el, "Generate key")).toBeDefined());
  await act(async () => button(el, "Generate key")!.click());
  expect(el.querySelector("dialog")!.textContent).toContain("active at once");
  const go = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Generate key") as HTMLButtonElement;
  await act(async () => go.click());
  await vi.waitFor(() => expect(el.querySelectorAll("tbody tr").length).toBe(1));
  expect(sent.filter((s) => s.method === "POST" && s.path === "/api/v1/tenants/acme/signing-keys")).toHaveLength(1);
  await act(async () => button(el, "Generate key")!.click());
  expect(el.querySelector("dialog")!.textContent).toContain("The new key is pending");
});

it("hides Generate while a key is pending; promotes and discards it after a warning", async () => {
  const { el, sent } = await open("owner", [pendingKey, key()], (req) => (req.method === "POST" ? json(key()) : undefined));
  await vi.waitFor(() => expect(button(el, "Promote")).toBeDefined());
  expect(button(el, "Generate key")).toBeUndefined();
  expect(el.querySelector('button[aria-label="Promote sk_pending"]')).not.toBeNull();
  await act(async () => button(el, "Promote")!.click());
  expect(el.querySelector("dialog")!.textContent).toContain("can't be undone");
  expect(el.querySelector("dialog")!.textContent).toContain("The active key sk_active is retired");
  const promote = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Promote") as HTMLButtonElement;
  await act(async () => promote.click());
  await vi.waitFor(() => expect(sent.some((s) => s.path === "/api/v1/tenants/acme/signing-keys/sk_pending/promote")).toBe(true));
  await vi.waitFor(() => expect(el.querySelector("dialog")).toBeNull());
  await act(async () => button(el, "Discard")!.click());
  const discard = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Discard") as HTMLButtonElement;
  await act(async () => discard.click());
  await vi.waitFor(() => expect(sent.some((s) => s.path === "/api/v1/tenants/acme/signing-keys/sk_pending/discard")).toBe(true));
});

it("refreshes after a refused promote and offers only Close", async () => {
  let gets = 0;
  const { el } = await open("owner", [pendingKey, key()], (req, u) => {
    if (req.method === "GET" && u.pathname.endsWith("/signing-keys")) gets++;
    if (req.method === "POST") return json({ code: "invalid_state", title: "Conflict", status: 409 }, 409);
    return undefined;
  });
  await vi.waitFor(() => expect(button(el, "Promote")).toBeDefined());
  const before = gets;
  await act(async () => button(el, "Promote")!.click());
  const promote = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Promote") as HTMLButtonElement;
  await act(async () => promote.click());
  await vi.waitFor(() => expect(el.querySelector('dialog [role="alert"]')).not.toBeNull());
  await vi.waitFor(() => expect(gets).toBeGreaterThan(before));
  expect([...el.querySelectorAll("dialog button")].map((b) => b.textContent)).toEqual(["Close"]);
});

it("admins see the keys but can't change them", async () => {
  const { el } = await open("admin", [pendingKey, key()]);
  await vi.waitFor(() => expect(el.querySelectorAll("tbody tr").length).toBe(2));
  for (const b of ["Generate key", "Promote", "Discard"]) expect(button(el, b)).toBeUndefined();
});

it("writes the Go key set with the key's bytes, decoded from base64url", () => {
  const pub = "K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k"; // the spec's example key, with - and _
  expect(Array.from(keyBytes(pub))).toEqual(Array.from(Buffer.from(pub, "base64url")));
  expect(keyBytes(pub)).toHaveLength(32);
  const go = goKeySet([{ kid: "sk_a", alg: "ed25519", public_key: pub }]);
  const hex = Array.from(Buffer.from(pub, "base64url"), (b) => "0x" + b.toString(16).padStart(2, "0")).join(", ");
  expect(go).toBe(`var trustedKeys = licensefile.KeySet{\n\t{KID: "sk_a", Alg: "ed25519", Key: []byte{${hex}}},\n}`);
});

it("copies the Go and JSON sets; not when the list is incomplete", async () => {
  const writes: string[] = [];
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText: async (s: string) => void writes.push(s) } });
  const { el } = await open("viewer", [key(), discarded]);
  await vi.waitFor(() => expect(button(el, "Copy Go")).toBeDefined());
  await act(async () => button(el, "Copy Go")!.click());
  await act(async () => button(el, "Copy JSON")!.click());
  expect(writes[0]).toContain('{KID: "sk_active", Alg: "ed25519", Key: []byte{0x01, ');
  expect(JSON.parse(writes[1]!)).toEqual([{ kid: "sk_active", alg: "ed25519", public_key: key().public_key }]);
  act(() => root?.unmount());
  document.body.innerHTML = "";
  const more = await open("viewer", [key()], (_req, u) => (u.pathname.endsWith("/signing-keys") ? json({ items: [key()], next_cursor: "c" }) : undefined));
  await vi.waitFor(() => expect(more.el.textContent).toContain("can't be copied here"));
  expect([button(more.el, "Copy Go")!.disabled, button(more.el, "Copy JSON")!.disabled]).toEqual([true, true]);
});

it("says nothing signs while no key is active, and a new key is pending then", async () => {
  const { el } = await open("owner", [oldKey]);
  await vi.waitFor(() => expect(el.textContent).toContain("No key is active"));
  await act(async () => button(el, "Generate key")!.click());
  expect(el.querySelector("dialog")!.textContent).toContain("The new key is pending");
  expect(el.querySelector("dialog")!.textContent).not.toContain("active at once");
});

it("keeps the dialog while a request is out: Esc, Cancel and the action wait", async () => {
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  let posts = 0;
  const { el } = await open("owner", [pendingKey, key()], (req) => {
    if (req.method !== "POST") return undefined;
    posts++;
    return held.then(() => json(key())) as unknown as Response;
  });
  await vi.waitFor(() => expect(button(el, "Discard")).toBeDefined());
  await act(async () => button(el, "Discard")!.click());
  const go = () => [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Discard") as HTMLButtonElement;
  await act(async () => go().click());
  await vi.waitFor(() => expect(go().disabled).toBe(true));
  await act(async () => el.querySelector("dialog")!.dispatchEvent(new Event("cancel", { cancelable: true })));
  expect(el.querySelector("dialog")).not.toBeNull();
  expect(button(el, "Cancel")!.disabled).toBe(true);
  expect(posts).toBe(1);
  await act(async () => release());
});

it("in a test-mode tenant: a banner on every page, the switcher says so, and the keys aren't for release builds (ADR-0047)", async () => {
  const { el } = await open("viewer", [], undefined, true, true);
  await vi.waitFor(() => expect(el.querySelectorAll("header option")).toHaveLength(1)); // the tenants have loaded
  expect(el.querySelector("main")!.firstElementChild?.textContent).toMatch(/^Test mode\. This tenant is for integration and CI\./);
  expect([...el.querySelectorAll("header option")].map((o) => o.textContent)).toEqual(["Acme (test)"]);
  expect(el.textContent).toContain("trust them in development and CI builds only, never in release builds");
});

it("a live tenant has no test-mode banner or note", async () => {
  const { el } = await open("viewer", []);
  await vi.waitFor(() => expect(el.querySelectorAll("header option")).toHaveLength(1)); // the tenants have loaded
  expect(el.textContent).not.toContain("Test mode");
  expect(el.textContent).not.toContain("never in release builds");
  expect([...el.querySelectorAll("header option")].map((o) => o.textContent)).toEqual(["Acme"]);
});

it("shows the tenant ID the SDKs need, to every member", async () => {
  const { el } = await open("viewer", [key()], undefined, false);
  await vi.waitFor(() => expect(el.textContent).toContain("Tenant ID"));
  expect(el.querySelector("code")?.textContent).toBe("tnt_1");
});

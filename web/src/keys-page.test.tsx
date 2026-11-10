import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { trustedKeySet, type SigningKey } from "./api/keys";
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
  kid: "sk_active", alg: "ed25519", public_key: "PUBactive", status: "active",
  created_at: "2026-11-01T00:00:00Z", activated_at: "2026-11-01T00:00:00Z", retired_at: null, ...over,
});
const pendingKey = key({ kid: "sk_pending", public_key: "PUBpending", status: "pending", activated_at: null });
const oldKey = key({ kid: "sk_old", public_key: "PUBold", status: "retired", retired_at: "2026-11-01T00:00:00Z", activated_at: "2026-10-01T00:00:00Z" });
const discarded = key({ kid: "sk_discarded", public_key: "PUBdiscarded", status: "retired", activated_at: null, retired_at: "2026-11-02T00:00:00Z" });

type Sent = { method: string; path: string; body: unknown; type: string | null };

async function open(role: string, hooks: unknown[], extra?: (req: Request, u: URL) => Response | undefined, all = true) {
  const sent: Sent[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const u = new URL(req.url);
      const body = req.method === "GET" || req.method === "DELETE" ? undefined : await req.clone().text().then((t) => (t ? JSON.parse(t) : undefined));
      if (u.pathname.startsWith("/api/v1/tenants/")) sent.push({ method: req.method, path: u.pathname, body, type: req.headers.get("Content-Type") });
      if (u.pathname === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
      if (u.pathname === "/api/v1/me/tenants")
        return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role, all_products: all, product_ids: all ? [] : ["prd_1"], mfa_policy: "none", accessible: true }] });
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
  expect(trustedKeySet([key()] as SigningKey[])).toEqual([{ kid: "sk_active", alg: "ed25519", public_key: "PUBactive" }]);
});

it("shows viewers the keys and the trusted key set, without controls", async () => {
  const { el } = await open("viewer", [pendingKey, key(), oldKey, discarded]);
  await vi.waitFor(() => expect(el.querySelectorAll("tbody tr").length).toBe(4));
  expect(el.textContent).toContain("Discarded");
  const set = JSON.parse(el.querySelector("pre")!.textContent!);
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

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { D1, first, H2, second } from "./lib/audit-chain.fixture";
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
  vi.unstubAllGlobals();
});

/** An entry as the server writes it: details raw, the rest as JSON. */
const itemText = (e: object & { details: unknown }, rawDetails: string) =>
  `{"details":${rawDetails},${JSON.stringify({ ...e, details: undefined }).slice(1)}`; // undefined drops the key
const chainBody = `{"items":[${itemText(second, "{}")},${itemText(first, D1)}]}`;

async function open(role: string, all: boolean, body: string | { status: number; body: string } = chainBody, path = "/t/acme/settings/audit") {
  const json = (b: unknown) => new Response(JSON.stringify(b), { headers: { "Content-Type": "application/json" } });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const p = new URL(req.url).pathname;
      if (p === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
      if (p === "/api/v1/me/tenants") return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role, all_products: all, product_ids: all ? [] : ["prd_1"] }] });
      if (p.endsWith("/audit-events")) {
        if (typeof body === "object" && "pages" in body) {
          const pages = (body as unknown as { pages: { first: string; second: string } }).pages;
          return new Response(new URL(req.url).searchParams.get("cursor") ? pages.second : pages.first, { headers: { "Content-Type": "application/json" } });
        }
        const r = typeof body === "string" ? { status: 200, body } : body;
        return new Response(r.body, { status: r.status, headers: { "Content-Type": r.status === 200 ? "application/json" : "application/problem+json" } });
      }
      if (p.endsWith("/summary")) return json({ licenses: { active: 0, suspended: 0, revoked: 0 } });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: [path] }));
  const el = document.createElement("div");
  document.body.append(el);
  root = createRoot(el);
  await act(async () =>
    root!.render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    ),
  );
  const button = (text: string) => [...el.querySelectorAll("button")].find((b) => b.textContent === text);
  const navLinks = () => [...el.querySelectorAll("nav a")].map((a) => a.textContent);
  return { el, button, navLinks };
}

it("lists entries, newest first, with the fields that matter", async () => {
  const { el } = await open("owner", true);
  await vi.waitFor(() => expect(el.textContent).toContain("license.issue"));
  const rows = [...el.querySelectorAll("tbody tr")].map((r) => r.textContent ?? "");
  expect(rows[0]).toContain("audit.prune");
  expect(rows[0]).toContain("system");
  expect(rows[1]).toContain("user usr_cccccccccccccccccccccccccc");
  expect(rows[1]).toContain("license lic_dddddddddddddddddddddddddd");
  expect(rows[1]).toContain("203.0.113.7");
});

it("shows hostile details as text, never as markup", async () => {
  const hostile = { ...second, details: { html: '<img src=x onerror="alert(1)"><script>alert(2)</script>' } };
  const { el, button } = await open("owner", true, `{"items":[${itemText(hostile, JSON.stringify(hostile.details))}]}`);
  await vi.waitFor(() => expect(button("Details")).toBeDefined());
  await act(async () => button("Details")!.click());
  const pre = el.querySelector("dialog pre")!;
  expect(pre.textContent).toContain('<img src=x onerror=\\"alert(1)\\"><script>alert(2)</script>');
  expect(document.querySelector("dialog img, dialog script")).toBeNull();
  expect(pre.children).toHaveLength(0); // plain text only
});

it("verifies the loaded chain, and finds an entry changed after it was written", async () => {
  let r = await open("owner", true);
  await vi.waitFor(() => expect(r.button("Verify loaded entries")).toBeDefined());
  await act(async () => r.button("Verify loaded entries")!.click());
  await vi.waitFor(() => expect(r.el.textContent).toContain("The 2 loaded entries (#1–#2) are consistent with each other"));
  expect(r.el.textContent).toContain(`Head (entry #2): ${H2}`); // to compare with a SIEM export
  act(() => root?.unmount());
  root = undefined;
  // The same body, with one entry's action rewritten (its hash unchanged).
  r = await open("owner", true, chainBody.replace('"action":"license.issue"', '"action":"license.revoke"'));
  await vi.waitFor(() => expect(r.button("Verify loaded entries")).toBeDefined());
  await act(async () => r.button("Verify loaded entries")!.click());
  await vi.waitFor(() => expect(r.el.querySelector('[role="alert"]')?.textContent).toContain("Entry #1 doesn't match its hash"));
});

it("a page it can't read exactly is still listed, and verify says which page", async () => {
  // Two "items" arrays: JSON.parse keeps the last, the scanner sees both, so they don't line up.
  const body = `{"items":[${itemText(first, D1)}],"items":[${itemText(second, "{}")},${itemText(first, D1)}]}`;
  const r = await open("owner", true, body);
  await vi.waitFor(() => expect(r.el.querySelectorAll("tbody tr")).toHaveLength(2));
  await act(async () => r.button("Verify loaded entries")!.click());
  await vi.waitFor(() => expect(r.el.querySelector('[role="alert"]')?.textContent).toContain("Can't verify page 1"));
});

it("a page the scanner can't read (an entry without details) is still listed", async () => {
  const noDetails = JSON.stringify({ ...second, details: undefined });
  const r = await open("owner", true, `{"items":[${noDetails},${itemText(first, D1)}]}`);
  await vi.waitFor(() => expect(r.el.querySelectorAll("tbody tr")).toHaveLength(2));
  await act(async () => r.button("Verify loaded entries")!.click());
  await vi.waitFor(() => expect(r.el.querySelector('[role="alert"]')?.textContent).toContain("Can't verify page 1"));
});

it("names the page it can't verify: page 2 of two", async () => {
  const noDetails = JSON.stringify({ ...first, details: undefined }); // page 2's entry lacks details
  const twoPages = { first: `{"items":[${itemText(second, "{}")}],"next_cursor":"c2"}`, second: `{"items":[${noDetails}]}` };
  const r = await open("owner", true, { pages: twoPages } as never);
  await vi.waitFor(() => expect(r.button("Load more")).toBeDefined());
  await act(async () => r.button("Load more")!.click());
  await vi.waitFor(() => expect(r.el.querySelectorAll("tbody tr")).toHaveLength(2));
  await act(async () => r.button("Verify loaded entries")!.click());
  await vi.waitFor(() => expect(r.el.querySelector('[role="alert"]')?.textContent).toContain("Can't verify page 2"));
});

it("drops a verify result when more entries load", async () => {
  const twoPages = { first: `{"items":[${itemText(second, "{}")}],"next_cursor":"c2"}`, second: `{"items":[${itemText(first, D1)}]}` };
  const r = await open("owner", true, { pages: twoPages } as never);
  await vi.waitFor(() => expect(r.button("Verify loaded entries")).toBeDefined());
  await act(async () => r.button("Verify loaded entries")!.click());
  await vi.waitFor(() => expect(r.el.textContent).toContain("are consistent with each other"));
  await act(async () => r.button("Load more")!.click());
  await vi.waitFor(() => expect(r.el.querySelectorAll("tbody tr")).toHaveLength(2));
  await vi.waitFor(() => expect(r.el.textContent).not.toContain("are consistent with each other"));
});

it("offers the audit log only to owners and admins with every product", async () => {
  for (const [role, all, shown] of [["owner", true, true], ["admin", true, true], ["admin", false, false], ["manager", true, false]] as const) {
    const { el, navLinks } = await open(role, all, chainBody, "/t/acme");
    // Decide only once the caller's membership has loaded (the switcher shows it).
    await vi.waitFor(() => expect(el.querySelector("header select option")?.textContent).toBe("Acme"));
    expect(navLinks().includes("Audit log")).toBe(shown);
    act(() => root?.unmount());
    root = undefined;
  }
});

it("a refusal shows its message", async () => {
  const { el } = await open("owner", true, { status: 403, body: JSON.stringify({ type: "about:blank", title: "Forbidden", status: 403, code: "forbidden", request_id: "r" }) });
  await vi.waitFor(() => expect(el.textContent).toContain("You don't have permission"));
});

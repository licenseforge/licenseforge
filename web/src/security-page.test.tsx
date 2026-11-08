import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { createAppRouter } from "./router";

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});
let root: Root | undefined;
afterEach(() => {
  act(() => root?.unmount());
  root = undefined;
  vi.unstubAllGlobals();
});

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

async function open(path: string, tenant: { role: string; mfa_policy: string; accessible: boolean }, ready: string, patch?: (body: unknown) => Response) {
  const patches: unknown[] = [];
  let tenantGets = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const u = new URL(req.url);
      if (u.pathname === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
      if (u.pathname === "/api/v1/me/tenants") {
        tenantGets++;
        return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", all_products: true, product_ids: [], ...tenant }] });
      }
      if (req.method === "PATCH") {
        const body = await req.json();
        patches.push(body);
        return patch?.(body) ?? json({ id: "tnt_1", slug: "acme", name: "Acme", mfa_policy: (body as { mfa_policy: string }).mfa_policy, active_api_tokens: 3 });
      }
      if (u.pathname.endsWith("/summary")) return json({ licenses: { active: 0, suspended: 0, revoked: 0 } });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient();
  const el = document.createElement("div");
  document.body.append(el);
  root = createRoot(el);
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: [path] }));
  await act(async () => root!.render(<QueryClientProvider client={qc}><RouterProvider router={router} /></QueryClientProvider>));
  await vi.waitFor(() => expect(el.textContent).toContain(ready)); // the tenants have loaded
  return { el, patches, tenantGets: () => tenantGets };
}
const radio = (el: HTMLElement, v: string) => el.querySelector<HTMLInputElement>(`input[name="mfa_policy"][value="${v}"]`)!;
const save = (el: HTMLElement) => act(async () => el.querySelector<HTMLFormElement>("main form")!.requestSubmit());

it("explains a tenant whose MFA policy this session doesn't meet, with the step-up", async () => {
  const { el } = await open("/t/acme", { role: "admin", mfa_policy: "phishing_resistant", accessible: false }, "requires a stronger sign-in");
  expect(el.querySelector("h1")!.textContent).toBe("Acme requires a stronger sign-in");
  expect(el.textContent).toContain("passkey or a security key");
  const link = [...el.querySelectorAll("a")].find((a) => a.textContent === "Sign in again")!;
  const u = new URL(link.href);
  expect([u.pathname, u.searchParams.get("assurance"), u.searchParams.get("return")]).toEqual(["/auth/login", "phishing_resistant", "/t/acme/"]);
  expect(el.querySelector('nav[aria-label="LicenseForge"]')).toBeNull(); // no tenant screens behind it
});

it("shows the tenant normally when the session meets its policy; Security is for owners", async () => {
  const admin = await open("/t/acme", { role: "admin", mfa_policy: "mfa", accessible: true }, "Audit log"); // shown once the membership loaded
  expect(admin.el.textContent).not.toContain("requires a stronger sign-in");
  expect([...admin.el.querySelectorAll("nav a")].some((a) => a.textContent === "Security")).toBe(false);
  act(() => root?.unmount());
  const owner = await open("/t/acme", { role: "owner", mfa_policy: "none", accessible: true }, "Security");
  expect([...owner.el.querySelectorAll("nav a")].some((a) => a.textContent === "Security")).toBe(true);
});

it("lets an owner raise the policy and says API tokens keep working", async () => {
  const { el, patches, tenantGets } = await open("/t/acme/settings/security", { role: "owner", mfa_policy: "none", accessible: true }, "Sign-in requirement");
  expect(radio(el, "none").checked).toBe(true);
  await act(async () => radio(el, "mfa").click());
  const before = tenantGets();
  await save(el);
  await vi.waitFor(() => expect(el.textContent).toContain("3 active API tokens keep working"));
  expect([...el.querySelectorAll('[role="status"] a')].map((a) => new URL((a as HTMLAnchorElement).href).pathname)).toEqual(["/t/acme/settings/api-tokens"]);
  expect(patches).toEqual([{ mfa_policy: "mfa" }]);
  expect(tenantGets()).toBeGreaterThan(before);
});

it("offers the step-up to the chosen level when the owner's sign-in doesn't meet it", async () => {
  const unmet = () => json({ type: "about:blank", title: "x", status: 409, code: "mfa_policy_unmet", request_id: "r" }, 409);
  const { el } = await open("/t/acme/settings/security", { role: "owner", mfa_policy: "mfa", accessible: true }, "Sign-in requirement", unmet);
  await act(async () => radio(el, "phishing_resistant").click());
  await save(el);
  await vi.waitFor(() => expect(el.textContent).toContain("you'd lock yourself out"));
  const link = [...el.querySelectorAll('[role="alert"] a')][0] as HTMLAnchorElement;
  expect(new URL(link.href).searchParams.get("assurance")).toBe("phishing_resistant");
  expect(new URL(link.href).searchParams.get("return")).toBe("/t/acme/settings/security/"); // back here to save
});

it("doesn't mention tokens when lowering the policy, and says 1 token in the singular", async () => {
  const lower = await open("/t/acme/settings/security", { role: "owner", mfa_policy: "mfa", accessible: true }, "Sign-in requirement");
  await act(async () => radio(lower.el, "none").click());
  await save(lower.el);
  await vi.waitFor(() => expect(lower.el.textContent).toContain("Saved."));
  expect(lower.el.querySelector('[role="status"]')!.textContent).toBe("Saved.");
  act(() => root?.unmount());
  const one = () => json({ id: "tnt_1", slug: "acme", name: "Acme", mfa_policy: "mfa", active_api_tokens: 1 });
  const raise = await open("/t/acme/settings/security", { role: "owner", mfa_policy: "none", accessible: true }, "Sign-in requirement", one);
  await act(async () => radio(raise.el, "mfa").click());
  await save(raise.el);
  await vi.waitFor(() => expect(raise.el.textContent).toContain("1 active API token keeps working"));
});

it("is read-only for other roles", async () => {
  const { el } = await open("/t/acme/settings/security", { role: "admin", mfa_policy: "mfa", accessible: true }, "Sign-in requirement");
  expect(radio(el, "mfa").checked).toBe(true);
  expect(radio(el, "none").matches(":disabled")).toBe(true); // inside the disabled fieldset
  expect(el.textContent).toContain("Only owners can change this.");
  expect([...el.querySelectorAll("button")].some((b) => b.textContent === "Save")).toBe(false);
});

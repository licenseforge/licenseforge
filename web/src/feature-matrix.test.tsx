import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import type { Feature, Plan } from "./api/catalog";
import { FeatureMatrix } from "./feature-matrix";

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
const feature = (key: string, type: "boolean" | "limit", archived = false): Feature => ({
  id: `ftr_${key}`, product_id: "prd_1", key, name: key.toUpperCase(), description: null, type, unit: null, archived_at: archived ? "2026-11-01T00:00:00Z" : null, created_at: "",
});
const plan = (id: string, name: string): Plan => ({
  id, product_id: "prd_1", slug: id, name, duration_months: 12, duration_seconds: null, expiry_basis: "from_issue", max_activations: null,
  max_rehosts: null, bind_type: "machine", offline_allowed: false, lease_seconds: 604800, max_offline_seconds: null, grace_seconds: 0, archived_at: null, created_at: "",
});
const features = [feature("sso", "boolean"), feature("max_users", "limit"), feature("legacy", "boolean", true), feature("gone", "boolean", true)];
const plans = [plan("pln_basic", "Basic"), plan("pln_pro", "Pro")];

async function render(opts: { write?: boolean; patch?: (plan: string, body: unknown) => Response | undefined | Promise<Response | undefined>; failGets?: () => boolean } = {}) {
  const grants: Record<string, Record<string, unknown>> = { pln_basic: { max_users: 5 }, pln_pro: { sso: true, max_users: -1, legacy: true } };
  const patches: { plan: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const id = new URL(req.url).pathname.split("/")[6]!; // /api/v1/tenants/acme/plans/{id}/features
      if (req.method === "PATCH") {
        const body = await req.json();
        patches.push({ plan: id, body });
        const r = await opts.patch?.(id, body);
        if (r) return r;
        const g = { ...grants[id] };
        for (const [k, v] of Object.entries(body as Record<string, unknown>)) if (v === null) delete g[k]; else g[k] = v;
        grants[id] = g;
        return json(g);
      }
      if (opts.failGets?.()) return json({ type: "about:blank", title: "x", status: 503, code: "internal", request_id: "r" }, 503);
      return json(grants[id]);
    }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const el = document.createElement("div");
  document.body.append(el);
  root = createRoot(el);
  await act(async () =>
    root!.render(
      <QueryClientProvider client={qc}>
        <FeatureMatrix tenant="acme" features={features} plans={plans} write={opts.write ?? true} />
      </QueryClientProvider>,
    ),
  );
  await vi.waitFor(() => expect(el.querySelector("table")).not.toBeNull());
  const field = (feature: string, plan: string) => el.querySelector<HTMLInputElement>(`input[aria-label="${feature} in ${plan}"]`)!;
  const button = (text: string) => [...el.querySelectorAll("button")].find((b) => b.textContent === text);
  const type = (input: HTMLInputElement, value: string) =>
    act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
  return { el, field, button, type, patches, grants, qc };
}

it("shows what each plan grants; an archived feature only where still granted, and not grantable anew", async () => {
  const { el, field } = await render();
  expect(field("SSO", "Basic").checked).toBe(false);
  expect(field("SSO", "Pro").checked).toBe(true);
  expect(field("MAX_USERS", "Basic").value).toBe("5");
  expect(field("MAX_USERS", "Pro").value).toBe("-1");
  expect(field("LEGACY", "Pro").disabled).toBe(false); // granted: can change or go
  expect(field("LEGACY", "Basic").disabled).toBe(true); // archived: not granted anew
  expect(el.textContent).not.toContain("GONE"); // archived and granted nowhere
});

it("saves one merge patch per changed plan, with only the touched cells", async () => {
  const { el, field, button, type, patches } = await render();
  expect(button("Save changes")!.disabled).toBe(true);
  await act(async () => field("SSO", "Basic").click());
  await type(field("MAX_USERS", "Basic"), "10");
  await act(async () => field("LEGACY", "Pro").click());
  await type(field("MAX_USERS", "Pro"), "-1"); // unchanged
  await act(async () => button("Save changes")!.click());
  await vi.waitFor(() => expect(el.textContent).toContain("Saved."));
  expect(patches).toEqual([
    { plan: "pln_basic", body: { sso: true, max_users: 10 } },
    { plan: "pln_pro", body: { legacy: null } }, // the same -1 typed again isn't a change event: untouched
  ]);
  await vi.waitFor(() => expect(field("SSO", "Basic").checked).toBe(true));
  expect(button("Save changes")!.disabled).toBe(true);
});

it("empties a limit to remove it", async () => {
  const { el, field, button, type, patches } = await render();
  await type(field("MAX_USERS", "Basic"), "");
  await act(async () => button("Save changes")!.click());
  await vi.waitFor(() => expect(el.textContent).toContain("Saved."));
  expect(patches).toEqual([{ plan: "pln_basic", body: { max_users: null } }]);
});

it("refuses a limit that isn't valid without a request for that plan", async () => {
  const { el, field, button, type, patches } = await render();
  await type(field("MAX_USERS", "Basic"), "1.5");
  await act(async () => field("SSO", "Pro").click());
  await act(async () => button("Save changes")!.click());
  await vi.waitFor(() => expect(el.textContent).toContain("Some limits aren't valid"));
  expect(field("MAX_USERS", "Basic").getAttribute("aria-invalid")).toBe("true");
  expect(patches).toEqual([{ plan: "pln_pro", body: { sso: null } }]); // the valid plan is saved
  expect(field("MAX_USERS", "Basic").value).toBe("1.5"); // kept for fixing
  expect(el.textContent).not.toContain("Saved.");
});

it("names a plan the server refused and keeps its edits", async () => {
  const problem = { type: "about:blank", title: "x", status: 422, code: "validation_failed", request_id: "r", errors: [{ field: "/sso", message: "archived" }] };
  const { el, field, button } = await render({ patch: (plan) => (plan === "pln_basic" ? json(problem, 422) : undefined) as Response });
  await act(async () => field("SSO", "Basic").click());
  await act(async () => button("Save changes")!.click());
  await vi.waitFor(() => expect(el.querySelector('[role="alert"]')?.textContent).toContain("Basic: not saved."));
  expect(field("SSO", "Basic").checked).toBe(true);
  expect(button("Save changes")!.disabled).toBe(false);
});

it("clears a grant another admin added after the page loaded", async () => {
  const { el, field, button, patches, grants } = await render();
  grants.pln_basic!.sso = true; // on the server now; the page loaded Basic without SSO
  await act(async () => field("SSO", "Basic").click());
  await act(async () => field("SSO", "Basic").click()); // shown unchecked again: the user wants it off
  await act(async () => button("Save changes")!.click());
  await vi.waitFor(() => expect(el.textContent).toContain("Saved."));
  expect(patches).toEqual([{ plan: "pln_basic", body: { sso: null } }]);
  expect(grants.pln_basic).not.toHaveProperty("sso");
});

it("locks the cells while saving, so no edit is lost", async () => {
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  const { el, field, button, patches } = await render({ patch: async () => { await held; return undefined; } });
  await act(async () => field("SSO", "Basic").click());
  await act(async () => button("Save changes")!.click());
  await vi.waitFor(() => expect(patches).toHaveLength(1));
  expect(field("SSO", "Pro").disabled).toBe(true);
  expect(field("MAX_USERS", "Basic").disabled).toBe(true);
  await act(async () => release());
  await vi.waitFor(() => expect(el.textContent).toContain("Saved."));
  expect(field("SSO", "Pro").disabled).toBe(false);
});

it("keeps the matrix and unsaved edits when a background refetch fails", async () => {
  let fail = false;
  const { el, field, qc } = await render({ failGets: () => fail });
  await act(async () => field("SSO", "Basic").click());
  fail = true;
  await act(async () => qc.invalidateQueries());
  await vi.waitFor(() => expect(qc.getQueryState(["plan-features", "acme", "pln_basic"])?.status).toBe("error"));
  await act(async () => new Promise((r) => setTimeout(r, 20))); // let the matrix render the error state
  expect(el.querySelector('[role="alert"]')).toBeNull();
  expect(el.querySelector("table")).not.toBeNull();
  expect(field("SSO", "Basic").checked).toBe(true);
});

it("is read-only without catalog:write", async () => {
  const { el, button } = await render({ write: false });
  expect([...el.querySelectorAll("input")].every((i) => i.disabled)).toBe(true);
  expect(button("Save changes")).toBeUndefined();
});

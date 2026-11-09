import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { PlatformPage } from "./platform-page";
import { createAppRouter } from "./router";

const TOKEN = "OWNER-INVITE-TOKEN-abc789";
const tenant = { id: "tnt_1", slug: "acme", name: "Acme Corp", mfa_policy: "none", created_at: "2026-11-08T00:00:00Z", has_members: false };
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" } });

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.open = true;
  };
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.open = false;
  };
});
afterEach(() => vi.unstubAllGlobals());

async function render(fetchImpl: (req: Request) => Promise<Response>) {
  vi.stubGlobal("fetch", vi.fn(fetchImpl));
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={qc}>
        <PlatformPage />
      </QueryClientProvider>,
    ),
  );
  return { el, root, qc };
}

const button = (el: HTMLElement, text: string) => [...el.querySelectorAll("button")].find((b) => b.textContent === text)!;

it("lists tenants, creates one and shows the owner's invite link once", async () => {
  let body: unknown;
  const { el, root, qc } = await render(async (req) => {
    if (req.method === "POST") {
      body = await req.json();
      return json({ tenant: { ...tenant, id: "tnt_2", slug: "globex", name: "Globex" }, invitation: { id: "inv_1", email: "o@globex.example", role: "owner", expires_at: "2026-11-15T00:00:00Z", token: TOKEN } }, 201);
    }
    return json({ items: [tenant] });
  });
  await vi.waitFor(() => expect(el.textContent).toContain("Acme Corp"));
  await act(async () => button(el, "New tenant").click());
  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  for (const [name, v] of [["slug", "globex"], ["name", "Globex"], ["owner_email", "o@globex.example"]]) {
    const input = el.querySelector<HTMLInputElement>(`input[name="${name}"]`)!;
    await act(async () => {
      setValue.call(input, v);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
  }
  await act(async () => el.querySelector("form")!.requestSubmit());
  await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toContain(`/invite#token=${TOKEN}`));
  expect(body).toEqual({ slug: "globex", name: "Globex", owner_email: "o@globex.example" });
  expect(el.textContent).toContain("o@globex.example");

  await act(async () => button(el, "Close").click());
  await vi.waitFor(() => expect(el.querySelector("input[readonly]")).toBeNull());
  const kept = JSON.stringify([
    document.body.innerHTML,
    qc.getQueryCache().getAll().map((q) => q.state),
    qc.getMutationCache().getAll().map((m) => m.state),
    { ...localStorage },
    { ...sessionStorage },
  ]);
  expect(kept).not.toContain(TOKEN);
  act(() => root.unmount());
});

it("shows field errors from the server", async () => {
  const { el, root } = await render(async (req) =>
    req.method === "POST"
      ? json({ code: "conflict", title: "Conflict", status: 409, errors: [{ field: "/slug", message: "already used by another tenant" }] }, 409)
      : json({ items: [] }),
  );
  await vi.waitFor(() => expect(el.textContent).toContain("No tenants yet."));
  await act(async () => button(el, "New tenant").click());
  await act(async () => el.querySelector("form")!.requestSubmit());
  await vi.waitFor(() => expect(el.textContent).toContain("already used by another tenant"));
  expect(el.querySelector('input[name="slug"]')!.getAttribute("aria-invalid")).toBe("true");
  act(() => root.unmount());
});

it("offers a step-up that comes back here when the session is short of the platform MFA policy", async () => {
  const { el, root } = await render(async () =>
    json({ code: "mfa_required", title: "MFA required", status: 403, required_assurance: "phishing_resistant", session_assurance: "mfa" }, 403),
  );
  await vi.waitFor(() => expect(el.querySelector("a")).not.toBeNull());
  const u = new URL(el.querySelector("a")!.getAttribute("href")!, "https://lf.example");
  expect(u.pathname).toBe("/auth/login");
  expect(u.searchParams.get("assurance")).toBe("phishing_resistant");
  expect(u.searchParams.get("return")).toBe("/platform/");
  expect(button(el, "New tenant")).toBeUndefined(); // nothing to create from a refused list
  act(() => root.unmount());
});

// The app with no tenants: a platform admin is sent to the platform screen
// and gets its nav link; anyone else sees neither, and it is never fetched.
it.each([true, false])("routes a user without tenants by the session's platform flag (admin: %s)", async (admin) => {
  const paths: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const path = new URL(req.url).pathname;
      paths.push(path);
      if (path === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "csrf", platform_admin: admin });
      if (path === "/api/v1/platform/tenants") return json({ items: [tenant] });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: ["/"] }));
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    ),
  );
  if (admin) {
    await vi.waitFor(() => expect(el.textContent).toContain("Acme Corp"));
    expect(router.state.location.pathname).toBe("/platform");
    expect([...el.querySelectorAll("a")].some((a) => a.textContent === "Tenants (platform)")).toBe(true);
  } else {
    await vi.waitFor(() => expect(paths).toContain("/api/v1/me/tenants"));
    await act(async () => {});
    expect(router.state.location.pathname).toBe("/");
    expect([...el.querySelectorAll("a")].some((a) => a.textContent === "Tenants (platform)")).toBe(false);
    expect(paths).not.toContain("/api/v1/platform/tenants");
  }
  act(() => root.unmount());
});

it("can't be closed while the create is in flight: its answer is the only copy of the invite link", async () => {
  let answer: (r: Response) => void = () => {};
  const { el, root } = await render(async (req) =>
    req.method === "POST" ? new Promise<Response>((r) => (answer = r)) : json({ items: [tenant] }),
  );
  await vi.waitFor(() => expect(el.textContent).toContain("Acme Corp"));
  await act(async () => button(el, "New tenant").click());
  await act(async () => el.querySelector("form")!.requestSubmit());
  expect(button(el, "Cancel").disabled).toBe(true);
  await act(async () => el.querySelector("dialog")!.dispatchEvent(new Event("cancel", { cancelable: true }))); // Esc
  expect(el.querySelector("dialog")).not.toBeNull();
  await act(async () =>
    answer(json({ tenant: { ...tenant, id: "tnt_3", slug: "late", name: "Late" }, invitation: { id: "inv_3", email: "o@late.example", role: "owner", expires_at: "2026-11-15T00:00:00Z", token: TOKEN } }, 201)),
  );
  await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toContain(TOKEN));
  expect(document.activeElement).toBe(el.querySelector("input[readonly]"));
  act(() => root.unmount());
});

it("labels MFA policies and explains a platform MFA refusal on create", async () => {
  const { el, root } = await render(async (req) =>
    req.method === "POST"
      ? json({ code: "mfa_required", title: "MFA required", status: 403, required_assurance: "mfa", session_assurance: "none" }, 403)
      : json({ items: [{ ...tenant, mfa_policy: "phishing_resistant" }] }),
  );
  await vi.waitFor(() => expect(el.textContent).toContain("Phishing-resistant"));
  expect(el.textContent).not.toContain("phishing_resistant");
  await act(async () => button(el, "New tenant").click());
  await act(async () => el.querySelector("form")!.requestSubmit());
  await vi.waitFor(() => expect(el.textContent).toContain("The platform screens need a stronger sign-in"));
  expect(el.textContent).not.toContain("This tenant");
  expect(new URL(el.querySelector("dialog a")!.getAttribute("href")!, "https://x").searchParams.get("return")).toBe("/platform/");
  act(() => root.unmount());
});

it("re-issues an owner invite: the new link once, or why not when the tenant has an owner", async () => {
  const posts: { path: string; body: unknown }[] = [];
  let conflict = false;
  const { el, root, qc } = await render(async (req) => {
    if (req.method === "POST") {
      posts.push({ path: new URL(req.url).pathname, body: await req.json() });
      return conflict
        ? json({ type: "about:blank", title: "Conflict", status: 409, code: "conflict", detail: "the tenant has an owner", request_id: "r" }, 409)
        : json({ tenant, invitation: { id: "inv_2", email: "new@acme.example", role: "owner", expires_at: "2026-11-16T00:00:00Z", token: TOKEN } }, 201);
    }
    return json({ items: [tenant] });
  });
  await vi.waitFor(() => expect(el.textContent).toContain("Acme Corp"));
  const open = async () => {
    await act(async () => el.querySelector<HTMLButtonElement>('button[aria-label="New owner invite for Acme Corp (acme)"]')!.click());
    const input = el.querySelector<HTMLInputElement>('input[name="owner_email"]')!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, " new@acme.example ");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => el.querySelector("form")!.requestSubmit());
  };
  await open();
  await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toContain(`/invite#token=${TOKEN}`));
  expect(posts).toEqual([{ path: "/api/v1/platform/tenants/tnt_1/owner-invitation", body: { owner_email: "new@acme.example" } }]);
  await act(async () => button(el, "Close").click());
  await vi.waitFor(() => expect(el.querySelector("input[readonly]")).toBeNull());
  expect(JSON.stringify([document.body.innerHTML, qc.getQueryCache().getAll().map((q) => q.state), qc.getMutationCache().getAll().map((m) => m.state)])).not.toContain(TOKEN);

  conflict = true;
  const lists = (fetch as unknown as { mock: { calls: [Request][] } }).mock.calls.filter(([r]) => r.method === "GET").length;
  await open();
  await vi.waitFor(() => expect(el.querySelector('[role="alert"]')?.textContent).toBe("This tenant already has an owner: its owners invite members."));
  await vi.waitFor(() => expect((fetch as unknown as { mock: { calls: [Request][] } }).mock.calls.filter(([r]) => r.method === "GET").length).toBeGreaterThan(lists)); // the stale row refreshed
  act(() => root.unmount());
});

// Re-issue: no closing mid-request; other refusals as on create.
it("the re-issue dialog waits for its answer and explains other refusals", async () => {
  let answer: (r: Response) => void = () => {};
  let reply: () => Promise<Response> = () => new Promise<Response>((r) => (answer = r));
  const { el, root } = await render(async (req) => (req.method === "POST" ? reply() : json({ items: [tenant] })));
  await vi.waitFor(() => expect(el.textContent).toContain("Acme Corp"));
  const submit = async () => {
    if (!el.querySelector("dialog")) await act(async () => el.querySelector<HTMLButtonElement>('button[aria-label="New owner invite for Acme Corp (acme)"]')!.click());
    await act(async () => el.querySelector("form")!.requestSubmit());
  };
  await submit();
  expect(button(el, "Cancel").disabled).toBe(true);
  await act(async () => el.querySelector("dialog")!.dispatchEvent(new Event("cancel", { cancelable: true }))); // Esc
  expect(el.querySelector("dialog")).not.toBeNull();
  await act(async () => answer(json({ code: "validation_failed", title: "x", status: 422, errors: [{ field: "/owner_email", message: "must be an email address" }] }, 422)));
  await vi.waitFor(() => expect(el.querySelector('input[name="owner_email"]')!.getAttribute("aria-invalid")).toBe("true"));
  reply = async () => json({ code: "mfa_required", title: "x", status: 403, required_assurance: "mfa", session_assurance: "none" }, 403);
  await submit();
  await vi.waitFor(() => expect(new URL(el.querySelector("dialog a")!.getAttribute("href")!, "https://x").searchParams.get("return")).toBe("/platform/"));
  reply = async () => json({ code: "not_found", title: "x", status: 404, request_id: "r" }, 404);
  await submit();
  await vi.waitFor(() => expect(el.querySelector('dialog [role="alert"]')?.textContent).toContain("Not found"));
  expect(el.textContent).not.toContain("already has an owner");
  act(() => root.unmount());
});

it("offers a new owner invite only for tenants nobody has joined yet", async () => {
  const { el, root } = await render(async () => json({ items: [tenant, { ...tenant, id: "tnt_9", slug: "busy", name: "Busy Co", has_members: true }] }));
  await vi.waitFor(() => expect(el.textContent).toContain("Busy Co"));
  expect(el.querySelector('button[aria-label="New owner invite for Acme Corp (acme)"]')).not.toBeNull();
  expect(el.querySelector('button[aria-label="New owner invite for Busy Co (busy)"]')).toBeNull();
  act(() => root.unmount());
});

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { forgetInviteToken, inviteWaiting, takeInviteToken } from "./invite";
import { createAppRouter } from "./router";

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});

let root: Root | undefined;
afterEach(() => {
  act(() => root?.unmount());
  root = undefined;
  forgetInviteToken();
  vi.unstubAllGlobals();
});

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const session = { user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "csrf" };
const tenants = { items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role: "viewer", all_products: true, product_ids: [] }] };

/** The app at url, with the server answering per method and path. */
async function open(url: string, server: { signedIn: boolean; accept?: number }) {
  const calls: Request[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      calls.push(req);
      const path = new URL(req.url).pathname;
      if (path === "/auth/session") return server.signedIn ? json(session) : json({}, 401);
      if (path === "/api/v1/me/tenants") return json(tenants);
      if (path === "/api/v1/invitations/accept") {
        return server.accept === 200
          ? json({ membership_id: "mem_1", tenant_id: "tnt_1", role: "viewer", all_products: true })
          : json({ type: "about:blank", title: "x", status: server.accept, code: server.accept === 422 ? "validation_failed" : "internal", request_id: "r" }, server.accept);
      }
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient();
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: [url] }));
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
  const accepts = () => calls.filter((r) => r.method === "POST" && r.url.endsWith("/invitations/accept"));
  const button = (text: string) => [...el.querySelectorAll("button")].find((b) => b.textContent === text);
  return { el, router, accepts, button };
}

it("signed out: explains signing in, keeps the token, strips it from the URL, accepts nothing", async () => {
  const { el, router, accepts } = await open("/invite#token=tok-1", { signedIn: false });
  await vi.waitFor(() => expect(el.textContent).toContain("Sign in with the email"));
  expect(accepts()).toHaveLength(0);
  expect(inviteWaiting()).toBe(true);
  expect(router.state.location.hash).toBe("");
  expect(router.state.location.href).not.toContain("tok-1");
});

it("never takes a token from the query string", async () => {
  const { el } = await open("/invite?token=leaky", { signedIn: true });
  await vi.waitFor(() => expect(el.textContent).toContain("incomplete"));
  expect(inviteWaiting()).toBe(false);
});

it("signed in: no auto-accept; a 422 forgets the token, says so, and disables Accept", async () => {
  const { el, accepts, button } = await open("/invite#token=tok-1", { signedIn: true, accept: 422 });
  await vi.waitFor(() => expect(button("Accept invitation")).toBeDefined());
  expect(accepts()).toHaveLength(0); // nothing until the user clicks
  await act(async () => button("Accept invitation")!.click());
  await vi.waitFor(() => expect(el.textContent).toContain("can't be accepted"));
  expect(await accepts()[0]!.text()).toBe('{"token":"tok-1"}');
  expect(inviteWaiting()).toBe(false);
  expect(button("Accept invitation")!.disabled).toBe(true);
});

it("after another error Accept can be retried", async () => {
  const { el, button } = await open("/invite#token=tok-1", { signedIn: true, accept: 500 });
  await vi.waitFor(() => expect(button("Accept invitation")).toBeDefined());
  await act(async () => button("Accept invitation")!.click());
  await vi.waitFor(() => expect(el.querySelector('[role="alert"]')).not.toBeNull());
  expect(button("Accept invitation")!.disabled).toBe(false);
  expect(inviteWaiting()).toBe(true);
});

it('"Not now" forgets the token and leaves', async () => {
  const { router, button } = await open("/invite#token=tok-1", { signedIn: true, accept: 200 });
  await vi.waitFor(() => expect(button("Not now")).toBeDefined());
  await act(async () => button("Not now")!.click());
  expect(inviteWaiting()).toBe(false);
  await vi.waitFor(() => expect(router.state.location.pathname).toBe("/t/acme"));
});

it("back from signing in, / sends the user to the waiting invitation, which still waits for a click", async () => {
  takeInviteToken("token=tok-2"); // kept before the sign-in round trip
  const { router, accepts, button } = await open("/", { signedIn: true, accept: 200 });
  await vi.waitFor(() => expect(router.state.location.pathname).toBe("/invite"));
  await vi.waitFor(() => expect(button("Accept invitation")).toBeDefined());
  expect(accepts()).toHaveLength(0);
});

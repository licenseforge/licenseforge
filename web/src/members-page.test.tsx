import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { invitationsQuery } from "./api/members";
import { ChangeDialog, InviteDialog } from "./members-page";

const TOKEN = "INVITE-TOKEN-xyz123";

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

function Harness() {
  const [open, setOpen] = useState(true);
  return open ? <InviteDialog tenant="acme" roles={["admin", "viewer"]} onClose={() => setOpen(false)} /> : <p>closed</p>;
}

it("shows the invite link once and keeps the token nowhere after the dialog closes", async () => {
  const row = {
    id: "inv_1", email: "new@example.com", role: "viewer", all_products: true, product_ids: [], status: "pending",
    invited_by: "usr_1", created_at: "2026-11-05T00:00:00Z", expires_at: "2026-11-12T00:00:00Z",
    accepted_at: null, accepted_by: null, revoked_at: null,
  };
  // After the create, list reads fail: a refetch can't overwrite a token wrongly cached.
  let created = false;
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      if (req.method === "POST") {
        created = true;
        return json({ ...row, token: TOKEN }, 201);
      }
      return created ? json({ code: "internal" }, 500) : json({ items: [row] });
    }),
  );
  const qc = new QueryClient();
  await qc.prefetchInfiniteQuery(invitationsQuery("acme"));
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={qc}>
        <Harness />
      </QueryClientProvider>,
    ),
  );
  const email = el.querySelector<HTMLInputElement>('input[name="email"]')!;
  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  await act(async () => {
    setValue.call(email, "new@example.com");
    email.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => el.querySelector("form")!.requestSubmit());
  await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toContain(`#token=${TOKEN}`));

  const close = [...el.querySelectorAll("button")].find((b) => b.textContent === "Close")!;
  await act(async () => close.click());
  await vi.waitFor(() => expect(el.textContent).toContain("closed"));

  const kept = JSON.stringify([
    document.body.innerHTML,
    qc.getQueryCache().getAll().map((q) => q.state),
    qc.getMutationCache().getAll().map((m) => m.state),
    { ...localStorage },
    { ...sessionStorage },
  ]);
  expect(kept).not.toContain(TOKEN);
  expect(kept).toContain("new@example.com"); // the list's metadata is cached, the token isn't
  act(() => root.unmount());
});

const member = {
  id: "mem_1", user_id: "usr_m", email: "m@example.com", name: "M", role: "admin" as const,
  all_products: true, product_ids: [], created_at: "2026-11-01T00:00:00Z",
};
const owner = { role: "owner" as const, scope: { all: true, products: [] } };

async function renderChange(fetchImpl: (req: Request) => Promise<Response>) {
  vi.stubGlobal("fetch", vi.fn(fetchImpl));
  const done = vi.fn();
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ChangeDialog tenant="acme" caller={owner} roles={["owner", "admin", "manager", "support", "viewer"]} change={{ kind: "role", member }} onClose={() => {}} onDone={done} />
      </QueryClientProvider>,
    ),
  );
  const confirm = () => [...el.querySelectorAll("button")].find((b) => b.textContent === "Change role")!;
  const boxes = () => [...el.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
  const pick = async (role: string) => {
    const select = el.querySelector("select")!;
    await act(async () => {
      select.value = role;
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
  };
  return { el, root, done, confirm, boxes, pick };
}

it("a role change: confirm waits for the preview, and an unticked box sends revoke_*=false", async () => {
  const sent: Request[] = [];
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  let release: () => void = () => {};
  const listsReady = new Promise<void>((r) => (release = r));
  const { root, done, confirm, boxes, pick } = await renderChange(async (req) => {
    sent.push(req);
    if (req.method === "GET") {
      await listsReady;
      return json({ items: [] });
    }
    return json({ ...member, role: "viewer", revoked_token_ids: [], revoked_invitation_ids: [] });
  });
  await pick("viewer");
  expect(confirm().disabled).toBe(true); // the preview is still loading
  await act(async () => release());
  await vi.waitFor(() => expect(confirm().disabled).toBe(false));
  await act(async () => boxes()[0]!.click()); // untick token revocation
  await act(async () => confirm().click());
  await vi.waitFor(() => expect(done).toHaveBeenCalled());
  const patch = sent.find((r) => r.method === "PATCH")!;
  expect(patch.url).toBe(`${window.location.origin}/api/v1/tenants/acme/members/mem_1?revoke_tokens=false`);
  act(() => root.unmount());
});

it("a failed preview starts with both boxes off and warns", async () => {
  const { el, root, boxes } = await renderChange(async () => new Response("{}", { status: 500 }));
  await vi.waitFor(() => expect(el.textContent).toContain("couldn't be loaded"));
  expect(boxes().map((b) => b.checked)).toEqual([false, false]);
  act(() => root.unmount());
});

it("marks tokens above the caller's role and says the server would refuse", async () => {
  const tok = {
    id: "tok_1", name: "deploy", role: "owner", all_products: true, product_ids: [], display: "lf_live_x", created_by: "usr_m",
    created_at: "2026-11-01T00:00:00Z", expires_at: "2099-01-01T00:00:00Z", last_used_at: null, revoked_at: null,
  };
  const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
  vi.stubGlobal("fetch", vi.fn(async (req: Request) => json({ items: new URL(req.url).pathname.endsWith("api-tokens") ? [tok] : [] })));
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={new QueryClient()}>
        <ChangeDialog tenant="acme" caller={{ role: "admin", scope: { all: true, products: [] } }} roles={["admin", "viewer"]} change={{ kind: "remove", member }} onClose={() => {}} onDone={() => {}} />
      </QueryClientProvider>,
    ),
  );
  await vi.waitFor(() => expect(el.textContent).toContain("deploy (owner, lf_live_x) (above your role)"));
  expect(el.textContent).toContain("the server will refuse this");
  act(() => root.unmount());
});

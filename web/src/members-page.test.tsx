import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { invitationsQuery } from "./api/members";
import { InviteDialog } from "./members-page";

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

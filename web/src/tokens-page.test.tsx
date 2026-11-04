import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { tokensQuery } from "./api/tokens";
import { CreateTokenDialog } from "./tokens-page";

const SECRET = "lf_live_TOPSECRETvalue1234";

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  // jsdom has no modal dialogs; open/close are all the component needs.
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
  return open ? <CreateTokenDialog tenant="acme" member={{ role: "owner", scope: { all: true, products: [] } }} onClose={() => setOpen(false)} /> : <p>closed</p>;
}

it("shows the secret once and keeps it nowhere after the dialog closes", async () => {
  const row = {
    id: "tok_1", name: "ci", role: "sdk", all_products: true, product_ids: [], display: "lf_live_TOPS…",
    created_by: "usr_1", created_at: "2026-11-04T00:00:00Z", expires_at: "2027-02-02T00:00:00Z",
    last_used_at: null, revoked_at: null,
  };
  // After the create, list reads fail: a refetch can't overwrite a secret
  // that the dialog wrongly put into the cached list.
  let created = false;
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      if (req.method === "POST") {
        created = true;
        return json({ ...row, token: SECRET }, 201);
      }
      return created ? json({ code: "internal" }, 500) : json({ items: [row] });
    }),
  );
  const qc = new QueryClient();
  await qc.prefetchInfiniteQuery(tokensQuery("acme")); // the list is cached, as on the page
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

  const name = el.querySelector<HTMLInputElement>('input[name="name"]')!;
  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  await act(async () => {
    setValue.call(name, "ci");
    name.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => el.querySelector("form")!.requestSubmit());
  await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toBe(SECRET));

  const close = [...el.querySelectorAll("button")].find((b) => b.textContent === "Close")!;
  await act(async () => close.click());
  await vi.waitFor(() => expect(el.textContent).toContain("closed"));

  const kept = JSON.stringify([
    el.innerHTML,
    document.body.innerHTML,
    qc.getQueryCache().getAll().map((q) => q.state),
    qc.getMutationCache().getAll().map((m) => m.state),
    { ...localStorage },
    { ...sessionStorage },
  ]);
  expect(kept).not.toContain(SECRET);
  expect(kept).toContain("lf_live_TOPS…"); // the list's metadata is cached, the secret isn't
  act(() => root.unmount());
});

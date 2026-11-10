import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { createAppRouter } from "./router";

const SECRET = "whsec_TOPSECRETsigningKey000000000000000000000=";
const ROTATED = "whsec_ROTATEDsigningKey11111111111111111111111=";

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

const hook = (over: Record<string, unknown> = {}) => ({
  id: "whe_1",
  url: "https://hooks.example.com:443",
  events: ["license.issued"],
  enabled: true,
  disabled_reason: null,
  created_at: "2026-11-10T00:00:00Z",
  updated_at: "2026-11-10T00:00:00Z",
  delivery: { seq: 40, attempts: 0, next_attempt_at: null, in_flight: false, next_seq: null },
  ...over,
});

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
      if (u.pathname === "/api/v1/tenants/acme/webhooks" && req.method === "GET") return json({ items: hooks });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient();
  const el = document.createElement("div");
  document.body.append(el);
  root = createRoot(el);
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: ["/t/acme/settings/webhooks"] }));
  await act(async () =>
    root!.render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    ),
  );
  await vi.waitFor(() => expect(el.querySelector("h1")?.textContent).toBe("Webhooks"));
  return { el, qc, sent };
}

const button = (el: HTMLElement, text: string) => [...el.querySelectorAll("button")].find((b) => b.textContent === text);
const setValue = (i: HTMLInputElement, v: string) => {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(i, v);
  i.dispatchEvent(new Event("input", { bubbles: true }));
};

it("shows viewers the endpoints and their delivery state, without controls", async () => {
  const { el } = await open("viewer", [hook({ delivery: { seq: 40, attempts: 3, next_attempt_at: "2026-11-10T12:00:00Z", in_flight: false, next_seq: 41 } })]);
  await vi.waitFor(() => expect(el.textContent).toContain("https://hooks.example.com:443"));
  expect(el.textContent).toContain("Retrying (3 failed)");
  expect(button(el, "Deliveries")).toBeDefined();
  for (const b of ["New endpoint", "Edit", "Disable", "Skip held event", "Rotate secret", "Delete"]) expect(button(el, b)).toBeUndefined();
  expect([...el.querySelectorAll("nav a")].some((a) => a.textContent === "Webhooks")).toBe(true);
});

it("lets an admin skip the event held back, by its seq", async () => {
  const { el, sent } = await open("admin", [hook({ delivery: { seq: 40, attempts: 5, next_attempt_at: null, in_flight: false, next_seq: 41 } })], (req, u) =>
    req.method === "POST" && u.pathname.endsWith("/skip-event") ? json(hook()) : undefined,
  );
  await vi.waitFor(() => expect(button(el, "Skip held event")).toBeDefined());
  await act(async () => button(el, "Skip held event")!.click());
  expect(el.textContent).toContain("Event 41 is passed over");
  const confirm = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Skip held event") as HTMLButtonElement;
  await act(async () => confirm.click());
  await vi.waitFor(() => expect(sent.find((s) => s.path.endsWith("/skip-event"))?.body).toEqual({ seq: 41 }));
});

it("edits events with a merge patch, keeping the URL when left empty", async () => {
  const { el, sent } = await open("owner", [hook()], (req) => (req.method === "PATCH" ? json(hook({ events: ["license.issued", "license.revoked"] })) : undefined));
  await vi.waitFor(() => expect(button(el, "Edit")).toBeDefined());
  await act(async () => button(el, "Edit")!.click());
  const revoked = [...el.querySelectorAll<HTMLInputElement>('dialog input[type="checkbox"]')].find((c) => c.parentElement?.textContent === "license.revoked")!;
  await act(async () => revoked.click());
  await act(async () => el.querySelector<HTMLFormElement>("dialog form")!.requestSubmit());
  await vi.waitFor(() => expect(sent.some((s) => s.method === "PATCH")).toBe(true));
  const patch = sent.find((s) => s.method === "PATCH")!;
  expect(patch.type).toBe("application/merge-patch+json");
  expect(patch.body).toEqual({ events: ["license.issued", "license.revoked"] });
});

it("shows a new endpoint's secret and a rotated one once, and keeps neither", async () => {
  let created = false;
  const { el, qc } = await open("owner", [hook()], (req, u) => {
    if (req.method === "POST" && u.pathname === "/api/v1/tenants/acme/webhooks") {
      created = true;
      return json({ ...hook({ id: "whe_2" }), secret: SECRET }, 201);
    }
    if (req.method === "POST" && u.pathname.endsWith("/rotate-secret")) return json({ ...hook(), secret: ROTATED });
    if (created && req.method === "GET" && u.pathname === "/api/v1/tenants/acme/webhooks") return json({ items: [hook(), hook({ id: "whe_2" })] });
    return undefined;
  });
  await vi.waitFor(() => expect(button(el, "New endpoint")).toBeDefined());
  await act(async () => button(el, "New endpoint")!.click());
  await act(async () => setValue(el.querySelector<HTMLInputElement>('dialog input[name="url"]')!, "https://hooks.example.com/x?token=t"));
  await act(async () => el.querySelector<HTMLFormElement>("dialog form")!.requestSubmit());
  await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toBe(SECRET));
  await act(async () => button(el, "Close")!.click());
  await vi.waitFor(() => expect(el.querySelector("input[readonly]")).toBeNull());

  await act(async () => button(el, "Rotate secret")!.click()); // asks first
  expect(el.querySelector("dialog")!.textContent).toContain("keeps signing for 24 hours");
  const go = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Rotate secret") as HTMLButtonElement;
  await act(async () => go.click());
  await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toBe(ROTATED));
  await act(async () => button(el, "Close")!.click());
  await vi.waitFor(() => expect(el.querySelector("input[readonly]")).toBeNull());

  const kept = JSON.stringify([
    document.body.innerHTML,
    qc.getQueryCache().getAll().map((q) => q.state),
    qc.getMutationCache().getAll().map((m) => m.state),
    { ...localStorage },
    { ...sessionStorage },
  ]);
  expect(kept).not.toContain(SECRET);
  expect(kept).not.toContain(ROTATED);
  expect(kept).toContain("https://hooks.example.com:443");
});

it("lists deliveries in the log's own words", async () => {
  const { el } = await open("viewer", [hook()], (_req, u) =>
    u.pathname.endsWith("/deliveries")
      ? json({
          items: [
            { id: "whd_1", seq: 41, event_id: "aud_1", event_type: "license.issued", attempt: 2, outcome: "success", error: null, status_code: 204, duration_ms: 31, attempted_at: "2026-11-10T12:00:00Z" },
            { id: "whd_2", seq: 41, event_id: "aud_1", event_type: "license.issued", attempt: 1, outcome: "failure", error: "http 500", status_code: 500, duration_ms: 12, attempted_at: "2026-11-10T11:59:00Z" },
          ],
        })
      : undefined,
  );
  await vi.waitFor(() => expect(button(el, "Deliveries")).toBeDefined());
  await act(async () => button(el, "Deliveries")!.click());
  await vi.waitFor(() => expect(el.querySelector("dialog")?.textContent).toContain("http 500"));
  expect(el.querySelector("dialog")!.textContent).toContain("Delivered");
  expect(el.querySelector("dialog")!.textContent).toContain("license.issued #41");
});

it("tells a product-scoped member webhooks are tenant-wide, with no controls or nav link", async () => {
  const { el } = await open("admin", [], undefined, false);
  await vi.waitFor(() => expect(el.textContent).toContain("Webhooks are tenant-wide"));
  expect(el.textContent).not.toContain("No webhook endpoints yet.");
  expect(button(el, "New endpoint")).toBeUndefined();
  expect([...el.querySelectorAll("nav a")].some((a) => a.textContent === "Webhooks")).toBe(false);
});

it("says what each delivery state means, and offers to skip only an event held back", async () => {
  const rows = [
    hook({ id: "whe_a", url: "https://a.example:443", enabled: false, disabled_reason: "deliveries failed for about 28 hours",
      delivery: { seq: 9, attempts: 8, next_attempt_at: null, in_flight: false, next_seq: 10 } }),
    hook({ id: "whe_b", url: "https://b.example:443", delivery: { seq: 9, attempts: 0, next_attempt_at: null, in_flight: false, next_seq: 10 } }),
    hook({ id: "whe_c", url: "https://c.example:443", enabled: false, disabled_reason: "disabled by a user" }),
    hook({ id: "whe_d", url: "https://d.example:443" }),
    hook({ id: "whe_e", url: "https://e.example:443", enabled: false, disabled_reason: "disabled by a user",
      delivery: { seq: 11, attempts: 0, next_attempt_at: null, in_flight: false, next_seq: 12 } }),
    hook({ id: "whe_f", url: "https://f.example:443", enabled: false, disabled_reason: "deliveries failed for about 28 hours",
      delivery: { seq: 11, attempts: 8, next_attempt_at: "2026-11-10T12:00:00Z", in_flight: false, next_seq: null } }),
  ];
  const { el } = await open("owner", rows);
  await vi.waitFor(() => expect(el.querySelectorAll("tbody tr").length).toBe(6));
  const row = (i: number) => el.querySelectorAll("tbody tr")[i]!;
  expect(row(0).textContent).toContain("Event 10 held back");
  expect(row(0).textContent).toContain("Disabled: deliveries failed for about 28 hours");
  expect(row(0).querySelector('button[aria-label="Skip held event: https://a.example:443"]')).not.toBeNull();
  expect(row(1).textContent).toContain("Sending");
  expect(row(1).textContent).not.toContain("Skip held event");
  expect(row(2).textContent).toContain("Paused");
  expect(row(2).textContent).toContain("Disabled: by a member");
  expect(row(3).textContent).toContain("Up to date");
  expect(row(4).textContent).toContain("Event 12 held back"); // disabled with one pending: held, no failures needed
  expect(row(5).textContent).toContain("Paused"); // disabled keeps its attempts, nothing pending: not "Retrying"
  expect(row(5).textContent).not.toContain("Retrying");
  expect(row(4).querySelector('button[aria-label="Skip held event: https://e.example:443"]')).not.toBeNull();
  // Every row's buttons say which endpoint they act on.
  expect(el.querySelector('button[aria-label="Delete: https://d.example:443"]')).not.toBeNull();
});

it("refreshes the list after a refused enable, and deletes with confirmation", async () => {
  let gets = 0;
  const { el, sent } = await open("owner", [hook({ enabled: false, disabled_reason: "disabled by a user" })], (req, u) => {
    if (req.method === "GET" && u.pathname === "/api/v1/tenants/acme/webhooks") gets++;
    if (req.method === "POST" && u.pathname.endsWith("/enable")) return json({ code: "invalid_state", title: "Conflict", status: 409 }, 409);
    if (req.method === "DELETE") return new Response(null, { status: 204 });
    return undefined;
  });
  await vi.waitFor(() => expect(button(el, "Enable")).toBeDefined());
  const before = gets;
  await act(async () => button(el, "Enable")!.click());
  await vi.waitFor(() => expect(el.querySelector('[role="alert"]')).not.toBeNull());
  await vi.waitFor(() => expect(gets).toBeGreaterThan(before));
  await act(async () => button(el, "Delete")!.click());
  const del = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Delete") as HTMLButtonElement;
  await act(async () => del.click());
  await vi.waitFor(() => expect(sent.some((x) => x.method === "DELETE" && x.path === "/api/v1/tenants/acme/webhooks/whe_1")).toBe(true));
});

it("shows the API's field errors on the URL and events", async () => {
  const { el } = await open("owner", [], (req) =>
    req.method === "POST"
      ? json({ code: "validation_failed", title: "Unprocessable", status: 422, errors: [{ field: "/url", message: "must be https" }, { field: "/events", message: "unknown event" }] }, 422)
      : undefined,
  );
  await vi.waitFor(() => expect(button(el, "New endpoint")).toBeDefined());
  await act(async () => button(el, "New endpoint")!.click());
  // With no event checked there's nothing to save.
  const boxes = [...el.querySelectorAll<HTMLInputElement>('dialog input[type="checkbox"]')].filter((c) => c.checked);
  for (const c of boxes) await act(async () => c.click());
  expect(button(el, "Add endpoint")!.disabled).toBe(true);
  await act(async () => boxes[0]!.click());
  expect(button(el, "Add endpoint")!.disabled).toBe(false);
  await act(async () => setValue(el.querySelector<HTMLInputElement>('dialog input[name="url"]')!, "http://x.example/"));
  await act(async () => el.querySelector<HTMLFormElement>("dialog form")!.requestSubmit());
  await vi.waitFor(() => expect(el.querySelector("#url-error")?.textContent).toBe("must be https"));
  expect(el.querySelector("#events-error")?.textContent).toBe("unknown event");
  expect(el.querySelector('dialog input[name="url"]')!.getAttribute("aria-invalid")).toBe("true");
});

it("pages through the delivery log", async () => {
  const d = (id: string) => ({ id, seq: 1, event_id: "aud_1", event_type: "license.issued", attempt: 1, outcome: "success", error: null, status_code: 204, duration_ms: 5, attempted_at: "2026-11-10T12:00:00Z" });
  const cursors: (string | null)[] = [];
  const { el } = await open("viewer", [hook()], (_req, u) => {
    if (!u.pathname.endsWith("/deliveries")) return undefined;
    cursors.push(u.searchParams.get("cursor"));
    return u.searchParams.get("cursor") ? json({ items: [d("whd_2")] }) : json({ items: [d("whd_1")], next_cursor: "c1" });
  });
  await vi.waitFor(() => expect(button(el, "Deliveries")).toBeDefined());
  await act(async () => button(el, "Deliveries")!.click());
  await vi.waitFor(() => expect(button(el, "Load more")).toBeDefined());
  await act(async () => button(el, "Load more")!.click());
  await vi.waitFor(() => expect(el.querySelectorAll("dialog tbody tr").length).toBe(2));
  expect(cursors).toEqual([null, "c1"]);
  expect(button(el, "Load more")).toBeUndefined();
});

it("keeps the rotate dialog open until the new secret arrives, whatever Esc or Cancel do", async () => {
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  const { el } = await open("owner", [hook()], (req, u) =>
    req.method === "POST" && u.pathname.endsWith("/rotate-secret") ? (held.then(() => json({ ...hook(), secret: ROTATED })) as unknown as Response) : undefined,
  );
  await vi.waitFor(() => expect(button(el, "Rotate secret")).toBeDefined());
  await act(async () => button(el, "Rotate secret")!.click());
  const go = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Rotate secret") as HTMLButtonElement;
  await act(async () => go.click());
  await act(async () => el.querySelector("dialog")!.dispatchEvent(new Event("cancel", { cancelable: true })));
  const cancel = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Cancel") as HTMLButtonElement;
  expect(cancel.disabled).toBe(true);
  expect(go.disabled).toBe(true); // one rotation per click
  await act(async () => cancel.click());
  expect(el.querySelector("dialog")).not.toBeNull();
  await act(async () => release());
  await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toBe(ROTATED));
});

it("keeps a new endpoint's dialog open while it is created", async () => {
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  const { el } = await open("owner", [], (req, u) =>
    req.method === "POST" && u.pathname === "/api/v1/tenants/acme/webhooks" ? (held.then(() => json({ ...hook(), secret: SECRET }, 201)) as unknown as Response) : undefined,
  );
  await vi.waitFor(() => expect(button(el, "New endpoint")).toBeDefined());
  await act(async () => button(el, "New endpoint")!.click());
  await act(async () => setValue(el.querySelector<HTMLInputElement>('dialog input[name="url"]')!, "https://hooks.example.com/"));
  await act(async () => el.querySelector<HTMLFormElement>("dialog form")!.requestSubmit());
  await act(async () => el.querySelector("dialog")!.dispatchEvent(new Event("cancel", { cancelable: true })));
  expect(el.querySelector("dialog")).not.toBeNull();
  expect(button(el, "Cancel")!.disabled).toBe(true);
  expect(button(el, "Add endpoint")!.disabled).toBe(true); // no second endpoint from a double submit
  await act(async () => release());
  await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toBe(SECRET));
});

it("refreshes the list after a refused confirm or edit, and offers no retry", async () => {
  let gets = 0;
  const { el } = await open("owner", [hook()], (req, u) => {
    if (req.method === "GET" && u.pathname === "/api/v1/tenants/acme/webhooks") gets++;
    if (req.method === "POST" && u.pathname.endsWith("/disable")) return json({ code: "not_found", title: "Not Found", status: 404 }, 404);
    if (req.method === "PATCH") return json({ code: "not_found", title: "Not Found", status: 404 }, 404);
    return undefined;
  });
  await vi.waitFor(() => expect(button(el, "Disable")).toBeDefined());
  let before = gets;
  await act(async () => button(el, "Disable")!.click());
  const go = [...el.querySelectorAll("dialog button")].find((b) => b.textContent === "Disable") as HTMLButtonElement;
  await act(async () => go.click());
  await vi.waitFor(() => expect(el.querySelector('dialog [role="alert"]')).not.toBeNull());
  await vi.waitFor(() => expect(gets).toBeGreaterThan(before));
  expect([...el.querySelectorAll("dialog button")].map((b) => b.textContent)).toEqual(["Close"]);
  await act(async () => button(el, "Close")!.click());

  before = gets;
  await act(async () => button(el, "Edit")!.click());
  await act(async () => el.querySelector<HTMLFormElement>("dialog form")!.requestSubmit());
  await vi.waitFor(() => expect(el.querySelector('dialog [role="alert"]')).not.toBeNull());
  await vi.waitFor(() => expect(gets).toBeGreaterThan(before));
});

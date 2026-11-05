import { QueryClient } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { formatCount, recentLicenses, summaryQuery } from "./overview";

afterEach(() => vi.unstubAllGlobals());

function serve(body: unknown) {
  const f = vi.fn<(req: Request) => Promise<Response>>(async () => new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", f);
  return f;
}

it("reads the counts in one GET /summary", async () => {
  const f = serve({ licenses: { active: 3, suspended: 1, revoked: 0 } });
  const s = await new QueryClient().fetchQuery(summaryQuery("acme"));
  expect(s.licenses).toEqual({ active: 3, suspended: 1, revoked: 0 });
  expect(s.customers).toBeUndefined();
  expect(f).toHaveBeenCalledTimes(1);
  const req = f.mock.calls[0]![0];
  expect([req.method, req.url]).toEqual(["GET", `${window.location.origin}/api/v1/tenants/acme/summary`]);
});

it("asks for the newest licenses only", async () => {
  const f = serve({ items: [{ id: "lic_1" }] });
  await recentLicenses("acme");
  expect(new URL(f.mock.calls[0]![0].url).searchParams.get("limit")).toBe("5");
});

it("formats counts", () => {
  expect(formatCount(2400)).toBe((2400).toLocaleString());
});

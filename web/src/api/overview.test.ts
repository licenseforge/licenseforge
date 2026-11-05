import { afterEach, expect, it, vi } from "vitest";
import { countActiveCustomers, countLicenses, formatCount, recentLicenses } from "./overview";

afterEach(() => vi.unstubAllGlobals());

/** A list served page by page: pages of the given sizes, then the end. */
function pages(sizes: number[], row: (i: number) => object) {
  const f = vi.fn<(req: Request) => Promise<Response>>(async (req) => {
    const at = Number(new URL(req.url).searchParams.get("cursor") ?? 0);
    const items = Array.from({ length: sizes[at] ?? 0 }, (_, i) => row(i));
    return new Response(JSON.stringify(at + 1 < sizes.length ? { items, next_cursor: String(at + 1) } : { items }), {
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", f);
  return f;
}

it("counts licenses of a status across pages, asking for 200 at a time", async () => {
  const f = pages([200, 200, 7], () => ({}));
  expect(await countLicenses("acme", "suspended")).toEqual({ n: 407, capped: false });
  const q = new URL(f.mock.calls[0]![0].url).searchParams;
  expect([q.get("status"), q.get("limit")]).toEqual(["suspended", "200"]);
});

it("says when it stopped at its bound", async () => {
  pages([200, 200, 200], () => ({}));
  const c = await countLicenses("acme", "active", 2);
  expect(c).toEqual({ n: 400, capped: true });
  expect(formatCount(c)).toBe(`${(400).toLocaleString()}+`);
  expect(formatCount({ n: 12, capped: false })).toBe("12");
});

it("counts only customers that aren't archived", async () => {
  pages([3], (i) => ({ archived_at: i === 1 ? "2026-11-01T00:00:00Z" : null }));
  expect(await countActiveCustomers("acme")).toEqual({ n: 2, capped: false });
});

it("asks for the newest licenses only", async () => {
  const f = pages([5], (i) => ({ id: `lic_${i}` }));
  expect(await recentLicenses("acme")).toHaveLength(5);
  expect(new URL(f.mock.calls[0]![0].url).searchParams.get("limit")).toBe("5");
});

import { api, unwrap } from "./client";
import type { LicenseStatus } from "./licenses";
import { everyPage } from "./members";

/** A count from paging a list: the API has no totals (ADR-0032), so it stops at a bound. */
export type Count = { n: number; capped: boolean };

const MAX_PAGES = 10; // 2,000 rows of 200: "2,000+" beyond

/** Licenses with status in the caller's product scope. */
export async function countLicenses(tenant: string, status: LicenseStatus, maxPages = MAX_PAGES): Promise<Count> {
  const r = await everyPage(
    async (cursor) =>
      unwrap(await api.GET("/tenants/{tenant}/licenses", { params: { path: { tenant }, query: { status, cursor, limit: 200 } } })),
    maxPages,
  );
  return { n: r.items.length, capped: !r.complete };
}

/** Customers that aren't archived (tenant-wide: needs access to every product). */
export async function countActiveCustomers(tenant: string, maxPages = MAX_PAGES): Promise<Count> {
  const r = await everyPage(
    async (cursor) =>
      unwrap(await api.GET("/tenants/{tenant}/customers", { params: { path: { tenant }, query: { cursor, limit: 200 } } })),
    maxPages,
  );
  // ponytail: an archived row still counts against the bound; a server-side count would fix both.
  return { n: r.items.filter((c) => !c.archived_at).length, capped: !r.complete };
}

/** The newest licenses (the list is newest first). */
export async function recentLicenses(tenant: string, n = 5) {
  return unwrap(await api.GET("/tenants/{tenant}/licenses", { params: { path: { tenant }, query: { limit: n } } })).items;
}

const number = new Intl.NumberFormat();
/** "12", or "2,000+" when the count stopped at its bound. */
export const formatCount = (c: Count) => `${number.format(c.n)}${c.capped ? "+" : ""}`;

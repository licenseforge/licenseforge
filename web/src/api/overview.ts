import { queryOptions } from "@tanstack/react-query";
import { api, unwrap } from "./client";
import type { components } from "./schema";

export type Summary = components["schemas"]["Summary"];

/**
 * Exact counts in the caller's scope, in one request (GET /summary): licenses
 * by status, and customers only for callers who see every product.
 */
export const summaryQuery = (tenant: string) =>
  queryOptions({
    queryKey: ["summary", tenant],
    queryFn: async () => unwrap(await api.GET("/tenants/{tenant}/summary", { params: { path: { tenant } } })),
  });

/** The newest licenses (the list is newest first). */
export async function recentLicenses(tenant: string, n = 5) {
  return unwrap(await api.GET("/tenants/{tenant}/licenses", { params: { path: { tenant }, query: { limit: n } } })).items;
}

const number = new Intl.NumberFormat();
export const formatCount = (n: number) => number.format(n);

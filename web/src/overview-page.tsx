import { useQueries, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { allCustomers, allProducts } from "@/api/catalog";
import type { LicenseStatus } from "@/api/licenses";
import { type Count, countActiveCustomers, countLicenses, formatCount, recentLicenses } from "@/api/overview";
import { tenantsQuery } from "@/api/tenants";
import { errorText } from "@/components/modal";
import { t } from "@/i18n";
import { expiryText } from "@/licenses-page";

const statuses: LicenseStatus[] = ["active", "suspended", "revoked"];
const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

function Tile({ label, count, isError, error }: { label: string; count?: Count; isError: boolean; error: unknown }) {
  return (
    <div className="rounded-md border p-4">
      <div className="text-sm text-muted-foreground">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums" aria-live="polite">
        {isError ? <span className="text-sm font-normal">{errorText(error)}</span> : count ? formatCount(count) : "…"}
      </div>
    </div>
  );
}

/**
 * The tenant overview (ADR-0020): licenses by status, active customers and
 * the newest licenses. Counts page the lists (the API has no totals).
 */
export function Overview() {
  const { slug } = useParams({ from: "/app/t/$slug/" });
  const { data: tenants = [] } = useQuery(tenantsQuery);
  const caller = tenants.find((tn) => tn.slug === slug);
  const seesCustomers = caller?.scope.all ?? false; // customers are tenant-wide
  const byStatus = useQueries({
    queries: statuses.map((s) => ({ queryKey: ["overview-licenses", slug, s], queryFn: () => countLicenses(slug, s) })),
  });
  const customers = useQuery({ queryKey: ["overview-customers", slug], queryFn: () => countActiveCustomers(slug), enabled: seesCustomers });
  const recent = useQuery({ queryKey: ["overview-recent", slug], queryFn: () => recentLicenses(slug) });
  const products = useQuery({ queryKey: ["products-all", slug], queryFn: () => allProducts(slug) });
  const names = useQuery({ queryKey: ["customers-all", slug], queryFn: () => allCustomers(slug), enabled: seesCustomers });
  const productName = (id: string) => products.data?.items.find((p) => p.id === id)?.name ?? id;
  const customerName = (id: string) => names.data?.items.find((c) => c.id === id)?.name ?? id;

  return (
    <>
      <h1 className="text-2xl font-semibold">{t("overview.title")}</h1>
      {caller && !caller.scope.all && <p className="mt-1 text-sm text-muted-foreground">{t("overview.scoped")}</p>}
      <h2 className="mt-6 font-semibold">{t("overview.licenses")}</h2>
      <div className="mt-2 grid gap-3 sm:grid-cols-3">
        {statuses.map((s, i) => (
          <Tile key={s} label={t(`licenses.status.${s}`)} count={byStatus[i]!.data} isError={byStatus[i]!.isError} error={byStatus[i]!.error} />
        ))}
      </div>
      {seesCustomers && (
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <Tile label={t("overview.customers")} count={customers.data} isError={customers.isError} error={customers.error} />
        </div>
      )}
      <div className="mt-8 flex items-center justify-between">
        <h2 className="font-semibold">{t("overview.recent")}</h2>
        <Link to="/t/$slug/licenses" params={{ slug }} className="text-sm underline">
          {t("nav.licenses")}
        </Link>
      </div>
      {recent.isError && <p role="alert" className="mt-2">{errorText(recent.error)}</p>}
      {recent.data?.length === 0 && <p className="mt-2 text-muted-foreground">{t("overview.recentNone")}</p>}
      {recent.data && recent.data.length > 0 && (
        <ul className="mt-2 divide-y rounded-md border text-sm">
          {recent.data.map((l) => (
            <li key={l.id} className="flex flex-wrap justify-between gap-2 p-3">
              <span>
                <span className="font-medium">{productName(l.product_id)}</span> · {customerName(l.customer_id)} ·{" "}
                <span className="font-mono text-xs">…{l.key_hint}</span>
              </span>
              <span className="text-muted-foreground">
                {t(`licenses.status.${l.status}`)} · {date.format(new Date(l.issued_at))} · {expiryText(l)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

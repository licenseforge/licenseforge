import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { allCustomers, allProducts } from "@/api/catalog";
import type { LicenseStatus } from "@/api/licenses";
import { formatCount, recentLicenses, summaryQuery } from "@/api/overview";
import { tenantsQuery } from "@/api/tenants";
import { errorText } from "@/components/modal";
import { t } from "@/i18n";
import { expiryText } from "@/licenses-page";

const statuses: LicenseStatus[] = ["active", "suspended", "revoked"];
const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

function Tile({ label, value }: { label: string; value?: number }) {
  return (
    <div className="rounded-md border p-4">
      <div className="text-sm text-muted-foreground">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums" aria-live="polite">
        {value === undefined ? "…" : formatCount(value)}
      </div>
    </div>
  );
}

/**
 * The tenant overview (ADR-0020): exact counts from GET /summary (licenses
 * by status; active customers when the server includes them) and the newest
 * licenses.
 */
export function Overview() {
  const { slug } = useParams({ from: "/app/t/$slug/" });
  const { data: tenants = [] } = useQuery(tenantsQuery);
  const caller = tenants.find((tn) => tn.slug === slug);
  const summary = useQuery(summaryQuery(slug));
  const recent = useQuery({ queryKey: ["overview-recent", slug], queryFn: () => recentLicenses(slug) });
  const products = useQuery({ queryKey: ["products-all", slug], queryFn: () => allProducts(slug) });
  // Customer names only for callers who see customers (tenant-wide).
  const names = useQuery({ queryKey: ["customers-all", slug], queryFn: () => allCustomers(slug), enabled: caller?.scope.all ?? false });
  const productName = (id: string) => products.data?.items.find((p) => p.id === id)?.name ?? id;
  const customerName = (id: string) => names.data?.items.find((c) => c.id === id)?.name ?? id;
  const customers = summary.data?.customers; // absent for callers who don't see every product

  return (
    <>
      <h1 className="text-2xl font-semibold">{t("overview.title")}</h1>
      {caller && !caller.scope.all && <p className="mt-1 text-sm text-muted-foreground">{t("overview.scoped")}</p>}
      {summary.isError && <p role="alert" className="mt-4">{errorText(summary.error)}</p>}
      <h2 className="mt-6 font-semibold">{t("overview.licenses")}</h2>
      <div className="mt-2 grid gap-3 sm:grid-cols-3">
        {statuses.map((s) => (
          <Tile key={s} label={t(`licenses.status.${s}`)} value={summary.data?.licenses[s]} />
        ))}
      </div>
      {customers && (
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <Tile label={t("overview.customers")} value={customers.active} />
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

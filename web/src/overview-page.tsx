import { useQueries, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { getCustomer, getProduct } from "@/api/catalog";
import type { LicenseStatus } from "@/api/licenses";
import { type DailyMetricsDay, dailyQuery, formatCount, recentLicenses, summaryQuery } from "@/api/overview";
import { tenantsQuery } from "@/api/tenants";
import { errorText } from "@/components/modal";
import { t } from "@/i18n";
import { expiryText } from "@/licenses-page";

const statuses: LicenseStatus[] = ["active", "suspended", "revoked"];
const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const month = new Intl.DateTimeFormat(undefined, { month: "long", year: "numeric", timeZone: "UTC" });

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

const series = ["licenses_issued", "activations", "deactivations"] as const;
const utcDay = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
const dayText = (d: string) => utcDay.format(new Date(`${d}T00:00:00Z`));

/**
 * One series as columns, a day each (ADR-0046): one color, so the title
 * names it; the total is in the title; each column's day and count is its
 * tooltip; the table below says the same in text.
 */
function DailyChart({ days, field }: { days: DailyMetricsDay[]; field: (typeof series)[number] }) {
  const values = days.map((d) => d[field]);
  const total = values.reduce((a, b) => a + b, 0);
  const max = Math.max(1, ...values);
  const W = 300, H = 80, slot = W / days.length, bar = Math.min(24, slot - 2);
  const label = t(`overview.daily.${field}`);
  const summary = t("overview.daily.total", { n: formatCount(total), days: String(days.length) });
  return (
    <figure className="rounded-md border p-4">
      <figcaption className="text-sm text-muted-foreground">
        {label} · {summary}
      </figcaption>
      <div className="mt-2 flex gap-2">
        <span className="text-xs text-muted-foreground tabular-nums" aria-hidden="true">{formatCount(Math.max(...values))}</span>
        <svg viewBox={`0 0 ${W} ${H}`} className="h-20 w-full" role="img" aria-label={`${label}: ${summary}`}>
          <line x1={0} x2={W} y1={H - 0.5} y2={H - 0.5} stroke="currentColor" className="text-muted-foreground/40" strokeWidth={1} />
          {days.map((d, i) => {
            const h = (d[field] / max) * (H - 4);
            const x = i * slot + (slot - bar) / 2;
            const r = Math.min(4, h, bar / 2); // 4px rounded data end, square at the baseline
            return (
              <g key={d.date}>
                <title>{`${dayText(d.date)}: ${formatCount(d[field])}`}</title>
                {/* the whole slot is the hover target, not just the column */}
                <rect x={i * slot} y={0} width={slot} height={H} fill="transparent" />
                {h > 0 && (
                  <path
                    className="fill-primary"
                    d={`M${x},${H} V${H - h + r} Q${x},${H - h} ${x + r},${H - h} H${x + bar - r} Q${x + bar},${H - h} ${x + bar},${H - h + r} V${H} Z`}
                  />
                )}
              </g>
            );
          })}
        </svg>
      </div>
      <div className="mt-1 flex justify-between text-xs text-muted-foreground" aria-hidden="true">
        <span>{dayText(days[0]!.date)}</span>
        <span>{dayText(days[days.length - 1]!.date)}</span>
      </div>
    </figure>
  );
}

function DailyCharts({ days }: { days: DailyMetricsDay[] }) {
  return (
    <>
      <div className="mt-2 grid gap-3 sm:grid-cols-3">
        {series.map((f) => (
          <DailyChart key={f} days={days} field={f} />
        ))}
      </div>
      <details className="mt-2 text-sm">
        <summary className="cursor-pointer text-muted-foreground">{t("overview.daily.table")}</summary>
        <table className="mt-2 w-full text-left tabular-nums">
          <thead>
            <tr className="border-b text-muted-foreground">
              <th scope="col" className="px-2 py-1 font-medium">{t("overview.daily.day")}</th>
              {series.map((f) => (
                <th key={f} scope="col" className="px-2 py-1 font-medium">{t(`overview.daily.${f}`)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {days.map((d) => (
              <tr key={d.date} className="border-b">
                <th scope="row" className="px-2 py-1 font-normal">{dayText(d.date)}</th>
                {series.map((f) => (
                  <td key={f} className="px-2 py-1">{formatCount(d[f])}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </>
  );
}

/**
 * The tenant overview (ADR-0020): exact counts from GET /summary (licenses
 * by status; customers and those active this month, ADR-0016, when the
 * server includes them) and the newest licenses.
 */
export function Overview() {
  const { slug } = useParams({ from: "/app/t/$slug/" });
  const { data: tenants = [] } = useQuery(tenantsQuery);
  const caller = tenants.find((tn) => tn.slug === slug);
  const summary = useQuery(summaryQuery(slug));
  const recent = useQuery({ queryKey: ["overview-recent", slug], queryFn: () => recentLicenses(slug) });
  const daily = useQuery(dailyQuery(slug));
  const customers = summary.data?.customers; // absent for callers who don't see every product
  // Names for the recent rows only: each distinct product and customer by ID
  // (at most five of each), customers only when the server says the caller
  // sees them.
  const distinct = (pick: (l: { product_id: string; customer_id: string }) => string) => [...new Set((recent.data ?? []).map(pick))];
  const productIds = distinct((l) => l.product_id);
  const customerIds = customers !== undefined ? distinct((l) => l.customer_id) : [];
  const products = useQueries({ queries: productIds.map((id) => ({ queryKey: ["product", slug, id], queryFn: () => getProduct(slug, id) })) });
  const customerRows = useQueries({ queries: customerIds.map((id) => ({ queryKey: ["customer", slug, id], queryFn: () => getCustomer(slug, id) })) });
  const productName = (id: string) => products[productIds.indexOf(id)]?.data?.name ?? id;
  const customerName = (id: string) => customerRows[customerIds.indexOf(id)]?.data?.name ?? id;

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
          {/* ADR-0016's measure: customers with a machine seen this month (UTC) */}
          <Tile label={t("overview.seenThisMonth", { month: month.format(new Date(customers.month_start)) })} value={customers.seen_this_month} />
        </div>
      )}
      <h2 className="mt-8 font-semibold">{t("overview.daily.title")}</h2>
      {daily.isError && <p role="alert" className="mt-2">{errorText(daily.error)}</p>}
      {daily.data && daily.data.length > 0 && <DailyCharts days={daily.data} />}
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

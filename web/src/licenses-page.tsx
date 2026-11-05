import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { ApiError, fieldErrors, onAuthError } from "@/api/client";
import { allCustomers, allProducts, parseRefs, refsBody } from "@/api/catalog";
import {
  actionsFor,
  canManageLicenses,
  changeLicense,
  issueLicense,
  type License,
  type LicenseAction,
  type LicenseFilter,
  type LicenseIssue,
  type LicenseIssued,
  type LicenseStatus,
  licensesQuery,
} from "@/api/licenses";
import { tenantsQuery } from "@/api/tenants";
import type { Membership } from "@/api/tokens";
import { errorText, input, Modal } from "@/components/modal";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const th = "px-2 py-2 font-medium";
const td = "px-2 py-2";
const statuses: LicenseStatus[] = ["active", "suspended", "revoked"];
const types: NonNullable<LicenseIssue["type"]>[] = ["paid", "trial", "dev", "community"];

/** Names for IDs: products and customers the caller can see. */
function useNames(tenant: string) {
  const products = useQuery({ queryKey: ["products-all", tenant], queryFn: () => allProducts(tenant) });
  const customers = useQuery({ queryKey: ["customers-all", tenant], queryFn: () => allCustomers(tenant) });
  const productName = (id: string) => products.data?.items.find((p) => p.id === id)?.name ?? id;
  const customerName = (id: string) => customers.data?.items.find((c) => c.id === id)?.name ?? id;
  const all = customers.data?.items ?? [];
  return {
    products: products.data?.items ?? [],
    customers: all, // the filter and names keep archived ones
    issuable: all.filter((c) => !c.archived_at), // archived customers get no new licenses
    complete: (products.data?.complete ?? true) && (customers.data?.complete ?? true),
    productName,
    customerName,
  };
}

export const expiryText = (l: Pick<License, "expires_at" | "expiry_basis">) =>
  l.expires_at ? date.format(new Date(l.expires_at)) : l.expiry_basis === "from_first_activation" ? t("licenses.fromFirstActivation") : t("licenses.perpetual");

export function LicensesPage() {
  const { slug } = useParams({ from: "/app/t/$slug/licenses" });
  const { data: tenants = [] } = useQuery(tenantsQuery);
  const caller: Membership = tenants.find((tn) => tn.slug === slug) ?? { role: "viewer", scope: { all: false, products: [] } };
  const manage = canManageLicenses(caller);
  const names = useNames(slug);
  const [filter, setFilter] = useState<LicenseFilter>({});
  const list = useInfiniteQuery(licensesQuery(slug, filter));
  const [open, setOpen] = useState<License | null>(null);
  const [issuing, setIssuing] = useState(false);
  const rows = list.data?.pages.flatMap((p) => p.items) ?? [];
  const pick = (k: keyof LicenseFilter, v: string) => setFilter((f) => ({ ...f, [k]: v || undefined }));

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">{t("licenses.title")}</h1>
        {manage && <Button onClick={() => setIssuing(true)}>{t("licenses.issue")}</Button>}
      </div>
      <div className="mt-4 flex flex-wrap gap-3 text-sm">
        <label className="flex items-center gap-2">
          {t("licenses.col.product")}
          <select className={input} value={filter.product_id ?? ""} onChange={(e) => pick("product_id", e.target.value)}>
            <option value="">{t("licenses.any")}</option>
            {names.products.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </label>
        {names.customers.length > 0 && (
          <label className="flex items-center gap-2">
            {t("licenses.col.customer")}
            <select className={input} value={filter.customer_id ?? ""} onChange={(e) => pick("customer_id", e.target.value)}>
              <option value="">{t("licenses.any")}</option>
              {names.customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
        )}
        <label className="flex items-center gap-2">
          {t("tokens.col.status")}
          <select className={input} value={filter.status ?? ""} onChange={(e) => pick("status", e.target.value)}>
            <option value="">{t("licenses.any")}</option>
            {statuses.map((s) => <option key={s} value={s}>{t(`licenses.status.${s}`)}</option>)}
          </select>
        </label>
      </div>
      {!names.complete && <p className="mt-2 text-sm">{t("licenses.listsIncomplete")}</p>}
      {list.isError && <p role="alert" className="mt-4">{errorText(list.error)}</p>}
      {list.isSuccess && rows.length === 0 && <p className="mt-6 text-muted-foreground">{t("licenses.empty")}</p>}
      {rows.length > 0 && (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-muted-foreground">
              <tr>
                <th scope="col" className={th}>{t("licenses.col.key")}</th>
                <th scope="col" className={th}>{t("licenses.col.product")}</th>
                <th scope="col" className={th}>{t("licenses.col.customer")}</th>
                <th scope="col" className={th}>{t("licenses.col.plan")}</th>
                <th scope="col" className={th}>{t("tokens.col.status")}</th>
                <th scope="col" className={th}>{t("tokens.col.expires")}</th>
                <th scope="col" className={th}><span className="sr-only">{t("licenses.details")}</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((l) => (
                <tr key={l.id} className="border-b">
                  <td className={`${td} font-mono text-xs`}>…{l.key_hint}</td>
                  <td className={td}>{names.productName(l.product_id)}</td>
                  <td className={td}>{names.customerName(l.customer_id)}</td>
                  <td className={td}>{l.plan_slug} ({t(`licenses.type.${l.type}`)})</td>
                  <td className={td}>{t(`licenses.status.${l.status}`)}</td>
                  <td className={td}>{expiryText(l)}</td>
                  <td className={`${td} text-right`}>
                    <Button variant="ghost" onClick={() => setOpen(l)}>{t("licenses.details")}</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {list.hasNextPage && (
        <Button variant="ghost" className="mt-2" disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
          {t("tokens.more")}
        </Button>
      )}
      {open && <LicenseDialog tenant={slug} license={open} manage={manage} names={names} onClose={() => setOpen(null)} onChanged={setOpen} />}
      {issuing && <IssueDialog tenant={slug} names={names} onClose={() => setIssuing(false)} />}
    </>
  );
}

/** A license's entitlement snapshot and dates, with the actions its status allows. */
export function LicenseDialog({ tenant, license: l, manage, names, onClose, onChanged }: {
  tenant: string; license: License; manage: boolean; names: ReturnType<typeof useNames>; onClose: () => void; onChanged: (l: License) => void;
}) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState<LicenseAction | null>(null);
  const act = useMutation({
    mutationFn: (a: LicenseAction) => changeLicense(tenant, l.id, a),
    onSuccess: async (updated) => {
      await qc.invalidateQueries({ queryKey: ["licenses", tenant] });
      setConfirm(null);
      onChanged(updated);
    },
  });
  const limits = Object.entries(l.entitlements.limits);
  const row = (k: string, v: string) => (
    <div className="flex justify-between gap-4 border-b py-1">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="text-right">{v}</dd>
    </div>
  );
  return (
    <Modal title={t("licenses.detailTitle", { hint: l.key_hint })} onClose={onClose}>
      <dl className="text-sm">
        {row(t("licenses.col.product"), names.productName(l.product_id))}
        {row(t("licenses.col.customer"), names.customerName(l.customer_id))}
        {row(t("licenses.col.plan"), `${l.plan_slug} (${t(`licenses.type.${l.type}`)})`)}
        {row(t("tokens.col.status"), t(`licenses.status.${l.status}`))}
        {row(t("tokens.col.expires"), expiryText(l))}
        {row(t("licenses.maxActivations"), l.max_activations === null ? t("licenses.unlimited") : String(l.max_activations))}
        {row(t("licenses.issued"), date.format(new Date(l.issued_at)))}
        {l.suspended_at && row(t("licenses.suspendedAt"), date.format(new Date(l.suspended_at)))}
        {l.revoked_at && row(t("licenses.revokedAt"), date.format(new Date(l.revoked_at)))}
        {Object.keys(l.external_refs).length > 0 && row(t("customers.col.refs"), Object.entries(l.external_refs).map(([k, v]) => `${k}=${v}`).join(", "))}
      </dl>
      <h3 className="mt-4 font-semibold">{t("licenses.entitlements")}</h3>
      <p className="mt-1 text-xs text-muted-foreground">{t("licenses.snapshot")}</p>
      <ul className="mt-2 flex flex-wrap gap-1 text-xs">
        {l.entitlements.features.length === 0 && <li className="text-muted-foreground">{t("members.previewNone")}</li>}
        {l.entitlements.features.map((f) => <li key={f} className="rounded border px-1.5 py-0.5 font-mono">{f}</li>)}
      </ul>
      {limits.length > 0 && (
        <table className="mt-2 w-full text-left text-sm">
          <tbody>
            {limits.map(([k, v]) => (
              <tr key={k} className="border-b">
                <td className="py-1 font-mono text-xs">{k}</td>
                <td className="py-1 text-right">{v === -1 ? t("licenses.unlimited") : v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {act.isError && <p role="alert" className="mt-3 text-sm font-medium">{errorText(act.error)}</p>}
      {confirm ? (
        <div role="group" aria-label={t(`licenses.confirm.${confirm}`)} className="mt-4 rounded-md border p-3 text-sm">
          <p className="font-medium">{t(`licenses.confirm.${confirm}`)}</p>
          <div className="mt-3 flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setConfirm(null)}>{t("tokens.cancel")}</Button>
            <Button disabled={act.isPending} onClick={() => act.mutate(confirm)}>{t(`licenses.action.${confirm}`)}</Button>
          </div>
        </div>
      ) : (
        <div className="mt-6 flex justify-end gap-2">
          {manage &&
            actionsFor(l.status).map((a) => (
              // reinstating loses nothing: no confirmation; suspending and revoking ask first
              <Button key={a} variant="ghost" disabled={act.isPending} onClick={() => (a === "reinstate" ? act.mutate(a) : setConfirm(a))}>
                {t(`licenses.action.${a}`)}
              </Button>
            ))}
          <Button variant="ghost" onClick={onClose}>{t("tokens.close")}</Button>
        </div>
      )}
    </Modal>
  );
}

/**
 * Whether a failed issue may be retried with the same Idempotency-Key. The
 * server keeps an answer for a key, 4xx included, so after a definitive 4xx
 * (a fixable form error) the next attempt needs a new key; after a network
 * error, a 5xx, or an idempotency conflict the same key must be reused, so a
 * retry can never issue a second license.
 */
export function keepIdempotencyKey(e: unknown): boolean {
  if (!(e instanceof ApiError)) return true; // the request may have reached the server
  return e.status >= 500 || e.code === "idempotency_in_progress" || e.code === "idempotency_key_reused";
}

export function IssueDialog({ tenant, names, onClose }: { tenant: string; names: ReturnType<typeof useNames>; onClose: () => void }) {
  const qc = useQueryClient();
  const [idempotencyKey, setIdempotencyKey] = useState(() => crypto.randomUUID()); // a retry can't issue twice
  const [issued, setIssued] = useState<LicenseIssued | null>(null); // the key lives here only
  const [error, setError] = useState<unknown>(null);
  const [refsError, setRefsError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const fields = fieldErrors(error);
  const close = () => {
    setIssued(null);
    onClose();
  };

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    let refs: Map<string, string>;
    try {
      refs = parseRefs(String(f.get("refs") ?? ""));
    } catch (err) {
      setRefsError(t("customers.refsInvalid", { line: (err as Error).message }));
      return;
    }
    setRefsError(null);
    setBusy(true);
    setError(null);
    try {
      // Not a useMutation: its result (the key) would stay in the mutation cache.
      const l = await issueLicense(tenant, {
        product_id: String(f.get("product_id") ?? ""),
        customer_id: String(f.get("customer_id") ?? "").trim(),
        plan_id: String(f.get("plan_id") ?? "").trim(),
        type: String(f.get("type")) as LicenseIssue["type"],
        ...(refs.size ? { external_refs: refsBody(refs) } : {}),
      }, idempotencyKey);
      setIssued(l);
      void qc.invalidateQueries({ queryKey: ["licenses", tenant] }); // metadata only
    } catch (err) {
      onAuthError(err);
      setError(err);
      if (!keepIdempotencyKey(err)) setIdempotencyKey(crypto.randomUUID());
    } finally {
      setBusy(false);
    }
  }

  if (issued) {
    return (
      <Modal title={t("licenses.keyTitle")} onClose={close}>
        <p role="alert" className="mb-3 text-sm font-medium">{t("licenses.keyWarning")}</p>
        <div className="flex gap-2">
          <input readOnly aria-label={t("licenses.col.key")} value={issued.key} onFocus={(e) => e.currentTarget.select()} className={`${input} font-mono`} autoComplete="off" spellCheck={false} />
          <Button aria-live="polite" onClick={() => void navigator.clipboard.writeText(issued.key).then(() => setCopy("copied"), () => setCopy("failed"))}>
            {copy === "copied" ? t("tokens.copied") : t("tokens.copy")}
          </Button>
        </div>
        {copy === "failed" && <p role="alert" className="mt-2 text-sm">{t("licenses.copyFailed")}</p>}
        <div className="mt-6 flex justify-end">
          <Button variant="ghost" onClick={close}>{t("tokens.close")}</Button>
        </div>
      </Modal>
    );
  }

  const select = (name: string, label: string, options: { id: string; name: string }[]) => (
    <label className="flex flex-col gap-1 text-sm">
      {label}
      <select name={name} required className={input} defaultValue="" aria-invalid={!!fields[name]} aria-describedby={fields[name] ? `${name}-error` : undefined}>
        <option value="" disabled>{t("licenses.choose")}</option>
        {options.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
      </select>
      {fields[name] && <span id={`${name}-error`}>{fields[name]}</span>}
    </label>
  );
  return (
    <Modal title={t("licenses.issue")} onClose={close}>
      {!names.complete && <p className="mb-3 text-sm">{t("licenses.listsIncomplete")}</p>}
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4" noValidate>
        {select("product_id", t("licenses.col.product"), names.products)}
        {names.issuable.length > 0 ? (
          select("customer_id", t("licenses.col.customer"), names.issuable)
        ) : (
          // A product-scoped caller can't list customers (they're tenant-wide): it issues by customer ID.
          <label className="flex flex-col gap-1 text-sm">
            {t("licenses.customerId")}
            <input name="customer_id" required className={`${input} font-mono`} placeholder="cus_…" aria-invalid={!!fields.customer_id} aria-describedby={fields.customer_id ? "customer-help customer_id-error" : "customer-help"} />
            <span id="customer-help" className="text-xs text-muted-foreground">{t("licenses.customerHelp")}</span>
            {fields.customer_id && <span id="customer_id-error">{fields.customer_id}</span>}
          </label>
        )}
        <label className="flex flex-col gap-1 text-sm">
          {t("licenses.planId")}
          <input name="plan_id" required className={`${input} font-mono`} placeholder="pln_…" aria-invalid={!!fields.plan_id} aria-describedby={fields.plan_id ? "plan-help plan_id-error" : "plan-help"} />
          <span id="plan-help" className="text-xs text-muted-foreground">{t("licenses.planHelp")}</span>
          {fields.plan_id && <span id="plan_id-error">{fields.plan_id}</span>}
        </label>
        <label className="flex flex-col gap-1 text-sm">
          {t("licenses.type")}
          <select name="type" className={input} defaultValue="paid">
            {types.map((ty) => <option key={ty} value={ty}>{t(`licenses.type.${ty}`)}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          {t("customers.col.refs")}
          <textarea name="refs" rows={2} placeholder="order=1234" className={`${input} h-auto py-1 font-mono`} aria-invalid={!!(refsError || fields.external_refs)} aria-describedby={refsError || fields.external_refs ? "refs-error" : undefined} />
          {(refsError || fields.external_refs) && <span id="refs-error">{refsError ?? fields.external_refs}</span>}
        </label>
        {error != null && <p role="alert" className="text-sm font-medium">{errorText(error)}</p>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={close}>{t("tokens.cancel")}</Button>
          <Button type="submit" disabled={busy}>{t("licenses.issue")}</Button>
        </div>
      </form>
    </Modal>
  );
}

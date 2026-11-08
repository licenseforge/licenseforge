import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { type FormEvent, type ReactNode, useState } from "react";
import { fieldErrors } from "@/api/client";
import {
  archiveCustomer,
  archiveProduct,
  canCreateProducts,
  canRenameProducts,
  canWriteCustomers,
  createCustomer,
  createProduct,
  type Customer,
  customerPatch,
  customersQuery,
  formatRefs,
  parseRefs,
  refsBody,
  type Product,
  productsQuery,
  renameProduct,
  updateCustomer,
} from "@/api/catalog";
import { tenantsQuery } from "@/api/tenants";
import type { Membership } from "@/api/tokens";
import { errorText, input, Modal } from "@/components/modal";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const th = "px-2 py-2 font-medium";
const td = "px-2 py-2";

/** The caller's membership here, and whether it has loaded (no notices or actions before). */
export function useCaller(slug: string): Membership & { loaded: boolean } {
  const { data: tenants, isSuccess } = useQuery(tenantsQuery);
  const m = tenants?.find((tn) => tn.slug === slug) ?? { role: "viewer" as const, scope: { all: false, products: [] } };
  return { ...m, loaded: isSuccess };
}

/** A form in a dialog: fields, a submit with the problem's message and field errors. */
export function FormDialog({ title, submit, onClose, onSubmit, error, busy, children }: {
  title: string; submit: string; onClose: () => void; onSubmit: (f: FormData) => void; error: unknown; busy: boolean; children: ReactNode;
}) {
  return (
    <Modal title={title} onClose={onClose}>
      <form
        noValidate
        className="flex flex-col gap-4"
        onSubmit={(e: FormEvent<HTMLFormElement>) => {
          e.preventDefault();
          onSubmit(new FormData(e.currentTarget));
        }}
      >
        {children}
        {error != null && (
          <p role="alert" className="text-sm font-medium">
            {errorText(error)}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            {t("tokens.cancel")}
          </Button>
          <Button type="submit" disabled={busy}>
            {submit}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

/** A labelled input; aria-describedby names only help and error text that is on the page. */
export function Field({ label, name, error, help, ...rest }: { label: string; name: string; error?: string; help?: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  const describedBy = [help && `${name}-help`, error && `${name}-error`].filter(Boolean).join(" ") || undefined;
  return (
    <div className="flex flex-col gap-1 text-sm">
      <label className="flex flex-col gap-1">
        {label}
        <input name={name} className={input} aria-invalid={!!error} aria-describedby={describedBy} {...rest} />
      </label>
      {help && <span id={`${name}-help`} className="text-xs text-muted-foreground">{help}</span>}
      {error && <span id={`${name}-error`}>{error}</span>}
    </div>
  );
}

export function ProductsPage() {
  const { slug } = useParams({ from: "/app/t/$slug/products" });
  const caller = useCaller(slug);
  const list = useInfiniteQuery(productsQuery(slug));
  const [dialog, setDialog] = useState<{ kind: "create" } | { kind: "rename" | "archive"; product: Product } | null>(null);
  const rows = list.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">{t("products.title")}</h1>
        {canCreateProducts(caller) && <Button onClick={() => setDialog({ kind: "create" })}>{t("products.new")}</Button>}
      </div>
      {caller.loaded && !caller.scope.all && <p className="mt-2 text-sm text-muted-foreground">{t("products.scoped")}</p>}
      {list.isError && <p role="alert" className="mt-4">{errorText(list.error)}</p>}
      {list.isSuccess && rows.length === 0 && <p className="mt-6 text-muted-foreground">{t("products.empty")}</p>}
      {rows.length > 0 && (
        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-muted-foreground">
              <tr>
                <th scope="col" className={th}>{t("tokens.col.name")}</th>
                <th scope="col" className={th}>{t("products.col.slug")}</th>
                <th scope="col" className={th}>{t("products.col.created")}</th>
                <th scope="col" className={th}>{t("tokens.col.status")}</th>
                <th scope="col" className={th}><span className="sr-only">{t("customers.actions")}</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr key={p.id} className="border-b">
                  <td className={`${td} font-medium`}>
                    <Link to="/t/$slug/products/$id" params={{ slug, id: p.id }} className="underline-offset-4 hover:underline">
                      {p.name}
                    </Link>
                  </td>
                  <td className={`${td} font-mono text-xs`}>{p.slug}</td>
                  <td className={td}>{date.format(new Date(p.created_at))}</td>
                  <td className={td}>
                    {p.archived_at ? t("products.archivedOn", { date: date.format(new Date(p.archived_at)) }) : t("tokens.status.active")}
                  </td>
                  <td className={`${td} whitespace-nowrap text-right`}>
                    {canRenameProducts(caller) && (
                      <Button variant="ghost" onClick={() => setDialog({ kind: "rename", product: p })}>
                        {t("products.rename")}
                      </Button>
                    )}
                    {/* catalog:write on the product, as rename; archiving is one-way */}
                    {canRenameProducts(caller) && !p.archived_at && (
                      <Button variant="ghost" onClick={() => setDialog({ kind: "archive", product: p })}>
                        {t("products.archive")}
                      </Button>
                    )}
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
      {dialog?.kind === "archive" ? (
        <ArchiveProductDialog tenant={slug} product={dialog.product} onClose={() => setDialog(null)} />
      ) : dialog ? (
        <ProductDialog tenant={slug} product={dialog.kind === "rename" ? dialog.product : null} onClose={() => setDialog(null)} />
      ) : null}
    </>
  );
}

function ProductDialog({ tenant, product, onClose }: { tenant: string; product: Product | null; onClose: () => void }) {
  const qc = useQueryClient();
  const save = useMutation({
    mutationFn: (f: FormData) =>
      product
        ? String(f.get("name") ?? "") === product.name
          ? Promise.resolve(null) // unchanged: no request
          : renameProduct(tenant, product.id, String(f.get("name") ?? "").trim())
        : createProduct(tenant, String(f.get("slug") ?? "").trim(), String(f.get("name") ?? "").trim()),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: productsQuery(tenant).queryKey });
      await qc.invalidateQueries({ queryKey: ["product", tenant] }); // the product page
      onClose();
    },
  });
  const fields = fieldErrors(save.error);
  return (
    <FormDialog
      title={product ? t("products.renameTitle", { slug: product.slug }) : t("products.new")}
      submit={product ? t("products.rename") : t("products.create")}
      onClose={onClose}
      onSubmit={(f) => save.mutate(f)}
      error={save.error}
      busy={save.isPending}
    >
      {!product && (
        <Field label={t("products.col.slug")} name="slug" required maxLength={63} pattern="[a-z0-9]+(-[a-z0-9]+)*" error={fields.slug} help={t("products.slugHelp")} />
      )}
      <Field label={t("tokens.col.name")} name="name" required maxLength={200} defaultValue={product?.name} error={fields.name} />
    </FormDialog>
  );
}

export function CustomersPage() {
  const { slug } = useParams({ from: "/app/t/$slug/customers" });
  const caller = useCaller(slug);
  const write = canWriteCustomers(caller);
  const list = useInfiniteQuery(customersQuery(slug));
  const [dialog, setDialog] = useState<{ kind: "create" } | { kind: "edit" | "archive"; customer: Customer } | null>(null);
  const rows = list.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">{t("customers.title")}</h1>
        {write && <Button onClick={() => setDialog({ kind: "create" })}>{t("customers.new")}</Button>}
      </div>
      {caller.loaded && !caller.scope.all && <p className="mt-2 text-sm text-muted-foreground">{t("customers.scoped")}</p>}
      {list.isError && <p role="alert" className="mt-4">{errorText(list.error)}</p>}
      {list.isSuccess && rows.length === 0 && caller.scope.all && <p className="mt-6 text-muted-foreground">{t("customers.empty")}</p>}
      {rows.length > 0 && (
        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-muted-foreground">
              <tr>
                <th scope="col" className={th}>{t("tokens.col.name")}</th>
                <th scope="col" className={th}>{t("invitations.col.email")}</th>
                <th scope="col" className={th}>{t("customers.col.refs")}</th>
                <th scope="col" className={th}>{t("tokens.col.status")}</th>
                <th scope="col" className={th}><span className="sr-only">{t("customers.actions")}</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id} className="border-b">
                  <td className={`${td} font-medium`}>{c.name}</td>
                  <td className={td}>{c.email ?? ""}</td>
                  <td className={`${td} font-mono text-xs`}>
                    {Object.entries(c.external_refs).map(([k, v]) => `${k}=${v}`).join(", ")}
                  </td>
                  <td className={td}>{c.archived_at ? t("customers.archived") : t("tokens.status.active")}</td>
                  <td className={`${td} whitespace-nowrap text-right`}>
                    {write && <Button variant="ghost" onClick={() => setDialog({ kind: "edit", customer: c })}>{t("customers.edit")}</Button>}
                    {write && !c.archived_at && (
                      <Button variant="ghost" onClick={() => setDialog({ kind: "archive", customer: c })}>{t("customers.archive")}</Button>
                    )}
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
      {dialog?.kind === "archive" ? (
        <ArchiveDialog tenant={slug} customer={dialog.customer} onClose={() => setDialog(null)} />
      ) : dialog ? (
        <CustomerDialog tenant={slug} customer={dialog.kind === "edit" ? dialog.customer : null} onClose={() => setDialog(null)} />
      ) : null}
    </>
  );
}

export function CustomerDialog({ tenant, customer, onClose }: { tenant: string; customer: Customer | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [refsError, setRefsError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: async (f: FormData) => {
      const name = String(f.get("name") ?? "");
      const email = String(f.get("email") ?? "");
      const refs = parseRefs(String(f.get("refs") ?? ""));
      if (customer) {
        const patch = customerPatch(customer, { name, email, refs });
        if (Object.keys(patch).length === 0) return null; // nothing changed: no request
        return updateCustomer(tenant, customer.id, patch);
      }
      return createCustomer(tenant, { name: name.trim(), ...(email.trim() ? { email: email.trim() } : {}), ...(refs.size ? { external_refs: refsBody(refs) } : {}) });
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: customersQuery(tenant).queryKey });
      onClose();
    },
  });
  const fields = fieldErrors(save.error);
  return (
    <FormDialog
      title={customer ? t("customers.editTitle", { name: customer.name }) : t("customers.new")}
      submit={customer ? t("customers.save") : t("customers.create")}
      onClose={onClose}
      onSubmit={(f) => {
        setRefsError(null);
        try {
          parseRefs(String(f.get("refs") ?? ""));
        } catch (e) {
          setRefsError(t("customers.refsInvalid", { line: (e as Error).message }));
          return;
        }
        save.mutate(f);
      }}
      error={save.error}
      busy={save.isPending}
    >
      <Field label={t("tokens.col.name")} name="name" required maxLength={200} defaultValue={customer?.name} error={fields.name} />
      <Field label={t("invitations.col.email")} name="email" type="email" maxLength={320} defaultValue={customer?.email ?? ""} error={fields.email} />
      {customer && customer.email && <p className="text-xs text-muted-foreground">{t("customers.emailClear")}</p>}
      <div className="flex flex-col gap-1 text-sm">
        <label className="flex flex-col gap-1">
          {t("customers.col.refs")}
          <textarea
            name="refs"
            rows={3}
            placeholder="stripe=cus_123"
            defaultValue={customer ? formatRefs(customer.external_refs) : ""}
            className={`${input} h-auto py-1 font-mono`}
            aria-invalid={!!(refsError || fields.external_refs)}
            aria-describedby={refsError || fields.external_refs ? "refs-help refs-error" : "refs-help"}
          />
        </label>
        <span id="refs-help" className="text-xs text-muted-foreground">{t("customers.refsHelp")}</span>
        {(refsError || fields.external_refs) && <span id="refs-error">{refsError ?? fields.external_refs}</span>}
      </div>
    </FormDialog>
  );
}

function ArchiveDialog({ tenant, customer, onClose }: { tenant: string; customer: Customer; onClose: () => void }) {
  const qc = useQueryClient();
  const archive = useMutation({
    mutationFn: () => archiveCustomer(tenant, customer.id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: customersQuery(tenant).queryKey });
      onClose();
    },
  });
  return (
    <Modal title={t("customers.archiveTitle", { name: customer.name })} onClose={onClose}>
      <p className="text-sm">{t("customers.archiveBody")}</p>
      {archive.isError && <p role="alert" className="mt-3 text-sm font-medium">{errorText(archive.error)}</p>}
      <div className="mt-6 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>{t("tokens.cancel")}</Button>
        <Button disabled={archive.isPending} onClick={() => archive.mutate()}>{t("customers.archive")}</Button>
      </div>
    </Modal>
  );
}

export function ArchiveProductDialog({ tenant, product, onClose }: { tenant: string; product: Product; onClose: () => void }) {
  const qc = useQueryClient();
  const archive = useMutation({
    mutationFn: () => archiveProduct(tenant, product.id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: productsQuery(tenant).queryKey });
      await qc.invalidateQueries({ queryKey: ["products-all", tenant] }); // the issue picker
      await qc.invalidateQueries({ queryKey: ["product", tenant] }); // the product page
      onClose();
    },
  });
  return (
    <Modal title={t("products.archiveTitle", { name: product.name })} onClose={onClose}>
      <p className="text-sm">{t("products.archiveBody")}</p>
      {archive.isError && <p role="alert" className="mt-3 text-sm font-medium">{errorText(archive.error)}</p>}
      <div className="mt-6 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>{t("tokens.cancel")}</Button>
        <Button disabled={archive.isPending} onClick={() => archive.mutate()}>{t("products.archive")}</Button>
      </div>
    </Modal>
  );
}

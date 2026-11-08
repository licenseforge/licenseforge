import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { useState } from "react";
import { fieldErrors } from "@/api/client";
import {
  archiveFeature,
  archivePlan,
  canRenameProducts,
  createFeature,
  createPlan,
  type Feature,
  FieldError,
  getProduct,
  type Plan,
  planBody,
  planTerm,
  productFeaturesQuery,
  productPlansQuery,
} from "@/api/catalog";
import { Field, FormDialog, useCaller } from "@/catalog-pages";
import { errorText, input, Modal } from "@/components/modal";
import { FeatureMatrix } from "@/feature-matrix";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const th = "px-2 py-2 font-medium";
const td = "px-2 py-2";

type Dialog =
  | { kind: "feature" | "plan" }
  | { kind: "archive-feature"; feature: Feature }
  | { kind: "archive-plan"; plan: Plan };

/**
 * A product's catalog (ADR-0015, ADR-0020): its features and plans, created
 * and archived here. Writing needs catalog:write on the product (admins and
 * owners; the server checks) and an active product.
 */
export function ProductPage() {
  const { slug, id } = useParams({ from: "/app/t/$slug/products/$id" });
  const caller = useCaller(slug);
  const product = useQuery({ queryKey: ["product", slug, id], queryFn: () => getProduct(slug, id) });
  const features = useQuery(productFeaturesQuery(slug, id));
  const plans = useQuery(productPlansQuery(slug, id));
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const write = canRenameProducts(caller) && product.data != null && product.data.archived_at == null;
  if (product.isError) return <p role="alert">{errorText(product.error)}</p>;
  if (!product.data) return <p role="status" className="text-muted-foreground">{t("product.loading")}</p>;
  const p = product.data;
  return (
    <>
      <Link to="/t/$slug/products" params={{ slug }} className="text-sm text-muted-foreground underline-offset-4 hover:underline">
        {t("product.back")}
      </Link>
      <h1 className="mt-2 text-2xl font-semibold">{p.name}</h1>
      <p className="mt-1 font-mono text-xs text-muted-foreground">{p.slug}</p>
      {p.archived_at && <p className="mt-2 text-sm">{t("product.archived")}</p>}

      <section aria-labelledby="features-title" className="mt-8">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h2 id="features-title" className="text-lg font-semibold">{t("product.features")}</h2>
          {write && <Button onClick={() => setDialog({ kind: "feature" })}>{t("product.newFeature")}</Button>}
        </div>
        {features.isError && <p role="alert" className="mt-2">{errorText(features.error)}</p>}
        {features.data && features.data.items.length === 0 && <p className="mt-2 text-muted-foreground">{t("product.noFeatures")}</p>}
        {features.data && features.data.items.length > 0 && (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b text-muted-foreground">
                <tr>
                  <th scope="col" className={th}>{t("product.col.key")}</th>
                  <th scope="col" className={th}>{t("tokens.col.name")}</th>
                  <th scope="col" className={th}>{t("product.col.type")}</th>
                  <th scope="col" className={th}>{t("tokens.col.status")}</th>
                  <th scope="col" className={th}><span className="sr-only">{t("customers.actions")}</span></th>
                </tr>
              </thead>
              <tbody>
                {features.data.items.map((f) => (
                  <tr key={f.id} className="border-b">
                    <td className={`${td} font-mono text-xs`}>{f.key}</td>
                    <td className={`${td} font-medium`}>{f.name}</td>
                    <td className={td}>{f.type === "limit" ? t("product.type.limit", { unit: f.unit ?? "" }).trim() : t("product.type.boolean")}</td>
                    <td className={td}>{f.archived_at ? t("customers.archived") : t("tokens.status.active")}</td>
                    <td className={`${td} text-right`}>
                      {write && !f.archived_at && (
                        <Button variant="ghost" onClick={() => setDialog({ kind: "archive-feature", feature: f })}>{t("products.archive")}</Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section aria-labelledby="plans-title" className="mt-8">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h2 id="plans-title" className="text-lg font-semibold">{t("product.plans")}</h2>
          {write && <Button onClick={() => setDialog({ kind: "plan" })}>{t("product.newPlan")}</Button>}
        </div>
        {plans.isError && <p role="alert" className="mt-2">{errorText(plans.error)}</p>}
        {plans.data && plans.data.items.length === 0 && <p className="mt-2 text-muted-foreground">{t("product.noPlans")}</p>}
        {plans.data && plans.data.items.length > 0 && (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b text-muted-foreground">
                <tr>
                  <th scope="col" className={th}>{t("products.col.slug")}</th>
                  <th scope="col" className={th}>{t("tokens.col.name")}</th>
                  <th scope="col" className={th}>{t("product.col.term")}</th>
                  <th scope="col" className={th}>{t("product.col.activations")}</th>
                  <th scope="col" className={th}>{t("product.col.binding")}</th>
                  <th scope="col" className={th}>{t("tokens.col.status")}</th>
                  <th scope="col" className={th}><span className="sr-only">{t("customers.actions")}</span></th>
                </tr>
              </thead>
              <tbody>
                {plans.data.items.map((pl) => (
                  <tr key={pl.id} className="border-b">
                    <td className={`${td} font-mono text-xs`}>{pl.slug}</td>
                    <td className={`${td} font-medium`}>{pl.name}</td>
                    <td className={td}>{termText(pl)}</td>
                    <td className={td}>{pl.max_activations == null ? t("product.unlimited") : pl.max_activations}</td>
                    <td className={td}>{t(`product.bind.${pl.bind_type}`)}</td>
                    <td className={td}>{pl.archived_at ? t("customers.archived") : t("tokens.status.active")}</td>
                    <td className={`${td} text-right`}>
                      {write && !pl.archived_at && (
                        <Button variant="ghost" onClick={() => setDialog({ kind: "archive-plan", plan: pl })}>{t("products.archive")}</Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {features.data && plans.data && features.data.items.length > 0 && plans.data.items.length > 0 && (
        <section aria-labelledby="matrix-title" className="mt-8">
          <h2 id="matrix-title" className="text-lg font-semibold">{t("matrix.title")}</h2>
          <FeatureMatrix tenant={slug} features={features.data.items} plans={plans.data.items} write={write} />
        </section>
      )}

      {dialog?.kind === "feature" && <FeatureDialog tenant={slug} product={id} onClose={() => setDialog(null)} />}
      {dialog?.kind === "plan" && <PlanDialog tenant={slug} product={id} onClose={() => setDialog(null)} />}
      {dialog?.kind === "archive-feature" && (
        <ArchiveDialog
          title={t("product.archiveFeatureTitle", { name: dialog.feature.name })}
          body={t("product.archiveFeatureBody")}
          run={() => archiveFeature(slug, dialog.feature.id)}
          invalidate={productFeaturesQuery(slug, id).queryKey}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "archive-plan" && (
        <ArchiveDialog
          title={t("product.archivePlanTitle", { name: dialog.plan.name })}
          body={t("product.archivePlanBody")}
          run={() => archivePlan(slug, dialog.plan.id)}
          invalidate={productPlansQuery(slug, id).queryKey}
          onClose={() => setDialog(null)}
        />
      )}
    </>
  );
}

function termText(p: Plan): string {
  const term = planTerm(p);
  return term.kind === "perpetual" ? t("product.perpetual") : t(`product.term.${term.kind}`, { n: String(term.n) });
}

function ArchiveDialog({ title, body, run, invalidate, onClose }: {
  title: string; body: string; run: () => Promise<unknown>; invalidate: readonly unknown[]; onClose: () => void;
}) {
  const qc = useQueryClient();
  const archive = useMutation({
    mutationFn: run,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: invalidate });
      onClose();
    },
  });
  return (
    <Modal title={title} onClose={onClose}>
      <p className="text-sm">{body}</p>
      {archive.isError && <p role="alert" className="mt-3 text-sm font-medium">{errorText(archive.error)}</p>}
      <div className="mt-6 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>{t("tokens.cancel")}</Button>
        <Button disabled={archive.isPending} onClick={() => archive.mutate()}>{t("products.archive")}</Button>
      </div>
    </Modal>
  );
}

function FeatureDialog({ tenant, product, onClose }: { tenant: string; product: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [type, setType] = useState<"boolean" | "limit">("boolean");
  const save = useMutation({
    mutationFn: (f: FormData) => {
      const unit = String(f.get("unit") ?? "").trim();
      const type = f.get("type") === "limit" ? "limit" : "boolean";
      return createFeature(tenant, {
        product_id: product, key: String(f.get("key") ?? "").trim(), name: String(f.get("name") ?? "").trim(), type,
        ...(type === "limit" && unit ? { unit } : {}),
      });
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: productFeaturesQuery(tenant, product).queryKey });
      onClose();
    },
  });
  const fields = fieldErrors(save.error);
  return (
    <FormDialog title={t("product.newFeature")} submit={t("product.create")} onClose={onClose} onSubmit={(f) => save.mutate(f)} error={save.error} busy={save.isPending}>
      <Field label={t("product.col.key")} name="key" required maxLength={63} error={fields.key} help={t("product.keyHelp")} />
      <Field label={t("tokens.col.name")} name="name" required maxLength={200} error={fields.name} />
      <label className="flex flex-col gap-1 text-sm">
        {t("product.col.type")}
        <select name="type" className={input} value={type} onChange={(e) => setType(e.target.value === "limit" ? "limit" : "boolean")}>
          <option value="boolean">{t("product.type.boolean")}</option>
          <option value="limit">{t("product.type.limitPlain")}</option>
        </select>
      </label>
      {type === "limit" && <Field label={t("product.unit")} name="unit" maxLength={40} error={fields.unit} help={t("product.unitHelp")} />}
    </FormDialog>
  );
}

function PlanDialog({ tenant, product, onClose }: { tenant: string; product: string; onClose: () => void }) {
  const qc = useQueryClient();
  const save = useMutation({
    mutationFn: (f: FormData) => {
      const get = (k: string) => String(f.get(k) ?? "");
      return createPlan(tenant, planBody(product, {
        slug: get("slug"), name: get("name"), term: get("term"), termUnit: get("term_unit") === "days" ? "days" : "months",
        maxActivations: get("max_activations"), bindType: get("bind_type"),
      }));
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: productPlansQuery(tenant, product).queryKey });
      onClose();
    },
  });
  // planBody's FieldError names the field it refused, before any request;
  // anything else (a server refusal, a network failure) is the dialog's
  // alert. Derived, so a new attempt clears it.
  const local = save.error instanceof FieldError ? save.error.field : null;
  const fields = { ...fieldErrors(save.error), ...(local ? { [local]: t("product.wholeNumber") } : {}) };
  const term = fields.duration_months ?? fields.duration_seconds ?? fields.term;
  return (
    <FormDialog title={t("product.newPlan")} submit={t("product.create")} onClose={onClose} onSubmit={(f) => save.mutate(f)} error={local ? null : save.error} busy={save.isPending}>
      <Field label={t("products.col.slug")} name="slug" required maxLength={63} error={fields.slug} help={t("product.planSlugHelp")} />
      <Field label={t("tokens.col.name")} name="name" required maxLength={200} error={fields.name} />
      <div className="flex gap-2">
        <div className="flex-1">
          <Field label={t("product.col.term")} name="term" inputMode="numeric" error={term} help={t("product.termHelp")} />
        </div>
        <label className="flex flex-col gap-1 text-sm">
          {t("product.termUnit")}
          <select name="term_unit" className={input} defaultValue="months">
            <option value="months">{t("product.months")}</option>
            <option value="days">{t("product.days")}</option>
          </select>
        </label>
      </div>
      <Field label={t("product.col.activations")} name="max_activations" inputMode="numeric" error={fields.max_activations} help={t("product.activationsHelp")} />
      <label className="flex flex-col gap-1 text-sm">
        {t("product.col.binding")}
        <select name="bind_type" className={input} defaultValue="machine" aria-invalid={!!fields.bind_type} aria-describedby={fields.bind_type ? "bind_type-error" : undefined}>
          <option value="machine">{t("product.bind.machine")}</option>
          <option value="cluster">{t("product.bind.cluster")}</option>
          <option value="none">{t("product.bind.none")}</option>
        </select>
        {fields.bind_type && <span id="bind_type-error">{fields.bind_type}</span>}
      </label>
      <p className="text-xs text-muted-foreground">{t("product.planDefaults")}</p>
    </FormDialog>
  );
}

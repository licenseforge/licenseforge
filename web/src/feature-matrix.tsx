import { useQueries, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { type Cell, type Feature, grantCells, grantsPatch, type Plan, planFeaturesQuery, updatePlanFeatures } from "@/api/catalog";
import { errorText } from "@/components/modal";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const cellInput = "h-8 w-24 rounded-md border bg-background px-2 text-sm tabular-nums";

/**
 * The feature × plan matrix (ADR-0015): what each plan grants, edited in
 * place and saved as one merge patch per changed plan (each all or nothing
 * on the server). An archived feature shows only where some plan still
 * grants it, and can't be granted anew; licenses already sold keep their
 * entitlements (ADR-0013).
 */
export function FeatureMatrix({ tenant, features, plans, write }: { tenant: string; features: Feature[]; plans: Plan[]; write: boolean }) {
  const qc = useQueryClient();
  const grants = useQueries({ queries: plans.map((p) => planFeaturesQuery(tenant, p.id)) });
  const [edits, setEdits] = useState<Record<string, Record<string, Cell>>>({}); // plan ID → touched cells
  const [invalid, setInvalid] = useState<Record<string, string[]>>({}); // plan ID → keys whose limit text isn't valid
  const [failed, setFailed] = useState<{ plan: string; error: unknown }[]>([]);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  // Only a first load that failed: a failed background refetch keeps the
  // data (and the unsaved edits) on screen.
  const failedLoad = grants.find((g) => g.isError && !g.data);
  if (failedLoad) return <p role="alert">{errorText(failedLoad.error)}</p>;
  if (!grants.every((g) => g.data)) return <p role="status" className="text-muted-foreground">{t("product.loading")}</p>;
  const before = (i: number) => grants[i]!.data!;
  const grantedAnywhere = (key: string) => plans.some((_, i) => Object.hasOwn(before(i), key));
  const rows = features.filter((f) => !f.archived_at || grantedAnywhere(f.key)).sort((a, b) => a.key.localeCompare(b.key));
  const start = plans.map((_, i) => grantCells(before(i), features));
  const cell = (i: number, key: string): Cell => edits[plans[i]!.id]?.[key] ?? start[i]![key]!;
  const shown = new Set(rows.map((f) => f.key));
  const edit = (plan: string, key: string, v: Cell) => {
    setSaved(false);
    setEdits((e) => ({ ...e, [plan]: { ...e[plan], [key]: v } }));
  };
  const dirty = Object.keys(edits).length > 0;

  async function save() {
    setBusy(true);
    setSaved(false);
    const bad: Record<string, string[]> = {};
    const errs: { plan: string; error: unknown }[] = [];
    const left: Record<string, Record<string, Cell>> = {};
    for (const p of plans) {
      // A feature archived and hidden meanwhile isn't sent (the server would
      // refuse the plan's whole patch).
      const touched = Object.fromEntries(Object.entries(edits[p.id] ?? {}).filter(([k]) => shown.has(k)));
      if (Object.keys(touched).length === 0) continue;
      const r = grantsPatch(touched);
      if ("invalid" in r) {
        bad[p.id] = r.invalid;
        left[p.id] = touched;
        continue;
      }
      try {
        await updatePlanFeatures(tenant, p.id, r.patch);
      } catch (error) {
        errs.push({ plan: p.id, error });
        left[p.id] = touched; // kept for another try
      }
      await qc.invalidateQueries({ queryKey: planFeaturesQuery(tenant, p.id).queryKey });
    }
    setInvalid(bad);
    setFailed(errs);
    setEdits(left);
    setSaved(Object.keys(bad).length === 0 && errs.length === 0);
    setBusy(false);
  }

  const name = (id: string) => plans.find((p) => p.id === id)?.name ?? id;
  return (
    <>
      <div className="mt-3 overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b text-muted-foreground">
            <tr>
              <th scope="col" className="px-2 py-2 font-medium">{t("matrix.feature")}</th>
              {plans.map((p) => (
                <th key={p.id} scope="col" className="px-2 py-2 font-medium">
                  {p.name}
                  {p.archived_at && <span className="block text-xs font-normal">{t("customers.archived")}</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.id} className="border-b">
                <th scope="row" className="px-2 py-2 text-left font-normal">
                  <span className="font-medium">{f.name}</span> <span className="font-mono text-xs text-muted-foreground">{f.key}</span>
                  {f.archived_at && <span className="block text-xs">{t("customers.archived")}</span>}
                </th>
                {plans.map((p, i) => {
                  const v = cell(i, f.key);
                  // An archived feature can change or go where granted, never be granted anew.
                  // Disabled while saving too: an edit made then would be lost.
                  const locked = !write || busy || (f.archived_at != null && !Object.hasOwn(before(i), f.key));
                  const label = t("matrix.cell", { feature: f.name, plan: p.name });
                  const bad = invalid[p.id]?.includes(f.key) ?? false;
                  return (
                    <td key={p.id} className="px-2 py-2">
                      {typeof v === "boolean" ? (
                        <input type="checkbox" aria-label={label} checked={v} disabled={locked} onChange={(e) => edit(p.id, f.key, e.target.checked)} />
                      ) : (
                        <input
                          type="text"
                          inputMode="numeric"
                          aria-label={label}
                          aria-invalid={bad}
                          className={cellInput}
                          value={v}
                          placeholder="—"
                          disabled={locked}
                          onChange={(e) => edit(p.id, f.key, e.target.value)}
                        />
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">{t("matrix.help")}</p>
      {Object.keys(invalid).length > 0 && (
        <p role="alert" className="mt-2 text-sm font-medium">{t("matrix.invalid", { plans: Object.keys(invalid).map(name).join(", ") })}</p>
      )}
      {failed.map((f) => (
        <p key={f.plan} role="alert" className="mt-2 text-sm font-medium">
          {t("matrix.failed", { plan: name(f.plan), error: errorText(f.error) })}
        </p>
      ))}
      {write && (
        <div className="mt-3 flex items-center gap-3">
          <Button disabled={!dirty || busy} onClick={() => void save()}>{t("matrix.save")}</Button>
          {dirty && (
            <Button variant="ghost" disabled={busy} onClick={() => { setEdits({}); setInvalid({}); setFailed([]); }}>
              {t("matrix.discard")}
            </Button>
          )}
          {saved && <span role="status" className="text-sm">{t("matrix.saved")}</span>}
        </div>
      )}
    </>
  );
}

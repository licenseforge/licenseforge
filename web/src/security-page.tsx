import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { ApiError } from "@/api/client";
import { type MfaPolicy, setMfaPolicy, stepUpHref, tenantsQuery } from "@/api/tenants";
import { errorText } from "@/components/modal";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const policies: MfaPolicy[] = ["none", "mfa", "phishing_resistant"];

/**
 * The tenant's MFA policy (ADR-0038): owners only (tenant:write), from a
 * session. Raising it needs a session that already meets the new level; the
 * server refuses otherwise (409 mfa_policy_unmet), and the page offers the
 * step-up to that level.
 */
export function SecurityPage() {
  const { slug } = useParams({ from: "/app/t/$slug/settings/security" });
  const qc = useQueryClient();
  const { data: tenants } = useQuery(tenantsQuery);
  const caller = tenants?.find((tn) => tn.slug === slug);
  const [choice, setChoice] = useState<MfaPolicy | null>(null);
  const save = useMutation({
    mutationFn: (p: MfaPolicy) => setMfaPolicy(slug, p),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: tenantsQuery.queryKey });
      setChoice(null);
    },
  });
  if (!caller) return null;
  const owner = caller.role === "owner";
  const current = choice ?? caller.mfaPolicy;
  const unmet = save.error instanceof ApiError && save.error.code === "mfa_policy_unmet" ? save.variables : null;
  return (
    <>
      <h1 className="text-2xl font-semibold">{t("security.title")}</h1>
      <form
        className="mt-6 max-w-xl"
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          if (current !== caller.mfaPolicy) save.mutate(current);
        }}
      >
        <fieldset disabled={!owner || save.isPending}>
          <legend className="font-semibold">{t("security.mfa")}</legend>
          <p className="mt-1 text-sm text-muted-foreground">{t("security.mfaHelp")}</p>
          <div className="mt-3 flex flex-col gap-2">
            {policies.map((p) => (
              <label key={p} className="flex items-center gap-2 text-sm">
                <input type="radio" name="mfa_policy" value={p} checked={current === p} onChange={() => { save.reset(); setChoice(p); }} />
                {t(`security.policy.${p}`)}
              </label>
            ))}
          </div>
          {owner && (
            <Button type="submit" className="mt-4" disabled={current === caller.mfaPolicy}>
              {t("security.save")}
            </Button>
          )}
        </fieldset>
        {!owner && <p className="mt-3 text-sm text-muted-foreground">{t("security.ownersOnly")}</p>}
        {save.isSuccess && (
          <p role="status" className="mt-3 text-sm">{t("security.saved", { tokens: String(save.data.active_api_tokens) })}</p>
        )}
        {unmet && unmet !== "none" ? (
          <div role="alert" className="mt-3 text-sm">
            <p className="font-medium">{t("security.unmet")}</p>
            <a href={stepUpHref(unmet, slug)} className="mt-2 inline-block underline">{t("mfa.stepUp")}</a>
          </div>
        ) : (
          save.isError && <p role="alert" className="mt-3 text-sm font-medium">{errorText(save.error)}</p>
        )}
      </form>
    </>
  );
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { useState } from "react";
import { onAuthError } from "@/api/client";
import {
  canManageKeys,
  canReadKeys,
  createSigningKey,
  discardSigningKey,
  goKeySet,
  promoteSigningKey,
  type SigningKey,
  signingKeysQuery,
  trustedKeySet,
} from "@/api/keys";
import { tenantsQuery } from "@/api/tenants";
import { errorText, Modal } from "@/components/modal";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const when = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

type Confirm = { action: "create" | "promote" | "discard"; key?: SigningKey };

/** Settings → Signing keys (ADR-0026): the public keys builds trust, and the owner's rotation steps. */
export function KeysPage() {
  const { slug } = useParams({ from: "/app/t/$slug/settings/signing-keys" });
  const { data: tenants = [] } = useQuery(tenantsQuery);
  const caller = tenants.find((tn) => tn.slug === slug);
  const manage = canManageKeys(caller);
  const list = useQuery({ ...signingKeysQuery(slug), enabled: canReadKeys(caller) });
  const qc = useQueryClient();
  const refresh = () => qc.invalidateQueries({ queryKey: signingKeysQuery(slug).queryKey });
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const keys = list.data?.items ?? [];
  const pending = keys.some((k) => k.status === "pending");
  const active = keys.find((k) => k.status === "active");
  const trusted = trustedKeySet(keys);
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t("keys.title")}</h1>
          <p className="mt-1 text-muted-foreground">{t("keys.body")}</p>
        </div>
        {manage && list.isSuccess && !pending && <Button onClick={() => setConfirm({ action: "create" })}>{t("keys.new")}</Button>}
      </div>
      {!canReadKeys(caller) && caller && <p className="mt-6 text-sm">{t("keys.scoped")}</p>}
      {list.isError && (
        <p role="alert" className="mt-6 text-sm font-medium">
          {errorText(list.error)}
        </p>
      )}
      {list.isSuccess && keys.length === 0 && <p className="mt-6 text-sm text-muted-foreground">{manage ? t("keys.emptyOwner") : t("keys.empty")}</p>}
      {keys.length > 0 && !active && <p role="status" className="mt-6 text-sm font-medium">{t("keys.noActive")}</p>}
      {keys.length > 0 && (
        <>
          <table className="mt-6 w-full text-left text-sm">
            <thead>
              <tr className="border-b text-muted-foreground">
                <th scope="col" className="px-2 py-2 font-medium">{t("keys.col.kid")}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t("keys.col.status")}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t("keys.col.dates")}</th>
                {manage && <th scope="col" className="px-2 py-2 font-medium">{t("keys.col.actions")}</th>}
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.kid} className="border-b align-top">
                  <td className="px-2 py-2 font-mono text-xs">{k.kid}</td>
                  <td className="px-2 py-2">{t(`keys.status.${k.status}`)}</td>
                  <td className="px-2 py-2 text-xs">
                    {t("keys.created", { when: when.format(new Date(k.created_at)) })}
                    {k.activated_at && <span className="block">{t("keys.activated", { when: when.format(new Date(k.activated_at)) })}</span>}
                    {k.retired_at && <span className="block">{t(k.activated_at ? "keys.retired" : "keys.discarded", { when: when.format(new Date(k.retired_at)) })}</span>}
                  </td>
                  {manage && (
                    <td className="px-2 py-2">
                      {k.status === "pending" && (
                        <span className="flex flex-wrap gap-2">
                          <Button variant="ghost" aria-label={t("keys.promoteNamed", { kid: k.kid })} onClick={() => setConfirm({ action: "promote", key: k })}>
                            {t("keys.promote")}
                          </Button>
                          <Button variant="ghost" aria-label={t("keys.discardNamed", { kid: k.kid })} onClick={() => setConfirm({ action: "discard", key: k })}>
                            {t("keys.discard")}
                          </Button>
                        </span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          {list.data?.next_cursor && <p className="mt-2 text-xs text-muted-foreground">{t("keys.incomplete")}</p>}
          <TrustedSet keys={trusted} complete={!list.data?.next_cursor} />
        </>
      )}
      {confirm && <ConfirmDialog tenant={slug} confirm={confirm} first={keys.length === 0} active={active} onDone={refresh} onClose={() => setConfirm(null)} />}
    </>
  );
}

/** The keys a vendor embeds: as Go for the SDK, and as the license format's JSON for anything else. */
function TrustedSet({ keys, complete }: { keys: ReturnType<typeof trustedKeySet>; complete: boolean }) {
  return (
    <section aria-labelledby="trusted-title" className="mt-8">
      <h2 id="trusted-title" className="text-lg font-semibold">{t("keys.trustedTitle")}</h2>
      <p className="mt-1 text-sm text-muted-foreground">{t("keys.trustedHelp")}</p>
      <p className="mt-1 text-sm font-medium">{t("keys.compromised")}</p>
      {!complete && <p className="mt-1 text-sm">{t("keys.incompleteCopy")}</p>}
      <Snippet id="go" title={t("keys.goTitle")} text={goKeySet(keys)} copyLabel={t("keys.copyGo")} complete={complete} />
      <Snippet id="json" title={t("keys.jsonTitle")} text={JSON.stringify(keys, null, 2)} copyLabel={t("keys.copyJson")} complete={complete} />
    </section>
  );
}

function Snippet({ id, title, text, copyLabel, complete }: { id: string; title: string; text: string; copyLabel: string; complete: boolean }) {
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  return (
    <div className="mt-4">
      <h3 id={`${id}-title`} className="text-sm font-semibold">{title}</h3>
      {/* focusable: keyboard users can scroll a wide key */}
      <pre id={id} tabIndex={0} aria-labelledby={`${id}-title`} className="mt-2 overflow-x-auto rounded-md border p-3 font-mono text-xs">{text}</pre>
      <div className="mt-2 flex items-center gap-2">
        <Button
          variant="ghost"
          disabled={!complete}
          onClick={() =>
            navigator.clipboard.writeText(text).then(
              () => setCopy("copied"),
              () => setCopy("failed"),
            )
          }
        >
          {copyLabel}
        </Button>
        <span role="status" className="text-sm">{copy === "copied" ? t("keys.copied") : copy === "failed" ? t("keys.copyFailed") : ""}</span>
      </div>
    </div>
  );
}

function ConfirmDialog({ tenant, confirm, first, active, onDone, onClose }: {
  tenant: string; confirm: Confirm; first: boolean; active: SigningKey | undefined; onDone: () => Promise<void>; onClose: () => void;
}) {
  const { action, key } = confirm;
  const run = useMutation({
    mutationFn: async () => {
      if (action === "create") return createSigningKey(tenant);
      if (action === "promote") return promoteSigningKey(tenant, key!.kid);
      return discardSigningKey(tenant, key!.kid);
    },
    onSuccess: async () => {
      await onDone();
      onClose();
    },
    onError: async (err) => {
      onAuthError(err);
      await onDone(); // 409: another owner moved first; show the current keys
    },
  });
  const label = ({ create: "keys.new", promote: "keys.promote", discard: "keys.discard" } as const)[action];
  const text = action === "create" ? (first ? "keys.confirm.first" : "keys.confirm.create") : (`keys.confirm.${action}` as const);
  return (
    <Modal title={key ? t("keys.confirmTitle", { action: t(label), kid: key.kid }) : t(label)} onClose={run.isPending ? () => {} : onClose}>
      <p className="text-sm">{t(text)}</p>
      {action === "promote" && active && <p className="mt-2 text-sm font-medium">{t("keys.confirm.retires", { kid: active.kid })}</p>}
      {run.isError && (
        <p role="alert" className="mt-3 text-sm font-medium">
          {errorText(run.error)}
        </p>
      )}
      <div className="mt-6 flex justify-end gap-2">
        <Button variant="ghost" disabled={run.isPending} onClick={onClose}>
          {run.isError ? t("keys.close") : t("keys.cancel")}
        </Button>
        {/* After a refusal the list shows the current keys: start again from them. */}
        {!run.isError && (
          <Button disabled={run.isPending} onClick={() => run.mutate()}>
            {t(label)}
          </Button>
        )}
      </div>
    </Modal>
  );
}

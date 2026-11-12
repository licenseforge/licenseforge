import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { fieldErrors, onAuthError } from "@/api/client";
import { errorText, input, Modal } from "@/components/modal";
import { tenantsQuery } from "@/api/tenants";
import {
  type ApiToken,
  type ApiTokenCreated,
  assignableTokenRoles,
  canManageTokens,
  createToken,
  type Membership,
  type Role,
  revokeToken,
  tokensQuery,
} from "@/api/tokens";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

export function TokensPage() {
  const { slug } = useParams({ from: "/app/t/$slug/settings/api-tokens" });
  const { data: tenants = [] } = useQuery(tenantsQuery);
  const member: Membership = tenants.find((tn) => tn.slug === slug) ?? { role: "viewer", scope: { all: false, products: [] } };
  const list = useInfiniteQuery(tokensQuery(slug));
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<ApiToken | null>(null);
  const tokens = list.data?.pages.flatMap((p) => p.items) ?? [];
  const manage = canManageTokens(member);
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t("tokens.title")}</h1>
          <p className="mt-1 text-muted-foreground">{t("tokens.body")}</p>
        </div>
        {manage && <Button onClick={() => setCreating(true)}>{t("tokens.new")}</Button>}
      </div>
      {list.isError && (
        <p role="alert" className="mt-4">
          {errorText(list.error)}
        </p>
      )}
      {list.isSuccess && tokens.length === 0 && <p className="mt-6 text-muted-foreground">{t("tokens.empty")}</p>}
      {tokens.length > 0 && (
        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-muted-foreground">
              <tr>
                {(["name", "role", "products", "token", "expires", "lastUsed", "status"] as const).map((c) => (
                  <th key={c} scope="col" className="px-2 py-2 font-medium">
                    {t(`tokens.col.${c}`)}
                  </th>
                ))}
                <th scope="col" className="px-2 py-2">
                  <span className="sr-only">{t("tokens.revoke")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((tok) => {
                const status = tok.revoked_at ? "revoked" : new Date(tok.expires_at) <= new Date() ? "expired" : "active";
                return (
                  <tr key={tok.id} className="border-b">
                    <td className="px-2 py-2 font-medium">{tok.name}</td>
                    <td className="px-2 py-2">{tok.role}</td>
                    <td className="px-2 py-2">
                      {tok.all_products ? t("tokens.allProducts") : t("tokens.someProducts", { count: String(tok.product_ids.length) })}
                    </td>
                    <td className="px-2 py-2 font-mono text-xs">{tok.display}</td>
                    <td className="px-2 py-2">{date.format(new Date(tok.expires_at))}</td>
                    <td className="px-2 py-2">{tok.last_used_at ? date.format(new Date(tok.last_used_at)) : t("tokens.never")}</td>
                    <td className="px-2 py-2">{t(`tokens.status.${status}`)}</td>
                    <td className="px-2 py-2 text-right">
                      {manage && status === "active" && (
                        <Button variant="ghost" onClick={() => setRevoking(tok)}>
                          {t("tokens.revoke")}
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {list.hasNextPage && (
        <Button variant="ghost" className="mt-4" disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
          {t("tokens.more")}
        </Button>
      )}
      {creating && <CreateTokenDialog tenant={slug} member={member} onClose={() => setCreating(false)} />}
      {revoking && <RevokeDialog tenant={slug} token={revoking} onClose={() => setRevoking(null)} />}
    </>
  );
}

const ttlDays = [7, 30, 90, 180, 365];

export function CreateTokenDialog({ tenant, member, onClose }: { tenant: string; member: Membership; onClose: () => void }) {
  const qc = useQueryClient();
  const roles = assignableTokenRoles(member);
  const [created, setCreated] = useState<ApiTokenCreated | null>(null); // the secret lives here only
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [all, setAll] = useState(true);
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const fields = fieldErrors(error);
  // Not while the request runs: the server may create the token and its secret,
  // shown once, after the dialog is gone.
  const close = () => {
    if (busy) return;
    setCreated(null);
    onClose();
  };

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const ids = String(f.get("product_ids") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    setBusy(true);
    setError(null);
    try {
      // Not a useMutation: its result (the secret) would stay in the mutation cache.
      const tok = await createToken(tenant, {
        name: String(f.get("name") ?? ""),
        role: String(f.get("role")) as Role,
        all_products: all,
        ...(all ? {} : { product_ids: ids }),
        ttl_seconds: Number(f.get("ttl_days")) * 86_400,
      });
      setCreated(tok);
      // Refetch the list (metadata only); the created object never enters the cache.
      void qc.invalidateQueries({ queryKey: tokensQuery(tenant).queryKey });
    } catch (err) {
      onAuthError(err);
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (created) {
    return (
      <Modal title={t("tokens.secretTitle")} onClose={close}>
        <p role="alert" className="mb-3 text-sm font-medium">
          {t("tokens.secretWarning")}
        </p>
        <div className="flex gap-2">
          <input
            readOnly
            aria-label={t("tokens.col.token")}
            value={created.token}
            onFocus={(e) => e.currentTarget.select()}
            className={`${input} font-mono`}
            autoComplete="off"
            spellCheck={false}
          />
          <Button
            onClick={() =>
              void navigator.clipboard.writeText(created.token).then(
                () => setCopy("copied"),
                () => setCopy("failed"), // no permission, or not a secure context
              )
            }
            aria-live="polite"
          >
            {copy === "copied" ? t("tokens.copied") : t("tokens.copy")}
          </Button>
        </div>
        {copy === "failed" && (
          <p role="alert" className="mt-2 text-sm">
            {t("tokens.copyFailed")}
          </p>
        )}
        <div className="mt-6 flex justify-end">
          <Button variant="ghost" onClick={close}>
            {t("tokens.close")}
          </Button>
        </div>
      </Modal>
    );
  }

  const fieldError = (name: string) =>
    fields[name] && (
      <span id={`${name}-error`} className="text-sm">
        {fields[name]}
      </span>
    );
  return (
    <Modal title={t("tokens.new")} onClose={close}>
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4" noValidate>
        <div className="flex flex-col gap-1 text-sm">
          <label className="flex flex-col gap-1">
            {t("tokens.field.name")}
            <input name="name" required maxLength={200} className={input} aria-invalid={!!fields.name} aria-describedby="name-error" />
          </label>
          {fieldError("name")}
        </div>
        <div className="flex flex-col gap-1 text-sm">
          <label className="flex flex-col gap-1">
            {t("tokens.field.role")}
            <select name="role" className={input} defaultValue="sdk" aria-invalid={!!fields.role} aria-describedby="role-error">
              {roles.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
          {fieldError("role")}
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" className="size-4" checked={all} onChange={(e) => setAll(e.target.checked)} />
          {t("tokens.field.allProducts")}
        </label>
        {!all && (
          <label className="flex flex-col gap-1 text-sm">
            {t("tokens.field.productIds")}
            <input
              name="product_ids"
              className={`${input} font-mono`}
              aria-invalid={!!fields.product_ids}
              aria-describedby="product_ids-error"
            />
          </label>
        )}
        {fieldError("product_ids")}
        <div className="flex flex-col gap-1 text-sm">
          <label className="flex flex-col gap-1">
            {t("tokens.field.ttl")}
            <select name="ttl_days" className={input} defaultValue="90" aria-invalid={!!fields.ttl_seconds} aria-describedby="ttl_seconds-error">
              {ttlDays.map((d) => (
                <option key={d} value={d}>
                  {t("tokens.ttl.days", { days: String(d) })}
                </option>
              ))}
            </select>
          </label>
          {fieldError("ttl_seconds")}
        </div>
        {error != null && (
          <p role="alert" className="text-sm font-medium">
            {errorText(error)}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" disabled={busy} onClick={close}>
            {t("tokens.cancel")}
          </Button>
          <Button type="submit" disabled={busy}>
            {t("tokens.create")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function RevokeDialog({ tenant, token, onClose }: { tenant: string; token: ApiToken; onClose: () => void }) {
  const qc = useQueryClient();
  const revoke = useMutation({
    mutationFn: () => revokeToken(tenant, token.id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: tokensQuery(tenant).queryKey });
      onClose();
    },
  });
  return (
    <Modal title={t("tokens.revokeTitle", { name: token.name })} onClose={onClose}>
      <p className="text-sm">{t("tokens.revokeBody")}</p>
      {revoke.isError && (
        <p role="alert" className="mt-3 text-sm font-medium">
          {errorText(revoke.error)}
        </p>
      )}
      <div className="mt-6 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          {t("tokens.cancel")}
        </Button>
        <Button disabled={revoke.isPending} onClick={() => revoke.mutate()}>
          {t("tokens.revoke")}
        </Button>
      </div>
    </Modal>
  );
}

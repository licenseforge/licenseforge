import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { fieldErrors, onAuthError } from "@/api/client";
import {
  allInvitations,
  allTokens,
  assignableMemberRoles,
  canManageMembers,
  changeRole,
  createInvitation,
  type Invitation,
  type InvitationCreated,
  inviteLink,
  invitationsQuery,
  type Member,
  type MemberRole,
  membersQuery,
  previewRemoval,
  previewRoleChange,
  removeMember,
  type Revoked,
  revokeInvitation,
  within,
} from "@/api/members";
import { sessionQuery } from "@/api/session";
import { tenantsQuery } from "@/api/tenants";
import type { ApiToken, Membership } from "@/api/tokens";
import { errorText, input, Modal } from "@/components/modal";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const scopeText = (x: { all_products: boolean; product_ids: string[] }) =>
  x.all_products ? t("tokens.allProducts") : t("tokens.someProducts", { count: String(x.product_ids.length) });
const th = "px-2 py-2 font-medium";
const td = "px-2 py-2";

type Change = { kind: "role" | "remove"; member: Member };

export function MembersPage() {
  const { slug } = useParams({ from: "/app/t/$slug/settings/members" });
  const { data: tenants = [] } = useQuery(tenantsQuery);
  const { data: session } = useQuery(sessionQuery);
  const caller: Membership = tenants.find((tn) => tn.slug === slug) ?? { role: "viewer", scope: { all: false, products: [] } };
  const roles = assignableMemberRoles(caller);
  const manage = canManageMembers(caller);
  const members = useInfiniteQuery(membersQuery(slug));
  const invitations = useInfiniteQuery(invitationsQuery(slug));
  const [change, setChange] = useState<Change | null>(null);
  const [inviting, setInviting] = useState(false);
  const [revokingInv, setRevokingInv] = useState<Invitation | null>(null);
  const [revoked, setRevoked] = useState<Revoked | null>(null);
  const memberRows = members.data?.pages.flatMap((p) => p.items) ?? [];
  const invitationRows = invitations.data?.pages.flatMap((p) => p.items) ?? [];
  // Only a role the caller holds itself can be given or taken away.
  const changeable = (m: Member) => manage && roles.includes(m.role);

  return (
    <>
      <h1 className="text-2xl font-semibold">{t("members.title")}</h1>
      {revoked && (
        <div role="status" className="mt-4 rounded-md border p-3 text-sm">
          <p>{t("members.revoked", { tokens: String(revoked.tokens.length), invitations: String(revoked.invitations.length) })}</p>
          {[...revoked.tokens, ...revoked.invitations].length > 0 && (
            <p className="mt-1 font-mono text-xs">{[...revoked.tokens, ...revoked.invitations].join(", ")}</p>
          )}
        </div>
      )}
      {members.isError && (
        <p role="alert" className="mt-4">
          {errorText(members.error)}
        </p>
      )}
      <div className="mt-4 overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b text-muted-foreground">
            <tr>
              <th scope="col" className={th}>{t("members.col.member")}</th>
              <th scope="col" className={th}>{t("tokens.col.role")}</th>
              <th scope="col" className={th}>{t("tokens.col.products")}</th>
              <th scope="col" className={th}>{t("members.col.joined")}</th>
              <th scope="col" className={th}><span className="sr-only">{t("members.remove")}</span></th>
            </tr>
          </thead>
          <tbody>
            {memberRows.map((m) => (
              <tr key={m.id} className="border-b">
                <td className={td}>
                  <div className="font-medium">
                    {m.name ?? m.email ?? m.user_id}
                    {m.user_id === session?.user.id && <span className="text-muted-foreground"> {t("members.you")}</span>}
                  </div>
                  {m.email && m.name && <div className="text-xs text-muted-foreground">{m.email}</div>}
                </td>
                <td className={td}>{m.role}</td>
                <td className={td}>{scopeText(m)}</td>
                <td className={td}>{date.format(new Date(m.created_at))}</td>
                <td className={`${td} whitespace-nowrap text-right`}>
                  {changeable(m) && (
                    <>
                      <Button variant="ghost" aria-label={t("members.roleFor", { name: m.name ?? m.email ?? m.user_id })} onClick={() => setChange({ kind: "role", member: m })}>
                        {t("members.change")}
                      </Button>
                      <Button variant="ghost" onClick={() => setChange({ kind: "remove", member: m })}>
                        {t("members.remove")}
                      </Button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {members.hasNextPage && (
        <Button variant="ghost" className="mt-2" disabled={members.isFetchingNextPage} onClick={() => void members.fetchNextPage()}>
          {t("tokens.more")}
        </Button>
      )}

      <div className="mt-10 flex flex-wrap items-center justify-between gap-4">
        <h2 className="text-xl font-semibold">{t("invitations.title")}</h2>
        {manage && <Button onClick={() => setInviting(true)}>{t("invitations.new")}</Button>}
      </div>
      {invitations.isError && (
        <p role="alert" className="mt-4">
          {errorText(invitations.error)}
        </p>
      )}
      {invitations.isSuccess && invitationRows.length === 0 && <p className="mt-4 text-muted-foreground">{t("invitations.empty")}</p>}
      {invitationRows.length > 0 && (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-muted-foreground">
              <tr>
                <th scope="col" className={th}>{t("invitations.col.email")}</th>
                <th scope="col" className={th}>{t("tokens.col.role")}</th>
                <th scope="col" className={th}>{t("tokens.col.products")}</th>
                <th scope="col" className={th}>{t("tokens.col.status")}</th>
                <th scope="col" className={th}>{t("tokens.col.expires")}</th>
                <th scope="col" className={th}><span className="sr-only">{t("tokens.revoke")}</span></th>
              </tr>
            </thead>
            <tbody>
              {invitationRows.map((i) => (
                <tr key={i.id} className="border-b">
                  <td className={`${td} font-medium`}>{i.email}</td>
                  <td className={td}>{i.role}</td>
                  <td className={td}>{scopeText(i)}</td>
                  <td className={td}>{t(`invitations.status.${i.status}`)}</td>
                  <td className={td}>{date.format(new Date(i.expires_at))}</td>
                  <td className={`${td} text-right`}>
                    {manage && i.status === "pending" && (
                      <Button variant="ghost" onClick={() => setRevokingInv(i)}>
                        {t("tokens.revoke")}
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {invitations.hasNextPage && (
        <Button variant="ghost" className="mt-2" disabled={invitations.isFetchingNextPage} onClick={() => void invitations.fetchNextPage()}>
          {t("tokens.more")}
        </Button>
      )}

      {change && (
        <ChangeDialog
          tenant={slug}
          caller={caller}
          roles={roles}
          change={change}
          onClose={() => setChange(null)}
          onDone={(r) => {
            setRevoked(r);
            setChange(null);
          }}
        />
      )}
      {inviting && <InviteDialog tenant={slug} roles={roles} onClose={() => setInviting(false)} />}
      {revokingInv && <RevokeInvitationDialog tenant={slug} invitation={revokingInv} onClose={() => setRevokingInv(null)} />}
    </>
  );
}

/**
 * A role change or a removal: previews what it revokes (tokens, invitations),
 * with a toggle for each. Confirming waits for the preview; if the preview
 * can't load, both toggles start off, so nothing unseen is revoked.
 */
export function ChangeDialog({ tenant, caller, roles, change, onClose, onDone }: {
  tenant: string; caller: Membership; roles: MemberRole[]; change: Change; onClose: () => void; onDone: (r: Revoked) => void;
}) {
  const qc = useQueryClient();
  const m = change.member;
  const name = m.name ?? m.email ?? m.user_id;
  const [role, setRole] = useState<MemberRole>(m.role); // the select lives here: arrow keys only move it
  const tokens = useQuery({ queryKey: ["api-tokens-all", tenant], queryFn: () => allTokens(tenant) });
  const invs = useQuery({ queryKey: ["invitations-all", tenant], queryFn: () => allInvitations(tenant) });
  const failed = tokens.isError || invs.isError;
  const loading = !failed && (tokens.isPending || invs.isPending);
  const [opts, setOpts] = useState({ tokens: true, invitations: true });
  const [failedOff, setFailedOff] = useState(false);
  if (failed && !failedOff) {
    setFailedOff(true); // once: the user may tick them again knowingly
    setOpts({ tokens: false, invitations: false });
  }
  const preview =
    tokens.data && invs.data
      ? change.kind === "role"
        ? previewRoleChange(m, role, tokens.data.items, invs.data.items)
        : previewRemoval(m, tokens.data.items, invs.data.items)
      : null;
  const incomplete = (tokens.data && !tokens.data.complete) || (invs.data && !invs.data.complete);
  // The server refuses the whole change (403) if it would revoke a token the caller couldn't assign.
  const aboveCaller = (tok: ApiToken) => tok.role !== "sdk" && !within(tok.role, caller.role);
  const blocked = opts.tokens && (preview?.tokens.some(aboveCaller) ?? false);
  const run = useMutation({
    mutationFn: async (): Promise<Revoked> => {
      if (change.kind === "remove") return removeMember(tenant, m.id, opts);
      const u = await changeRole(tenant, m.id, role, opts);
      return { tokens: u.revoked_token_ids, invitations: u.revoked_invitation_ids };
    },
    onSuccess: async (r) => {
      for (const key of ["members", "invitations", "api-tokens", "api-tokens-all", "invitations-all"]) {
        await qc.invalidateQueries({ queryKey: [key, tenant] });
      }
      onDone(r);
    },
  });
  const title = change.kind === "role" ? t("members.changeTitle", { name }) : t("members.removeTitle", { name });
  return (
    <Modal title={title} onClose={onClose}>
      {change.kind === "remove" && <p className="mb-3 text-sm">{t("members.removeBody")}</p>}
      {change.kind === "role" && (
        <label className="mb-3 flex flex-col gap-1 text-sm">
          {t("tokens.field.role")}
          <select className={input} value={role} onChange={(e) => setRole(e.target.value as MemberRole)}>
            {roles.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </label>
      )}
      {loading && <p className="text-sm text-muted-foreground">{t("members.previewLoading")}</p>}
      {failed && (
        <p role="alert" className="mb-3 text-sm font-medium">
          {t("members.previewFailed")}
        </p>
      )}
      {incomplete && <p className="mb-3 text-sm">{t("members.previewIncomplete")}</p>}
      <Preview
        label={t("members.revokeTokens")}
        checked={opts.tokens}
        onChange={(v) => setOpts({ ...opts, tokens: v })}
        items={preview?.tokens.map((tok) => `${tok.name} (${tok.role}, ${tok.display})${aboveCaller(tok) ? ` ${t("members.aboveYou")}` : ""}`)}
      />
      {blocked && (
        <p role="alert" className="ml-6 text-sm">
          {t("members.aboveYouHint")}
        </p>
      )}
      <Preview
        label={t("members.revokeInvitations")}
        checked={opts.invitations}
        onChange={(v) => setOpts({ ...opts, invitations: v })}
        items={preview?.invitations.map((i: Invitation) => `${i.email} (${i.role})`)}
      />
      {run.isError && (
        <p role="alert" className="mt-3 text-sm font-medium">
          {errorText(run.error)}
        </p>
      )}
      <div className="mt-6 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          {t("tokens.cancel")}
        </Button>
        <Button disabled={run.isPending || loading || (change.kind === "role" && role === m.role)} onClick={() => run.mutate()}>
          {change.kind === "role" ? t("members.change") : t("members.remove")}
        </Button>
      </div>
    </Modal>
  );
}

function Preview({ label, checked, onChange, items }: { label: string; checked: boolean; onChange: (v: boolean) => void; items?: string[] }) {
  return (
    <fieldset className="mt-3 text-sm">
      <label className="flex items-center gap-2">
        <input type="checkbox" className="size-4" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        {label}
      </label>
      {items === undefined ? null : items.length === 0 ? (
        <p className="ml-6 text-muted-foreground">{t("members.previewNone")}</p>
      ) : (
        <ul className="ml-6 list-disc pl-4">
          {items.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

export function InviteDialog({ tenant, roles, onClose }: { tenant: string; roles: MemberRole[]; onClose: () => void }) {
  const qc = useQueryClient();
  const [created, setCreated] = useState<InvitationCreated | null>(null); // the link token lives here only
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [all, setAll] = useState(true);
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const fields = fieldErrors(error);
  // Not while the request runs: the server may create the invitation and its link,
  // shown once, after the dialog is gone.
  const close = () => {
    if (busy) return;
    setCreated(null);
    onClose();
  };

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const ids = String(f.get("product_ids") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    setBusy(true);
    setError(null);
    try {
      // Not a useMutation: its result (the link token) would stay in the mutation cache.
      const inv = await createInvitation(tenant, {
        email: String(f.get("email") ?? ""),
        role: String(f.get("role")) as MemberRole,
        all_products: all,
        ...(all ? {} : { product_ids: ids }),
      });
      setCreated(inv);
      void qc.invalidateQueries({ queryKey: invitationsQuery(tenant).queryKey }); // metadata only
    } catch (err) {
      onAuthError(err);
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (created) {
    const link = inviteLink(created.token);
    return (
      <Modal title={t("invitations.linkTitle", { email: created.email })} onClose={close}>
        <p role="alert" className="mb-3 text-sm font-medium">
          {t("invitations.linkWarning")}
        </p>
        <div className="flex gap-2">
          <input readOnly aria-label={t("invitations.link")} value={link} onFocus={(e) => e.currentTarget.select()} className={`${input} font-mono`} autoComplete="off" spellCheck={false} />
          <Button
            aria-live="polite"
            onClick={() => void navigator.clipboard.writeText(link).then(() => setCopy("copied"), () => setCopy("failed"))}
          >
            {copy === "copied" ? t("tokens.copied") : t("tokens.copy")}
          </Button>
        </div>
        {copy === "failed" && (
          <p role="alert" className="mt-2 text-sm">
            {t("invitations.copyFailed")}
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

  const fieldError = (name: string) => fields[name] && <span id={`${name}-error`} className="text-sm">{fields[name]}</span>;
  return (
    <Modal title={t("invitations.new")} onClose={close}>
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4" noValidate>
        <div className="flex flex-col gap-1 text-sm">
          <label className="flex flex-col gap-1">
            {t("invitations.col.email")}
            <input name="email" type="email" required maxLength={320} className={input} aria-invalid={!!fields.email} aria-describedby="email-error" />
          </label>
          {fieldError("email")}
        </div>
        <div className="flex flex-col gap-1 text-sm">
          <label className="flex flex-col gap-1">
            {t("tokens.field.role")}
            <select name="role" className={input} defaultValue={roles.at(-1)} aria-invalid={!!fields.role} aria-describedby="role-error">
              {roles.map((r) => (
                <option key={r} value={r}>{r}</option>
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
            <input name="product_ids" className={`${input} font-mono`} aria-invalid={!!fields.product_ids} aria-describedby="product_ids-error" />
          </label>
        )}
        {fieldError("product_ids")}
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
            {t("invitations.send")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function RevokeInvitationDialog({ tenant, invitation, onClose }: { tenant: string; invitation: Invitation; onClose: () => void }) {
  const qc = useQueryClient();
  const revoke = useMutation({
    mutationFn: () => revokeInvitation(tenant, invitation.id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: invitationsQuery(tenant).queryKey });
      onClose();
    },
  });
  return (
    <Modal title={t("invitations.revokeTitle", { email: invitation.email })} onClose={onClose}>
      <p className="text-sm">{t("invitations.revokeBody")}</p>
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

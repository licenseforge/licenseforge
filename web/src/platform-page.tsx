import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError, fieldErrors, onAuthError } from "@/api/client";
import { inviteLink } from "@/api/members";
import { createPlatformTenant, type PlatformTenant, type PlatformTenantCreated, platformStepUpHref, platformTenantsQuery, reinviteOwner } from "@/api/platform";
import type { MfaPolicy } from "@/api/tenants";
import { Field } from "@/catalog-pages";
import { errorText, input, Modal } from "@/components/modal";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const th = "px-2 py-2 font-medium";
const td = "px-2 py-2";

/** Platform admins' tenant list and onboarding (ADR-0042). The server checks the admin on every request. */
export function PlatformPage() {
  const list = useInfiniteQuery(platformTenantsQuery);
  const [creating, setCreating] = useState(false);
  const [reinviting, setReinviting] = useState<PlatformTenant | null>(null);
  const rows = list.data?.pages.flatMap((p) => p.items) ?? [];
  const mfaLabel = (p: MfaPolicy) => t(`platform.mfa.${p}`);
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">{t("platform.title")}</h1>
        {list.isSuccess && <Button onClick={() => setCreating(true)}>{t("platform.new")}</Button>}
      </div>
      <p className="mt-2 text-sm text-muted-foreground">{t("platform.intro")}</p>
      {list.isError && <PlatformError error={list.error} className="mt-4" />}
      {list.isSuccess && rows.length === 0 && <p className="mt-6 text-muted-foreground">{t("platform.empty")}</p>}
      {rows.length > 0 && (
        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-muted-foreground">
              <tr>
                <th scope="col" className={th}>{t("tokens.col.name")}</th>
                <th scope="col" className={th}>{t("products.col.slug")}</th>
                <th scope="col" className={th}>{t("platform.col.mfa")}</th>
                <th scope="col" className={th}>{t("products.col.created")}</th>
                <th scope="col" className={th}><span className="sr-only">{t("platform.reinvite")}</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((tn) => (
                <tr key={tn.id} className="border-b">
                  <td className={`${td} font-medium`}>
                    {tn.name}
                    {tn.test && (
                      <>
                        {" "}
                        <span className="ml-2 rounded border border-dashed px-1 text-xs font-normal">{t("platform.testBadge")}</span>
                      </>
                    )}
                  </td>
                  <td className={`${td} font-mono text-xs`}>{tn.slug}</td>
                  <td className={td}>{mfaLabel(tn.mfa_policy)}</td>
                  <td className={td}>{date.format(new Date(tn.created_at))}</td>
                  <td className={`${td} whitespace-nowrap text-right`}>
                    {/* only before anyone joined: then the tenant's owners invite (ADR-0042) */}
                    {!tn.has_members && (
                      <Button variant="ghost" aria-label={t("platform.reinviteNamed", { name: tn.name, slug: tn.slug })} onClick={() => setReinviting(tn)}>
                        {t("platform.reinvite")}
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
      {creating && <CreateTenantDialog onClose={() => setCreating(false)} />}
      {reinviting && <ReinviteDialog tenant={reinviting} onClose={() => setReinviting(null)} />}
    </>
  );
}

/** An error from the platform API; a platform MFA refusal offers the step-up back here. */
function PlatformError({ error, className = "" }: { error: unknown; className?: string }) {
  const stepUp = platformStepUpHref(error);
  if (!stepUp) return <p role="alert" className={className}>{errorText(error)}</p>;
  return (
    <div role="alert" className={`flex flex-col items-start gap-2 ${className}`}>
      <p>{t("platform.mfaRequired")}</p>
      <a href={stepUp} className="inline-flex h-9 items-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground">
        {t("mfa.stepUp")}
      </a>
    </div>
  );
}

function CreateTenantDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [created, setCreated] = useState<PlatformTenantCreated | null>(null); // the link token lives here only
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const fields = fieldErrors(error);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      // Not a useMutation: its result (the link token) would stay in the mutation cache.
      const c = await createPlatformTenant(String(f.get("slug") ?? "").trim(), String(f.get("name") ?? "").trim(), String(f.get("owner_email") ?? "").trim(), f.get("test") === "on");
      setCreated(c);
      void qc.invalidateQueries({ queryKey: platformTenantsQuery.queryKey });
    } catch (err) {
      onAuthError(err);
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  // No closing while the create is in flight: its answer holds the only
  // copy of the owner's invite link, and the tenant can't be created again.
  const close = () => {
    if (!busy) onClose();
  };

  if (created) {
    return (
      <Modal title={t("platform.createdTitle", { name: created.tenant.name })} onClose={onClose}>
        <InviteLink created={created} onClose={onClose} />
      </Modal>
    );
  }

  return (
    <Modal title={t("platform.new")} onClose={close}>
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4" noValidate>
        <Field label={t("products.col.slug")} name="slug" required maxLength={63} pattern="[a-z0-9]+(-[a-z0-9]+)*" error={fields.slug} help={t("platform.slugHelp")} />
        <Field label={t("tokens.col.name")} name="name" required maxLength={200} error={fields.name} />
        <Field label={t("platform.ownerEmail")} name="owner_email" type="email" required maxLength={320} error={fields.owner_email} help={t("platform.ownerHelp")} />
        <div className="text-sm">
          <label className="flex items-center gap-2 font-medium">
            <input type="checkbox" name="test" className="size-4" aria-describedby="test-help" />
            {t("platform.test")}
          </label>
          <p id="test-help" className="ml-6 text-muted-foreground">{t("platform.testHelp")}</p>
        </div>
        {error != null && <PlatformError error={error} className="text-sm font-medium" />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={close} disabled={busy}>
            {t("tokens.cancel")}
          </Button>
          <Button type="submit" disabled={busy}>
            {t("platform.create")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

/** The owner's invite link, shown once: the dialog's state is its only copy. */
function InviteLink({ created, onClose }: { created: PlatformTenantCreated; onClose: () => void }) {
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const link = inviteLink(created.invitation.token);
  return (
    <>
      <p className="mb-2 text-sm">{t("invitations.linkTitle", { email: created.invitation.email })}</p>
      <p role="alert" className="mb-3 text-sm font-medium">
        {t("invitations.linkWarning")}
      </p>
      <div className="flex gap-2">
        {/* autoFocus: the dialog's content changed under the focused button */}
        <input autoFocus readOnly aria-label={t("invitations.link")} value={link} onFocus={(e) => e.currentTarget.select()} className={`${input} font-mono`} autoComplete="off" spellCheck={false} />
        <Button aria-live="polite" onClick={() => void navigator.clipboard.writeText(link).then(() => setCopy("copied"), () => setCopy("failed"))}>
          {copy === "copied" ? t("tokens.copied") : t("tokens.copy")}
        </Button>
      </div>
      {copy === "failed" && (
        <p role="alert" className="mt-2 text-sm">
          {t("invitations.copyFailed")}
        </p>
      )}
      <div className="mt-6 flex justify-end">
        <Button variant="ghost" onClick={onClose}>
          {t("tokens.close")}
        </Button>
      </div>
    </>
  );
}

/** A new owner invite for a tenant without an owner (ADR-0042, amended). */
function ReinviteDialog({ tenant, onClose }: { tenant: PlatformTenant; onClose: () => void }) {
  const qc = useQueryClient();
  const [created, setCreated] = useState<PlatformTenantCreated | null>(null); // the link token lives here only
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const fields = fieldErrors(error);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      // Not a useMutation: its result (the link token) would stay in the mutation cache.
      setCreated(await reinviteOwner(tenant.id, String(f.get("owner_email") ?? "").trim()));
    } catch (err) {
      onAuthError(err);
      setError(err);
      // Joined meanwhile: the list's has_members is stale, so is the row's action.
      if (err instanceof ApiError && err.code === "conflict") void qc.invalidateQueries({ queryKey: platformTenantsQuery.queryKey });
    } finally {
      setBusy(false);
    }
  }
  // As for create: the answer holds the only copy of the new link.
  const close = () => {
    if (!busy) onClose();
  };

  if (created) {
    return (
      <Modal title={t("platform.reinvitedTitle", { name: tenant.name })} onClose={onClose}>
        <InviteLink created={created} onClose={onClose} />
      </Modal>
    );
  }
  const hasOwner = error instanceof ApiError && error.code === "conflict";
  return (
    <Modal title={t("platform.reinviteTitle", { name: tenant.name })} onClose={close}>
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4" noValidate>
        <p className="text-sm text-muted-foreground">{t("platform.reinviteHelp")}</p>
        <Field label={t("platform.ownerEmail")} name="owner_email" type="email" required maxLength={320} error={fields.owner_email} help={t("platform.ownerHelp")} />
        {hasOwner && (
          <p role="alert" className="text-sm font-medium">
            {t("platform.hasOwner")}
          </p>
        )}
        {error != null && !hasOwner && <PlatformError error={error} className="text-sm font-medium" />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={close} disabled={busy}>
            {t("tokens.cancel")}
          </Button>
          <Button type="submit" disabled={busy}>
            {t("platform.reinviteSubmit")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

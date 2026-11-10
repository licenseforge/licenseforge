import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { fieldErrors, onAuthError } from "@/api/client";
import { tenantsQuery } from "@/api/tenants";
import {
  canManageWebhooks,
  createWebhook,
  deleteWebhook,
  heldBack,
  rotateWebhookSecret,
  skipWebhookEvent,
  updateWebhook,
  type Webhook,
  type WebhookCreated,
  type WebhookEventType,
  webhookAction,
  webhookDeliveriesQuery,
  webhookEvents,
  webhooksQuery,
} from "@/api/webhooks";
import { errorText, input, Modal } from "@/components/modal";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

const when = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

type Confirm = { hook: Webhook; action: "disable" | "skip-to-now" | "skipEvent" | "delete" };

export function WebhooksPage() {
  const { slug } = useParams({ from: "/app/t/$slug/settings/webhooks" });
  const { data: tenants = [] } = useQuery(tenantsQuery);
  const manage = canManageWebhooks(tenants.find((tn) => tn.slug === slug));
  const list = useQuery(webhooksQuery(slug));
  const qc = useQueryClient();
  const refresh = () => qc.invalidateQueries({ queryKey: webhooksQuery(slug).queryKey });
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Webhook | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [secret, setSecret] = useState<WebhookCreated | null>(null); // a rotated secret, shown once
  const [log, setLog] = useState<Webhook | null>(null);
  const enable = useMutation({ mutationFn: (h: Webhook) => webhookAction(slug, h.id, "enable"), onSuccess: refresh, onError: onAuthError });
  // Not a useMutation: its result (the secret) would stay in the mutation cache.
  const [rotating, setRotating] = useState(false);
  const [rotateError, setRotateError] = useState<unknown>(null);
  async function rotate(h: Webhook) {
    setRotating(true);
    setRotateError(null);
    try {
      setSecret(await rotateWebhookSecret(slug, h.id));
      void refresh();
    } catch (err) {
      onAuthError(err);
      setRotateError(err);
    } finally {
      setRotating(false);
    }
  }
  const hooks = list.data?.items ?? [];
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t("webhooks.title")}</h1>
          <p className="mt-1 text-muted-foreground">{t("webhooks.body")}</p>
        </div>
        {manage && <Button onClick={() => setCreating(true)}>{t("webhooks.new")}</Button>}
      </div>
      {list.isError && (
        <p role="alert" className="mt-4">
          {errorText(list.error)}
        </p>
      )}
      {(enable.isError || rotateError != null) && (
        <p role="alert" className="mt-4">
          {errorText(enable.error ?? rotateError)}
        </p>
      )}
      {list.isSuccess && hooks.length === 0 && <p className="mt-6 text-muted-foreground">{t("webhooks.empty")}</p>}
      {hooks.length > 0 && (
        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-muted-foreground">
              <tr>
                {(["url", "events", "status", "delivery"] as const).map((c) => (
                  <th key={c} scope="col" className="px-2 py-2 font-medium">
                    {t(`webhooks.col.${c}`)}
                  </th>
                ))}
                <th scope="col" className="px-2 py-2">
                  <span className="sr-only">{t("webhooks.edit")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {hooks.map((h) => (
                <tr key={h.id} className="border-b align-top">
                  <td className="px-2 py-2 font-mono text-xs">{h.url}</td>
                  <td className="px-2 py-2">{h.events.join(", ")}</td>
                  <td className="px-2 py-2">
                    {h.enabled ? t("webhooks.status.enabled") : t("webhooks.status.disabled", { reason: h.disabled_reason ?? "" })}
                  </td>
                  <td className="px-2 py-2">{deliveryText(h)}</td>
                  <td className="px-2 py-2">
                    <div className="flex flex-wrap justify-end gap-1">
                      <Button variant="ghost" onClick={() => setLog(h)}>
                        {t("webhooks.deliveries")}
                      </Button>
                      {manage && (
                        <>
                          <Button variant="ghost" onClick={() => setEditing(h)}>
                            {t("webhooks.edit")}
                          </Button>
                          {h.enabled ? (
                            <Button variant="ghost" onClick={() => setConfirm({ hook: h, action: "disable" })}>
                              {t("webhooks.disable")}
                            </Button>
                          ) : (
                            <Button variant="ghost" disabled={enable.isPending} onClick={() => enable.mutate(h)}>
                              {t("webhooks.enable")}
                            </Button>
                          )}
                          {heldBack(h) && (
                            <Button variant="ghost" onClick={() => setConfirm({ hook: h, action: "skipEvent" })}>
                              {t("webhooks.skipEvent")}
                            </Button>
                          )}
                          <Button variant="ghost" onClick={() => setConfirm({ hook: h, action: "skip-to-now" })}>
                            {t("webhooks.skipToNow")}
                          </Button>
                          <Button variant="ghost" disabled={rotating} onClick={() => void rotate(h)}>
                            {t("webhooks.rotate")}
                          </Button>
                          <Button variant="ghost" onClick={() => setConfirm({ hook: h, action: "delete" })}>
                            {t("webhooks.delete")}
                          </Button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {creating && <EndpointDialog tenant={slug} onClose={() => setCreating(false)} />}
      {editing && <EndpointDialog tenant={slug} hook={editing} onClose={() => setEditing(null)} />}
      {secret && <SecretDialog secret={secret.secret} onClose={() => setSecret(null)} />}
      {confirm && <ConfirmDialog tenant={slug} confirm={confirm} onDone={refresh} onClose={() => setConfirm(null)} />}
      {log && <DeliveriesDialog tenant={slug} hook={log} onClose={() => setLog(null)} />}
    </>
  );
}

function deliveryText(h: Webhook) {
  const d = h.delivery;
  if (heldBack(h) && !h.enabled) return t("webhooks.delivery.held", { seq: String(d.next_seq) });
  if (d.attempts > 0)
    return t("webhooks.delivery.retrying", { attempts: String(d.attempts), when: d.next_attempt_at ? when.format(new Date(d.next_attempt_at)) : "—" });
  return d.next_seq != null || d.in_flight ? t("webhooks.delivery.pending") : t("webhooks.delivery.ok");
}

/** Create (no hook) or edit an endpoint; a new endpoint's secret is shown once, from component state. */
export function EndpointDialog({ tenant, hook, onClose }: { tenant: string; hook?: Webhook; onClose: () => void }) {
  const qc = useQueryClient();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [events, setEvents] = useState<WebhookEventType[]>(hook?.events ?? ["license.issued", "license.revoked"]);
  const [created, setCreated] = useState<WebhookCreated | null>(null);
  const fields = fieldErrors(error);
  const close = () => {
    setCreated(null);
    onClose();
  };
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const url = String(new FormData(e.currentTarget).get("url") ?? "").trim();
    setBusy(true);
    setError(null);
    try {
      // Not a useMutation: a created endpoint's secret would stay in the mutation cache.
      if (hook) {
        await updateWebhook(tenant, hook.id, { events, ...(url ? { url } : {}) });
      } else {
        setCreated(await createWebhook(tenant, url, events));
      }
      void qc.invalidateQueries({ queryKey: webhooksQuery(tenant).queryKey });
      if (hook) close();
    } catch (err) {
      onAuthError(err);
      setError(err);
    } finally {
      setBusy(false);
    }
  }
  if (created) return <SecretDialog secret={created.secret} onClose={close} />;
  return (
    <Modal title={hook ? t("webhooks.editTitle", { url: hook.url }) : t("webhooks.new")} onClose={close}>
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4" noValidate>
        <div className="flex flex-col gap-1 text-sm">
          <label className="flex flex-col gap-1">
            {t("webhooks.field.url")}
            <input
              name="url"
              type="url"
              required={!hook}
              maxLength={2048}
              autoComplete="off"
              spellCheck={false}
              className={`${input} font-mono`}
              aria-invalid={!!fields.url}
              aria-describedby="url-help url-error"
            />
          </label>
          <span id="url-help" className="text-muted-foreground">
            {hook ? t("webhooks.editUrlHelp") : t("webhooks.field.urlHelp")}
          </span>
          {fields.url && <span id="url-error">{fields.url}</span>}
        </div>
        <fieldset className="flex flex-col gap-1 text-sm" aria-describedby="events-error">
          <legend className="mb-1">{t("webhooks.field.events")}</legend>
          {webhookEvents.map((ev) => (
            <label key={ev} className="flex items-center gap-2">
              <input
                type="checkbox"
                className="size-4"
                checked={events.includes(ev)}
                onChange={(e) => setEvents(e.target.checked ? [...events, ev] : events.filter((x) => x !== ev))}
              />
              <span className="font-mono">{ev}</span>
            </label>
          ))}
          {fields.events && <span id="events-error">{fields.events}</span>}
        </fieldset>
        {error != null && (
          <p role="alert" className="text-sm font-medium">
            {errorText(error)}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={close}>
            {t("webhooks.cancel")}
          </Button>
          <Button type="submit" disabled={busy}>
            {hook ? t("webhooks.save") : t("webhooks.create")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function SecretDialog({ secret, onClose }: { secret: string; onClose: () => void }) {
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  return (
    <Modal title={t("webhooks.secretTitle")} onClose={onClose}>
      <p role="alert" className="mb-3 text-sm font-medium">
        {t("webhooks.secretWarning")}
      </p>
      <div className="flex gap-2">
        <input
          readOnly
          aria-label={t("webhooks.secretTitle")}
          value={secret}
          onFocus={(e) => e.currentTarget.select()}
          className={`${input} font-mono`}
          autoComplete="off"
          spellCheck={false}
        />
        <Button
          onClick={() =>
            void navigator.clipboard.writeText(secret).then(
              () => setCopy("copied"),
              () => setCopy("failed"),
            )
          }
          aria-live="polite"
        >
          {copy === "copied" ? t("webhooks.copied") : t("webhooks.copy")}
        </Button>
      </div>
      {copy === "failed" && (
        <p role="alert" className="mt-2 text-sm">
          {t("webhooks.copyFailed")}
        </p>
      )}
      <div className="mt-6 flex justify-end">
        <Button variant="ghost" onClick={onClose}>
          {t("webhooks.close")}
        </Button>
      </div>
    </Modal>
  );
}

function ConfirmDialog({ tenant, confirm, onDone, onClose }: { tenant: string; confirm: Confirm; onDone: () => Promise<void>; onClose: () => void }) {
  const { hook, action } = confirm;
  const seq = hook.delivery.next_seq ?? 0;
  const run = useMutation({
    mutationFn: async () => {
      if (action === "delete") return deleteWebhook(tenant, hook.id);
      if (action === "skipEvent") return void (await skipWebhookEvent(tenant, hook.id, seq));
      return void (await webhookAction(tenant, hook.id, action));
    },
    onSuccess: async () => {
      await onDone();
      onClose();
    },
    onError: async (err) => {
      onAuthError(err);
      await onDone(); // a 409 means the state moved: show the current one
    },
  });
  const label = ({ disable: "webhooks.disable", "skip-to-now": "webhooks.skipToNow", skipEvent: "webhooks.skipEvent", delete: "webhooks.delete" } as const)[action];
  return (
    <Modal title={t("webhooks.confirmTitle", { action: t(label), url: hook.url })} onClose={onClose}>
      <p className="text-sm">{t(`webhooks.confirm.${action}`, { seq: String(seq) })}</p>
      {run.isError && (
        <p role="alert" className="mt-3 text-sm font-medium">
          {errorText(run.error)}
        </p>
      )}
      <div className="mt-6 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          {t("webhooks.cancel")}
        </Button>
        <Button disabled={run.isPending} onClick={() => run.mutate()}>
          {t(label)}
        </Button>
      </div>
    </Modal>
  );
}

function DeliveriesDialog({ tenant, hook, onClose }: { tenant: string; hook: Webhook; onClose: () => void }) {
  const q = useInfiniteQuery(webhookDeliveriesQuery(tenant, hook.id));
  const rows = q.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <Modal title={t("webhooks.deliveriesTitle", { url: hook.url })} onClose={onClose}>
      {q.isError && <p role="alert">{errorText(q.error)}</p>}
      {q.isSuccess && rows.length === 0 && <p className="text-sm text-muted-foreground">{t("webhooks.deliveriesEmpty")}</p>}
      {rows.length > 0 && (
        <table className="w-full text-left text-sm">
          <thead className="border-b text-muted-foreground">
            <tr>
              {(["when", "event", "attempt", "result", "duration"] as const).map((c) => (
                <th key={c} scope="col" className="px-2 py-1 font-medium">
                  {t(`webhooks.dcol.${c}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.id} className="border-b">
                <td className="px-2 py-1">{when.format(new Date(d.attempted_at))}</td>
                <td className="px-2 py-1 font-mono text-xs">
                  {d.event_type} #{d.seq}
                </td>
                <td className="px-2 py-1">{d.attempt}</td>
                <td className="px-2 py-1">{d.outcome === "success" ? t("webhooks.result.success") : d.error}</td>
                <td className="px-2 py-1">{d.duration_ms} ms</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {q.hasNextPage && (
        <Button variant="ghost" className="mt-2" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
          {t("webhooks.deliveriesMore")}
        </Button>
      )}
      <div className="mt-4 flex justify-end">
        <Button variant="ghost" onClick={onClose}>
          {t("webhooks.close")}
        </Button>
      </div>
    </Modal>
  );
}

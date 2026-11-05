import { useInfiniteQuery, useMutation } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { useState } from "react";
import { actorText, type AuditEvent, auditQuery, detailsText, objectText } from "@/api/audit";
import { errorText, Modal } from "@/components/modal";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";
import { type ChainResult, verifyChain } from "@/lib/audit-chain";

// Seconds matter in an audit log; the exact database time is in the cell's title.
const time = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });
const th = "px-2 py-2 font-medium";
const td = "px-2 py-2 align-top";

function chainText(r: ChainResult) {
  return r.ok
    ? t("audit.verified", { count: String(r.checked), from: String(r.fromSeq), to: String(r.toSeq) })
    : t(`audit.broken.${r.reason}`, { seq: String(r.seq) });
}

export function AuditPage() {
  const { slug } = useParams({ from: "/app/t/$slug/settings/audit" });
  const list = useInfiniteQuery(auditQuery(slug));
  const [open, setOpen] = useState<AuditEvent | null>(null);
  const pages = list.data?.pages ?? [];
  const rows = pages.flatMap((p) => p.items);
  // Over what is loaded, newest first: each page's entries with their raw details.
  const verify = useMutation({
    mutationFn: () => verifyChain(pages.flatMap((p) => p.items.map((event, i) => ({ event, rawDetails: p.rawDetails[i]! })))),
  });
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{t("audit.title")}</h1>
          <p className="mt-1 text-muted-foreground">{t("audit.body")}</p>
        </div>
        {rows.length > 0 && (
          <Button variant="ghost" disabled={verify.isPending} onClick={() => verify.mutate()}>
            {t("audit.verify")}
          </Button>
        )}
      </div>
      {verify.data && (
        <p role={verify.data.ok ? "status" : "alert"} className={`mt-3 text-sm ${verify.data.ok ? "" : "font-medium"}`}>
          {chainText(verify.data)}
        </p>
      )}
      {list.isError && <p role="alert" className="mt-4">{errorText(list.error)}</p>}
      {list.isSuccess && rows.length === 0 && <p className="mt-6 text-muted-foreground">{t("audit.empty")}</p>}
      {rows.length > 0 && (
        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-muted-foreground">
              <tr>
                <th scope="col" className={th}>{t("audit.col.seq")}</th>
                <th scope="col" className={th}>{t("audit.col.time")}</th>
                <th scope="col" className={th}>{t("audit.col.actor")}</th>
                <th scope="col" className={th}>{t("audit.col.action")}</th>
                <th scope="col" className={th}>{t("audit.col.outcome")}</th>
                <th scope="col" className={th}>{t("audit.col.object")}</th>
                <th scope="col" className={th}>{t("audit.col.source")}</th>
                <th scope="col" className={th}><span className="sr-only">{t("audit.open")}</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id} className="border-b">
                  <td className={`${td} tabular-nums`}>{e.seq}</td>
                  <td className={`${td} whitespace-nowrap`} title={e.occurred_at}>{time.format(new Date(e.occurred_at))}</td>
                  <td className={`${td} font-mono text-xs`}>{actorText(e)}</td>
                  <td className={`${td} font-mono text-xs`}>{e.action}</td>
                  <td className={td}>{t(`audit.outcome.${e.outcome}`)}</td>
                  <td className={`${td} font-mono text-xs`}>{objectText(e)}</td>
                  <td className={`${td} font-mono text-xs`}>{e.source_ip ?? ""}</td>
                  <td className={`${td} text-right`}>
                    <Button variant="ghost" onClick={() => setOpen(e)}>{t("audit.open")}</Button>
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
      {open && <AuditDialog event={open} onClose={() => setOpen(null)} />}
    </>
  );
}

/** One entry: every field, and details as escaped, indented JSON text (never HTML). */
export function AuditDialog({ event: e, onClose }: { event: AuditEvent; onClose: () => void }) {
  const row = (k: string, v: string | number | null) => (
    <div className="flex justify-between gap-4 border-b py-1">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="break-all text-right font-mono text-xs">{v ?? ""}</dd>
    </div>
  );
  return (
    <Modal title={t("audit.detailTitle", { seq: String(e.seq) })} onClose={onClose}>
      <dl className="text-sm">
        {row(t("audit.col.time"), e.occurred_at)}
        {row(t("audit.col.actor"), actorText(e))}
        {row(t("audit.col.action"), e.action)}
        {row(t("audit.col.outcome"), t(`audit.outcome.${e.outcome}`))}
        {row(t("audit.col.object"), objectText(e))}
        {row(t("audit.col.source"), e.source_ip)}
        {row(t("audit.userAgent"), e.user_agent)}
        {row("ID", e.id)}
        {row(t("audit.hash"), e.hash)}
        {row(t("audit.prevHash"), e.prev_hash)}
      </dl>
      <h3 className="mt-4 font-semibold">{t("audit.details")}</h3>
      {/* Text, never innerHTML: React escapes it. */}
      <pre className="mt-2 max-h-80 overflow-auto rounded-md border p-2 text-xs">{detailsText(e.details)}</pre>
      <div className="mt-6 flex justify-end">
        <Button variant="ghost" onClick={onClose}>{t("tokens.close")}</Button>
      </div>
    </Modal>
  );
}

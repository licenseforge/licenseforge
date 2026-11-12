import { type ReactNode, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { errorText } from "@/components/modal";
import { t } from "@/i18n";

/** Days an archived row stays listed by default (ADR-0015, amended); after that it is hidden but still restorable. */
export const ARCHIVED_SHOWN_DAYS = 30;

/** Archived more than ARCHIVED_SHOWN_DAYS ago. */
export function oldArchived(archivedAt: string | null | undefined, now = Date.now()): boolean {
  return archivedAt != null && now - Date.parse(archivedAt) > ARCHIVED_SHOWN_DAYS * 86_400_000;
}

/** A list without rows archived long ago, and the toggle that shows them. */
export function useArchivedFilter<T extends { archived_at?: string | null }>(rows: T[]): { rows: T[]; toggle: ReactNode } {
  const [all, setAll] = useState(false);
  const hidden = rows.filter((r) => oldArchived(r.archived_at)).length;
  return {
    rows: all ? rows : rows.filter((r) => !oldArchived(r.archived_at)),
    toggle:
      hidden > 0 || all ? (
        <Button variant="ghost" className="mt-2" aria-pressed={all} onClick={() => setAll(!all)}>
          {all ? t("archived.hideOld", { days: String(ARCHIVED_SHOWN_DAYS) }) : t("archived.showOld", { n: String(hidden), days: String(ARCHIVED_SHOWN_DAYS) })}
        </Button>
      ) : null,
  };
}

/** Restores an archived row: no confirmation, archiving again undoes it. */
export function RestoreButton({ name, run, onDone }: { name: string; run: () => Promise<unknown>; onDone: () => Promise<unknown> }) {
  const restore = useMutation({ mutationFn: run, onSuccess: onDone });
  return (
    <>
      <Button variant="ghost" disabled={restore.isPending} aria-label={t("archived.restoreNamed", { name })} onClick={() => restore.mutate()}>
        {t("archived.restore")}
      </Button>
      {restore.isError && <span role="alert" className="ml-2 text-sm font-medium">{errorText(restore.error)}</span>}
    </>
  );
}

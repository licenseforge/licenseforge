import { type ReactNode, useEffect, useRef } from "react";
import { ApiError } from "@/api/client";
import { problemMessage } from "@/i18n";

/** The message for an error from the API: its problem code, else generic. */
export const errorText = (e: unknown) => problemMessage(e instanceof ApiError ? e.code : "unknown");

export const input = "h-9 w-full rounded-md border bg-background px-2 text-sm outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50";

/**
 * A native modal <dialog>: focus trap, Esc and inert background from the
 * browser, and no injected <style> (Radix's modal Dialog needs one, which the
 * CSP blocks). Closing unmounts the content, so its state is gone.
 */
export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
    return () => d?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      aria-labelledby="dialog-title"
      onCancel={(e) => {
        e.preventDefault(); // Esc: close through React so the state goes with it
        onClose();
      }}
      className="m-auto w-full max-w-lg rounded-md border bg-popover p-6 text-popover-foreground shadow-md backdrop:bg-black/50"
    >
      <h2 id="dialog-title" className="mb-4 text-lg font-semibold">
        {title}
      </h2>
      {children}
    </dialog>
  );
}


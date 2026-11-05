// Client-side check of the audit chain (ADR-0027) over the pages the viewer
// has loaded, with the algorithm documented on AuditEvent.hash in
// api/openapi.yaml. It needs each entry's details exactly as sent, so pages
// are read as text and the raw details are cut out of it here.
import type { components } from "@/api/schema";

type AuditEvent = components["schemas"]["AuditEvent"];

/**
 * The raw JSON text of items[i].details in a page body, in item order. A
 * small scanner rather than JSON.parse: re-serializing would change the
 * bytes the hash covers (key order, spacing, escapes).
 */
export function detailsSpans(body: string): string[] {
  let i = 0;
  const ws = () => {
    while (i < body.length && " \t\n\r".includes(body[i]!)) i++;
  };
  const fail = (): never => {
    throw new Error(`audit page: bad JSON at ${i}`);
  };
  const expect = (c: string) => {
    ws();
    if (body[i] !== c) fail();
    i++;
  };
  const string = (): string => {
    ws();
    const start = i;
    if (body[i] !== '"') fail();
    for (i++; i < body.length && body[i] !== '"'; i++) if (body[i] === "\\") i++;
    if (i >= body.length) fail();
    i++;
    return JSON.parse(body.slice(start, i)) as string;
  };
  const skip = (): void => {
    ws();
    const c = body[i];
    if (c === '"') return void string();
    if (c === "{" || c === "[") {
      const close = c === "{" ? "}" : "]";
      i++;
      ws();
      if (body[i] === close) return void i++;
      for (;;) {
        if (c === "{") {
          string();
          expect(":");
        }
        skip();
        ws();
        if (body[i] === ",") i++;
        else if (body[i] === close) return void i++;
        else fail();
      }
    }
    const m = /^(?:-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(body.slice(i, i + 64));
    if (!m) fail();
    i += m![0].length;
  };
  /** Calls onKey for each key of the object at i, which must consume the value. */
  const object = (onKey: (k: string) => void) => {
    expect("{");
    ws();
    if (body[i] === "}") return void i++;
    for (;;) {
      const k = string();
      expect(":");
      onKey(k);
      ws();
      if (body[i] === ",") i++;
      else if (body[i] === "}") return void i++;
      else fail();
    }
  };
  const out: string[] = [];
  object((k) => {
    if (k !== "items") return skip();
    expect("[");
    ws();
    if (body[i] === "]") return void i++;
    for (;;) {
      let details: string | undefined;
      object((field) => {
        if (field !== "details") return skip();
        ws();
        const start = i;
        skip();
        details = body.slice(start, i);
      });
      if (details === undefined) fail();
      out.push(details!);
      ws();
      if (body[i] === ",") i++;
      else if (body[i] === "]") return void i++;
      else fail();
    }
  });
  return out;
}

const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (b) => parseInt(b, 16));
const hexOf = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

/** The entry's hash, as AuditEvent.hash documents it; rawDetails is details as sent. */
export async function auditHash(e: AuditEvent, rawDetails: string): Promise<string> {
  const text = new TextEncoder();
  const fields: Uint8Array[] = [
    "lf-audit-v1", e.id, e.tenant_id, String(e.seq), e.occurred_at, e.actor_type, e.actor_id ?? "", e.action,
    e.object_type ?? "", e.object_id ?? "", e.outcome, e.source_ip ?? "", e.user_agent ?? "", rawDetails,
  ].map((f) => text.encode(f));
  fields.push(hexBytes(e.prev_hash));
  const parts: Uint8Array[] = [];
  for (const f of fields) {
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, f.length); // big-endian
    parts.push(len, f);
  }
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    all.set(p, at);
    at += p.length;
  }
  return hexOf(await crypto.subtle.digest("SHA-256", all));
}

export type ChainResult =
  | { ok: true; checked: number; fromSeq: number; toSeq: number }
  | { ok: false; seq: number; reason: "hash" | "link" | "gap" | "start" };

/**
 * Checks loaded entries, newest first: each hash recomputes, each entry's
 * prev_hash is the next older one's hash, seqs have no holes, and seq 1
 * starts from zeros. It can't see entries before the oldest loaded one.
 */
export async function verifyChain(entries: { event: AuditEvent; rawDetails: string }[]): Promise<ChainResult> {
  for (let i = 0; i < entries.length; i++) {
    const { event: e, rawDetails } = entries[i]!;
    if ((await auditHash(e, rawDetails)) !== e.hash.toLowerCase()) return { ok: false, seq: e.seq, reason: "hash" };
    const older = entries[i + 1]?.event;
    if (older) {
      if (older.seq !== e.seq - 1) return { ok: false, seq: e.seq, reason: "gap" };
      if (e.prev_hash.toLowerCase() !== older.hash.toLowerCase()) return { ok: false, seq: e.seq, reason: "link" };
    } else if (e.seq === 1 && !/^0{64}$/.test(e.prev_hash)) {
      return { ok: false, seq: e.seq, reason: "start" };
    }
  }
  const seqs = entries.map((x) => x.event.seq);
  return { ok: true, checked: entries.length, fromSeq: Math.min(...seqs), toSeq: Math.max(...seqs) };
}

// A license on an air-gapped machine (ADR-0006, ADR-0043), as the Go SDK's
// offline package: the app writes an activation request, someone carries it
// to the vendor's LicenseForge and carries the signed license file back, the
// app installs it. To give the seat back, the app deletes the file and writes
// a deactivation receipt for the vendor.
//
// The installed file and the files returned are kept in a ClockStore (its own
// file: FileClockStore, never the clock guard's). Every use verifies the file
// again, so a renewed file installed by another process is picked up without
// a restart.
import { randomBytes } from "node:crypto";
import { type ClockStore, type Guard } from "./clock.js";
import { type Fingerprint } from "./fingerprint.js";
import { check, type CheckOptions, type Claims, LicenseError, parseClaims, type PublicKey, type Status, verify } from "./licensefile.js";
import { encodeReceipt, encodeRequest, fileSHA256 } from "./offline.js";
import { SDK_VERSION } from "./online.js";

/**
 * no_license: none installed. bad_file: the file doesn't verify, or isn't for
 * this tenant, product or machine. returned: this machine returned it (or a
 * newer file of its license): request a new one. older_file: a newer file of
 * the same license is installed. other_license: another license is installed;
 * deactivate it first. foreign_state: the store holds other state (the clock
 * guard's?): give each its own file. clock_not_saved: the file's iat is
 * ahead of this machine's clock and the clock guard couldn't be raised to it.
 */
export type OfflineErrorCode = "no_license" | "bad_file" | "returned" | "older_file" | "other_license" | "foreign_state" | "clock_not_saved";

export class OfflineError extends Error {
  constructor(
    readonly code: OfflineErrorCode,
    detail: string,
    options?: { cause?: unknown },
  ) {
    super(`licenseforge offline: ${code}: ${detail}`, options);
    this.name = "OfflineError";
  }
}

export interface OfflineConfig {
  /** tnt_…, the license's tenant claim. */
  tenantId: string;
  /** The product slug the app expects. */
  product: string;
  /** As the user typed it: it goes in the request. */
  licenseKey: string;
  keys: readonly PublicKey[];
  /** compute(tenantId, product, …): a machine or cluster binding. */
  fingerprint: Fingerprint;
  hostname?: string;
  appVersion?: string;
  /**
   * The installed file and the files returned: its own FileClockStore, never
   * the clock guard's. On a memory store a returned file could be installed
   * again after a restart. Unreadable or damaged state counts as none
   * (ADR-0014), like deleted state.
   */
  store: ClockStore;
  /** Protects the time checks against the clock being turned back (ADR-0018); strongly advised offline. */
  clock?: Guard;
  clockToleranceSeconds?: number;
  buildDate?: Date;
}

/** What the store holds: the installed file, and license ID → iat (ISO) of the newest file returned. A Map: any lid is a plain key. */
interface State {
  file?: string;
  returned: Map<string, string>;
}

/**
 * Runs one license on one machine.
 * ponytail: no cross-process lock (FileClockStore has none, unlike Go's
 * FileStore): two processes changing the state at once can lose one change,
 * e.g. a returned file's record. Deleting the state does as much (ADR-0014);
 * add a lock file if that matters.
 */
export class OfflineClient {
  private readonly cfg: OfflineConfig;

  constructor(cfg: OfflineConfig) {
    if (!cfg.tenantId || !cfg.product || !cfg.licenseKey || cfg.keys.length === 0 || !cfg.fingerprint?.fingerprint || !cfg.store) {
      throw new TypeError("licenseforge offline: tenantId, product, licenseKey, keys, fingerprint and store are required");
    }
    if (cfg.fingerprint.binding !== "machine" && cfg.fingerprint.binding !== "cluster") {
      throw new TypeError("licenseforge offline: fingerprint.binding must be machine or cluster");
    }
    this.cfg = { ...cfg };
  }

  /** An activation request (lfreq1) for this machine, to carry to the vendor. It contains the license key: handle it like the key. */
  request(now: Date = new Date()): string {
    const c = this.cfg;
    return encodeRequest({
      tenant: c.tenantId,
      product: c.product,
      key: c.licenseKey,
      binding: { type: c.fingerprint.binding, fingerprint: c.fingerprint.fingerprint },
      fpSource: c.fingerprint.source,
      nonce: randomBytes(16),
      created: now,
      ...(c.hostname ? { hostname: c.hostname } : {}),
      ...(c.appVersion ? { appVersion: c.appVersion } : {}),
      sdkVersion: SDK_VERSION,
    });
  }

  /**
   * Verifies file (the vendor's answer to request) and installs it, replacing
   * the installed file of the same license: a renewal, or the same file
   * again. Refused: a file not usable now, one this machine returned
   * (returned), one older than the installed file of its license
   * (older_file), another license's while one is installed (other_license);
   * an installed file that no longer verifies here blocks nothing. With a
   * clock guard, a file whose iat is ahead of this machine's clock raises the
   * guard to it once its checks pass (refused if the guard can't hold it).
   */
  install(file: string, local: Date = new Date()): { claims: Claims; status: Status } {
    const claims = this.verify(file);
    const o = this.options(local);
    let status: Status;
    try {
      status = check(claims, o);
    } catch (e) {
      // The vendor's clock may be ahead of this machine's: within the guard's
      // tolerance its iat is a time this machine will accept (ADR-0018), once
      // the guard holds it; if it can't, current() would refuse the file.
      const g = this.cfg.clock;
      if (!(e instanceof LicenseError && e.code === "clock_skew" && g && claims.issuedAt.getTime() <= local.getTime() + g.toleranceMs)) throw e;
      status = check(claims, { ...o, now: claims.issuedAt });
      if (!g.observe(claims.issuedAt, local)) {
        throw new OfflineError("clock_not_saved", "the file's iat is ahead of this machine's clock and the clock guard can't hold it");
      }
    }
    this.update((s) => {
      const r = s.returned.get(claims.licenseId);
      if (r !== undefined && claims.issuedAt.getTime() <= Date.parse(r)) throw new OfflineError("returned", "this license file was returned; request a new one");
      if (s.file) {
        let cur: Claims | undefined;
        try {
          cur = this.verify(s.file);
        } catch {
          cur = undefined; // an installed file that no longer verifies blocks nothing
        }
        if (cur && cur.licenseId !== claims.licenseId) throw new OfflineError("other_license", "another license is installed; deactivate it first");
        if (cur && claims.issuedAt < cur.issuedAt) throw new OfflineError("older_file", "a newer license file is installed");
      }
      return { ...s, file };
    });
    return { claims, status };
  }

  /** The installed file, verified and checked now: its claims and status. Any error means: don't run as licensed. */
  current(local: Date = new Date()): { claims: Claims; status: Status } {
    let file: string | undefined;
    this.update((s) => {
      file = s.file;
      return undefined;
    });
    if (!file) throw new OfflineError("no_license", "no license file installed");
    const claims = this.verify(file);
    return { claims, status: check(claims, this.options(local)) };
  }

  /**
   * Gives the seat back: deletes the installed file, remembers it so it
   * can't be installed again, and returns the deactivation receipt (lfrcpt1)
   * for the vendor, once the state is saved. Keep it until the vendor has it:
   * it is the only proof. A file that no longer verifies here (its key
   * dropped from keys, a changed fingerprint) can't be deactivated here
   * (bad_file): the vendor frees the seat from the dashboard.
   */
  deactivate(now: Date = new Date()): string {
    let receipt = "";
    this.update((s) => {
      if (!s.file) throw new OfflineError("no_license", "no license file installed");
      const claims = this.verify(s.file);
      receipt = encodeReceipt({
        tenant: this.cfg.tenantId,
        licenseId: claims.licenseId,
        fingerprint: this.cfg.fingerprint.fingerprint,
        fileSHA256: fileSHA256(s.file),
        nonce: randomBytes(16),
        created: now,
      });
      const returned = new Map(s.returned);
      const r = returned.get(claims.licenseId);
      if (r === undefined || claims.issuedAt.getTime() > Date.parse(r)) returned.set(claims.licenseId, claims.issuedAt.toISOString());
      return { returned };
    });
    return receipt;
  }

  /** The file as issued for this machine: signature, the claim checks at its own iat, tenant, product, binding to this fingerprint. */
  private verify(file: string): Claims {
    try {
      const claims = parseClaims(verify(file, this.cfg.keys).payload);
      check(claims, { now: claims.issuedAt, product: this.cfg.product, fingerprint: this.cfg.fingerprint.fingerprint });
      if (claims.tenant !== this.cfg.tenantId || claims.binding.type !== this.cfg.fingerprint.binding) {
        throw new Error(`for tenant ${JSON.stringify(claims.tenant)}, binding ${claims.binding.type}`);
      }
      return claims;
    } catch (e) {
      throw new OfflineError("bad_file", "license file not valid for this machine", { cause: e });
    }
  }

  /** Check options now; with a clock guard, the time has passed its rollback check (ClockError otherwise). */
  private options(local: Date): CheckOptions {
    const c = this.cfg;
    return {
      now: c.clock ? c.clock.now(local).now : local,
      product: c.product,
      fingerprint: c.fingerprint.fingerprint,
      ...(c.clockToleranceSeconds !== undefined ? { clockToleranceSeconds: c.clockToleranceSeconds } : {}),
      ...(c.buildDate ? { buildDate: c.buildDate } : {}),
    };
  }

  /** Runs fn on the stored state; fn returns the new state, or undefined for no change. */
  private update(fn: (s: State) => State | undefined): void {
    const next = fn(decode(this.cfg.store.load()));
    if (!next) return;
    const doc: Record<string, unknown> = { offline: 1 };
    if (next.file) doc.file = next.file;
    if (next.returned.size > 0) doc.returned = Object.fromEntries(next.returned);
    this.cfg.store.save(Buffer.from(JSON.stringify(doc), "utf8"));
  }
}

// Unparsable state counts as none, as in the clock guard: corrupting it gains
// no more than deleting it (ADR-0014). Well-formed state of another kind is
// foreign_state: the stores are mixed up, and writing would destroy it.
function decode(b: Uint8Array | undefined): State {
  const none: State = { returned: new Map() };
  let v: unknown;
  try {
    v = b && b.length > 0 ? JSON.parse(Buffer.from(b).toString("utf8")) : undefined;
  } catch {
    return none;
  }
  if (v === null || typeof v !== "object" || Array.isArray(v) || Object.keys(v).length === 0) return none;
  const s = v as Record<string, unknown>;
  if (s.offline !== 1) throw new OfflineError("foreign_state", "the store holds other state (shared with the clock guard?); use a store of its own");
  if (s.file !== undefined && typeof s.file !== "string") return none; // ours, but damaged: none
  const returned = new Map<string, string>();
  if (s.returned !== undefined) {
    if (s.returned === null || typeof s.returned !== "object" || Array.isArray(s.returned)) return none;
    for (const [k, t] of Object.entries(s.returned)) {
      if (typeof t !== "string" || Number.isNaN(Date.parse(t))) return none;
      returned.set(k, t);
    }
  }
  return s.file ? { file: s.file, returned } : { returned };
}

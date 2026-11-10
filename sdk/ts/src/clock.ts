// Protection against the system clock being turned back (ADR-0018), as the Go
// SDK's clock package: a high-water mark of the latest trusted time.
// now(local) returns max(local, mark), the time to check licenses with; a
// local clock more than the tolerance behind the mark is a rollback.
//
// The mark is raised by now itself and by observe (a license iat that passed
// its checks, capped at local + tolerance), and set by reset (a verified
// lease's iat after an online refresh: the only way to lower it). The stored
// mark is authenticated with HMAC-SHA256 under a key derived from the license
// key; state that fails it, is corrupt or unreadable counts as no state, like
// deleted state (within the threat model, ADR-0014; max_offline bounds the
// gain). Offline recovery from a rollback, after fixing the clock: delete the
// state file.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";

export const DEFAULT_TOLERANCE_SECONDS = 24 * 3600;
/** The smallest mark increase worth writing: no fsync on every check. */
const PERSIST_EVERY_MS = 60_000;

/**
 * "rollback": the local clock is too far behind the last trusted time: fix
 * it, refresh online, or (offline) delete the state. The check always runs:
 * unreadable state counts as none.
 */
export class ClockError extends Error {
  constructor(readonly code: "rollback", detail: string) {
    super(`licenseforge clock: ${detail}`);
    this.name = "ClockError";
  }
}

/** Persists the guard's state. load returns undefined for no state; save may throw (then the mark isn't persisted). */
export interface ClockStore {
  load(): Uint8Array | undefined;
  save(state: Uint8Array): void;
}

/** The result of a check: the time to use, and whether the new mark was saved. */
export interface ClockNow {
  now: Date;
  /** false: the time is valid but the mark couldn't be saved (read-only storage). */
  persisted: boolean;
}

export class Guard {
  readonly toleranceMs: number;
  private readonly key: Buffer;

  /** A guard for one license, its state in store, authenticated with a key derived from licenseKey. */
  constructor(
    private readonly store: ClockStore,
    licenseKey: string,
    opts: { toleranceSeconds?: number } = {},
  ) {
    if (!licenseKey) throw new TypeError("licenseforge clock: empty license key");
    const tol = opts.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
    if (!Number.isFinite(tol) || tol < 0) throw new RangeError("licenseforge clock: tolerance must be ≥ 0");
    this.toleranceMs = tol * 1000;
    this.key = createHash("sha256").update(`licenseforge clock v1|${licenseKey}`, "utf8").digest();
  }

  private mac(mark: string): Buffer {
    return createHmac("sha256", this.key).update(`v1|${mark}`, "utf8").digest();
  }

  /** The stored mark in ms, or undefined for no state (empty, corrupt, or failing the MAC). */
  private decode(b: Uint8Array | undefined): number | undefined {
    if (!b || b.length === 0) return undefined;
    try {
      const s = JSON.parse(Buffer.from(b).toString("utf8"));
      if (typeof s?.mark !== "string" || typeof s?.mac !== "string") return undefined;
      const want = this.mac(s.mark);
      const got = Buffer.from(s.mac, "base64");
      if (got.length !== want.length || !timingSafeEqual(got, want)) return undefined;
      const t = Date.parse(s.mark);
      return Number.isNaN(t) ? undefined : t;
    } catch {
      return undefined;
    }
  }

  private encode(ms: number): Uint8Array {
    const mark = new Date(ms).toISOString();
    return Buffer.from(JSON.stringify({ mark, mac: this.mac(mark).toString("base64") }), "utf8");
  }

  /** Runs fn on the stored mark; fn returns the new mark or undefined for "no change". */
  private update(fn: (mark: number | undefined) => number | undefined): boolean {
    let cur: Uint8Array | undefined;
    let readable = true;
    try {
      cur = this.store.load();
    } catch {
      readable = false; // counts as no state, like deletion; reported as not persisted
    }
    const next = fn(this.decode(cur));
    if (next === undefined) return readable;
    try {
      this.store.save(this.encode(next));
      return readable;
    } catch {
      return false;
    }
  }

  /** The time to check licenses with, given the system clock (default: now). Throws ClockError rollback. */
  now(local: Date = new Date()): ClockNow {
    const l = valid(local, "local");
    let now = l;
    const persisted = this.update((mark) => {
      if (mark !== undefined && l < mark - this.toleranceMs) {
        throw new ClockError("rollback", "system clock is behind the last trusted time; fix the clock, refresh the license online, or (offline) delete the clock state");
      }
      if (mark !== undefined && mark > now) now = mark;
      return mark === undefined || l - mark >= PERSIST_EVERY_MS ? l : undefined;
    });
    return { now: new Date(now), persisted };
  }

  /**
   * Raises the mark to t, a time known to be genuine (the iat of a license
   * that passed its checks); capped at local + tolerance, so a fast vendor
   * clock can't lock out an honest user. Returns whether it was saved.
   */
  observe(t: Date, local: Date = new Date()): boolean {
    const v = Math.min(valid(t, "t"), valid(local, "local") + this.toleranceMs);
    return this.update((mark) => (mark === undefined || v > mark ? v : undefined));
  }

  /**
   * Sets the mark to serverTime after a successful online refresh, even
   * lower: the online way out of a rollback. serverTime must be
   * authenticated (a verified lease's iat), never an HTTP Date header.
   */
  reset(serverTime: Date): boolean {
    const v = valid(serverTime, "serverTime");
    return this.update(() => v);
  }
}

function valid(d: Date, name: string): number {
  if (!(d instanceof Date) || Number.isNaN(d.getTime())) throw new TypeError(`licenseforge clock: ${name} must be a valid Date`);
  return d.getTime();
}

/** Keeps the mark in memory: it resets on every restart, so use a file for offline licenses. */
export class MemoryClockStore implements ClockStore {
  private state: Uint8Array | undefined;
  load() {
    return this.state;
  }
  save(s: Uint8Array) {
    this.state = s;
  }
}

/**
 * Keeps the state in a file, written atomically: a temp file (mode 0600) in
 * the same directory, fsync, rename, fsync of the directory. A missing file
 * is no state.
 * ponytail: no cross-process lock (Node has no flock, unlike the Go SDK's
 * FileStore): two processes updating at once can lose a raise, so the mark
 * may end at either one's value, never below what either read; the rollback
 * check always runs. Add an O_EXCL lock file if that matters.
 */
export class FileClockStore implements ClockStore {
  constructor(readonly path: string) {}
  load(): Uint8Array | undefined {
    try {
      return readFileSync(this.path);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw e;
    }
  }
  save(state: Uint8Array): void {
    const dir = dirname(this.path);
    const tmp = join(dir, `.licenseforge-clock-${process.pid}-${Math.random().toString(36).slice(2)}`);
    try {
      const fd = openSync(tmp, "wx", 0o600);
      try {
        writeSync(fd, state);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      // On Windows the rename fails while another program (antivirus,
      // backup) has the target open: retry briefly, as the Go SDK does.
      for (let attempt = 0; ; attempt++) {
        try {
          renameSync(tmp, this.path);
          break;
        } catch (e) {
          if (attempt === 4) throw e;
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
        }
      }
    } catch (e) {
      rmSync(tmp, { force: true }); // a failed write leaves no temp file
      throw e;
    }
    let dfd: number | undefined;
    try {
      dfd = openSync(dir, "r"); // make the rename durable; not possible on Windows
      fsyncSync(dfd);
    } catch {
      // the filesystem handles it there
    } finally {
      if (dfd !== undefined) closeSync(dfd);
    }
  }
}

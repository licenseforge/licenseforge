// The SDK's client for the activation API (ADR-0004, ADR-0034), as the Go
// SDK's online package: activate this machine with a license key, keep its
// signed lease fresh, deactivate it.
//
// Every lease the server returns is verified (signature against the
// vendor's embedded keys, claims, product, tenant, this machine's
// fingerprint and binding) before it is used or cached. A cached lease keeps
// the app running through server outages until max_offline or exp (+ grace)
// runs out.
//
// Time (ADR-0018): each verified lease's iat is server time. The client
// keeps its offset to the local clock and checks with max(local,
// local + offset); with a clock guard it also resets the mark to the iat.
// The HTTP Date header is never trusted.
import { randomBytes, randomInt, X509Certificate } from "node:crypto";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import type { Guard } from "./clock.js";
import type { Fingerprint } from "./fingerprint.js";
import { check, type CheckOptions, type Claims, Entitlements, type PublicKey, parseClaims, type Status, verify } from "./licensefile.js";

/** Sent with activations and refreshes; kept with package.json's version. */
export const SDK_VERSION = "ts/0.1.0-alpha.1"; // = package.json version (test/version.test.ts)

/** The API's stable problem codes, and the client's own conditions. */
export type OnlineErrorCode =
  | "unauthenticated"
  | "invalid_request"
  | "license_suspended"
  | "license_revoked"
  | "license_expired"
  | "activation_limit_reached"
  | "rehost_limit_reached"
  | "binding_mismatch"
  | "not_activated"
  | "offline_seat"
  | "rate_limited"
  | "idempotency_key_reused"
  | "idempotency_in_progress"
  | "server_error"
  | "unexpected_status"
  | "network"
  | "bad_lease" // the answer didn't verify; never cached
  | "no_lease" // activate first
  | "superseded"; // forget or deactivate ran while the call was in flight

const API_CODES = new Set<string>([
  "unauthenticated", "invalid_request", "license_suspended", "license_revoked", "license_expired", "activation_limit_reached",
  "rehost_limit_reached", "binding_mismatch", "not_activated", "offline_seat", "rate_limited", "idempotency_key_reused", "idempotency_in_progress",
]);

export class OnlineError extends Error {
  constructor(
    readonly code: OnlineErrorCode,
    detail: string,
    readonly status = 0,
    readonly requestId = "",
    readonly retryAfterMs = 0,
  ) {
    super(`licenseforge online: ${code}: ${detail}`);
    this.name = "OnlineError";
  }
}

/** Keeps the verified lease across restarts; leases are re-verified when loaded. "" means none / delete. */
export interface LeaseStore {
  load(): string | Promise<string>;
  save(lease: string): void | Promise<void>;
}

export interface ClientConfig {
  /** The server's API base URL, https (http only for loopback): the license key travels with each request. */
  baseURL: string;
  /** tnt_…, the license's tenant claim. */
  tenantId: string;
  /** The product slug the app expects. */
  product: string;
  licenseKey: string;
  keys: readonly PublicKey[];
  /** compute(tenantId, product, …) */
  fingerprint: Fingerprint;
  hostname?: string;
  appVersion?: string;
  /** Absent: memory only (a warning: nothing survives a restart). */
  store?: LeaseStore;
  /** Reset to each lease's iat (ADR-0018). */
  clock?: Guard;
  clockToleranceSeconds?: number;
  buildDate?: Date;
  /** Per call, for network errors, 429, 5xx and idempotency_in_progress. Default 4. */
  maxAttempts?: number;
  /** Per request. Default 30 s. */
  timeoutMs?: number;
  /**
   * A server behind a private CA: its certificate(s), PEM. The client then
   * trusts only these, not Node's bundled CAs (or NODE_EXTRA_CA_CERTS).
   */
  ca?: string | Buffer;
}

export interface Lease {
  file: string;
  claims: Claims;
  activationId: string;
}

const BACKOFF_BASE_MS = 1000;
const BACKOFF_MAX_MS = 5 * 60_000;
const MAX_RETRY_AFTER_MS = 10 * 60_000;
/** The least run waits after a successful refresh, whatever refresh_after says (ADR-0034). */
export const MIN_REFRESH_INTERVAL_MS = 60_000;
const FAIL_MARGIN_MS = 2 * 60_000;
const MAX_ANSWER = 1 << 20;

function loopback(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h);
}

/** A deep copy, Dates included, so callers can't change the cached lease. */
function clone(c: Claims): Claims {
  const d = (x: Date) => new Date(x.getTime());
  const out: Claims = { ...c, issuedAt: d(c.issuedAt), binding: { ...c.binding }, entitlements: new Entitlements([...c.entitlements.features], new Map(c.entitlements.limits)) };
  for (const k of ["notBefore", "expires", "refreshAfter", "updatesUntil"] as const) {
    const v = c[k];
    if (v) out[k] = d(v);
  }
  return out;
}

export class Client {
  private readonly base: URL;
  private readonly cfg: Required<Pick<ClientConfig, "maxAttempts" | "timeoutMs">> & ClientConfig;
  private lease = "";
  private claims: Claims | undefined;
  private offsetMs = 0; // server time minus local time, from the last lease
  private gen = 0; // bumped by forget: in-flight calls from before don't commit
  private ver = 0; // bumped by every commit and forget
  private warnings: Error[] = [];
  private commitChain: Promise<unknown> = Promise.resolve();
  /** Test hooks. */
  now: () => number = Date.now;
  sleep: (ms: number, signal?: AbortSignal) => Promise<void> = sleepMs;
  rand: (n: number) => number = (n) => (n <= 0 ? 0 : randomInt(Math.min(n, 2 ** 48 - 1)));

  private constructor(cfg: ClientConfig) {
    let u: URL;
    try {
      u = new URL(cfg.baseURL.replace(/\/+$/, ""));
    } catch {
      throw new TypeError("licenseforge online: baseURL must be an https URL (http only for loopback hosts)");
    }
    if (!(u.protocol === "https:" || (u.protocol === "http:" && loopback(u.hostname))) || u.username || u.password || u.search || u.hash) {
      throw new TypeError("licenseforge online: baseURL must be an https URL (http only for loopback hosts) without credentials, query or fragment: the license key travels with each request");
    }
    if (!cfg.tenantId || !cfg.product || !cfg.licenseKey || cfg.keys.length === 0 || !cfg.fingerprint?.fingerprint) {
      throw new TypeError("licenseforge online: tenantId, product, licenseKey, keys and fingerprint are required");
    }
    if (cfg.fingerprint.binding !== "machine" && cfg.fingerprint.binding !== "cluster") throw new TypeError("licenseforge online: fingerprint.binding must be machine or cluster");
    if (cfg.timeoutMs !== undefined && !(Number.isFinite(cfg.timeoutMs) && cfg.timeoutMs > 0)) throw new RangeError("licenseforge online: timeoutMs must be > 0");
    if (cfg.ca !== undefined) checkPEM(cfg.ca);
    this.base = u;
    // A copy of a Buffer ca: the caller reusing theirs doesn't change whom a live client trusts.
    this.cfg = { ...cfg, maxAttempts: cfg.maxAttempts && cfg.maxAttempts > 0 ? cfg.maxAttempts : 4, timeoutMs: cfg.timeoutMs ?? 30_000 };
    if (Buffer.isBuffer(cfg.ca)) this.cfg.ca = Buffer.from(cfg.ca);
  }

  /** Checks cfg and loads a cached lease from cfg.store if one verifies. */
  static async create(cfg: ClientConfig): Promise<Client> {
    const c = new Client(cfg);
    if (!cfg.store) {
      c.warn(new Error("licenseforge online: no store: the lease lives in memory only and is lost on restart (ADR-0018)"));
      return c;
    }
    let s = "";
    try {
      s = await cfg.store.load();
    } catch (e) {
      c.warn(new Error(`licenseforge online: loading the stored lease: ${String(e)}`));
    }
    if (s) {
      try {
        const claims = c.verifyFresh(s);
        c.lease = s;
        c.claims = claims;
        // A cache starting empty must not let an old lease pass for new.
        if (cfg.clock && !cfg.clock.observe(claims.issuedAt, new Date(c.now()))) c.warn(new Error("licenseforge online: clock mark not persisted"));
      } catch (e) {
        c.warn(new Error(`licenseforge online: stored lease not used: ${String(e)}`));
      }
    }
    return c;
  }

  private warn(e: Error) {
    this.warnings.push(e);
  }

  /** Returns, and forgets, the non-fatal problems since the last call. run reports them to its onError too. */
  takeWarnings(): Error[] {
    const w = this.warnings;
    this.warnings = [];
    return w;
  }

  /** Activates this machine and returns the verified lease. Retries reuse one Idempotency-Key: never a second seat. */
  async activate(signal?: AbortSignal): Promise<Lease> {
    return (await this.leaseCall("activate", randomBytes(16).toString("base64url"), this.cfg.maxAttempts, signal)).lease;
  }

  /** A new lease for this machine (also the SDK's validate). not_activated: the activation is gone; activate again. */
  async refresh(signal?: AbortSignal): Promise<Lease> {
    return (await this.leaseCall("refresh", "", this.cfg.maxAttempts, signal)).lease;
  }

  /** Frees this machine's seat and drops the cached lease; a machine already not activated is success too. */
  async deactivate(signal?: AbortSignal): Promise<void> {
    try {
      await this.call("deactivate", { fingerprint: this.cfg.fingerprint.fingerprint }, "", 204, this.cfg.maxAttempts, signal);
    } catch (e) {
      if (!(e instanceof OnlineError && e.code === "not_activated")) throw e;
    }
    await this.forget();
  }

  /**
   * Drops the cached and stored lease without contacting the server: the way
   * out of a lease that can't be replaced (one with a far-future iat makes
   * every later lease look like a replay). Then refresh or activate.
   */
  forget(): Promise<void> {
    return this.forgetIf(undefined);
  }

  /** Forgets only if nothing was committed or forgotten since ver. */
  private forgetIf(ver: number | undefined): Promise<void> {
    return this.serial(async () => {
      if (ver !== undefined && this.ver !== ver) return;
      this.lease = "";
      this.claims = undefined;
      this.offsetMs = 0;
      this.gen++;
      this.ver++;
      if (this.cfg.store) await this.cfg.store.save("");
    });
  }

  /** One commit at a time, so the comparison, the cache, the clock and the store all end with the same lease. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.commitChain.then(fn, fn);
    this.commitChain = next.catch(() => undefined);
    return next;
  }

  private async leaseCall(op: string, idemKey: string, attempts: number, signal?: AbortSignal): Promise<{ lease: Lease; ver: number }> {
    const body: Record<string, string> = { fingerprint: this.cfg.fingerprint.fingerprint, fp_source: this.cfg.fingerprint.source, sdk_version: SDK_VERSION };
    if (this.cfg.hostname) body.hostname = this.cfg.hostname;
    if (this.cfg.appVersion) body.app_version = this.cfg.appVersion;
    const { gen, ver } = this;
    const raw = await this.call(op, body, idemKey, 200, attempts, signal);
    let r: { lease?: unknown; activation_id?: unknown };
    try {
      r = JSON.parse(raw);
    } catch (e) {
      throw new OnlineError("bad_lease", `answer isn't JSON: ${String(e)}`);
    }
    if (typeof r?.lease !== "string") throw new OnlineError("bad_lease", "answer has no lease");
    const lease = r.lease;
    const local = this.now();
    const claims = this.verifyFresh(lease);
    return this.serial(async () => {
      if (this.gen !== gen) throw new OnlineError("superseded", "the lease was forgotten while the call ran");
      // An older lease than the one held is a replay: it could wind the clock guard back (ADR-0018).
      if (this.claims && claims.issuedAt.getTime() < this.claims.issuedAt.getTime()) throw new OnlineError("bad_lease", "issued before the current lease");
      this.lease = lease;
      this.claims = claims;
      this.offsetMs = claims.issuedAt.getTime() - local;
      this.ver++;
      // The lease is in use from here; the clock and store failing are warnings.
      if (this.cfg.clock && !this.cfg.clock.reset(claims.issuedAt)) this.warn(new Error("licenseforge online: clock mark not persisted"));
      if (this.cfg.store) {
        try {
          await this.cfg.store.save(lease);
        } catch (e) {
          this.warn(new Error(`licenseforge online: lease not stored: ${String(e)}`));
        }
      }
      return { lease: { file: lease, claims: clone(claims), activationId: typeof r.activation_id === "string" ? r.activation_id : "" }, ver };
    });
  }

  /** The signature, the claims as of the lease's own iat (server time), the product, this machine, the tenant and the binding. */
  private verifyFresh(lease: string): Claims {
    let claims: Claims;
    try {
      claims = parseClaims(verify(lease, this.cfg.keys).payload);
      check(claims, { now: claims.issuedAt, product: this.cfg.product, fingerprint: this.cfg.fingerprint.fingerprint });
    } catch (e) {
      throw new OnlineError("bad_lease", String(e));
    }
    if (claims.tenant !== this.cfg.tenantId) throw new OnlineError("bad_lease", `lease for tenant ${JSON.stringify(claims.tenant)}`);
    // An online lease always binds this machine or cluster: an unbound one would run anywhere.
    if (claims.binding.type !== this.cfg.fingerprint.binding) throw new OnlineError("bad_lease", `lease binds ${claims.binding.type}, not ${this.cfg.fingerprint.binding}`);
    return claims;
  }

  private checkOptions(): CheckOptions {
    const local = this.now();
    const o: CheckOptions = { now: new Date(Math.max(local, local + this.offsetMs)), product: this.cfg.product, fingerprint: this.cfg.fingerprint.fingerprint };
    if (this.cfg.clockToleranceSeconds !== undefined) o.clockToleranceSeconds = this.cfg.clockToleranceSeconds;
    if (this.cfg.buildDate) o.buildDate = this.cfg.buildDate;
    return o;
  }

  /** The check options current uses: with a clock guard, the time has passed the rollback check (throws ClockError). */
  private currentOptions(): CheckOptions {
    const o = this.checkOptions();
    if (this.cfg.clock) o.now = this.cfg.clock.now(o.now).now;
    return o;
  }

  /**
   * Checks the cached lease now: its claims and status (valid, or grace:
   * usable with a warning). Throws when the app must not run as licensed:
   * OnlineError no_lease, a LicenseError from the checks, a ClockError.
   */
  current(): { claims: Claims; status: Status } {
    if (!this.claims) throw new OnlineError("no_lease", "no lease: activate first");
    const claims = clone(this.claims);
    return { claims, status: check(claims, this.currentOptions()) };
  }

  /** Server time minus local time from the last lease, in ms (whole seconds: iat is). */
  serverOffsetMs(): number {
    return this.offsetMs;
  }

  /** How long run may wait with a lease that passes current: half the time to exp and iat+max_offline; a margin before it fails locally. */
  private wakeBounds(cl: Claims, now: number): { half: number; beforeFail: number } {
    let half = 0;
    let beforeFail = 0;
    const bound = (b: number, d: number) => (d > 0 && (b === 0 || d < b) ? d : b);
    let fail: number | undefined;
    if (cl.maxOfflineSeconds !== undefined) {
      const off = cl.issuedAt.getTime() + cl.maxOfflineSeconds * 1000;
      half = bound(half, (off - now) / 2);
      fail = off;
    }
    if (cl.expires) {
      half = bound(half, (cl.expires.getTime() - now) / 2);
      const e = cl.expires.getTime() + cl.graceSeconds * 1000;
      if (fail === undefined || e < fail) fail = e;
    }
    if (fail !== undefined) {
      try {
        const left = fail - this.currentOptions().now.getTime();
        beforeFail = bound(beforeFail, left - Math.min(left / 10, FAIL_MARGIN_MS));
      } catch {
        // a clock rollback: no bound from it
      }
    }
    return { half, beforeFail };
  }

  /**
   * Refreshes the lease until signal aborts: from refresh_after on, at once
   * on the first pass if the cached lease doesn't pass current, never sooner
   * than MIN_REFRESH_INTERVAL_MS after a success, with jitter; failures back
   * off exponentially, not sooner than Retry-After. Every failure and warning
   * goes to onError. Rejects with what the app must act on: no_lease;
   * not_activated (activate again) and license_revoked, after forgetting the
   * lease when the API said so; unauthenticated, binding_mismatch,
   * offline_seat (the lease is kept until it ends); or the abort.
   */
  async run(signal: AbortSignal, onError?: (e: Error) => void): Promise<never> {
    const report = (e: Error) => onError?.(e);
    let failures = 0;
    let retryMs = 0;
    let refreshed = false;
    for (;;) {
      for (const w of this.takeWarnings()) report(w);
      const claims = this.claims;
      if (!claims) throw new OnlineError("no_lease", "no lease to keep fresh");
      const now = this.now() + this.offsetMs; // refresh_after and exp are server times
      let invalid = false;
      try {
        this.current();
      } catch {
        invalid = true;
      }
      let wait: number;
      if (failures > 0) wait = Math.max(this.backoff(failures), retryMs);
      else if (invalid && !refreshed) wait = 0; // a fresh lease may fix it; once refreshed, it can't
      else if (claims.refreshAfter) wait = claims.refreshAfter.getTime() - now;
      else if (claims.expires) wait = Math.min(BACKOFF_MAX_MS, (claims.expires.getTime() - now) / 2);
      else wait = BACKOFF_MAX_MS;
      let half = 0;
      let beforeFail = 0;
      if (failures === 0 && !invalid) ({ half, beforeFail } = this.wakeBounds(claims, now));
      if (half > 0) wait = Math.min(wait, half);
      wait = Math.max(wait, 0);
      wait += this.rand(Math.floor(wait / 10) + 1); // spread fleets out
      if (beforeFail > 0 && wait > beforeFail) wait = beforeFail - this.rand(Math.floor(beforeFail / 10) + 1);
      if (refreshed && failures === 0) wait = Math.max(wait, MIN_REFRESH_INTERVAL_MS);
      await this.sleep(wait, signal);
      let ver = 0;
      try {
        ver = this.ver;
        await this.leaseCall("refresh", "", 1, signal); // one attempt: this loop retries
        failures = 0;
        retryMs = 0;
        refreshed = true;
        continue;
      } catch (e) {
        if (signal.aborted) throw signal.reason;
        if (!(e instanceof Error)) throw e;
        report(e);
        const oe = e instanceof OnlineError ? e : undefined;
        if (oe && ((oe.status === 403 && oe.code === "license_revoked") || (oe.status === 404 && oe.code === "not_activated"))) {
          try {
            await this.forgetIf(ver);
          } catch (fe) {
            report(fe as Error);
          }
          throw e;
        }
        if (oe && ["license_revoked", "not_activated", "unauthenticated", "binding_mismatch", "offline_seat"].includes(oe.code)) throw e;
        failures++;
        retryMs = oe?.retryAfterMs ?? 0;
      }
    }
  }

  /** The wait after n consecutive failures: exponential, jitter in the upper half, until BACKOFF_MAX_MS (never shortened). */
  private backoff(n: number): number {
    const d = BACKOFF_BASE_MS * 2 ** Math.min(n - 1, 20);
    if (d >= BACKOFF_MAX_MS) return BACKOFF_MAX_MS;
    return d / 2 + this.rand(d / 2 + 1);
  }

  /** POSTs body to op; retries network errors, 429, 5xx and idempotency_in_progress up to attempts, honouring Retry-After. */
  private async call(op: string, body: object, idemKey: string, want: number, attempts: number, signal?: AbortSignal): Promise<string> {
    const u = new URL(this.base.href);
    u.pathname = `${u.pathname.replace(/\/$/, "")}/api/v1/activation/tenants/${encodeURIComponent(this.cfg.tenantId)}/${op}`;
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.once(u.href, JSON.stringify(body), idemKey, want, signal);
      } catch (e) {
        const retryable = !(e instanceof OnlineError) || e.code === "network" || e.status === 429 || e.status >= 500 || e.code === "idempotency_in_progress";
        if (!retryable || attempt >= attempts || signal?.aborted) throw e;
        const ra = e instanceof OnlineError ? e.retryAfterMs : 0;
        await this.sleep(ra > 0 ? ra : this.backoff(attempt), signal);
      }
    }
  }

  private async once(url: string, body: string, idemKey: string, want: number, signal?: AbortSignal): Promise<string> {
    const headers: Record<string, string> = {
      Authorization: `License ${this.cfg.licenseKey}`,
      "Content-Type": "application/json",
      "User-Agent": `licenseforge-sdk-${SDK_VERSION}`,
    };
    if (idemKey) headers["Idempotency-Key"] = idemKey;
    const timeout = AbortSignal.timeout(this.cfg.timeoutMs);
    let res: { status: number; headers: IncomingHttpHeaders };
    let raw: string;
    try {
      ({ res, raw } = await post(new URL(url), headers, body, this.cfg.ca, signal ? AbortSignal.any([signal, timeout]) : timeout));
    } catch (e) {
      if (signal?.aborted) throw signal.reason;
      throw new OnlineError("network", String(e));
    }
    if (res.status === want) return raw;
    const retryAfterMs = parseRetryAfter(header(res.headers["retry-after"]), this.now());
    // The stable codes count only in a problem answer with a 4xx status: a
    // proxy's error page or a garbled 5xx must not read as "revoked".
    const type = (header(res.headers["content-type"]) ?? "").split(";")[0]!.trim().toLowerCase();
    if (type === "application/problem+json" && res.status >= 400 && res.status < 500) {
      try {
        const p = JSON.parse(raw);
        if (typeof p?.code === "string" && API_CODES.has(p.code)) {
          throw new OnlineError(p.code as OnlineErrorCode, String(p.detail ?? ""), res.status, String(p.request_id ?? ""), retryAfterMs);
        }
      } catch (e) {
        if (e instanceof OnlineError) throw e;
      }
    }
    if (res.status >= 500) {
      // Never a refusal (above), but its code and detail (e.g. no_signing_key) are worth reporting.
      let detail = `status ${res.status}`;
      let requestId = "";
      if (type === "application/problem+json") {
        try {
          const p = JSON.parse(raw);
          if (typeof p?.code === "string") detail += `: ${p.code}${typeof p.detail === "string" && p.detail ? `: ${p.detail}` : ""}`;
          if (typeof p?.request_id === "string") requestId = p.request_id;
        } catch {
          // not a problem answer after all
        }
      }
      throw new OnlineError("server_error", detail, res.status, requestId, retryAfterMs);
    }
    if (res.status === 429) throw new OnlineError("rate_limited", "status 429", res.status, "", retryAfterMs);
    throw new OnlineError("unexpected_status", `status ${res.status}`, res.status, "", retryAfterMs);
  }
}

/** Every PEM block in ca must be a certificate that parses: Node's TLS would otherwise trust nothing, silently, and every call fail. */
function checkPEM(ca: string | Buffer): void {
  const blocks = String(ca).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  try {
    if (blocks.length === 0) throw new Error("no certificate");
    // Certificates only, as Java's CertificateFactory: a key in a "CA" file is a mistake to report, not to ship.
    for (const [, label] of String(ca).matchAll(/-----BEGIN ([^-]*)-----/g)) if (label !== "CERTIFICATE") throw new Error(`a ${label} block`);
    for (const b of blocks) new X509Certificate(b);
  } catch (e) {
    throw new TypeError(`licenseforge online: ca must be PEM certificates (${String(e)})`);
  }
}

const header = (v: string | string[] | undefined): string | null => (Array.isArray(v) ? v[0] : v) ?? null;

/**
 * One POST, the answer capped at 1 MiB. node:http(s) rather than fetch, so a
 * private CA can be given per client; it never follows redirects (the
 * license key is in a header). signal covers the whole exchange.
 */
function post(url: URL, headers: Record<string, string>, body: string, ca: string | Buffer | undefined, signal: AbortSignal): Promise<{ res: { status: number; headers: IncomingHttpHeaders }; raw: string }> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(body, "utf8");
    const opts = { method: "POST", headers: { ...headers, "Content-Length": String(payload.length) }, signal };
    const req = url.protocol === "https:" ? httpsRequest(url, { ...opts, ca, minVersion: "TLSv1.2" }) : httpRequest(url, opts);
    req.on("response", (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > MAX_ANSWER) req.destroy(new Error("answer over 1 MiB"));
        else chunks.push(c);
      });
      res.on("error", reject); // cut off mid-answer too
      res.on("end", () => resolve({ res: { status: res.statusCode ?? 0, headers: res.headers }, raw: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end(payload);
  });
}

/** Retry-After as delay-seconds or an HTTP date, capped at 10 minutes. */
export function parseRetryAfter(h: string | null, nowMs: number): number {
  if (!h) return 0;
  let d = 0;
  if (/^\d+$/.test(h.trim())) d = Number(h.trim()) * 1000;
  else {
    const t = Date.parse(h);
    if (!Number.isNaN(t)) d = t - nowMs;
  }
  return Math.max(0, Math.min(d, MAX_RETRY_AFTER_MS));
}

function sleepMs(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(signal.reason);
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, Math.min(ms, 2 ** 31 - 1));
    const onAbort = () => {
      clearTimeout(t);
      reject(signal!.reason);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

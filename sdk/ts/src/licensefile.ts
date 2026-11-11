// lf1 license files: envelope, signature, claims and claim checks, in the
// order spec/license-format.md defines, so every SDK reports the same class.
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { JSONError, parseObject, type Value } from "./json.js";

/** The error classes shared by all SDKs and the conformance vectors. */
export type ErrorCode =
  | "malformed"
  | "unknown_key"
  | "unsupported_alg"
  | "bad_signature"
  | "invalid_key_set"
  | "unsupported_version"
  | "wrong_product"
  | "binding_mismatch"
  | "clock_skew"
  | "not_yet_valid"
  | "offline_exceeded"
  | "expired"
  | "updates_expired";

/** A license that can't be used, with its spec class in `code`. */
export class LicenseError extends Error {
  constructor(readonly code: ErrorCode, detail?: string) {
    super(detail ? `licenseforge: ${code}: ${detail}` : `licenseforge: ${code}`);
    this.name = "LicenseError";
  }
}

/** A trusted verification key. `alg` binds the algorithm to the key, never the file. */
export interface PublicKey {
  kid: string;
  alg: string;
  key: Uint8Array;
}

export const MAX_SIZE = 64 * 1024;
const BEGIN = "-----BEGIN LICENSEFORGE LICENSE-----";
const END = "-----END LICENSEFORGE LICENSE-----";
const kidRE = /^[A-Za-z0-9_:-]{1,128}$/;
const fail = (code: ErrorCode, detail?: string): never => {
  throw new LicenseError(code, detail);
};

/** Decodes canonical base64url (RFC 4648 §5, no padding, no stray bits), or null. */
export function b64url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const b = Buffer.from(s, "base64url");
  return b.toString("base64url") === s ? new Uint8Array(b) : null;
}

/** Removes the BOM, armor and whitespace (SP, HT, CR, LF only), returning the bare token. */
function unarmor(input: string): string {
  let s = input.startsWith("\uFEFF") ? input.slice(1) : input;
  // Loops, not /\s+$/: a trailing-anchored regex backtracks quadratically on
  // a long interior run of whitespace (unsigned input, up to 64 KiB).
  const ws = (c: string | undefined) => c === " " || c === "\t" || c === "\r" || c === "\n";
  let a = 0;
  let z = s.length;
  while (a < z && ws(s[a])) a++;
  while (z > a && ws(s[z - 1])) z--;
  s = s.slice(a, z);
  if (s.startsWith(BEGIN)) {
    if (!s.endsWith(END) || s.length < BEGIN.length + END.length) fail("malformed", "missing end armor");
    s = s.slice(BEGIN.length, s.length - END.length);
  }
  s = s.replace(/[ \t\r\n]/g, "");
  if (s === "") fail("malformed");
  return s;
}

/**
 * The spec's envelope checks up to the key lookup (size, BOM, armor,
 * whitespace, four parts, version, kid, canonical base64url): the token's
 * parts, its signature bytes and its payload bytes.
 */
export function envelope(license: string): { token: string; kid: string; body: string; sig: Uint8Array; payload: Uint8Array } {
  if (Buffer.byteLength(license, "utf8") > MAX_SIZE) fail("malformed", "too large");
  const token = unarmor(license);
  const parts = token.split(".");
  const [ver, kid = "", body = "", sigText = ""] = parts;
  if (parts.length !== 4 || ver !== "lf1" || !kidRE.test(kid) || body === "") fail("malformed");
  const sig = b64url(sigText);
  if (!sig) return fail("malformed", "signature encoding");
  const payload = b64url(body);
  if (!payload) return fail("malformed", "payload encoding");
  return { token, kid, body, sig, payload };
}

/**
 * Checks a license's envelope and signature against the trusted keys and
 * returns the verified payload bytes and the key ID. It doesn't look at the
 * claims: use `open` for that.
 */
export function verify(license: string, keys: readonly PublicKey[]): { payload: Uint8Array; kid: string } {
  const { kid, body, sig, payload } = envelope(license);
  const found = keys.filter((k) => k.kid === kid);
  if (found.length === 0) fail("unknown_key");
  if (found.length > 1) fail("invalid_key_set", `duplicate kid ${JSON.stringify(kid)}`);
  const key = found[0]!;
  if (key.alg !== "ed25519") fail("unsupported_alg");
  if (key.key.length !== 32) fail("invalid_key_set", `ed25519 key for ${JSON.stringify(kid)} has length ${key.key.length}`);
  if (weakEd25519(key.key)) fail("invalid_key_set", `ed25519 key for ${JSON.stringify(kid)} is not a canonical, full-order point`);
  if (sig.length !== 64) fail("malformed", "signature length");
  // A weak R (spec): with R = identity and S = k·a, Go's cofactorless check accepts and OpenSSL refuses.
  if (weakEd25519(sig.subarray(0, 32))) fail("bad_signature");
  const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key.key).toString("base64url") }, format: "jwk" });
  // OpenSSL's Ed25519 refuses a non-canonical S (S ≥ L), as the spec requires.
  if (!cryptoVerify(null, Buffer.from(`lf1.${kid}.${body}`, "ascii"), pub, sig)) fail("bad_signature");
  return { payload, kid };
}

// The eight small-order points' canonical encodings (spec: weak keys). Go's
// cofactorless verification accepts a chosen signature for any message under
// them; every SDK refuses the key so they all answer the same.
const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]);

/** A 32-byte key the spec refuses: a small-order point, or a non-canonical encoding. */
export function weakEd25519(key: Uint8Array): boolean {
  if (SMALL_ORDER.has(Buffer.from(key).toString("hex"))) return true;
  // y (little-endian, top bit cleared) ≥ p = 2^255 − 19 (ed ff … ff 7f).
  const mid = key.subarray(1, 31);
  const top = key[31]! & 0x7f;
  const high = top === 0x7f && mid.every((b) => b === 0xff);
  if (high && key[0]! >= 0xed) return true;
  // Negative zero: the sign bit with x = 0 (y = 1 or y = p − 1).
  if (key[31]! & 0x80) {
    if (key[0] === 1 && top === 0 && mid.every((b) => b === 0)) return true;
    if (key[0] === 0xec && high) return true;
  }
  return false;
}

export type BindingType = "none" | "machine" | "cluster";

/** -1: the limit value meaning "no limit". */
export const UNLIMITED = -1;

/** The features and limits a license grants (ADR-0015). Unknown keys are never an error. */
export class Entitlements {
  constructor(readonly features: readonly string[] = [], readonly limits: ReadonlyMap<string, number> = new Map()) {}
  /** Whether the license grants the boolean feature `key` (exact, case-sensitive; never looks at limits). */
  hasFeature(key: string): boolean {
    return this.features.includes(key);
  }
  /** The limit for `key`: UNLIMITED (-1), a non-negative value, or 0 when the license doesn't set it. */
  limit(key: string): number {
    return this.limits.get(key) ?? 0;
  }
  /** Whether a resulting total of `n` (after the action, e.g. users + 1) is within the limit `key`. */
  allows(key: string, n: number): boolean {
    if (!Number.isSafeInteger(n) || n < 0) return false;
    const l = this.limit(key);
    return l === UNLIMITED || n <= l;
  }
}

/** A verified lf1 payload. Optional fields are undefined when absent. */
export interface Claims {
  licenseId: string;
  tenant: string;
  product: string;
  plan: string;
  customerId: string;
  customerName: string;
  issuedAt: Date;
  notBefore?: Date;
  expires?: Date; // undefined = perpetual
  refreshAfter?: Date;
  updatesUntil?: Date;
  graceSeconds: number; // absent = 0
  maxOfflineSeconds?: number; // undefined = not limited; 0 is a real limit
  binding: { type: BindingType; fingerprint: string };
  entitlements: Entitlements;
}

const intRE = /^-?(0|[1-9][0-9]*)$/;
const timeRE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;
const durationRE = /^P(?:([0-9]{1,6})D)?(?:T(?:([0-9]{1,6})H)?(?:([0-9]{1,6})M)?(?:([0-9]{1,6})S)?)?$/;
const MAX_DURATION_SECONDS = 36500 * 86400;

type Obj = Map<string, Value>;

function str(m: Obj, key: string): string | undefined {
  const v = m.get(key);
  if (v === undefined) return undefined;
  if (v.kind !== "string") fail("malformed", `${key} must be a string`);
  return (v as { value: string }).value;
}

function obj(m: Obj, key: string): Obj | undefined {
  const v = m.get(key);
  if (v === undefined) return undefined;
  if (v.kind !== "object") fail("malformed", `${key} must be an object`);
  return (v as { entries: Obj }).entries;
}

function int(v: Value, key: string): string {
  if (v.kind !== "number" || !intRE.test(v.token)) fail("malformed", `${key} must be an integer`);
  return (v as { token: string }).token;
}

/** Parses exactly YYYY-MM-DDTHH:MM:SSZ, a real date, year 1970–9999. */
export function parseTime(s: string): Date {
  const m = timeRE.exec(s);
  if (!m) return fail("malformed", `timestamp ${JSON.stringify(s)}`);
  const [y, mo, d, h, mi, se] = m.slice(1).map(Number) as [number, number, number, number, number, number];
  const t = new Date(Date.UTC(y, mo - 1, d, h, mi, se)); // an impossible day rolls into another month
  if (y < 1970 || t.getUTCFullYear() !== y || t.getUTCMonth() !== mo - 1 || h > 23 || mi > 59 || se > 59) {
    fail("malformed", `timestamp ${JSON.stringify(s)}`);
  }
  return t;
}

/** Parses P[nD][T[nH][nM][nS]] into seconds, at most 36,500 days. */
export function parseDuration(s: string): number {
  const m = durationRE.exec(s);
  if (!m || s === "P" || s.endsWith("T")) return fail("malformed", `duration ${JSON.stringify(s)}`);
  const secs = [86400, 3600, 60, 1].reduce((sum, unit, i) => sum + (m[i + 1] ? Number(m[i + 1]) * unit : 0), 0);
  if (secs > MAX_DURATION_SECONDS) fail("malformed", `duration ${JSON.stringify(s)} exceeds 36500 days`);
  return secs;
}

const optTime = (m: Obj, key: string) => {
  const s = str(m, key);
  return s === undefined ? undefined : parseTime(s);
};

/** Decodes a verified payload under the spec's strict encoding rules. */
export function parseClaims(payload: Uint8Array): Claims {
  let m: Obj;
  try {
    // fatal: invalid UTF-8 is malformed; ignoreBOM: a BOM stays and is refused by the parser.
    m = parseObject(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(payload));
  } catch (e) {
    if (e instanceof JSONError || e instanceof TypeError) return fail("malformed", e.message);
    throw e;
  }
  // Version first: a future version may change any other field.
  const v = m.get("v");
  if (v === undefined) fail("malformed", "missing v");
  if (int(v!, "v") !== "1") fail("unsupported_version");

  const lid = str(m, "lid");
  const product = str(m, "product");
  if (!lid) fail("malformed", "missing or empty lid");
  if (!product) fail("malformed", "missing or empty product");
  const tenant = str(m, "tenant") ?? "";
  const plan = str(m, "plan") ?? "";
  const cust = obj(m, "customer");
  const customerId = (cust && str(cust, "id")) ?? "";
  const customerName = (cust && str(cust, "name")) ?? "";
  const issuedAt = optTime(m, "iat");
  if (!issuedAt) return fail("malformed", "missing iat");
  const c: Claims = {
    licenseId: lid!,
    tenant,
    product: product!,
    plan,
    customerId,
    customerName,
    issuedAt,
    graceSeconds: 0,
    binding: { type: "none", fingerprint: "" },
    entitlements: new Entitlements(),
  };
  for (const [key, field] of [["nbf", "notBefore"], ["exp", "expires"], ["refresh_after", "refreshAfter"], ["updates_until", "updatesUntil"]] as const) {
    const t = optTime(m, key);
    if (t) c[field] = t;
  }
  const grace = str(m, "grace");
  if (grace !== undefined) c.graceSeconds = parseDuration(grace);
  const maxOffline = str(m, "max_offline");
  if (maxOffline !== undefined) c.maxOfflineSeconds = parseDuration(maxOffline);
  if ((tenant + product).includes("\0")) fail("malformed", "tenant and product must not contain NUL");

  const bind = obj(m, "bind");
  if (bind) {
    const type = str(bind, "type") ?? "none";
    const fp = str(bind, "fp");
    if (type === "none") {
      if (fp !== undefined) fail("malformed", "bind type none must not have fp");
    } else if (type === "machine" || type === "cluster") {
      if (!fp) fail("malformed", `${type} binding without fp`);
    } else {
      fail("malformed", `unknown binding type ${JSON.stringify(type)}`);
    }
    c.binding = { type: type as BindingType, fingerprint: fp ?? "" };
  }
  // A bound license's fingerprint is derived from tenant and product.
  if (c.binding.type !== "none" && tenant === "") fail("malformed", `${c.binding.type} binding without tenant`);

  const ent = obj(m, "entitlements");
  if (ent) {
    const features: string[] = [];
    const f = ent.get("features");
    if (f !== undefined) {
      if (f.kind !== "array") fail("malformed", "features must be an array");
      for (const it of (f as { items: Value[] }).items) {
        if (it.kind !== "string") fail("malformed", "features[] must be a string");
        features.push((it as { value: string }).value);
      }
    }
    const limits = new Map<string, number>();
    for (const [k, raw] of obj(ent, "limits") ?? []) {
      const tok = int(raw, `limits.${k}`);
      const n = Number(tok);
      if (!Number.isSafeInteger(n) || n < -1) fail("malformed", `limit ${JSON.stringify(k)} out of range`);
      limits.set(k, n === 0 ? 0 : n); // -0 is 0
    }
    c.entitlements = new Entitlements(features, limits);
  }
  return c;
}

/** The local facts a license is checked against. */
export interface CheckOptions {
  now: Date;
  product: string;
  /** The local machine or cluster fingerprint. */
  fingerprint?: string;
  /** The app's build date; when unset, updates_until isn't checked. */
  buildDate?: Date;
  /** How far in the future iat may be, in seconds: absent = 24 h (ADR-0018), 0 = strict. */
  clockToleranceSeconds?: number;
}

/** "grace": past exp but within grace, usable: warn the user. New values may be added. */
export type Status = "valid" | "grace";

export const DEFAULT_CLOCK_TOLERANCE_SECONDS = 24 * 3600;

/** Applies the spec's claim checks in order: a usable license's status, or a LicenseError. */
export function check(c: Claims, o: CheckOptions): Status {
  const validDate = (d: unknown) => d instanceof Date && !Number.isNaN(d.getTime());
  if (!validDate(o.now)) throw new TypeError("licenseforge: now must be a valid Date");
  // An invalid build date would compare false and skip updates_until: fail closed.
  if (o.buildDate !== undefined && !validDate(o.buildDate)) throw new TypeError("licenseforge: buildDate must be a valid Date");
  const tol = o.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS;
  if (!Number.isFinite(tol) || tol < 0) throw new RangeError("licenseforge: clockToleranceSeconds must be ≥ 0");
  const now = o.now.getTime();
  const at = (d: Date, plusSeconds = 0) => d.getTime() + plusSeconds * 1000;
  if (c.product !== o.product) fail("wrong_product");
  if (c.binding.type !== "none" && (c.binding.fingerprint === "" || c.binding.fingerprint !== o.fingerprint)) fail("binding_mismatch");
  if (at(c.issuedAt) > now + tol * 1000) fail("clock_skew");
  if (c.notBefore && now < at(c.notBefore)) fail("not_yet_valid");
  if (c.maxOfflineSeconds !== undefined && now > at(c.issuedAt, c.maxOfflineSeconds)) fail("offline_exceeded");
  if (c.expires && now > at(c.expires, c.graceSeconds)) fail("expired");
  if (c.updatesUntil && o.buildDate && o.buildDate.getTime() > at(c.updatesUntil)) fail("updates_expired");
  return c.expires && now > at(c.expires) ? "grace" : "valid";
}

/**
 * Verifies a license, parses its claims and checks them: the usual entry
 * point. Throws a LicenseError when the license can't be used; its claims
 * come back only when everything passed.
 */
export function open(license: string, keys: readonly PublicKey[], o: CheckOptions): { claims: Claims; status: Status } {
  const claims = parseClaims(verify(license, keys).payload);
  return { claims, status: check(claims, o) };
}

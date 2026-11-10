// Offline activation artifacts (ADR-0043, spec "Offline activation"): the
// activation request an air-gapped machine writes (lfreq1) and the
// deactivation receipt it writes when it returns its seat (lfrcpt1). Both are
// unsigned and carried by hand; the server checks them against what it
// issued. The lf1 claim strictness, plus: no unknown fields.
import { createHash } from "node:crypto";
import { JSONError, parseObject, type Value } from "./json.js";
import { b64url, envelope, LicenseError, parseTime } from "./licensefile.js";

export const MAX_OFFLINE_SIZE = 4096;

/** Asks the vendor's LicenseForge for an offline license file for this machine. As sensitive as its key. */
export interface ActivationRequest {
  tenant: string;
  product: string;
  key: string;
  binding: { type: "machine" | "cluster"; fingerprint: string };
  fpSource: "machine-id" | "kubernetes" | "env" | "override";
  nonce: Uint8Array; // 16 random bytes
  created: Date;
  hostname?: string;
  appVersion?: string;
  sdkVersion?: string;
}

/** Returns an offline seat: the file with fileSHA256 was deleted on the machine with fingerprint. */
export interface DeactivationReceipt {
  tenant: string;
  licenseId: string;
  fingerprint: string;
  fileSHA256: string;
  nonce: Uint8Array;
  created: Date;
}

const fpRE = /^sha256:[0-9a-f]{64}$/;
const hexRE = /^[0-9a-f]{64}$/;
const hostnameRE = /^[A-Za-z0-9._-]{1,253}$/;
const versionRE = /^[ -~]{1,64}$/;
const sources = ["machine-id", "kubernetes", "env", "override"] as const;

const malformed = (detail: string): never => {
  throw new LicenseError("malformed", detail);
};

/** Removes one leading BOM and every SP, HT, CR and LF. */
const stripSpace = (s: string) => (s.startsWith("\uFEFF") ? s.slice(1) : s).replace(/[ \t\r\n]/g, "");

type Obj = Map<string, Value>;

function decode(version: string, input: string, known: readonly string[]): Obj {
  if (Buffer.byteLength(input, "utf8") > MAX_OFFLINE_SIZE) malformed(`larger than ${MAX_OFFLINE_SIZE} bytes`);
  const token = stripSpace(input); // no armor: an armored token fails the prefix
  if (!token.startsWith(version + ".")) malformed(`not an ${version} token`);
  const payload = b64url(token.slice(version.length + 1));
  if (!payload) return malformed("payload encoding");
  let m: Obj;
  try {
    m = parseObject(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(payload));
  } catch (e) {
    if (e instanceof JSONError || e instanceof TypeError) return malformed(e.message);
    throw e;
  }
  const v = m.get("v");
  if (v === undefined) malformed("missing v");
  if (v!.kind !== "number" || !/^-?(0|[1-9][0-9]*)$/.test(v!.token)) malformed("v must be an integer");
  if ((v as { token: string }).token !== "1") throw new LicenseError("unsupported_version", `${version} v ${(v as { token: string }).token}`);
  for (const k of m.keys()) if (!known.includes(k)) malformed(`unknown field ${JSON.stringify(k)}`);
  return m;
}

function str(m: Obj, key: string): string | undefined {
  const v = m.get(key);
  if (v === undefined) return undefined;
  return v.kind === "string" ? v.value : malformed(`${key} must be a string`);
}

function req(m: Obj, key: string): string {
  const s = str(m, key);
  return s ? s : malformed(`missing or empty ${key}`);
}

/** A required, non-empty string of at most max UTF-8 bytes, without NUL. */
function name(m: Obj, key: string, max: number): string {
  const s = req(m, key);
  if (Buffer.byteLength(s, "utf8") > max || s.includes("\0")) malformed(`${key} must be at most ${max} bytes without NUL`);
  return s;
}

function nonceAndCreated(m: Obj): { nonce: Uint8Array; created: Date } {
  const n = req(m, "nonce");
  const nonce = b64url(n);
  // Canonical base64url of 16 bytes is always 22 characters (no CR or LF here).
  if (!nonce || nonce.length !== 16) malformed("nonce must be 16 bytes, base64url");
  return { nonce: nonce!, created: parseTime(req(m, "created")) };
}

/** Reads an lfreq1 token; LicenseError malformed or unsupported_version. */
export function parseRequest(input: string): ActivationRequest {
  const m = decode("lfreq1", input, ["v", "tenant", "product", "key", "bind", "fp_source", "nonce", "created", "hostname", "app_version", "sdk_version"]);
  const tenant = name(m, "tenant", 256);
  const product = name(m, "product", 256);
  const key = req(m, "key");
  if (key.length > 128 || !/^[!-~]+$/.test(key)) malformed("key must be up to 128 printable ASCII characters");
  // An offline request always binds (a site license needs none): exactly type and fp.
  const bind = m.get("bind");
  if (bind === undefined || bind.kind !== "object") return malformed("bind must be an object");
  const type = str(bind.entries, "type");
  const fp = str(bind.entries, "fp");
  if (type !== "machine" && type !== "cluster") malformed("bind type must be machine or cluster");
  if (!fp || !fpRE.test(fp)) malformed("fp must be sha256: and 64 lowercase hex digits");
  if (bind.entries.size !== 2) malformed("bind has unknown fields");
  const fpSource = req(m, "fp_source");
  if (!(sources as readonly string[]).includes(fpSource)) malformed("fp_source must be machine-id, kubernetes, env or override");
  if ((fpSource === "kubernetes") !== (type === "cluster")) malformed("a cluster binding comes from kubernetes, and only it");
  const r: ActivationRequest = {
    tenant,
    product,
    key,
    binding: { type: type as "machine" | "cluster", fingerprint: fp! },
    fpSource: fpSource as ActivationRequest["fpSource"],
    ...nonceAndCreated(m),
  };
  for (const [k, field, re] of [["hostname", "hostname", hostnameRE], ["app_version", "appVersion", versionRE], ["sdk_version", "sdkVersion", versionRE]] as const) {
    const v = str(m, k);
    if (v === undefined) continue;
    if (!re.test(v)) malformed(`${k} ${JSON.stringify(v)}`);
    r[field] = v;
  }
  return r;
}

/** Reads an lfrcpt1 token, with parseRequest's error classes. */
export function parseReceipt(input: string): DeactivationReceipt {
  const m = decode("lfrcpt1", input, ["v", "tenant", "license_id", "fp", "file_sha256", "nonce", "created"]);
  const tenant = name(m, "tenant", 256);
  const licenseId = name(m, "license_id", 128);
  const fingerprint = req(m, "fp");
  if (!fpRE.test(fingerprint)) malformed("fp must be sha256: and 64 lowercase hex digits");
  const fileSHA256 = req(m, "file_sha256");
  if (!hexRE.test(fileSHA256)) malformed("file_sha256 must be 64 lowercase hex digits");
  return { tenant, licenseId, fingerprint, fileSHA256, ...nonceAndCreated(m) };
}

/** YYYY-MM-DDTHH:MM:SSZ, whole seconds. */
const timestamp = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

/** JSON with the keys sorted, as Go's encoder writes it; then checked by the parser. */
function encode(version: string, fields: Record<string, unknown>, check: (s: string) => unknown): string {
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v === "string" && !v.isWellFormed()) malformed(`${k} is not valid Unicode`);
  }
  const sorted = Object.fromEntries(Object.entries(fields).sort(([a], [b]) => (a < b ? -1 : 1)));
  const s = `${version}.${Buffer.from(JSON.stringify(sorted), "utf8").toString("base64url")}`;
  check(s); // an SDK can't write what the server refuses
  return s;
}

/** An lfreq1 token for r. The key loses the spaces and line breaks pasted with it. */
export function encodeRequest(r: ActivationRequest): string {
  if (!(r.created instanceof Date) || Number.isNaN(r.created.getTime())) malformed("created must be a valid Date");
  const fields: Record<string, unknown> = {
    v: 1,
    tenant: r.tenant,
    product: r.product,
    key: stripSpace(r.key),
    bind: { fp: r.binding.fingerprint, type: r.binding.type },
    fp_source: r.fpSource,
    nonce: Buffer.from(r.nonce).toString("base64url"),
    created: timestamp(r.created),
  };
  if (r.hostname) fields.hostname = r.hostname;
  if (r.appVersion) fields.app_version = r.appVersion;
  if (r.sdkVersion) fields.sdk_version = r.sdkVersion;
  return encode("lfreq1", fields, parseRequest);
}

/** An lfrcpt1 token for r. */
export function encodeReceipt(r: DeactivationReceipt): string {
  if (!(r.created instanceof Date) || Number.isNaN(r.created.getTime())) malformed("created must be a valid Date");
  return encode(
    "lfrcpt1",
    { v: 1, tenant: r.tenant, license_id: r.licenseId, fp: r.fingerprint, file_sha256: r.fileSHA256, nonce: Buffer.from(r.nonce).toString("base64url"), created: timestamp(r.created) },
    parseReceipt,
  );
}

/**
 * A license file's file_sha256 for a receipt: SHA-256 of its token as verify
 * reads it (armor, BOM and whitespace removed), lowercase hex. A file that
 * fails the envelope checks has none (LicenseError malformed).
 */
export function fileSHA256(file: string): string {
  return createHash("sha256").update(envelope(file).token, "ascii").digest("hex");
}

/** A request's or receipt's identity: SHA-256 of the token with the BOM and whitespace removed, lowercase hex. */
export function offlineSHA256(input: string): string {
  return createHash("sha256").update(stripSpace(input), "utf8").digest("hex");
}

// The default machine or cluster fingerprint a license is bound to
// (ADR-0017, spec/license-format.md "Fingerprints"). Sources, first match
// wins: the vendor's override, LICENSEFORGE_FINGERPRINT if the vendor allows
// it, Kubernetes (the kube-system namespace UID), the OS machine ID.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { request } from "node:https";
import type { Claims } from "./licensefile.js";

/** Where a fingerprint came from; recorded with activations. */
export type FingerprintSource = "override" | "env" | "kubernetes" | "machine-id";

export interface Fingerprint {
  fingerprint: string; // "sha256:<hex>"
  source: FingerprintSource;
  binding: "machine" | "cluster";
}

/**
 * Why there's no fingerprint. "no_fingerprint": no stable, unique ID here
 * (mount the host /etc/machine-id, or have the vendor enable an override);
 * "transient": a source was temporarily unavailable (retry later);
 * "invalid": bad tenant, product or override input; "failed": a source
 * answered with a permanent error (RBAC, certificate, override threw).
 */
export class FingerprintError extends Error {
  constructor(readonly code: "no_fingerprint" | "transient" | "invalid" | "failed", detail: string) {
    super(`licenseforge fingerprint: ${detail}`);
    this.name = "FingerprintError";
  }
}

/** Set by the vendor embedding the SDK, not by end users. */
export interface FingerprintOptions {
  /** A raw ID chosen by the vendor (hardware serial, cloud instance ID…); wins over every source. */
  override?: () => string | Promise<string>;
  /** Let end users set LICENSEFORGE_FINGERPRINT. Off by default: anyone who can set it can share one binding. */
  allowEnvOverride?: boolean;
}

export const ENV_OVERRIDE = "LICENSEFORGE_FINGERPRINT";

/**
 * "sha256:" + hex(SHA-256 of the UTF-8 bytes of "lf-fp-v1", tenant, product
 * and raw ID joined by 0x00). All non-empty and well-formed; no NUL in
 * tenant or product.
 */
export function hash(tenant: string, product: string, rawID: string): string {
  if (rawID === "") throw new FingerprintError("invalid", "empty raw ID");
  if (tenant === "" || product === "" || (tenant + product).includes("\0")) {
    throw new FingerprintError("invalid", "tenant and product IDs must be non-empty and contain no NUL");
  }
  if (![tenant, product, rawID].every((s) => s.isWellFormed())) throw new FingerprintError("invalid", "IDs must be valid Unicode");
  return "sha256:" + createHash("sha256").update(`lf-fp-v1\0${tenant}\0${product}\0${rawID}`, "utf8").digest("hex");
}

/** Removes only SP, HT, CR and LF at both ends, as every SDK does. */
function trim(s: string): string {
  const ws = (c: string | undefined) => c === " " || c === "\t" || c === "\r" || c === "\n";
  let a = 0;
  let z = s.length;
  while (a < z && ws(s[a])) a++;
  while (z > a && ws(s[z - 1])) z--;
  return s.slice(a, z);
}

/** The sources compute reads, injectable for tests. */
export interface FingerprintEnv {
  getenv(name: string): string | undefined;
  kubernetes(): Promise<string>;
  machineID(): Promise<string>;
}

const defaultEnv: FingerprintEnv = {
  getenv: (n) => process.env[n],
  kubernetes: () => kubeSystemUID(),
  machineID: () => osMachineID(),
};

/**
 * The default fingerprint for a tenant's product on this machine. tenant and
 * product are the license's claims (the tenant ID such as "tnt_8f2c", not a
 * dashboard slug); forLicense takes them from a verified license.
 */
export async function compute(tenant: string, product: string, opts: FingerprintOptions = {}, env: FingerprintEnv = defaultEnv): Promise<Fingerprint> {
  hash(tenant, product, "-"); // validate the IDs before touching any source
  const result = (raw: string, source: FingerprintSource, binding: "machine" | "cluster" = "machine"): Fingerprint => ({
    fingerprint: hash(tenant, product, raw),
    source,
    binding,
  });
  if (opts.override) {
    let raw: string;
    try {
      raw = await opts.override();
    } catch (e) {
      throw new FingerprintError("failed", `override: ${String(e)}`);
    }
    if (typeof raw !== "string" || (raw = trim(raw)) === "") throw new FingerprintError("invalid", "override returned an empty ID");
    return result(raw, "override");
  }
  if (opts.allowEnvOverride) {
    const raw = trim(env.getenv(ENV_OVERRIDE) ?? "");
    // Node decodes invalid UTF-8 in the environment as U+FFFD: refused, as Go refuses invalid UTF-8.
    if (raw.includes("\uFFFD")) throw new FingerprintError("invalid", `${ENV_OVERRIDE} isn't valid UTF-8`);
    if (raw !== "") return result(raw, "env");
  }
  if (env.getenv("KUBERNETES_SERVICE_HOST")) return result(await env.kubernetes(), "kubernetes", "cluster");
  return result(await env.machineID(), "machine-id");
}

/** The fingerprint for a verified, bound license, with its tenant and product. */
export function forLicense(claims: Claims, opts: FingerprintOptions = {}): Promise<Fingerprint> {
  return compute(claims.tenant, claims.product, opts);
}

// --- Kubernetes ---

const SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount";

/** Reads the kube-system namespace UID with the pod's service account (RBAC: get namespaces/kube-system). */
async function kubeSystemUID(): Promise<string> {
  let token: string;
  let ca: Buffer;
  try {
    token = trim(readFileSync(`${SA_DIR}/token`, "utf8"));
    ca = readFileSync(`${SA_DIR}/ca.crt`);
  } catch (e) {
    throw new FingerprintError("failed", `kubernetes: no service account token or CA (is automountServiceAccountToken disabled?): ${String(e)}`);
  }
  const host = process.env.KUBERNETES_SERVICE_HOST!;
  const port = process.env.KUBERNETES_SERVICE_PORT || "443";
  if (!/^\d{1,5}$/.test(port) || Number(port) > 65535) throw new FingerprintError("failed", `kubernetes: KUBERNETES_SERVICE_PORT ${JSON.stringify(port)} isn't a port`);
  return namespaceUID({ host, port: Number(port), token, ca }, [500, 2000]);
}

/** Certificate problems are configuration errors: retrying won't help. */
const certErrors = new Set([
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
  "UNABLE_TO_DECRYPT_CERT_SIGNATURE",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "CERT_UNTRUSTED",
  "CERT_REJECTED",
  "CERT_REVOKED",
  "CERT_SIGNATURE_FAILURE",
  "CERT_CHAIN_TOO_LONG",
  "PATH_LENGTH_EXCEEDED",
  "INVALID_CA",
  "INVALID_PURPOSE",
  "ERROR_IN_CERT_NOT_BEFORE_FIELD",
  "ERROR_IN_CERT_NOT_AFTER_FIELD",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

/** The whole request, body included (a socket timeout alone resets on every byte). */
const REQUEST_MS = 5000;

/** Fetches the UID, retrying transient failures (network, timeout, 429, 5xx) after each backoff (ms). */
export async function namespaceUID(target: { host: string; port: number; token: string; ca: Buffer }, backoff: number[]): Promise<string> {
  for (let attempt = 0; ; attempt++) {
    const r = await getNamespaceUID(target);
    if (r.ok) return r.uid;
    if (r.permanent) throw new FingerprintError("failed", `kubernetes: ${r.detail}`);
    if (attempt >= backoff.length) throw new FingerprintError("transient", `kubernetes: ${r.detail}`);
    await new Promise((res) => setTimeout(res, backoff[attempt]));
  }
}

type Attempt = { ok: true; uid: string } | { ok: false; permanent: boolean; detail: string };

function getNamespaceUID(t: { host: string; port: number; token: string; ca: Buffer }): Promise<Attempt> {
  return new Promise((done) => {
    let settled = false;
    const resolve = (a: Attempt) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      done(a);
    };
    const deadline = setTimeout(() => {
      resolve({ ok: false, permanent: false, detail: `no answer within ${REQUEST_MS} ms` });
      req?.destroy();
    }, REQUEST_MS);
    let req: ReturnType<typeof request> | undefined;
    try {
      req = request(
      { host: t.host, port: t.port, path: "/api/v1/namespaces/kube-system", method: "GET", ca: t.ca, minVersion: "TLSv1.2", headers: { Authorization: `Bearer ${t.token}` } },
      (res) => {
        const status = res.statusCode ?? 0;
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size <= 1 << 20) return void chunks.push(c);
          resolve({ ok: false, permanent: true, detail: "answer over 1 MiB" }); // like a decode error: retrying won't help
          req?.destroy();
        });
        res.on("end", () => {
          if (status === 429 || status >= 500) return resolve({ ok: false, permanent: false, detail: `GET namespace kube-system: ${status}` });
          if (status !== 200) return resolve({ ok: false, permanent: true, detail: `GET namespace kube-system: ${status} (needs RBAC get on namespaces/kube-system)` });
          let uid: unknown;
          try {
            uid = JSON.parse(Buffer.concat(chunks).toString("utf8"))?.metadata?.uid;
          } catch (e) {
            return resolve({ ok: false, permanent: true, detail: `decode namespace: ${String(e)}` });
          }
          if (typeof uid !== "string" || uid === "") return resolve({ ok: false, permanent: true, detail: "kube-system namespace has no uid" });
          resolve({ ok: true, uid });
        });
        res.on("error", (e) => resolve({ ok: false, permanent: false, detail: String(e) }));
      },
    );
    } catch (e) {
      // e.g. a token with a line break: an invalid header, a configuration error
      return resolve({ ok: false, permanent: true, detail: String(e) });
    }
    req.on("error", (e: NodeJS.ErrnoException) => resolve({ ok: false, permanent: certErrors.has(e.code ?? ""), detail: String(e) }));
    req.end();
  });
}

// --- OS machine IDs ---

async function osMachineID(): Promise<string> {
  switch (process.platform) {
    case "linux":
      return linuxMachineID({ readFile: (p) => readFileSync(p, "latin1"), exists: existsSync });
    case "win32":
      return windowsMachineGuid();
    case "darwin":
      return macPlatformUUID();
    default:
      throw new FingerprintError("no_fingerprint", `no machine ID source on ${process.platform}: have the vendor supply an override`);
  }
}

const run = (file: string, args: string[]) =>
  new Promise<string>((resolve, reject) => execFile(file, args, { timeout: 10_000, windowsHide: true }, (err, out) => (err ? reject(err) : resolve(out))));

/** HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid, 64-bit view, as stored. */
async function windowsMachineGuid(): Promise<string> {
  const root = process.env.SystemRoot ?? "C:\\Windows";
  const out = await run(`${root}\\System32\\reg.exe`, ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid", "/reg:64"]).catch((e) => {
    throw new FingerprintError("no_fingerprint", `MachineGuid: ${String(e)}`);
  });
  // reg.exe prints "    MachineGuid    REG_SZ    <value>": the value as stored, after the 4-space separator.
  const m = /^ {4}MachineGuid {4}REG_SZ {4}(.*?)\r?$/m.exec(out);
  if (!m || m[1] === "") throw new FingerprintError("no_fingerprint", "MachineGuid not found, empty or not a string");
  return m[1]!;
}

/** IOPlatformUUID from ioreg, as printed (uppercase). */
async function macPlatformUUID(): Promise<string> {
  const out = await run("/usr/sbin/ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"]).catch((e) => {
    throw new FingerprintError("no_fingerprint", `ioreg: ${String(e)}`);
  });
  const m = /"IOPlatformUUID" = "([0-9A-Fa-f-]{36})"/.exec(out);
  if (!m) throw new FingerprintError("no_fingerprint", "IOPlatformUUID not found");
  return m[1]!;
}

/** What linuxMachineID reads, injectable for tests. readFile throws when absent. */
export interface LinuxFS {
  readFile(path: string): string;
  exists(path: string): boolean;
}

const tryRead = (fs: LinuxFS, p: string): string | undefined => {
  try {
    return fs.readFile(p);
  } catch {
    return undefined;
  }
};

/**
 * A stable, unique Linux machine ID, or no_fingerprint: a machine-id on
 * tmpfs/ramfs is regenerated every boot; in an application container only the
 * host's /etc/machine-id bind-mounted in is trusted; otherwise /etc/machine-id,
 * then /var/lib/dbus/machine-id.
 */
export function linuxMachineID(fs: LinuxFS): string {
  const none = (why: string): never => {
    throw new FingerprintError("no_fingerprint", why);
  };
  const m = containingMount(tryRead(fs, "/proc/self/mountinfo") ?? "", "/etc/machine-id");
  if (m && (m.fstype === "tmpfs" || m.fstype === "ramfs")) none("machine-id is on a tmpfs: regenerated every boot");
  if (appContainer(fs)) {
    // Only a bind mount of a file that is itself a machine-id.
    if (!m || m.point !== "/etc/machine-id" || !m.root.endsWith("/etc/machine-id")) {
      none("in a container: mount the host /etc/machine-id, or have the vendor enable an override");
    }
    const b = tryRead(fs, "/etc/machine-id");
    return b === undefined ? none("no /etc/machine-id") : parseMachineID(b);
  }
  let last = "no machine-id";
  for (const p of ["/etc/machine-id", "/var/lib/dbus/machine-id"]) {
    const b = tryRead(fs, p);
    if (b === undefined) continue;
    try {
      return parseMachineID(b);
    } catch {
      last = "machine-id missing or uninitialized";
    }
  }
  return none(last);
}

/** Application containers; system containers (lxc, lxc-libvirt, systemd-nspawn) aren't; unknown kinds fail closed. */
function appContainer(fs: LinuxFS): boolean {
  if (fs.exists("/.dockerenv") || fs.exists("/run/.containerenv")) return true;
  let kind = "";
  const sd = tryRead(fs, "/run/systemd/container");
  if (sd !== undefined) {
    kind = trim(sd);
  } else {
    for (const kv of (tryRead(fs, "/proc/1/environ") ?? "").split("\0")) {
      if (kv.startsWith("container=")) kind = kv.slice("container=".length);
    }
  }
  return !["", "lxc", "lxc-libvirt", "systemd-nspawn"].includes(kind);
}

interface Mount {
  root: string;
  point: string;
  fstype: string;
}

/** The mount holding path: the longest mount point equal to or above it, the last such entry winning. */
export function containingMount(mountinfo: string, path: string): Mount | undefined {
  let best: Mount | undefined;
  for (const line of mountinfo.split("\n")) {
    const at = line.indexOf(" - ");
    if (at < 0) continue;
    // Spaces only: the kernel escapes space, tab, newline and backslash, so
    // any other byte (\v, a Unicode space) belongs to the field.
    const f = line.slice(0, at).split(" ").filter(Boolean);
    const g = line.slice(at + 3).split(" ").filter(Boolean);
    if (f.length < 5 || g.length < 1) continue;
    const m = { root: unescapeMount(f[3]!), point: unescapeMount(f[4]!), fstype: g[0]! };
    if (!(m.point === path || m.point === "/" || path.startsWith(m.point + "/"))) continue;
    if (!best || m.point.length >= best.point.length) best = m;
  }
  return best;
}

/** Decodes mountinfo's octal escapes (\040 for a space). */
export function unescapeMount(s: string): string {
  return s.replace(/\\([0-7]{3})/g, (all, o: string) => (parseInt(o, 8) < 256 ? String.fromCharCode(parseInt(o, 8)) : all));
}

/** The systemd format: 32 lowercase hex characters; empty or "uninitialized" isn't an ID. */
export function parseMachineID(s: string): string {
  const id = trim(s);
  if (!/^[0-9a-f]{32}$/.test(id)) throw new FingerprintError("no_fingerprint", "machine-id missing or uninitialized");
  return id;
}

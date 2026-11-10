// Lease stores for the online client (ADR-0004), as the Go SDK's: a file,
// or one key of a Kubernetes ConfigMap or Secret through the in-cluster API,
// so every replica of a cluster-bound app shares the lease (it is signed,
// not secret). A stored lease is verified again when loaded.
import { randomInt } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:https";
import { FileClockStore } from "./clock.js";
import type { LeaseStore } from "./online.js";

/** The lease in a file, written atomically with mode 0600; "" empties it. Use a persistent path. */
export class FileLeaseStore implements LeaseStore {
  private readonly file: FileClockStore;
  constructor(readonly path: string) {
    if (!path) throw new TypeError("licenseforge lease store: empty path");
    this.file = new FileClockStore(path);
  }
  load(): string {
    const b = this.file.load();
    return b ? Buffer.from(b).toString("utf8").trim() : "";
  }
  save(lease: string): void {
    this.file.save(Buffer.from(lease, "utf8"));
  }
}

const SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount";
const dnsLabel = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
const dnsSubdomain = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const dataKey = /^[-._a-zA-Z0-9]{1,253}$/;

/** Where the Kubernetes API is, as the pod's service account sees it. Tests pass their own. */
export interface KubernetesAPI {
  host: string;
  port: number;
  ca: Buffer;
  namespace: string; // the pod's
  token: () => string; // read on every request: projected tokens rotate
}

function inCluster(): KubernetesAPI {
  const host = process.env.KUBERNETES_SERVICE_HOST;
  if (!host) throw new Error("licenseforge lease store: not in a Kubernetes cluster (no KUBERNETES_SERVICE_HOST)");
  const port = process.env.KUBERNETES_SERVICE_PORT || "443";
  if (!/^[1-9]\d{0,4}$/.test(port) || Number(port) > 65535) throw new Error(`licenseforge lease store: KUBERNETES_SERVICE_PORT ${JSON.stringify(port)} isn't a port`);
  let ca: Buffer;
  let namespace: string;
  try {
    ca = readFileSync(`${SA_DIR}/ca.crt`);
    namespace = readFileSync(`${SA_DIR}/namespace`, "utf8").trim();
  } catch (e) {
    throw new Error(`licenseforge lease store: no service account (automountServiceAccountToken?): ${String(e)}`);
  }
  return { host, port: Number(port), ca, namespace, token: () => readFileSync(`${SA_DIR}/token`, "utf8").trim() };
}

class APIError extends Error {
  constructor(readonly status: number, msg: string) {
    super(`kubernetes API: ${status} ${msg}`);
  }
}

/** A whole load or save, every attempt: the client holds its commit while saving. */
const API_TIMEOUT_MS = 15_000;

abstract class KubernetesStore implements LeaseStore {
  private api: KubernetesAPI | undefined;
  constructor(
    private readonly resource: "configmaps" | "secrets",
    private readonly kind: "ConfigMap" | "Secret",
    readonly opts: { name: string; namespace?: string; key?: string; api?: KubernetesAPI },
  ) {}

  private target(): { api: KubernetesAPI; path: string; key: string } {
    this.api ??= this.opts.api ?? inCluster();
    const ns = this.opts.namespace || this.api.namespace;
    const key = this.opts.key || "lease";
    const name = this.opts.name;
    if (!dnsLabel.test(ns)) throw new Error(`licenseforge lease store: namespace ${JSON.stringify(ns)} isn't a valid name`);
    if (name.length > 253 || !dnsSubdomain.test(name)) throw new Error(`licenseforge lease store: ${this.kind} name ${JSON.stringify(name)} isn't a valid name`);
    if (!dataKey.test(key) || key.startsWith("..") || key === ".") throw new Error(`licenseforge lease store: key ${JSON.stringify(key)} isn't a valid ${this.kind} key`);
    return { api: this.api, path: `/api/v1/namespaces/${ns}/${this.resource}/${name}`, key };
  }

  private decode(v: unknown): string {
    const s = typeof v === "string" ? v : "";
    if (this.kind !== "Secret") return s;
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) throw new Error("the Secret's value isn't base64");
    return Buffer.from(s, "base64").toString("utf8");
  }

  private encode(lease: string): string {
    return this.kind === "Secret" ? Buffer.from(lease, "utf8").toString("base64") : lease;
  }

  /** "" when the object or the key is missing. */
  async load(): Promise<string> {
    const { api, path, key } = this.target();
    const deadline = Date.now() + API_TIMEOUT_MS;
    try {
      const obj = (await call(api, "GET", path, undefined, deadline)) as { data?: Record<string, unknown> };
      return this.decode(obj?.data?.[key]);
    } catch (e) {
      if (e instanceof APIError && e.status === 404) return "";
      throw new Error(`licenseforge lease store: loading ${this.kind} ${path}: ${String(e)}`);
    }
  }

  /**
   * Sets (or, for "", removes) the key: reads the object and writes it back
   * conditional on its resourceVersion, everything else kept; creates it if
   * missing. A concurrent writer (409) or a deletion meanwhile (404) means
   * another round after a short jittered pause.
   */
  async save(lease: string): Promise<void> {
    const { api, path, key } = this.target();
    const deadline = Date.now() + API_TIMEOUT_MS;
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.saveOnce(api, path, key, lease, deadline);
      } catch (e) {
        const status = e instanceof APIError ? e.status : 0;
        if ((status === 409 || status === 404) && attempt < 4 && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 50 + randomInt(200)));
          continue;
        }
        const hint = status === 403 ? ` (create the ${this.kind} beforehand and grant get and update on it by name)` : "";
        throw new Error(`licenseforge lease store: saving ${this.kind} ${path}: ${String(e)}${hint}`);
      }
    }
  }

  private async saveOnce(api: KubernetesAPI, path: string, key: string, lease: string, deadline: number): Promise<void> {
    let obj: { data?: Record<string, unknown> } & Record<string, unknown>;
    try {
      obj = (await call(api, "GET", path, undefined, deadline)) as typeof obj;
    } catch (e) {
      if (!(e instanceof APIError && e.status === 404)) throw e;
      if (lease === "") return; // nothing to remove
      const create = { apiVersion: "v1", kind: this.kind, metadata: { name: this.opts.name }, data: { [key]: this.encode(lease) } };
      await call(api, "POST", path.slice(0, path.lastIndexOf("/")), create, deadline); // 409 if created meanwhile: another round
      return;
    }
    const data = obj.data && typeof obj.data === "object" ? { ...obj.data } : {};
    if (lease === "") delete data[key];
    else data[key] = this.encode(lease);
    await call(api, "PUT", path, { ...obj, data }, deadline); // carries the resourceVersion read: conditional
  }
}

/**
 * The lease in one key of a ConfigMap (RBAC: get and update on it, by
 * resourceNames; create it beforehand, since create can't be limited to a name).
 */
export class KubernetesConfigMapStore extends KubernetesStore {
  constructor(opts: { name: string; namespace?: string; key?: string; api?: KubernetesAPI }) {
    super("configmaps", "ConfigMap", opts);
  }
}

/** KubernetesConfigMapStore on a Secret, for clusters whose policy prefers Secrets (ADR-0004, amended). */
export class KubernetesSecretStore extends KubernetesStore {
  constructor(opts: { name: string; namespace?: string; key?: string; api?: KubernetesAPI }) {
    super("secrets", "Secret", opts);
  }
}

function call(api: KubernetesAPI, method: string, path: string, body: unknown, deadline: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let token: string;
    try {
      token = api.token();
    } catch (e) {
      return reject(e);
    }
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const left = deadline - Date.now();
    if (left <= 0) return reject(new Error("timed out"));
    let req: ReturnType<typeof request>;
    try {
      req = request({
        host: api.host, port: api.port, path, method, ca: api.ca, minVersion: "TLSv1.2",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(payload && { "Content-Length": payload.length }) },
      });
    } catch (e) {
      return reject(e);
    }
    const timer = setTimeout(() => req.destroy(new Error("timed out")), Math.min(left, 10_000));
    req.on("response", (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > 4 << 20) req.destroy(new Error("answer over 4 MiB")); // a near-limit object
        else chunks.push(c);
      });
      res.on("end", () => {
        clearTimeout(timer);
        const raw = Buffer.concat(chunks).toString("utf8");
        const status = res.statusCode ?? 0;
        if (status < 200 || status > 299) {
          let msg = raw.slice(0, 200);
          try {
            msg = JSON.parse(raw)?.message || msg;
          } catch {
            // not a Status object
          }
          return reject(new APIError(status, msg));
        }
        if (!raw) return resolve(undefined);
        try {
          resolve(JSON.parse(raw));
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    req.end(payload);
  });
}

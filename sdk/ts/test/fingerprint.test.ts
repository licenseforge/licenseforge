// Fingerprints: the shared vectors, the Go SDK's Linux cases, source order,
// and the Kubernetes lookup against a local TLS server.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { compute, type FingerprintEnv, FingerprintError, hash } from "../src/index.js";
import { linuxMachineID, namespaceUID, parseMachineID, unescapeMount } from "../src/fingerprint.js";

const code = async (fn: () => unknown) => {
  try {
    await fn();
    return "ok";
  } catch (e) {
    return e instanceof FingerprintError ? e.code : `threw ${String(e)}`;
  }
};

test("fingerprint.json: every SDK derives exactly these values", () => {
  const v = JSON.parse(readFileSync(new URL("../../../../spec/vectors/fingerprint.json", import.meta.url), "utf8"));
  assert.ok(v.cases.length > 0);
  for (const c of v.cases) {
    if (c.fingerprint) assert.equal(hash(c.tenant, c.product, c.raw_id), c.fingerprint, c.name);
    else assert.throws(() => hash(c.tenant, c.product, c.raw_id), FingerprintError, c.name);
  }
  assert.throws(() => hash("tnt", "p", "\uD800"), FingerprintError, "lone surrogate");
});

const validID = "0123456789abcdef0123456789abcdef";
const fakeFS = (files: Record<string, string>) => ({
  readFile: (p: string) => {
    if (p in files) return files[p]!;
    throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
  },
  exists: (p: string) => p in files,
});
const rootExt4 = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n";
const bindMount = (root: string, fstype: string) => `35 22 0:31 ${root} /etc/machine-id ro,relatime - ${fstype} src rw\n`;

test("Linux machine-id: the Go SDK's cases", () => {
  const cases: [string, Record<string, string>, string][] = [
    ["host", { "/etc/machine-id": validID + "\n" }, validID],
    ["dbus fallback when etc is uninitialized", { "/etc/machine-id": "uninitialized\n", "/var/lib/dbus/machine-id": validID }, validID],
    ["dbus fallback when etc is missing", { "/var/lib/dbus/machine-id": validID }, validID],
    ["transient tmpfs machine-id refused", { "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/machine-id", "tmpfs") }, ""],
    ["persistent bind mount on host ok", { "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/persist/etc/machine-id", "btrfs") }, validID],
    ["root on tmpfs refused", { "/etc/machine-id": validID, "/proc/self/mountinfo": "22 1 0:5 / / rw - tmpfs none rw\n" }, ""],
    ["etc on ramfs refused", { "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + "30 22 0:6 / /etc rw - ramfs none rw\n" }, ""],
    ["last stacked mount wins (tmpfs on top)", { "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/etc/machine-id", "ext4") + bindMount("/machine-id", "tmpfs") }, ""],
    ["last stacked mount wins (ext4 on top)", { "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/machine-id", "tmpfs") + bindMount("/etc/machine-id", "ext4") }, validID],
    ["docker with image machine-id refused", { "/.dockerenv": "", "/etc/machine-id": validID }, ""],
    ["docker with host machine-id mounted", { "/.dockerenv": "", "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/etc/machine-id", "ext4") }, validID],
    ["docker with ostree-style host path", { "/.dockerenv": "", "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/ostree/deploy/fedora/deploy/abc/etc/machine-id", "xfs") }, validID],
    ["docker with arbitrary shared file refused", { "/.dockerenv": "", "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/home/user/shared-id", "ext4") }, ""],
    ["docker with escaped path", { "/.dockerenv": "", "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/my\\040disk/etc/machine-id", "ext4") }, validID],
    ["podman marker", { "/run/.containerenv": "", "/etc/machine-id": validID }, ""],
    ["systemd container marker docker", { "/run/systemd/container": "docker\n", "/etc/machine-id": validID }, ""],
    ["unknown container type fails closed", { "/run/systemd/container": "something-new", "/etc/machine-id": validID }, ""],
    ["nspawn system container uses its own id", { "/run/systemd/container": "systemd-nspawn\n", "/etc/machine-id": validID }, validID],
    ["lxc system container uses its own id", { "/proc/1/environ": "PATH=/bin\0container=lxc\0", "/etc/machine-id": validID }, validID],
    ["oci container in pid 1 environ", { "/proc/1/environ": "container=oci\0", "/etc/machine-id": validID }, ""],
    ["the last container= in environ wins", { "/proc/1/environ": "container=lxc\0container=oci\0", "/etc/machine-id": validID }, ""],
    ["a \\v in a host path is part of the field (Go and TS alike)", { "/.dockerenv": "", "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/x\v/etc/machine-id", "ext4") }, validID],
    ["a Unicode space in a tmpfs root doesn't hide the tmpfs", { "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/a\u00a0b", "tmpfs") }, ""],
    ["no machine-id at all", {}, ""],
  ];
  for (const [name, files, want] of cases) {
    if (want) assert.equal(linuxMachineID(fakeFS(files)), want, name);
    else assert.throws(() => linuxMachineID(fakeFS(files)), (e) => e instanceof FingerprintError && e.code === "no_fingerprint", name);
  }
  for (const bad of ["", "uninitialized\n", "0123456789ABCDEF0123456789ABCDEF", "short"]) assert.throws(() => parseMachineID(bad), FingerprintError, bad);
  assert.equal(unescapeMount("/my\\040disk\\134x"), "/my disk\\x");
});

const env = (vars: Record<string, string>, k8s = "ns-uid", machine = validID): FingerprintEnv => ({
  getenv: (n) => vars[n],
  kubernetes: async () => k8s,
  machineID: async () => machine,
});

test("compute: override, then the env override if allowed, then Kubernetes, then the machine ID", async () => {
  const fp = (raw: string) => hash("tnt_acme", "acme-db", raw);
  assert.deepEqual(await compute("tnt_acme", "acme-db", {}, env({})), { fingerprint: fp(validID), source: "machine-id", binding: "machine" });
  assert.deepEqual(await compute("tnt_acme", "acme-db", {}, env({ KUBERNETES_SERVICE_HOST: "10.0.0.1" })), { fingerprint: fp("ns-uid"), source: "kubernetes", binding: "cluster" });
  // The env override only when the vendor allows it; trimmed; empty is skipped.
  assert.equal((await compute("tnt_acme", "acme-db", {}, env({ LICENSEFORGE_FINGERPRINT: "user" }))).source, "machine-id");
  assert.deepEqual(await compute("tnt_acme", "acme-db", { allowEnvOverride: true }, env({ LICENSEFORGE_FINGERPRINT: " user\n", KUBERNETES_SERVICE_HOST: "x" })), { fingerprint: fp("user"), source: "env", binding: "machine" });
  assert.equal((await compute("tnt_acme", "acme-db", { allowEnvOverride: true }, env({ LICENSEFORGE_FINGERPRINT: " \t" }))).source, "machine-id");
  // Only SP, HT, CR, LF are trimmed (not \v or Unicode spaces), as in every SDK.
  assert.equal((await compute("tnt_acme", "acme-db", { allowEnvOverride: true }, env({ LICENSEFORGE_FINGERPRINT: "\vX\u00a0 " }))).fingerprint, fp("\vX\u00a0"));
  assert.equal(await code(() => compute("tnt_acme", "acme-db", { allowEnvOverride: true }, env({ LICENSEFORGE_FINGERPRINT: "a\uFFFDb" }))), "invalid", "invalid UTF-8 from the environment");
  // The vendor's override wins over everything; sync or async; empty is an error.
  assert.deepEqual(await compute("tnt_acme", "acme-db", { override: () => "\tserial-1 ", allowEnvOverride: true }, env({ LICENSEFORGE_FINGERPRINT: "user" })), { fingerprint: fp("serial-1"), source: "override", binding: "machine" });
  assert.equal((await compute("tnt_acme", "acme-db", { override: async () => "serial-2" }, env({}))).fingerprint, fp("serial-2"));
  assert.equal(await code(() => compute("tnt_acme", "acme-db", { override: () => " \r\n" }, env({}))), "invalid");
  assert.equal(await code(() => compute("tnt_acme", "acme-db", { override: () => { throw new Error("tpm"); } }, env({}))), "failed");
  // Bad IDs are refused before any source is read.
  let read = false;
  const spy: FingerprintEnv = { getenv: () => undefined, kubernetes: async () => "x", machineID: async () => ((read = true), validID) };
  assert.equal(await code(() => compute("", "acme-db", {}, spy)), "invalid");
  assert.equal(await code(() => compute("tnt\0x", "acme-db", {}, spy)), "invalid");
  assert.equal(read, false);
});

// A local Kubernetes API with a throwaway self-signed certificate (openssl).
function tlsPair(san = "DNS:localhost,IP:127.0.0.1") {
  const dir = mkdtempSync(join(tmpdir(), "lf-k8s-"));
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost",
      "-addext", `subjectAltName=${san}`, "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
    return { key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("Kubernetes: the namespace UID with the token; retries transient answers; permanent ones fail", async () => {
  const { key, cert } = tlsPair();
  const answers: [number, string][] = [];
  const seen: string[] = [];
  const srv = createServer({ key, cert }, (req, res) => {
    seen.push(`${req.method} ${req.url} ${req.headers.authorization}`);
    const [status, body] = answers.shift() ?? [500, ""];
    res.writeHead(status, { "Content-Type": "application/json" }).end(body);
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const target = { host: "127.0.0.1", port: (srv.address() as AddressInfo).port, token: "sa-token", ca: cert };
  try {
    answers.push([200, `{"metadata":{"uid":"5f0c2d8e-1b2a"}}`]);
    assert.equal(await namespaceUID(target, []), "5f0c2d8e-1b2a");
    assert.deepEqual(seen, ["GET /api/v1/namespaces/kube-system Bearer sa-token"]);
    answers.push([503, ""], [429, ""], [200, `{"metadata":{"uid":"u2"}}`]);
    assert.equal(await namespaceUID(target, [1, 1]), "u2", "two transient answers, then the UID");
    answers.push([503, ""], [503, ""]);
    assert.equal(await code(() => namespaceUID(target, [1])), "transient", "retries exhausted");
    for (const [status, body] of [[403, ""], [404, ""], [200, "not json"], [200, `{"metadata":{}}`]] as const) {
      answers.push([status, body]);
      seen.length = 0;
      assert.equal(await code(() => namespaceUID(target, [1, 1])), "failed", `${status} ${body}`);
      assert.equal(seen.length, 1, "no retry for a permanent answer");
    }
    // Another CA: a configuration error, not retried.
    seen.length = 0;
    assert.equal(await code(() => namespaceUID({ ...target, ca: tlsPair().cert }, [1, 1])), "failed");
    assert.equal(seen.length, 0);
    // An answer over 1 MiB is permanent, like a decode error.
    answers.push([200, JSON.stringify({ metadata: { uid: "u" }, pad: "x".repeat(1 << 20) })]); // valid JSON, too big
    seen.length = 0;
    assert.equal(await code(() => namespaceUID(target, [1, 1])), "failed");
    assert.equal(seen.length, 1);
    // A token with a line break can't be sent: permanent, a FingerprintError.
    assert.equal(await code(() => namespaceUID({ ...target, token: "a\nb" }, [1, 1])), "failed");
  } finally {
    srv.close();
  }
});

test("Kubernetes: a name the certificate doesn't cover is permanent; a server dripping bytes hits the 5 s deadline", async () => {
  const onlyDNS = tlsPair("DNS:localhost"); // not 127.0.0.1
  const srv = createServer({ key: onlyDNS.key, cert: onlyDNS.cert }, (_req, res) => res.end("{}"));
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as AddressInfo).port;
  try {
    assert.equal(await code(() => namespaceUID({ host: "127.0.0.1", port, token: "t", ca: onlyDNS.cert }, [1, 1])), "failed");
  } finally {
    srv.close();
  }
  const pair = tlsPair();
  const drip = createServer({ key: pair.key, cert: pair.cert }, (_req, res) => {
    res.writeHead(200);
    const t = setInterval(() => res.write(" "), 1000); // one byte a second: never idle for 5 s
    res.on("close", () => clearInterval(t));
  });
  await new Promise<void>((r) => drip.listen(0, "127.0.0.1", r));
  const start = Date.now();
  try {
    assert.equal(await code(() => namespaceUID({ host: "127.0.0.1", port: (drip.address() as AddressInfo).port, token: "t", ca: pair.cert }, [])), "transient");
    const took = Date.now() - start;
    assert.ok(took >= 4500 && took < 8000, `took ${took} ms`);
  } finally {
    drip.closeAllConnections();
    drip.close();
  }
});

test("this machine: a fingerprint, or a clear no_fingerprint (containers, unknown OS)", async () => {
  const saved = process.env.KUBERNETES_SERVICE_HOST;
  delete process.env.KUBERNETES_SERVICE_HOST;
  try {
    const r = await compute("tnt_acme", "acme-db").catch((e) => e);
    if (r instanceof FingerprintError) assert.equal(r.code, "no_fingerprint", r.message);
    else assert.match(r.fingerprint, /^sha256:[0-9a-f]{64}$/);
  } finally {
    if (saved !== undefined) process.env.KUBERNETES_SERVICE_HOST = saved;
  }
});

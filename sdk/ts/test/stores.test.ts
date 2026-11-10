// Lease stores: a file, and ConfigMap/Secret keys through a fake Kubernetes API.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FileLeaseStore, type KubernetesAPI, KubernetesConfigMapStore, KubernetesSecretStore } from "../src/index.js";

test("FileLeaseStore: atomic, mode 0600, trimmed on load, \"\" empties it", () => {
  const dir = mkdtempSync(join(tmpdir(), "lf-lease-"));
  try {
    const s = new FileLeaseStore(join(dir, "lease"));
    assert.equal(s.load(), "");
    s.save("lf1.abc\n");
    assert.equal(s.load(), "lf1.abc");
    assert.equal(statSync(join(dir, "lease")).mode & 0o777, 0o600);
    s.save("");
    assert.equal(s.load(), "");
    assert.throws(() => new FileLeaseStore(""), TypeError);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function tls() {
  const dir = mkdtempSync(join(tmpdir(), "lf-kube-"));
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
    return { key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// A fake API: objects by path, resourceVersion conditional PUT, optional injected conflicts and refusals.
async function fakeAPI() {
  const { key, cert } = tls();
  const objects = new Map<string, Record<string, any>>();
  const log: string[] = [];
  const inject: { method: string; status: number }[] = [];
  let rv = 0;
  const srv = createServer({ key, cert }, async (req, res) => {
    let b = "";
    for await (const c of req) b += c;
    log.push(`${req.method} ${req.url} ${req.headers.authorization}`);
    const send = (status: number, body?: unknown) => res.writeHead(status, { "Content-Type": "application/json" }).end(body === undefined ? "" : JSON.stringify(body));
    const i = inject.findIndex((x) => x.method === req.method);
    if (i >= 0) return send(inject.splice(i, 1)[0]!.status, { kind: "Status", message: "injected" });
    const url = req.url!;
    if (req.method === "GET") return objects.has(url) ? send(200, objects.get(url)) : send(404, { message: "not found" });
    const obj = JSON.parse(b);
    if (req.method === "POST") {
      const p = `${url}/${obj.metadata.name}`;
      if (objects.has(p)) return send(409, { message: "exists" });
      obj.metadata.resourceVersion = String(++rv);
      objects.set(p, obj);
      return send(201, obj);
    }
    if (req.method === "PUT") {
      const cur = objects.get(url);
      if (!cur) return send(404, { message: "gone" });
      if (cur.metadata.resourceVersion !== obj.metadata?.resourceVersion) return send(409, { message: "conflict" });
      obj.metadata.resourceVersion = String(++rv);
      objects.set(url, obj);
      return send(200, obj);
    }
    send(405);
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const api: KubernetesAPI = { host: "127.0.0.1", port: (srv.address() as AddressInfo).port, ca: cert, namespace: "apps", token: () => "sa-token" };
  return { api, objects, log, inject, close: () => srv.close() };
}

test("ConfigMap: missing is \"\"; save creates; updates keep everything else; \"\" removes the key", async () => {
  const k = await fakeAPI();
  try {
    const s = new KubernetesConfigMapStore({ name: "acme-license", api: k.api });
    const path = "/api/v1/namespaces/apps/configmaps/acme-license";
    assert.equal(await s.load(), "");
    await s.save("lf1.one");
    assert.equal(await s.load(), "lf1.one");
    assert.equal(k.objects.get(path)!.data.lease, "lf1.one");
    assert.ok(k.log.every((l) => l.endsWith("Bearer sa-token")));
    // Someone else's labels and keys survive our update.
    const o = k.objects.get(path)!;
    o.metadata.labels = { team: "db" };
    o.data.other = "keep";
    await s.save("lf1.two");
    assert.deepEqual(k.objects.get(path)!.data, { lease: "lf1.two", other: "keep" });
    assert.deepEqual(k.objects.get(path)!.metadata.labels, { team: "db" });
    await s.save("");
    assert.deepEqual(k.objects.get(path)!.data, { other: "keep" });
    assert.equal(await s.load(), "");
    // Another namespace and key, by name.
    const t = new KubernetesConfigMapStore({ name: "x", namespace: "other", key: "lic.txt", api: k.api });
    await t.save("lf1.three");
    assert.equal(k.objects.get("/api/v1/namespaces/other/configmaps/x")!.data["lic.txt"], "lf1.three");
  } finally {
    k.close();
  }
});

test("Secret: the value is base64; a conflict means another round; 403 says what RBAC is needed", async () => {
  const k = await fakeAPI();
  try {
    const s = new KubernetesSecretStore({ name: "acme-license", api: k.api });
    await s.save("lf1.secret");
    assert.equal(k.objects.get("/api/v1/namespaces/apps/secrets/acme-license")!.data.lease, Buffer.from("lf1.secret").toString("base64"));
    assert.equal(await s.load(), "lf1.secret");
    k.inject.push({ method: "PUT", status: 409 });
    await s.save("lf1.after-conflict");
    assert.equal(await s.load(), "lf1.after-conflict");
    k.inject.push({ method: "PUT", status: 403 });
    await assert.rejects(s.save("lf1.x"), /grant get and update on it by name/);
    k.inject.push({ method: "GET", status: 500 });
    await assert.rejects(s.load(), /loading Secret/);
    k.objects.get("/api/v1/namespaces/apps/secrets/acme-license")!.data.lease = "not base64!";
    await assert.rejects(s.load(), /isn't base64/);
  } finally {
    k.close();
  }
});

test("names are checked before any request", async () => {
  const k = await fakeAPI();
  try {
    for (const opts of [{ name: "Bad_Name" }, { name: "ok", namespace: "Bad NS" }, { name: "ok", key: ".." }, { name: "ok", key: "a/b" }, { name: "x".repeat(254) }]) {
      await assert.rejects(new KubernetesConfigMapStore({ ...opts, api: k.api }).load(), /isn't a valid/, JSON.stringify(opts));
    }
    assert.equal(k.log.length, 0);
  } finally {
    k.close();
  }
});

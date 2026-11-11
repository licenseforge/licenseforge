// The online client: the Go SDK's online tests, ported to a local server.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPrivateKey, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createTLSServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Client, ClockError, Guard, type LeaseStore, MemoryClockStore, OnlineError, type PublicKey, SDK_VERSION } from "../src/index.js";

// The vectors' test key (spec/vectors/lf1.json): seed and public key.
const seed = Buffer.from("licenseforge-test-vector-seed-01");
const pub = Buffer.from("K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k", "base64url");
const priv = createPrivateKey({ key: { kty: "OKP", crv: "Ed25519", d: seed.toString("base64url"), x: pub.toString("base64url") }, format: "jwk" });
const keys: PublicKey[] = [{ kid: "test:2026-11", alg: "ed25519", key: new Uint8Array(pub) }];
const fp = { fingerprint: "sha256:" + "a".repeat(64), source: "machine-id" as const, binding: "machine" as const };

const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
function lease(o: { iatMs: number; tenant?: string; product?: string; fp?: string; bind?: string; refreshAfterMs?: number; expMs?: number; kid?: string; maxOffline?: string }): string {
  const payload: Record<string, unknown> = {
    v: 1, lid: "lic_1", tenant: o.tenant ?? "tnt_acme", product: o.product ?? "acme-db", iat: iso(o.iatMs),
    exp: iso(o.expMs ?? o.iatMs + 7 * 86400_000), refresh_after: iso(o.refreshAfterMs ?? o.iatMs + 3600_000),
    bind: o.bind === "none" ? { type: "none" } : { type: o.bind ?? "machine", fp: o.fp ?? fp.fingerprint },
  };
  if (o.maxOffline) payload.max_offline = o.maxOffline;
  const msg = `lf1.${o.kid ?? "test:2026-11"}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
  return `${msg}.${sign(null, Buffer.from(msg), priv).toString("base64url")}`;
}

type Answer = { status: number; body?: string; type?: string; headers?: Record<string, string>; hold?: Promise<void> };
async function server() {
  const answers: Answer[] = [];
  const seen: { path: string; auth: string; idem: string; body: Record<string, string> }[] = [];
  const srv = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    let b = "";
    for await (const c of req) b += c;
    seen.push({ path: req.url ?? "", auth: req.headers.authorization ?? "", idem: String(req.headers["idempotency-key"] ?? ""), body: b ? JSON.parse(b) : {} });
    const a = answers.shift() ?? { status: 500 };
    if (a.hold) await a.hold;
    res.writeHead(a.status, { "Content-Type": a.type ?? "application/json", ...a.headers }).end(a.body ?? "");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  return { base, answers, seen, close: () => srv.close() };
}
const ok = (l: string) => ({ status: 200, body: JSON.stringify({ lease: l, activation_id: "act_1" }) });
const problem = (status: number, code: string) => ({ status, type: "application/problem+json", body: JSON.stringify({ code, detail: "d", request_id: "R1" }) });
const now = Date.parse("2026-11-10T12:00:00Z");

async function client(base: string, extra: Partial<Parameters<typeof Client.create>[0]> = {}) {
  const c = await Client.create({ baseURL: base, tenantId: "tnt_acme", product: "acme-db", licenseKey: "LF-KEY", keys, fingerprint: fp, hostname: "db-1", appVersion: "2.0", ...extra });
  c.now = () => now;
  c.sleep = async () => {}; // no real waits in tests
  return c;
}
const code = async (p: Promise<unknown> | (() => unknown)) => {
  try {
    await (typeof p === "function" ? p() : p);
    return "ok";
  } catch (e) {
    return e instanceof OnlineError ? e.code : e instanceof ClockError ? `clock:${e.code}` : (e as { code?: string }).code ?? String(e);
  }
};

test("activate: one verified lease, the key in a header, one idempotency key across retries", async () => {
  const s = await server();
  try {
    const c = await client(s.base);
    s.answers.push({ status: 503 }, ok(lease({ iatMs: now })));
    const l = await c.activate();
    assert.equal(l.activationId, "act_1");
    assert.equal(l.claims.product, "acme-db");
    assert.equal(s.seen.length, 2);
    assert.equal(s.seen[0]!.path, "/api/v1/activation/tenants/tnt_acme/activate");
    assert.equal(s.seen[0]!.auth, "License LF-KEY");
    assert.ok(s.seen[0]!.idem.length >= 16 && s.seen[0]!.idem === s.seen[1]!.idem, "retries reuse one Idempotency-Key");
    assert.deepEqual(s.seen[0]!.body, { fingerprint: fp.fingerprint, fp_source: "machine-id", sdk_version: SDK_VERSION, hostname: "db-1", app_version: "2.0" });
    assert.equal(c.current().status, "valid");
    s.answers.push(ok(lease({ iatMs: now + 1000 })));
    await c.refresh();
    assert.equal(s.seen[2]!.idem, "", "refresh has no idempotency key");
  } finally {
    s.close();
  }
});

test("a lease that doesn't verify is never used or cached", async () => {
  const s = await server();
  try {
    const c = await client(s.base);
    for (const bad of [
      lease({ iatMs: now, tenant: "tnt_other" }),
      lease({ iatMs: now, product: "other" }),
      lease({ iatMs: now, fp: "sha256:" + "b".repeat(64) }),
      lease({ iatMs: now, bind: "cluster" }),
      lease({ iatMs: now, bind: "none" }),
      lease({ iatMs: now, kid: "test:unknown" }),
      lease({ iatMs: now }).slice(0, -2) + "AA",
    ]) {
      s.answers.push(ok(bad));
      assert.equal(await code(c.activate()), "bad_lease");
    }
    s.answers.push({ status: 200, body: "not json" }, { status: 200, body: "{}" });
    assert.equal(await code(c.activate()), "bad_lease");
    assert.equal(await code(c.activate()), "bad_lease");
    assert.equal(await code(() => c.current()), "no_lease");
  } finally {
    s.close();
  }
});

test("problem codes count only from a 4xx problem answer; retries only for network, 429, 5xx, in progress", async () => {
  const s = await server();
  try {
    const c = await client(s.base, { maxAttempts: 3 });
    s.answers.push(problem(403, "license_revoked"));
    const e = await c.activate().catch((x) => x);
    assert.ok(e instanceof OnlineError && e.code === "license_revoked" && e.status === 403 && e.requestId === "R1");
    assert.equal(s.seen.length, 1, "a refusal isn't retried");
    s.answers.push({ status: 403, type: "text/html", body: JSON.stringify({ code: "license_revoked" }) });
    assert.equal(await code(c.activate()), "unexpected_status", "a proxy page isn't a refusal, even with that text");
    const once = await client(s.base, { maxAttempts: 1 });
    s.answers.push({ status: 503, type: "application/problem+json", body: JSON.stringify({ code: "license_revoked" }) });
    assert.equal(await code(once.activate()), "server_error", "a 5xx problem never reads as revoked");
    s.answers.push({ status: 503, type: "application/problem+json", body: JSON.stringify({ code: "license_revoked" }) }, { status: 503 }, { status: 503 });
    assert.equal(await code(c.activate()), "server_error", "a 5xx never reads as revoked; retried to the limit");
    s.answers.push(problem(409, "idempotency_in_progress"), problem(429, "rate_limited"), ok(lease({ iatMs: now })));
    assert.equal(await code(c.activate()), "ok");
    s.answers.push({ status: 302, headers: { Location: "https://evil.example/" } });
    assert.equal(await code(c.refresh()), "unexpected_status", "redirects aren't followed");
  } finally {
    s.close();
  }
});

test("Retry-After sets the wait between attempts, capped", async () => {
  const s = await server();
  try {
    const c = await client(s.base);
    const waits: number[] = [];
    c.sleep = async (ms) => void waits.push(ms);
    s.answers.push({ status: 503, headers: { "Retry-After": "7" } }, { status: 429, headers: { "Retry-After": "99999" } }, ok(lease({ iatMs: now })));
    await c.activate();
    assert.deepEqual(waits, [7000, 600_000]);
  } finally {
    s.close();
  }
});

test("store: saved on commit, loaded and re-verified on create, a bad stored lease ignored with a warning", async () => {
  const s = await server();
  try {
    let stored = "";
    const store: LeaseStore = { load: () => stored, save: (l) => void (stored = l) };
    const c = await client(s.base, { store });
    assert.deepEqual(c.takeWarnings(), []);
    s.answers.push(ok(lease({ iatMs: now })));
    const l = await c.activate();
    assert.equal(stored, l.file);
    const again = await client(s.base, { store });
    assert.equal(again.current().claims.licenseId, "lic_1", "the stored lease, verified again");
    stored = lease({ iatMs: now, tenant: "tnt_other" });
    const bad = await client(s.base, { store });
    assert.equal(await code(() => bad.current()), "no_lease");
    assert.match(String(bad.takeWarnings()[0]), /stored lease not used/);
    assert.match(String((await client(s.base)).takeWarnings()[0]), /memory only/, "no store: a warning");
    await c.forget();
    assert.equal(stored, "", "forget clears the store");
  } finally {
    s.close();
  }
});

test("an older lease than the one held is a replay; forget is the way out of a far-future one", async () => {
  const s = await server();
  try {
    const c = await client(s.base);
    s.answers.push(ok(lease({ iatMs: now + 86400_000 * 30 })), ok(lease({ iatMs: now })));
    await c.activate();
    assert.equal(await code(c.refresh()), "bad_lease");
    await c.forget();
    s.answers.push(ok(lease({ iatMs: now })));
    assert.equal(await code(c.refresh()), "ok");
  } finally {
    s.close();
  }
});

test("forget while a call is in flight: its lease isn't used", async () => {
  const s = await server();
  try {
    const c = await client(s.base);
    let release!: () => void;
    s.answers.push({ ...ok(lease({ iatMs: now })), hold: new Promise<void>((r) => (release = r)) });
    const p = c.activate();
    await new Promise((r) => setTimeout(r, 50));
    await c.forget();
    release();
    assert.equal(await code(p), "superseded");
    assert.equal(await code(() => c.current()), "no_lease");
  } finally {
    s.close();
  }
});

test("deactivate: 204 or already not activated is success, and drops the lease", async () => {
  const s = await server();
  try {
    const c = await client(s.base);
    s.answers.push(ok(lease({ iatMs: now })), { status: 204 });
    await c.activate();
    await c.deactivate();
    assert.deepEqual(s.seen[1]!.body, { fingerprint: fp.fingerprint });
    assert.equal(await code(() => c.current()), "no_lease");
    s.answers.push(problem(404, "not_activated"));
    assert.equal(await code(c.deactivate()), "ok");
    s.answers.push(problem(401, "unauthenticated"));
    assert.equal(await code(c.deactivate()), "unauthenticated");
  } finally {
    s.close();
  }
});

test("current checks with max(local, local + server offset); claims are copies", async () => {
  const s = await server();
  try {
    const c = await client(s.base);
    s.answers.push(ok(lease({ iatMs: now + 3600_000, expMs: now + 3600_000 + 60_000 })));
    await c.activate(); // the server is an hour ahead of the local clock
    assert.equal(c.serverOffsetMs(), 3600_000);
    c.now = () => now + 120_000; // two minutes on: past exp by the server's clock
    assert.equal(await code(() => c.current()), "expired");
    c.now = () => now;
    const { claims } = c.current();
    (claims.entitlements.features as string[]).push("x");
    claims.binding.fingerprint = "changed";
    claims.expires!.setUTCFullYear(2099); // e.g. app code computing a display date
    claims.issuedAt.setUTCFullYear(1999);
    assert.equal(c.current().claims.expires!.getTime(), now + 3600_000 + 60_000, "the cached expiry is unchanged");
    assert.equal(c.current().claims.issuedAt.getTime(), now + 3600_000);
    assert.equal(c.current().claims.binding.fingerprint, fp.fingerprint);
    assert.equal(c.current().claims.entitlements.hasFeature("x"), false);
  } finally {
    s.close();
  }
});

test("clock guard: reset to each lease's iat; a rollback fails current", async () => {
  const s = await server();
  try {
    const clock = new Guard(new MemoryClockStore(), "LF-KEY");
    clock.now(new Date(now + 40 * 86400_000)); // the local clock once ran a month ahead
    const c = await client(s.base, { clock });
    s.answers.push(ok(lease({ iatMs: now })));
    await c.activate(); // the verified iat resets the mark
    assert.equal(c.current().status, "valid");
    clock.now(new Date(now + 10 * 86400_000));
    assert.equal(await code(() => c.current()), "clock:rollback");
  } finally {
    s.close();
  }
});

test("run: refreshes, then stops on revocation after forgetting the lease", async () => {
  const s = await server();
  try {
    const c = await client(s.base);
    const waits: number[] = [];
    c.sleep = async (ms) => void waits.push(ms);
    c.rand = () => 0;
    // The second lease says refresh at once (refresh_after = iat, as with max_offline 0).
    s.answers.push(ok(lease({ iatMs: now })), ok(lease({ iatMs: now + 1000, refreshAfterMs: now + 1000 })), { status: 503 }, problem(403, "license_revoked"));
    await c.activate();
    const errors: Error[] = [];
    const e = await c.run(new AbortController().signal, (x) => errors.push(x)).catch((x) => x);
    assert.ok(e instanceof OnlineError && e.code === "license_revoked");
    assert.equal(waits[0], 3600_000, "first refresh at refresh_after");
    assert.equal(waits[1], 60_000, "at least MIN_REFRESH_INTERVAL after a success");
    assert.ok(waits[2]! >= 500 && waits[2]! <= 1000, "backoff after a failure");
    assert.match(String(errors[0]), /memory only/, "warnings are reported too");
    assert.deepEqual(errors.slice(1).map((x) => (x as OnlineError).code), ["server_error", "license_revoked"]);
    assert.equal(await code(() => c.current()), "no_lease", "the server said: no longer licensed");
  } finally {
    s.close();
  }
});

test("run: keeps the lease on unauthenticated; refreshes at once when the cached lease fails current; aborts", async () => {
  const s = await server();
  try {
    const c = await client(s.base);
    const waits: number[] = [];
    c.sleep = async (ms) => void waits.push(ms);
    c.rand = () => 0;
    s.answers.push(ok(lease({ iatMs: now, maxOffline: "PT0S" })), problem(401, "unauthenticated"));
    await c.activate();
    c.now = () => now + 5000; // max_offline PT0S: invalid at once
    assert.equal(await code(c.run(new AbortController().signal)), "unauthenticated");
    assert.equal(waits[0], 0, "a cached lease failing current: refresh at once");
    c.now = () => now;
    assert.equal(c.current().claims.licenseId, "lic_1", "kept");
    const ac = new AbortController();
    c.sleep = async () => ac.abort(new Error("stop"));
    const e = await c.run(ac.signal).catch((x) => x);
    assert.equal(String(e), "Error: stop");
  } finally {
    s.close();
  }
});

test("create validates its config", async () => {
  const good = { baseURL: "https://api.example", tenantId: "t", product: "p", licenseKey: "k", keys, fingerprint: fp };
  for (const bad of [
    { ...good, baseURL: "http://api.example" },
    { ...good, baseURL: "https://u:p@api.example" },
    { ...good, baseURL: "https://api.example?x=1" },
    { ...good, baseURL: "not a url" },
    { ...good, tenantId: "" },
    { ...good, keys: [] },
    { ...good, fingerprint: { ...fp, binding: "none" as "machine" } },
  ]) {
    await assert.rejects(Client.create(bad), TypeError, JSON.stringify(bad.baseURL));
  }
  for (const ca of ["", "not pem", Buffer.from("x")]) await assert.rejects(Client.create({ ...good, ca }), TypeError, `ca ${String(ca)}`);
  for (const timeoutMs of [0, -1, Number.NaN]) await assert.rejects(Client.create({ ...good, timeoutMs }), RangeError, String(timeoutMs));
  await Client.create({ ...good, baseURL: "http://localhost:8080/lf/" }); // loopback http is fine
});

/** A self-signed certificate for 127.0.0.1, and a second one the client is never told about. */
function certs() {
  const dir = mkdtempSync(join(tmpdir(), "lf-online-"));
  try {
    const one = (n: string) => {
      execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", join(dir, `${n}k.pem`), "-out", join(dir, `${n}c.pem`)], { stdio: "ignore" });
      return { key: readFileSync(join(dir, `${n}k.pem`)), cert: readFileSync(join(dir, `${n}c.pem`)) };
    };
    return { server: one("s"), other: one("o") };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("ca: a server behind a private CA is trusted with it, and only with it", async () => {
  const { server: tls, other } = certs();
  const srv = createTLSServer(tls, (_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ lease: lease({ iatMs: now }), activation_id: "act_1" }));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const base = `https://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    const c = await client(base, { ca: tls.cert, maxAttempts: 1 });
    await c.activate();
    assert.equal(c.current().claims.licenseId, "lic_1");
    assert.equal(await code((await client(base, { maxAttempts: 1 })).activate()), "network", "not in Node's CAs");
    assert.equal(await code((await client(base, { ca: other.cert, maxAttempts: 1 })).activate()), "network", "another CA");
    assert.equal(await code((await client(base, { ca: String(tls.cert), maxAttempts: 1 })).activate()), "ok", "a PEM string");
  } finally {
    srv.close();
  }
});

test("an answer over 1 MiB, cut off, or stalled past timeoutMs is a network error", async () => {
  let n = 0;
  const srv = createServer((_req, res) => {
    const i = n++;
    if (i === 0) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("x".repeat((1 << 20) + 1));
    } else if (i === 1) {
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "100" });
      res.write("{", () => res.destroy()); // cut off mid-answer
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write("{"); // and never more
    }
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const c = await client(`http://127.0.0.1:${(srv.address() as AddressInfo).port}`, { maxAttempts: 1, timeoutMs: 300 });
    assert.equal(await code(c.activate()), "network", "over 1 MiB");
    assert.equal(await code(c.activate()), "network", "cut off");
    const t = Date.now();
    assert.equal(await code(c.activate()), "network", "stalled");
    assert.ok(Date.now() - t < 5000);
  } finally {
    srv.closeAllConnections();
    srv.close();
  }
});

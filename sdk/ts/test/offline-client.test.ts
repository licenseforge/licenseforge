// The offline client: the Go SDK's offline tests (sdk/go/offline), ported.
import assert from "node:assert/strict";
import { createPrivateKey, sign } from "node:crypto";
import { test } from "node:test";
import { type ClockStore, Guard, OfflineClient, type OfflineConfig, OfflineError, fileSHA256, parseReceipt, parseRequest, type PublicKey } from "../src/index.js";

// The vectors' test key (spec/vectors/lf1.json): seed and public key.
const seed = Buffer.from("licenseforge-test-vector-seed-01");
const pub = Buffer.from("K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k", "base64url");
const jwk = (d: Buffer) => createPrivateKey({ key: { kty: "OKP", crv: "Ed25519", d: d.toString("base64url"), x: pub.toString("base64url") }, format: "jwk" });
const priv = jwk(seed);
const keys: PublicKey[] = [{ kid: "k1", alg: "ed25519", key: new Uint8Array(pub) }];
const tenant = "tnt_01jcz5b2y3c4d5e6f7g8h9j0k1";
const machine = "sha256:81fe9b1a2812e068c320c4264f01b6d4d186a83cc0008fe954fd5d1b6e3f3684";
const other = "sha256:" + "0".repeat(64);
const T0 = Date.parse("2026-11-09T12:00:00Z");
const H = 3600_000;
const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

class MemStore implements ClockStore {
  b: Uint8Array | undefined;
  failSave = false;
  load() {
    return this.b;
  }
  save(s: Uint8Array) {
    if (this.failSave) throw new Error("read-only file system");
    this.b = s;
  }
}

type Claims = { lid?: string; tenant?: string; product?: string; iatMs?: number; expMs?: number | null; grace?: string; updatesUntilMs?: number; bind?: { type: string; fp?: string } };
/** A license file (defaults: this tenant, product and machine, issued an hour before T0, valid a day). */
function file(c: Claims = {}, key = priv): string {
  const iat = c.iatMs ?? T0 - H;
  const p: Record<string, unknown> = {
    v: 1, lid: c.lid ?? "lic_a", tenant: c.tenant ?? tenant, product: c.product ?? "acme-db", plan: "pro", iat: iso(iat),
    bind: c.bind ?? { type: "machine", fp: machine },
  };
  if (c.expMs !== null) p.exp = iso(c.expMs ?? iat + 24 * H);
  if (c.grace) p.grace = c.grace;
  if (c.updatesUntilMs !== undefined) p.updates_until = iso(c.updatesUntilMs);
  const msg = `lf1.k1.${Buffer.from(JSON.stringify(p)).toString("base64url")}`;
  return `${msg}.${sign(null, Buffer.from(msg), key).toString("base64url")}`;
}

function client(over: Partial<OfflineConfig> = {}) {
  const store = new MemStore();
  const c = new OfflineClient({
    tenantId: tenant, product: "acme-db", licenseKey: "LF-ABCDE-FGHIJ", keys,
    fingerprint: { fingerprint: machine, source: "machine-id", binding: "machine" }, hostname: "air-1", store, ...over,
  });
  return { c, store: (over.store as MemStore | undefined) ?? store };
}
const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return e instanceof OfflineError || (e as { code?: string }).code ? (e as { code: string }).code : String(e);
  }
  return "ok";
};
const now = new Date(T0);

test("request carries this machine and fresh nonces", () => {
  const { c } = client();
  const r = parseRequest(c.request(now));
  assert.equal(r.tenant, tenant);
  assert.equal(r.product, "acme-db");
  assert.equal(r.key, "LF-ABCDE-FGHIJ");
  assert.deepEqual(r.binding, { type: "machine", fingerprint: machine });
  assert.equal(r.fpSource, "machine-id");
  assert.equal(r.hostname, "air-1");
  assert.ok(r.sdkVersion?.startsWith("ts/"));
  assert.equal(r.created.getTime(), T0);
  const r2 = parseRequest(c.request(now));
  assert.equal(r.nonce.length, 16);
  assert.notDeepEqual(r.nonce, r2.nonce);
});

test("install, current, deactivate; a returned or older file can't come back", () => {
  const { c, store } = client();
  assert.equal(code(() => c.current(now)), "no_license");
  const f = file();
  const got = c.install(f, now);
  assert.equal(got.status, "valid");
  assert.equal(got.claims.licenseId, "lic_a");
  // Another client on the same store (another process) sees it.
  const { c: c2 } = client({ store });
  assert.equal(c2.current(now).status, "valid");
  assert.equal(code(() => c2.current(new Date(T0 + 24 * H))), "expired"); // past exp
  const receipt = c.deactivate(now);
  const r = parseReceipt(receipt);
  assert.deepEqual([r.tenant, r.licenseId, r.fingerprint, r.fileSHA256], [tenant, "lic_a", machine, fileSHA256(f)]);
  assert.equal(code(() => c.current(now)), "no_license");
  assert.equal(code(() => c.deactivate(now)), "no_license");
  assert.equal(code(() => c.install(f, now)), "returned");
  assert.equal(code(() => c.install(file({ iatMs: T0 - H - 60_000 }), now)), "returned");
  assert.equal(code(() => c.install(file({ iatMs: T0 - H + 60_000 }), now)), "ok"); // newer
  // Another license's file waits until lic_a is deactivated.
  const b = file({ lid: "lic_b" });
  assert.equal(code(() => c.install(b, now)), "other_license");
  c.deactivate(now);
  assert.equal(code(() => c.install(b, now)), "ok");
  // Deactivate saves before it answers: on a failed write, no receipt and the file stays.
  store.failSave = true;
  assert.match(code(() => c.deactivate(now)), /read-only/);
  store.failSave = false;
  assert.equal(c.current(now).claims.licenseId, "lic_b");
  // An expired file can still be returned.
  assert.equal(code(() => c.deactivate(new Date(T0 + 48 * H))), "ok");
});

test("an older file doesn't roll back a renewal; a file that no longer verifies blocks nothing", () => {
  const { c, store } = client();
  const old = file();
  const renewed = file({ iatMs: T0 - H + 60_000 });
  c.install(renewed, now);
  assert.equal(code(() => c.install(old, now)), "older_file");
  assert.equal(c.current(now).claims.issuedAt.getTime(), T0 - H + 60_000);
  assert.equal(code(() => c.install(renewed, now)), "ok"); // the same file again
  const { c: moved } = client({ store, fingerprint: { fingerprint: other, source: "machine-id", binding: "machine" } });
  assert.equal(code(() => moved.install(file({ bind: { type: "machine", fp: other } }), now)), "ok");
});

test("grace, updates_until and binding type", () => {
  const { c, store } = client();
  assert.equal(c.install(file({ expMs: T0 - 10 * 60_000, grace: "PT1H" }), now).status, "grace");
  const { c: built } = client({ store, buildDate: now });
  assert.equal(code(() => built.current(now)), "ok");
  c.install(file({ iatMs: T0 - H + 1000, updatesUntilMs: T0 - 24 * H }), now);
  assert.equal(code(() => built.current(now)), "updates_expired");
  assert.equal(code(() => c.install(file({ bind: { type: "cluster", fp: machine } }), now)), "bad_file");
});

test("state: damaged counts as none; another kind's state fails loudly", () => {
  const { c, store } = client();
  for (const s of ["{not json", "null", "{}", "[]", '{"offline":1,"file":5}', '{"offline":1,"returned":{"lic_a":"x"}}']) {
    store.b = Buffer.from(s);
    assert.equal(code(() => c.current(now)), "no_license", s);
  }
  // A damaged entry makes the whole state none, a valid file in it included (as Go's decoding).
  store.b = Buffer.from(JSON.stringify({ offline: 1, file: file(), returned: { lic_a: "x" } }));
  assert.equal(code(() => c.current(now)), "no_license");
  assert.equal(code(() => c.install(file(), now)), "ok"); // repairs it
  store.b = Buffer.from('{"mark":"2026-11-09T12:00:00.000Z","mac":"x"}'); // the clock guard's state
  assert.equal(code(() => c.current(now)), "foreign_state");
  assert.equal(code(() => c.install(file(), now)), "foreign_state");
  assert.equal(Buffer.from(store.b!).toString(), '{"mark":"2026-11-09T12:00:00.000Z","mac":"x"}', "left as it was");
  store.b = Buffer.from('{"offline":2}'); // another version's
  assert.equal(code(() => c.current(now)), "foreign_state");
});

test("install refusals store nothing", () => {
  const { c, store } = client();
  const cases: [string, string, string][] = [
    ["other machine", file({ bind: { type: "machine", fp: other } }), "bad_file"],
    ["other tenant", file({ tenant: "tnt_01jcz5b2y3c4d5e6f7g8h9j0k2" }), "bad_file"],
    ["other product", file({ product: "other" }), "bad_file"],
    ["unbound", file({ bind: { type: "none" } }), "bad_file"],
    ["expired", file({ iatMs: T0 - 48 * H, expMs: T0 - H }), "expired"],
    ["another key", file({}, jwk(Buffer.alloc(32, 6))), "bad_file"],
    ["garbage", "not a license", "bad_file"],
  ];
  for (const [name, f, want] of cases) assert.equal(code(() => c.install(f, now)), want, name);
  assert.equal(store.b, undefined);
});

test("clock guard: install raises it to a future iat; refused when it can't hold it; rollback stops the license", () => {
  // The vendor's clock an hour ahead, strict claim tolerance: only the guard makes the iat reachable.
  const gs = new MemStore();
  const { c } = client({ clock: new Guard(gs, "LF-ABCDE-FGHIJ"), clockToleranceSeconds: 0 });
  const ahead = file({ iatMs: T0 + H });
  assert.equal(c.install(ahead, now).status, "valid");
  assert.equal(c.current(now).status, "valid"); // through the raised guard

  // A guard that can't be saved: refused, and nothing stored.
  const unheld = new MemStore();
  unheld.failSave = true;
  const { c: c2, store: s2 } = client({ clock: new Guard(unheld, "LF-ABCDE-FGHIJ"), clockToleranceSeconds: 0 });
  assert.equal(code(() => c2.install(ahead, now)), "clock_not_saved");
  assert.equal(s2.b, undefined);
  // Five minutes fast needs no raise (the default claim tolerance).
  const { c: c3 } = client({ clock: new Guard(unheld, "LF-ABCDE-FGHIJ") });
  assert.equal(code(() => c3.install(file({ iatMs: T0 + 5 * 60_000 }), now)), "ok");

  // A file 100 h ahead is refused, leaving the installed file as it was.
  const { c: c4 } = client({ clock: new Guard(new MemStore(), "LF-ABCDE-FGHIJ") });
  c4.install(file(), now);
  assert.notEqual(code(() => c4.install(file({ iatMs: T0 + 100 * H, expMs: T0 + 101 * H }), now)), "ok");
  assert.equal(c4.current(now).status, "valid");

  // A clock turned back past the tolerance stops the license.
  const { c: c5 } = client({ clock: new Guard(new MemStore(), "LF-ABCDE-FGHIJ", { toleranceSeconds: 0 }) });
  c5.install(file(), now);
  assert.equal(code(() => c5.current(new Date(T0 - 2 * H))), "rollback");
});

test("the guard raise stops at its tolerance; a file failing at its own iat doesn't raise it", () => {
  const strict = (gs: MemStore, over: Partial<OfflineConfig> = {}) => client({ clock: new Guard(gs, "LF-ABCDE-FGHIJ", { toleranceSeconds: 3600 }), clockToleranceSeconds: 0, ...over }).c;
  assert.equal(code(() => strict(new MemStore()).install(file({ iatMs: T0 + H }), now)), "ok"); // exactly local + tolerance
  assert.equal(code(() => strict(new MemStore()).install(file({ iatMs: T0 + H + 1000 }), now)), "clock_skew");
  const g = new Guard(new MemStore(), "LF-ABCDE-FGHIJ", { toleranceSeconds: 3600 });
  const late = file({ iatMs: T0 + 30 * 60_000, updatesUntilMs: T0 - 24 * H });
  assert.equal(code(() => client({ clock: g, clockToleranceSeconds: 0, buildDate: now }).c.install(late, now)), "updates_expired");
  assert.equal(g.now(now).now.getTime(), T0, "the guard wasn't raised to the file's iat");
});

test("any license ID is remembered as returned", () => {
  for (const lid of ["toString", "constructor", "__proto__", "hasOwnProperty"]) {
    const { c } = client();
    const f = file({ lid });
    c.install(f, now);
    c.deactivate(now);
    assert.equal(code(() => c.install(f, now)), "returned", lid);
  }
});

test("config is checked", () => {
  assert.throws(() => client({ licenseKey: "" }), TypeError);
  assert.throws(() => client({ fingerprint: { fingerprint: machine, source: "machine-id", binding: "none" as "machine" } }), TypeError);
});

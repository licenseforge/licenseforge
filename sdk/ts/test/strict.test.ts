// What the shared vectors don't cover: strict JSON and timestamp details,
// the entitlement lookups and the check options.
import assert from "node:assert/strict";
import { test } from "node:test";
import { check, Entitlements, LicenseError, parseClaims, UNLIMITED, verify } from "../src/index.js";
import { parseTime, weakEd25519 } from "../src/licensefile.js";

const base = { v: 1, lid: "lic_1", product: "p", iat: "2026-11-01T00:00:00Z" };
const claims = (json: string) => parseClaims(new TextEncoder().encode(json));
const code = (fn: () => unknown) => {
  try {
    fn();
    return "ok";
  } catch (e) {
    return e instanceof LicenseError ? e.code : `threw ${String(e)}`;
  }
};

test("strict JSON: control characters, escapes and number forms in payloads", () => {
  const ok = JSON.stringify(base);
  assert.equal(code(() => claims(ok)), "ok");
  for (const [name, text] of [
    ["raw tab in a string", ok.replace('"lic_1"', '"lic\t1"')],
    ["raw newline in a string", ok.replace('"lic_1"', '"lic\n1"')],
    ["bad escape", ok.replace('"lic_1"', '"lic\\x1"')],
    ["short \\u escape", ok.replace('"lic_1"', '"lic\\u12"')],
    ["lone low surrogate", ok.replace('"lic_1"', '"\\udc00"')],
    ["high surrogate then a non-surrogate", ok.replace('"lic_1"', '"\\ud800\\u0041"')],
    ["leading zero", ok.replace('"v":1', '"v":01')],
    ["plus sign", ok.replace('"v":1', '"v":+1')],
    ["trailing comma", ok.replace("}", ",}")],
    ["single quotes", ok.replace('"lic_1"', "'lic_1'")],
    ["BOM before the object", "\uFEFF" + ok],
    ["NUL in tenant", JSON.stringify({ ...base, tenant: "t\u0000x" })],
  ] as const) {
    assert.equal(code(() => claims(text)), "malformed", name);
  }
  assert.equal(claims(ok.replace('"lic_1"', '"\\ud83d\\ude00\\u00e9"')).licenseId, "😀é", "a surrogate pair and an escape decode");
  assert.equal(code(() => parseClaims(new Uint8Array([0x7b, 0xff, 0x7d]))), "malformed", "invalid UTF-8");
});

test("timestamps: exact form, real dates, 1970–9999", () => {
  assert.equal(parseTime("2028-02-29T23:59:59Z").toISOString(), "2028-02-29T23:59:59.000Z");
  for (const s of ["2026-02-30T00:00:00Z", "2027-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-11-31T00:00:00Z", "2026-11-01T24:00:00Z", "2026-11-01T00:60:00Z", "2026-11-01T00:00:60Z", "1969-12-31T23:59:59Z", "2026-11-01t00:00:00Z", "2026-11-01T00:00:00z", "2026-11-01T00:00:00.5Z", "2026-11-01T00:00:00+00:00"]) {
    assert.equal(code(() => parseTime(s)), "malformed", s);
  }
});

test("entitlements: exact features, limits with UNLIMITED, allows takes the resulting total", () => {
  const c = claims(JSON.stringify({ ...base, entitlements: { features: ["sso"], limits: { seats: 3, nodes: -1, zero: 0, neg: 7 } } }).replace('"neg":7', '"neg":-0'));
  const e = c.entitlements;
  assert.equal(e.hasFeature("sso"), true);
  assert.equal(e.hasFeature("SSO"), false);
  assert.equal(e.hasFeature("seats"), false, "never looks at limits");
  assert.equal(e.limit("seats"), 3);
  assert.equal(e.limit("nodes"), UNLIMITED);
  assert.equal(e.limit("missing"), 0);
  assert.ok(Object.is(e.limit("neg"), 0), "-0 is 0");
  assert.deepEqual([0, 3, 4].map((n) => e.allows("seats", n)), [true, true, false]);
  assert.deepEqual([0, 1e9].map((n) => e.allows("nodes", n)), [true, true]);
  assert.deepEqual([0, 1].map((n) => e.allows("missing", n)), [true, false]);
  for (const n of [-1, 1.5, Number.NaN, Infinity, 2 ** 53]) assert.equal(e.allows("nodes", n), false, String(n));
  assert.equal(new Entitlements().hasFeature("x"), false);
  for (const limits of [{ x: 1.0 }, { x: -2 }, { x: 9007199254740992 }]) {
    const raw = JSON.stringify({ ...base, entitlements: { limits } }).replace('"x":1', '"x":1.0');
    assert.equal(code(() => claims(raw)), "malformed", raw);
  }
});

test("check options: now is required, tolerance must be ≥ 0, 0 is strict", () => {
  const c = claims(JSON.stringify({ ...base, iat: "2026-11-01T00:00:01Z" }));
  const now = parseTime("2026-11-01T00:00:00Z");
  assert.equal(check(c, { now, product: "p" }), "valid", "24h default tolerance");
  assert.equal(code(() => check(c, { now, product: "p", clockToleranceSeconds: 0 })), "clock_skew");
  assert.throws(() => check(c, { now, product: "p", clockToleranceSeconds: -1 }), RangeError);
  assert.throws(() => check(c, { now: new Date(Number.NaN), product: "p" }), TypeError);
  assert.throws(() => check(c, { now: "2026-11-01" as unknown as Date, product: "p" }), TypeError);
  assert.throws(() => check(c, { now, product: "p", buildDate: new Date("garbage") }), TypeError, "an invalid build date fails closed");
});

test("envelope: a long run of whitespace inside unsigned input is cheap", () => {
  const input = "a" + " \t\r\n".repeat(16000) + "a"; // 64,002 bytes, under the limit
  const start = performance.now();
  assert.throws(() => verify(input, []), (e) => e instanceof LicenseError && e.code === "malformed");
  assert.ok(performance.now() - start < 100, `took ${performance.now() - start} ms`);
});

test("weak ed25519 keys: every small-order and non-canonical encoding, and no ordinary key", () => {
  const hex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
  const weak = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0100000000000000000000000000000000000000000000000000000000000080", // negative zero
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  ].map(hex);
  for (let k = 0; k < 19; k++) {
    const b = new Uint8Array(32).fill(0xff);
    b[0] = 0xed + k;
    b[31] = 0x7f;
    weak.push(b, Uint8Array.from([...b.subarray(0, 31), 0xff])); // y = p + k, either sign
  }
  for (const k of weak) assert.equal(weakEd25519(k), true, Buffer.from(k).toString("hex"));
  const strong = [
    "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p − 2
    "0200000000000000000000000000000000000000000000000000000000000000", // y = 2
    "2b57583dbe767c93f76025809070aaf98b68ffc231df60a3df6dba5383ea23a9", // the vectors' test key
  ].map(hex);
  for (const k of strong) assert.equal(weakEd25519(k), false, Buffer.from(k).toString("hex"));
});

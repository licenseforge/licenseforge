// The shared conformance vectors (spec/vectors): every SDK must give the
// expected class for every case.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { check, LicenseError, parseClaims, parseKeySet, type PublicKey, verify } from "../src/index.js";
import { parseDuration, parseTime } from "../src/licensefile.js";

const vectors = (name: string) => JSON.parse(readFileSync(new URL(`../../../../spec/vectors/${name}`, import.meta.url), "utf8"));
const code = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    if (e instanceof LicenseError) return e.code;
    throw e;
  }
  return "valid";
};

test("lf1.json: envelope and signature", () => {
  const v = vectors("lf1.json");
  // Through parseKeySet, as an app loads them; a bad alg, key length or a
  // weak key loads as given and surfaces in verify.
  const keys: PublicKey[] = parseKeySet(JSON.stringify(v.keys));
  assert.ok(v.cases.length > 0);
  for (const c of v.cases) {
    let got = "valid";
    try {
      const r = verify(c.license, keys);
      if (c.expect === "valid") {
        assert.equal(r.kid, c.kid, c.name);
        assert.equal(Buffer.from(r.payload).toString("utf8"), c.payload, c.name);
      }
    } catch (e) {
      if (!(e instanceof LicenseError)) throw e;
      got = e.code;
    }
    assert.equal(got, c.expect, c.name);
  }
});

test("lf1-claims.json: claim encoding and checks", () => {
  const v = vectors("lf1-claims.json");
  assert.ok(v.cases.length > 0);
  for (const c of v.cases) {
    const o = c.options ?? {};
    let status = "";
    const got = code(() => {
      const claims = parseClaims(new TextEncoder().encode(c.payload));
      status = check(claims, {
        now: parseTime(o.now),
        product: o.product ?? "",
        ...(o.fingerprint !== undefined && { fingerprint: o.fingerprint }),
        ...(o.build_date !== undefined && { buildDate: parseTime(o.build_date) }),
        ...(o.clock_tolerance !== undefined && { clockToleranceSeconds: parseDuration(o.clock_tolerance) }),
      });
    });
    assert.equal(got === "valid" ? status : got, c.expect, c.name); // valid or grace when usable
  }
});

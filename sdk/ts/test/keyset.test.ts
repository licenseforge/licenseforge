// parseKeySet: the same cases as the Go SDK's keyset_test.go.
import assert from "node:assert/strict";
import { test } from "node:test";
import { LicenseError, parseKeySet } from "../src/index.js";

const vecKey = "K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k"; // spec/vectors/lf1.json test:2026-11

test("parseKeySet reads the dashboard's JSON", () => {
  const ks = parseKeySet(`[{"kid":"sk_a","alg":"ed25519","public_key":"${vecKey}"},{"kid":"sk_b","alg":"ml-dsa-65","public_key":"AAAA"}]`);
  assert.equal(ks.length, 2);
  assert.deepEqual([ks[0]!.kid, ks[0]!.alg, Buffer.from(ks[0]!.key).toString("base64url")], ["sk_a", "ed25519", vecKey]);
  assert.deepEqual([ks[1]!.alg, ks[1]!.key.length], ["ml-dsa-65", 3]);
  assert.equal(parseKeySet(new TextEncoder().encode(`[{"kid":"a","alg":"ed25519","public_key":"AAAA"}]`)).length, 1, "bytes too");
});

test("what verify decides loads as given", () => {
  const ks = parseKeySet(
    `[{"kid":"d","alg":"ed25519","public_key":"AAAA"},{"kid":"d","alg":"ed25519","public_key":"AAAA"},{"kid":"x","alg":"rsa","public_key":"AAAA"},` +
      `{"kid":"e","alg":"","public_key":"AAAA"},{"kid":"z","alg":"ed25519","public_key":""}]`,
  );
  assert.equal(ks.length, 5);
  assert.equal(ks[4]!.key.length, 0);
});

test("what can't be represented, or reads differently elsewhere, is invalid_key_set", () => {
  const cases: [string, string | Uint8Array][] = [
    ["not json", "{"],
    ["not an array", `{"kid":"a","alg":"ed25519","public_key":"AAAA"}`],
    ["empty", "[]"],
    ["null", "null"],
    ["trailing data", `[{"kid":"a","alg":"ed25519","public_key":"AAAA"}] []`],
    ["typo in field", `[{"kid":"a","alg":"ed25519","publicKey":"AAAA"}]`],
    ["unknown field", `[{"kid":"a","alg":"ed25519","public_key":"AAAA","use":"sig"}]`],
    ["missing key", `[{"kid":"a","alg":"ed25519"}]`],
    ["missing kid", `[{"alg":"ed25519","public_key":"AAAA"}]`],
    ["missing alg", `[{"kid":"a","public_key":"AAAA"}]`],
    ["padded", `[{"kid":"a","alg":"ed25519","public_key":"AAA="}]`],
    ["standard alphabet", `[{"kid":"a","alg":"ed25519","public_key":"AA+/"}]`],
    ["non-canonical bits", `[{"kid":"a","alg":"ed25519","public_key":"AB"}]`],
    ["bad kid", `[{"kid":"a.b","alg":"ed25519","public_key":"AAAA"}]`],
    ["upper-case fields", `[{"KID":"a","ALG":"ed25519","Public_Key":"AAAA"}]`],
    ["kelvin sign", `[{"Kid":"a","alg":"ed25519","public_key":"AAAA"}]`],
    ["repeated key", `[{"kid":"a","alg":"ed25519","public_key":"AAAA","public_key":"${vecKey}"}]`],
    ["case-variant repeat", `[{"kid":"a","alg":"ed25519","public_key":"AAAA","PUBLIC_KEY":"${vecKey}"}]`],
    ["repeated kid", `[{"kid":"a","kid":"b","alg":"ed25519","public_key":"AAAA"}]`],
    ["null field", `[{"kid":"a","alg":null,"public_key":"AAAA"}]`],
    ["number field", `[{"kid":"a","alg":1,"public_key":"AAAA"}]`],
    ["null entry", "[null]"],
    ["newline in key", `[{"kid":"a","alg":"ed25519","public_key":"AA\\nAA"}]`],
    ["CR in key", `[{"kid":"a","alg":"ed25519","public_key":"AA\\rAA"}]`],
    ["long non-canonical", `[{"kid":"a","alg":"ed25519","public_key":"${vecKey.slice(0, -1)}l"}]`],
    ["long padded", `[{"kid":"a","alg":"ed25519","public_key":"${vecKey}="}]`],
    ["lone surrogate escape", `[{"kid":"a","alg":"\\ud800","public_key":"AAAA"}]`],
    ["lone surrogate in a string", `[{"kid":"a","alg":"\uD800","public_key":"AAAA"}]`],
    ["invalid UTF-8", Uint8Array.from([...new TextEncoder().encode(`[{"kid":"a","alg":"ed`), 0xff, ...new TextEncoder().encode(`","public_key":"AAAA"}]`)])],
    ["BOM", `﻿[{"kid":"a","alg":"ed25519","public_key":"AAAA"}]`],
    ["BOM in bytes", Uint8Array.from([0xef, 0xbb, 0xbf, ...new TextEncoder().encode(`[{"kid":"a","alg":"ed25519","public_key":"AAAA"}]`)])],
  ];
  for (const [name, input] of cases) {
    assert.throws(() => parseKeySet(input), (e) => e instanceof LicenseError && e.code === "invalid_key_set", name);
  }
});

test("error messages don't echo the file's field names or values", () => {
  for (const input of [`[{"kid":"a","alg":"ed25519","s3cr3t_field":"AAAA"}]`, `[{"kid":"a","alg":"ed25519","public_key":"AAAA","s3cr3t":1,"s3cr3t":2}]`]) {
    assert.throws(() => parseKeySet(input), (e) => e instanceof LicenseError && !e.message.includes("s3cr3t"), input);
  }
});

// Offline requests and receipts: spec/vectors/offline.json, and encoding
// round trips (an SDK can't write what the server refuses).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { encodeReceipt, encodeRequest, fileSHA256, LicenseError, offlineSHA256, parseReceipt, parseRequest } from "../src/index.js";

const v = JSON.parse(readFileSync(new URL("../../../../spec/vectors/offline.json", import.meta.url), "utf8"));
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const iso = (d: Date) => d.toISOString().replace(".000Z", "Z");

test("offline.json: requests and receipts give the expected class and fields", () => {
  assert.ok(v.cases.length > 0);
  assert.ok(v.cases.some((c: { want?: object }) => c.want), "some cases list fields");
  for (const c of v.cases) {
    let got: Record<string, string> | undefined;
    let result = "ok";
    try {
      if (c.kind === "request") {
        const r = parseRequest(c.input);
        got = { tenant: r.tenant, product: r.product, key: r.key, bind_type: r.binding.type, fp: r.binding.fingerprint, fp_source: r.fpSource, nonce: b64(r.nonce), created: iso(r.created) };
        if (r.hostname !== undefined) got.hostname = r.hostname;
        if (r.appVersion !== undefined) got.app_version = r.appVersion;
        if (r.sdkVersion !== undefined) got.sdk_version = r.sdkVersion;
      } else {
        const r = parseReceipt(c.input);
        got = { tenant: r.tenant, license_id: r.licenseId, fp: r.fingerprint, file_sha256: r.fileSHA256, nonce: b64(r.nonce), created: iso(r.created) };
      }
    } catch (e) {
      if (!(e instanceof LicenseError)) throw e;
      result = e.code;
    }
    assert.equal(result, c.result, c.name);
    if (c.result !== "ok" || !c.want) continue; // some ok cases check only the class
    for (const [k, want] of Object.entries(c.want)) assert.equal(got![k], want, `${c.name}: ${k}`); // want lists the fields to compare
  }
});

test("offline.json: one file_sha256 however the file was carried; none for a file that isn't one", () => {
  assert.ok(v.file_hashes.length > 0);
  for (const c of v.file_hashes) {
    if (c.file_sha256) assert.equal(fileSHA256(c.input), c.file_sha256, c.name);
    else assert.throws(() => fileSHA256(c.input), (e) => e instanceof LicenseError && e.code === "malformed", c.name);
  }
});

const fp = "sha256:81fe9b1a2812e068c320c4264f01b6d4d186a83cc0008fe954fd5d1b6e3f3684";
const nonce = Uint8Array.from({ length: 16 }, (_, i) => i);

test("encodeRequest and encodeReceipt round-trip, refuse what the parser refuses, and write whole seconds", () => {
  const req = {
    tenant: "tnt_acme", product: "acme-db", key: "LF-ABCDE-\nFGHIJ ", binding: { type: "machine" as const, fingerprint: fp },
    fpSource: "machine-id" as const, nonce, created: new Date("2026-11-08T10:00:00.789Z"), hostname: "db-1", appVersion: "2.4.0",
  };
  const r = parseRequest(encodeRequest(req));
  assert.deepEqual([r.key, r.created.toISOString(), r.hostname, r.appVersion, r.sdkVersion], ["LF-ABCDE-FGHIJ", "2026-11-08T10:00:00.000Z", "db-1", "2.4.0", undefined]);
  // Go's encoder sorts the keys: the same request reads the same bytes.
  const json = Buffer.from(encodeRequest(req).slice("lfreq1.".length), "base64url").toString();
  assert.equal(json, `{"app_version":"2.4.0","bind":{"fp":"${fp}","type":"machine"},"created":"2026-11-08T10:00:00Z","fp_source":"machine-id","hostname":"db-1","key":"LF-ABCDE-FGHIJ","nonce":"AAECAwQFBgcICQoLDA0ODw","product":"acme-db","tenant":"tnt_acme","v":1}`);
  for (const bad of [{ ...req, fpSource: "kubernetes" as const }, { ...req, hostname: "bad host" }, { ...req, nonce: new Uint8Array(15) }, { ...req, tenant: "t\0x" }, { ...req, created: new Date(Number.NaN) }, { ...req, product: "\uD800" }]) {
    assert.throws(() => encodeRequest(bad), (e) => e instanceof LicenseError && e.code === "malformed");
  }
  const rc = { tenant: "tnt_acme", licenseId: "lic_1", fingerprint: fp, fileSHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", nonce, created: new Date("2026-11-08T10:00:00Z") };
  assert.deepEqual(parseReceipt(encodeReceipt(rc)), rc);
  assert.throws(() => encodeReceipt({ ...rc, fileSHA256: "ABC" }), LicenseError);
});

test("offlineSHA256 ignores the BOM and whitespace a transfer adds", () => {
  const tok = encodeReceipt({ tenant: "t", licenseId: "l", fingerprint: fp, fileSHA256: "0".repeat(64), nonce, created: new Date(0) });
  const h = offlineSHA256(tok);
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(offlineSHA256(`﻿${tok.slice(0, 10)}\r\n${tok.slice(10)}\n`), h);
});

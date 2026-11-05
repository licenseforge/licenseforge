import { describe, expect, it } from "vitest";
import { auditHash, detailsSpans, verifyChain } from "./audit-chain";

import { D1, first, H1, H2, second, ZERO } from "./audit-chain.fixture";

/** A page body as the server writes it: details raw, in an arbitrary key position. */
const page = (items: string[]) => `{"items":[${items.join(",")}],"next_cursor":"Mg"}`;
const item1 = `{"id":"${first.id}","user_agent":"Mozilla/5.0 \\"quoted\\"","note":"\\"details\\": {fake}","details":${D1},"seq":1}`;
const item2 = `{ "details" : {} , "id":"${second.id}", "x":[{"details":"nested, not this"}]}`;

describe("detailsSpans", () => {
  it("cuts each item's details out of the raw body, byte for byte", () => {
    expect(detailsSpans(page([item2, item1]))).toEqual(["{}", D1]);
    expect(detailsSpans(`{"items":[]}`)).toEqual([]);
  });
  it("refuses a body it can't read rather than guessing", () => {
    expect(() => detailsSpans(`{"items":[{"id":"x"}]}`)).toThrow(); // no details
    expect(() => detailsSpans(`{"items":[{"details":{]}`)).toThrow();
  });
});

describe("auditHash", () => {
  it("matches the server's hash, null fields as empty", async () => {
    expect(await auditHash(first, D1)).toBe(H1);
    expect(await auditHash(second, "{}")).toBe(H2);
  });
  it("depends on the raw details, not their parsed value", async () => {
    expect(await auditHash(first, JSON.stringify(first.details))).not.toBe(H1); // re-serialized: the escapes come out differently
  });
});

/** Entries of loaded page 1 (raw details as sent). */
const p1 = (xs: { event: typeof first | typeof second; rawDetails: string | null }[]) => xs.map((x) => ({ ...x, page: 1 }));

describe("verifyChain (newest first)", () => {
  const chain = p1([{ event: second, rawDetails: "{}" }, { event: first, rawDetails: D1 }]);
  it("accepts an intact chain from seq 1", async () => {
    expect(await verifyChain(chain)).toEqual({ ok: true, checked: 2, fromSeq: 1, toSeq: 2 });
  });
  it("finds a changed field", async () => {
    expect(await verifyChain([chain[0]!, { ...chain[1]!, event: { ...first, action: "license.revoke" } }])).toEqual({ ok: false, seq: 1, reason: "hash" });
  });
  it("finds changed details", async () => {
    expect(await verifyChain([chain[0]!, { ...chain[1]!, rawDetails: D1.replace("1", "2") }])).toEqual({ ok: false, seq: 1, reason: "hash" });
  });
  it("finds a broken link", async () => {
    // a self-consistent entry 2 that doesn't point at entry 1
    const forged = { ...second, prev_hash: ZERO };
    forged.hash = await auditHash(forged, "{}");
    expect(await verifyChain(p1([{ event: forged, rawDetails: "{}" }, { event: first, rawDetails: D1 }]))).toEqual({ ok: false, seq: 2, reason: "link" });
  });
  it("finds a broken link deeper in: three entries, broken between 2 and 3", async () => {
    const third = { ...second, id: "aud_ffffffffffffffffffffffffff", seq: 3, prev_hash: "ab".repeat(32) }; // not entry 2's hash
    third.hash = await auditHash(third, "{}");
    expect(await verifyChain(p1([{ event: third, rawDetails: "{}" }, { event: second, rawDetails: "{}" }, { event: first, rawDetails: D1 }]))).toEqual({
      ok: false,
      seq: 3,
      reason: "link",
    });
  });
  it("finds a missing entry", async () => {
    const third = { ...second, id: "aud_ffffffffffffffffffffffffff", seq: 3, prev_hash: H2 };
    third.hash = await auditHash(third, "{}");
    expect(await verifyChain(p1([{ event: third, rawDetails: "{}" }, { event: first, rawDetails: D1 }]))).toEqual({ ok: false, seq: 3, reason: "gap" });
  });
  it("seq 1 must start from zeros", async () => {
    const bad = { ...first, prev_hash: "1".repeat(64) };
    bad.hash = await auditHash(bad, D1);
    expect(await verifyChain(p1([{ event: bad, rawDetails: D1 }]))).toEqual({ ok: false, seq: 1, reason: "start" });
  });
  it("refuses hashes that aren't 64 lowercase hex digits", async () => {
    for (const bad of [{ hash: H1.toUpperCase() }, { hash: H1.slice(2) }, { prev_hash: "0".repeat(63) + "g" }]) {
      expect(await verifyChain(p1([{ event: { ...first, ...bad }, rawDetails: D1 }]))).toEqual({ ok: false, seq: 1, reason: "hash" });
    }
  });
  it("reports a page whose raw details couldn't be read", async () => {
    const entries = [chain[0]!, { ...chain[1]!, rawDetails: null, page: 2 }];
    expect(await verifyChain(entries)).toEqual({ ok: false, page: 2, reason: "page" });
  });
  it("can't judge the link below the oldest loaded entry", async () => {
    expect(await verifyChain([chain[0]!])).toEqual({ ok: true, checked: 1, fromSeq: 2, toSeq: 2 });
  });
});

describe("raw details and JSON.parse agree", () => {
  it("a duplicate details key: the last one wins in both", () => {
    const body = `{"items":[{"details":{"a":1},"id":"x","details":{"b":2}}]}`;
    expect(detailsSpans(body)).toEqual(['{"b":2}']);
    expect((JSON.parse(body) as { items: { details: unknown }[] }).items[0]!.details).toEqual({ b: 2 });
  });
  it("numbers of any length are read", () => {
    expect(detailsSpans(`{"items":[{"details":{"n":${"9".repeat(80)}}}]}`)).toEqual([`{"n":${"9".repeat(80)}}`]);
  });
});

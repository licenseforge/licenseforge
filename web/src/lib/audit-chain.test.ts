import { describe, expect, it } from "vitest";
import { auditHash, detailsSpans, verifyChain } from "./audit-chain";

// Vectors from the server's audit.Hash (internal/audit), not from this code.
const ZERO = "0".repeat(64);
const H1 = "80eb4bb09a6fcc47a920048909d9ce291140f66c23817980b577d5d9dd632f57";
const H2 = "22a81332267713fa765caf9ba6e320800f4a9572ac78348a8d44a4703828a9d3";
// An escape (backslash u00e9) and escaped quotes, built from char codes so no tool rewrites them: the hash
// covers them as sent, and re-serializing would change them.
const BS = String.fromCharCode(92);
const D1 = `{"note":"<a&b> ü ${BS}u00e9 ${BS}"q${BS}"","i":1,"nested":{"x":[1,2]}}`;
const first = {
  id: "aud_aaaaaaaaaaaaaaaaaaaaaaaaaa", tenant_id: "tnt_bbbbbbbbbbbbbbbbbbbbbbbbbb", seq: 1, occurred_at: "2026-11-05T05:23:00.120000Z",
  actor_type: "user" as const, actor_id: "usr_cccccccccccccccccccccccccc", action: "license.issue",
  object_type: "license", object_id: "lic_dddddddddddddddddddddddddd", outcome: "success" as const,
  source_ip: "203.0.113.7", user_agent: 'Mozilla/5.0 "quoted"', details: JSON.parse(D1) as Record<string, unknown>, prev_hash: ZERO, hash: H1,
};
const second = {
  id: "aud_eeeeeeeeeeeeeeeeeeeeeeeeee", tenant_id: first.tenant_id, seq: 2, occurred_at: "2026-11-05T05:23:01.120000Z",
  actor_type: "system" as const, actor_id: null, action: "audit.prune", object_type: null, object_id: null, outcome: "failure" as const,
  source_ip: null, user_agent: null, details: {}, prev_hash: H1, hash: H2,
};

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

describe("verifyChain (newest first)", () => {
  const chain = [{ event: second, rawDetails: "{}" }, { event: first, rawDetails: D1 }];
  it("accepts an intact chain from seq 1", async () => {
    expect(await verifyChain(chain)).toEqual({ ok: true, checked: 2, fromSeq: 1, toSeq: 2 });
  });
  it("finds a changed field", async () => {
    expect(await verifyChain([chain[0]!, { event: { ...first, action: "license.revoke" }, rawDetails: D1 }])).toEqual({ ok: false, seq: 1, reason: "hash" });
  });
  it("finds changed details", async () => {
    expect(await verifyChain([chain[0]!, { event: first, rawDetails: D1.replace("1", "2") }])).toEqual({ ok: false, seq: 1, reason: "hash" });
  });
  it("finds a broken link", async () => {
    // a self-consistent entry 2 that doesn't point at entry 1
    const forged = { ...second, prev_hash: ZERO };
    forged.hash = await auditHash(forged, "{}");
    expect(await verifyChain([{ event: forged, rawDetails: "{}" }, chain[1]!])).toEqual({ ok: false, seq: 2, reason: "link" });
  });
  it("finds a missing entry", async () => {
    const third = { ...second, id: "aud_ffffffffffffffffffffffffff", seq: 3, prev_hash: H2 };
    third.hash = await auditHash(third, "{}");
    expect(await verifyChain([{ event: third, rawDetails: "{}" }, chain[1]!])).toEqual({ ok: false, seq: 3, reason: "gap" });
  });
  it("seq 1 must start from zeros", async () => {
    const bad = { ...first, prev_hash: "1".repeat(64) };
    bad.hash = await auditHash(bad, D1);
    expect(await verifyChain([{ event: bad, rawDetails: D1 }])).toEqual({ ok: false, seq: 1, reason: "start" });
  });
  it("can't judge the link below the oldest loaded entry", async () => {
    expect(await verifyChain([chain[0]!])).toEqual({ ok: true, checked: 1, fromSeq: 2, toSeq: 2 });
  });
});

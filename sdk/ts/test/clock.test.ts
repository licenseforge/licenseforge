// The clock guard (ADR-0018): the Go SDK's clock tests, ported.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { check, ClockError, type ClockStore, FileClockStore, Guard, MemoryClockStore, parseClaims, LicenseError } from "../src/index.js";

const t0 = new Date("2026-11-15T12:00:00Z");
const at = (ms: number) => new Date(t0.getTime() + ms);
const H = 3600_000;
const rollback = (e: unknown) => e instanceof ClockError && e.code === "rollback";

class FlakyStore implements ClockStore {
  b: Uint8Array | undefined;
  failSave = false;
  failLoad = false;
  load() {
    if (this.failLoad) throw new Error("EIO");
    return this.b;
  }
  save(s: Uint8Array) {
    if (this.failSave) throw new Error("EROFS");
    this.b = s;
  }
}

test("never moves backwards; a rollback beyond the tolerance is refused", () => {
  const g = new Guard(new MemoryClockStore(), "LF-KEY");
  assert.deepEqual(g.now(t0), { now: t0, persisted: true });
  const later = at(48 * H);
  g.now(later);
  assert.deepEqual(g.now(at(48 * H - 23 * H)).now, later, "small rollback: the mark");
  assert.throws(() => g.now(at(48 * H - 24 * H - 1000)), rollback);
  assert.doesNotThrow(() => g.now(at(48 * H - 24 * H)), "exactly at the tolerance");
});

test("tolerance options and inputs", () => {
  const strict = new Guard(new MemoryClockStore(), "k", { toleranceSeconds: 0 });
  strict.now(t0);
  assert.throws(() => strict.now(at(-1000)), rollback);
  assert.throws(() => new Guard(new MemoryClockStore(), "k", { toleranceSeconds: -1 }), RangeError);
  assert.throws(() => new Guard(new MemoryClockStore(), ""), TypeError);
  assert.throws(() => strict.now(new Date(Number.NaN)), TypeError);
});

test("observe caps future times and never lowers the mark", () => {
  const g = new Guard(new MemoryClockStore(), "k");
  g.observe(at(72 * H), t0); // a vendor clock 3 days fast
  assert.deepEqual(g.now(t0).now, at(24 * H), "capped at local + tolerance");
  assert.doesNotThrow(() => g.now(at(60_000)), "the honest clock right after");
  g.observe(at(-H), t0);
  assert.deepEqual(g.now(t0).now, at(24 * H));
});

test("the guard doesn't hide the license's future-iat check", () => {
  const g = new Guard(new MemoryClockStore(), "k");
  const c = parseClaims(new TextEncoder().encode(`{"v":1,"lid":"l","product":"p","iat":"2026-11-18T12:00:00Z"}`));
  assert.throws(() => check(c, { now: g.now(t0).now, product: "p" }), (e) => e instanceof LicenseError && e.code === "clock_skew");
});

test("reset can lower the mark (the online way out)", () => {
  const g = new Guard(new MemoryClockStore(), "k");
  g.now(at(30 * 24 * H));
  assert.throws(() => g.now(t0), rollback);
  g.reset(t0);
  assert.deepEqual(g.now(t0).now, t0);
});

test("a read-only store doesn't lock out; rollback still detected from the last saved mark", () => {
  const s = new FlakyStore();
  const g = new Guard(s, "k");
  g.now(t0);
  s.failSave = true;
  assert.deepEqual(g.now(at(H)), { now: at(H), persisted: false });
  assert.throws(() => g.now(at(-25 * H)), rollback);
  s.failSave = false;
  s.failLoad = true; // unreadable: no state, like deletion; not persisted
  assert.equal(g.now(at(-25 * H)).persisted, false);
});

test("writes only when the mark moves a minute", () => {
  const s = new FlakyStore();
  const g = new Guard(s, "k");
  g.now(t0);
  const before = Buffer.from(s.b!).toString();
  g.now(at(30_000));
  assert.equal(Buffer.from(s.b!).toString(), before);
  g.now(at(60_000));
  assert.notEqual(Buffer.from(s.b!).toString(), before);
});

test("tampered, foreign or corrupt state counts as none", () => {
  const s = new FlakyStore();
  const g = new Guard(s, "k");
  g.now(at(30 * 24 * H));
  const edited = Buffer.from(s.b!).toString().replace('"mark":"2026', '"mark":"2099');
  s.b = Buffer.from(edited);
  assert.deepEqual(g.now(at(30 * 24 * H)).now, at(30 * 24 * H), "an edited mark isn't trusted");
  const s2 = new FlakyStore();
  new Guard(s2, "k").now(at(30 * 24 * H));
  assert.doesNotThrow(() => new Guard(s2, "LF-RENEWED-KEY").now(t0), "a new key starts fresh");
  for (const b of ["", '{"mark":"2026-11-15T12:0', "garbage", '{"mark":1,"mac":2}', "null"]) {
    s.b = Buffer.from(b);
    assert.doesNotThrow(() => g.now(t0), b);
  }
});

test("FileClockStore: written atomically, mode 0600; a missing file is no state", () => {
  const dir = mkdtempSync(join(tmpdir(), "lf-clock-"));
  const path = join(dir, "clock.json");
  const g = new Guard(new FileClockStore(path), "k");
  assert.equal(new FileClockStore(path).load(), undefined);
  g.now(at(10 * 24 * H));
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.match(readFileSync(path, "utf8"), /"mark":"2026-11-25T12:00:00.000Z"/);
  assert.throws(() => new Guard(new FileClockStore(path), "k").now(t0), rollback, "another guard reads the same file");
  writeFileSync(path, "garbage");
  assert.doesNotThrow(() => g.now(t0), "a corrupt file is no state");
});

test("FileClockStore: an unwritable directory or unreadable path doesn't lock out", { skip: process.getuid?.() === 0 }, () => {
  const dir = mkdtempSync(join(tmpdir(), "lf-clock-ro-"));
  chmodSync(dir, 0o500);
  try {
    assert.deepEqual(new Guard(new FileClockStore(join(dir, "clock.json")), "k").now(t0), { now: t0, persisted: false });
  } finally {
    chmodSync(dir, 0o700);
  }
  const d2 = mkdtempSync(join(tmpdir(), "lf-clock-dir-"));
  mkdirSync(join(d2, "clock.json")); // reading a directory fails
  assert.equal(new Guard(new FileClockStore(join(d2, "clock.json")), "k").now(t0).persisted, false);
});

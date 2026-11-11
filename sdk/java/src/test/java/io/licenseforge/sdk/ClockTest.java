package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import io.licenseforge.sdk.Clock.ClockException;
import io.licenseforge.sdk.Clock.FileStore;
import io.licenseforge.sdk.Clock.Guard;
import io.licenseforge.sdk.Clock.MemoryStore;
import io.licenseforge.sdk.Clock.Now;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The clock guard (ADR-0018): the Go and TypeScript SDKs' clock tests, ported. */
class ClockTest {
  static final Instant T0 = Instant.parse("2026-11-15T12:00:00Z");
  static final Duration H = Duration.ofHours(1);

  static Instant at(Duration d) {
    return T0.plus(d);
  }

  static void rollback(Guard g, Instant local) {
    assertEquals(ClockException.Code.ROLLBACK, assertThrows(ClockException.class, () -> g.now(local)).code());
  }

  /** A store that can fail reads or writes. */
  static final class Flaky implements Clock.Store {
    byte[] b;
    boolean failSave;
    boolean failLoad;

    @Override
    public boolean update(UnaryOperator<byte[]> fn) {
      byte[] next = fn.apply(failLoad ? null : b);
      if (next != null && !failSave) b = next;
      return !failLoad && (next == null || !failSave);
    }
  }

  @Test
  void neverBackwards() throws Exception {
    Guard g = new Guard(new MemoryStore(), "LF-KEY");
    assertEquals(new Now(T0, true), g.now(T0));
    Instant later = at(H.multipliedBy(48));
    g.now(later);
    assertEquals(later, g.now(at(H.multipliedBy(25))).now(), "small rollback: the mark");
    rollback(g, at(H.multipliedBy(24).minusSeconds(1)));
    assertDoesNotThrow(() -> g.now(at(H.multipliedBy(24))), "exactly at the tolerance");
  }

  @Test
  void toleranceAndInputs() throws Exception {
    Guard strict = new Guard(new MemoryStore(), "k", Duration.ZERO);
    strict.now(T0);
    rollback(strict, T0.minusSeconds(1));
    assertThrows(IllegalArgumentException.class, () -> new Guard(new MemoryStore(), "k", Duration.ofSeconds(-1)));
    assertThrows(IllegalArgumentException.class, () -> new Guard(new MemoryStore(), "k", Duration.ofDays(36501)));
    assertThrows(IllegalArgumentException.class, () -> new Guard(new MemoryStore(), ""));
    assertThrows(NullPointerException.class, () -> strict.now(null));
  }

  @Test
  void observeCapsAndNeverLowers() throws Exception {
    Guard g = new Guard(new MemoryStore(), "k");
    g.observe(at(H.multipliedBy(72)), T0); // a vendor clock 3 days fast
    assertEquals(at(H.multipliedBy(24)), g.now(T0).now(), "capped at local + tolerance");
    assertDoesNotThrow(() -> g.now(T0.plusSeconds(60)), "the honest clock right after");
    g.observe(T0.minus(H), T0);
    assertEquals(at(H.multipliedBy(24)), g.now(T0).now());
  }

  @Test
  void guardDoesNotHideFutureIat() throws Exception {
    Guard g = new Guard(new MemoryStore(), "k");
    Claims c = LicenseFile.parseClaims("{\"v\":1,\"lid\":\"l\",\"product\":\"p\",\"iat\":\"2026-11-18T12:00:00Z\"}".getBytes(StandardCharsets.UTF_8));
    LicenseException e = assertThrows(LicenseException.class, () -> LicenseFile.check(c, CheckOptions.of(g.now(T0).now(), "p")));
    assertEquals(LicenseException.Code.CLOCK_SKEW, e.code());
  }

  @Test
  void resetLowers() throws Exception {
    Guard g = new Guard(new MemoryStore(), "k");
    g.now(at(Duration.ofDays(30)));
    rollback(g, T0);
    g.reset(T0);
    assertEquals(T0, g.now(T0).now());
  }

  @Test
  void readOnlyStoreDoesNotLockOut() throws Exception {
    Flaky s = new Flaky();
    Guard g = new Guard(s, "k");
    g.now(T0);
    s.failSave = true;
    assertEquals(new Now(at(H), false), g.now(at(H)));
    rollback(g, T0.minus(H.multipliedBy(25)));
    s.failSave = false;
    s.failLoad = true; // unreadable: no state, like deletion; not persisted
    assertFalse(g.now(T0.minus(H.multipliedBy(25))).persisted());
  }

  @Test
  void writesOnlyWhenTheMarkMovesAMinute() throws Exception {
    Flaky s = new Flaky();
    Guard g = new Guard(s, "k");
    g.now(T0);
    String before = new String(s.b, StandardCharsets.UTF_8);
    g.now(T0.plusSeconds(30));
    assertEquals(before, new String(s.b, StandardCharsets.UTF_8));
    g.now(T0.plusSeconds(60));
    assertNotEquals(before, new String(s.b, StandardCharsets.UTF_8));
  }

  @Test
  void tamperedForeignOrCorruptStateIsNone() throws Exception {
    Flaky s = new Flaky();
    Guard g = new Guard(s, "k");
    Instant late = at(Duration.ofDays(30));
    g.now(late);
    s.b = new String(s.b, StandardCharsets.UTF_8).replace("\"mark\":\"2026", "\"mark\":\"2099").getBytes(StandardCharsets.UTF_8);
    assertEquals(late, g.now(late).now(), "an edited mark isn't trusted");
    Flaky s2 = new Flaky();
    new Guard(s2, "k").now(late);
    assertDoesNotThrow(() -> new Guard(s2, "LF-RENEWED-KEY").now(T0), "a new key starts fresh");
    for (String b : List.of("", "{\"mark\":\"2026-11-15T12:0", "garbage", "{\"mark\":1,\"mac\":2}", "null", "{\"mark\":\"x\",\"mac\":\"!!\"}")) {
      s.b = b.getBytes(StandardCharsets.UTF_8);
      assertDoesNotThrow(() -> g.now(T0), b);
    }
  }

  @Test
  void fileStore(@TempDir Path dir) throws Exception {
    Path p = dir.resolve("clock.json");
    Guard g = new Guard(new FileStore(p), "k");
    g.now(at(Duration.ofDays(10)));
    if (!System.getProperty("os.name").startsWith("Windows")) assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(p)));
    assertTrue(Files.readString(p).contains("\"mark\":\"2026-11-25T12:00:00Z\""));
    rollback(new Guard(new FileStore(p), "k"), T0); // another guard reads the same file
    Files.writeString(p, "garbage");
    assertDoesNotThrow(() -> g.now(T0), "a corrupt file is no state");
    try (Stream<Path> s = Files.list(dir)) {
      assertEquals(List.of("clock.json", "clock.json.lock"), s.map(x -> x.getFileName().toString()).sorted().toList());
    }
  }

  @Test
  void fileStoreFailures(@TempDir Path dir) throws Exception {
    assumeFalse("root".equals(System.getProperty("user.name")));
    Path p = dir.resolve("clock.json");
    Files.createDirectory(p); // the rename onto a directory and the read fail
    assertFalse(new Guard(new FileStore(p), "k").now(T0).persisted());
    try (Stream<Path> s = Files.list(dir)) {
      assertEquals(List.of("clock.json", "clock.json.lock"), s.map(x -> x.getFileName().toString()).sorted().toList(), "no temp file left");
    }
    if (System.getProperty("os.name").startsWith("Windows")) return;
    Path ro = Files.createDirectory(dir.resolve("ro"));
    Files.setPosixFilePermissions(ro, PosixFilePermissions.fromString("r-x------"));
    try {
      assertEquals(new Now(T0, false), new Guard(new FileStore(ro.resolve("clock.json")), "k").now(T0));
    } finally {
      Files.setPosixFilePermissions(ro, PosixFilePermissions.fromString("rwx------"));
    }
  }

  @Test
  void lockHeldOrStateUnreadable(@TempDir Path dir) throws Exception {
    assumeFalse("root".equals(System.getProperty("user.name")));
    Path p = dir.resolve("clock.json");
    // Another holder of the lock for the whole wait: the check runs, the write is skipped.
    try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(dir.resolve("clock.json.lock"),
        java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE); java.nio.channels.FileLock l = ch.lock()) {
      assertTrue(l.isValid());
      assertEquals(new Now(T0, false), new Guard(new FileStore(p), "k").now(T0));
    }
    assertFalse(Files.exists(p));
    // An unreadable file counts as no state and is reported as not persisted, even when the write works.
    new Guard(new FileStore(p), "k").now(T0);
    if (System.getProperty("os.name").startsWith("Windows")) return;
    Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("---------"));
    assertFalse(new Guard(new FileStore(p), "k").now(T0.plus(H)).persisted());
  }

  @Test
  void concurrentGuardsOnOneFile(@TempDir Path dir) throws Exception {
    Path p = dir.resolve("clock.json");
    Thread[] ts = new Thread[8];
    for (int i = 0; i < ts.length; i++) {
      Instant mine = T0.plus(Duration.ofMinutes(i * 2L));
      ts[i] = new Thread(() -> new Guard(new FileStore(p), "k").observe(mine, mine));
      ts[i].start();
    }
    for (Thread t : ts) t.join();
    // Serialized: the highest raise survives.
    assertEquals(T0.plus(Duration.ofMinutes(14)), new Guard(new FileStore(p), "k").now(T0).now());
  }
}

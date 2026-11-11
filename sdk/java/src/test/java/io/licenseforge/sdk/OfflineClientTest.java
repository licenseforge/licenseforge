package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.licenseforge.sdk.Claims.BindingType;
import io.licenseforge.sdk.Fingerprints.Fingerprint;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/** The offline client: the Go SDK's offline tests (sdk/go/offline), ported. */
class OfflineClientTest {
  static final String TENANT = "tnt_01jcz5b2y3c4d5e6f7g8h9j0k1";
  static final String MACHINE = "sha256:81fe9b1a2812e068c320c4264f01b6d4d186a83cc0008fe954fd5d1b6e3f3684";
  static final String OTHER = "sha256:" + "0".repeat(64);
  static final List<PublicKey> KEYS = List.of(new PublicKey("k1", "ed25519", Base64.getUrlDecoder().decode("K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k")));
  static final Fingerprint FP = new Fingerprint(MACHINE, FingerprintSource.MACHINE_ID, BindingType.MACHINE);
  static final Instant T0 = Instant.parse("2026-11-09T12:00:00Z");
  static final Duration H = Duration.ofHours(1);

  static final class MemStore implements Clock.Store {
    byte[] b;
    boolean failSave;

    @Override
    public synchronized boolean update(UnaryOperator<byte[]> fn) {
      byte[] next = fn.apply(b == null ? null : b.clone());
      if (next == null) return true;
      if (failSave) return false;
      b = next;
      return true;
    }
  }

  /** A license file: this tenant, product and machine, issued an hour before T0, valid a day, unless changed. */
  record F(String lid, String tenant, String product, Instant iat, Instant exp, String grace, Instant updatesUntil, String bind, byte[] seed) {
    static F of() {
      return new F("lic_a", TENANT, "acme-db", T0.minus(H), null, null, null, "{\"type\":\"machine\",\"fp\":\"" + MACHINE + "\"}",
          "licenseforge-test-vector-seed-01".getBytes(StandardCharsets.US_ASCII));
    }

    F lid(String v) {
      return new F(v, tenant, product, iat, exp, grace, updatesUntil, bind, seed);
    }

    F tenant(String v) {
      return new F(lid, v, product, iat, exp, grace, updatesUntil, bind, seed);
    }

    F product(String v) {
      return new F(lid, tenant, v, iat, exp, grace, updatesUntil, bind, seed);
    }

    F iat(Instant v) {
      return new F(lid, tenant, product, v, exp, grace, updatesUntil, bind, seed);
    }

    F exp(Instant v) {
      return new F(lid, tenant, product, iat, v, grace, updatesUntil, bind, seed);
    }

    F grace(String v) {
      return new F(lid, tenant, product, iat, exp, v, updatesUntil, bind, seed);
    }

    F updatesUntil(Instant v) {
      return new F(lid, tenant, product, iat, exp, grace, v, bind, seed);
    }

    F bind(String v) {
      return new F(lid, tenant, product, iat, exp, grace, updatesUntil, v, seed);
    }

    F seed(byte[] v) {
      return new F(lid, tenant, product, iat, exp, grace, updatesUntil, bind, v);
    }

    String sign() throws Exception {
      String p = "{\"v\":1,\"lid\":\"" + lid + "\",\"tenant\":\"" + tenant + "\",\"product\":\"" + product + "\",\"plan\":\"pro\",\"iat\":\"" + iat
          + "\",\"exp\":\"" + (exp == null ? iat.plus(Duration.ofDays(1)) : exp) + "\"" + (grace == null ? "" : ",\"grace\":\"" + grace + "\"")
          + (updatesUntil == null ? "" : ",\"updates_until\":\"" + updatesUntil + "\"") + ",\"bind\":" + bind + "}";
      String msg = "lf1.k1." + Base64.getUrlEncoder().withoutPadding().encodeToString(p.getBytes(StandardCharsets.UTF_8));
      PrivateKey k = KeyFactory.getInstance("Ed25519").generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
      Signature s = Signature.getInstance("Ed25519");
      s.initSign(k);
      s.update(msg.getBytes(StandardCharsets.US_ASCII));
      return msg + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign());
    }
  }

  static OfflineClient.Config cfg(MemStore store) {
    return OfflineClient.Config.builder(TENANT, "acme-db", "LF-ABCDE-FGHIJ", KEYS, FP, store).hostname("air-1");
  }

  static OfflineClient client(MemStore store) {
    return new OfflineClient(cfg(store));
  }

  static OfflineClient withClock(MemStore store, Clock.Guard g, Duration tolerance) {
    OfflineClient.Config c = cfg(store).clock(g);
    return new OfflineClient(tolerance == null ? c : c.clockTolerance(tolerance));
  }

  interface Call {
    void run() throws Exception;
  }

  /** "ok", or the refusal's code. */
  static String code(Call c) {
    try {
      c.run();
      return "ok";
    } catch (OfflineClient.OfflineException e) {
      return e.code().name();
    } catch (LicenseException e) {
      return e.code().name();
    } catch (Clock.ClockException e) {
      return e.code().name();
    } catch (Exception e) {
      return e.getClass().getSimpleName() + ": " + e.getMessage();
    }
  }

  static final String MACHINE_BIND = "{\"type\":\"machine\",\"fp\":\"" + MACHINE + "\"}";

  @Test
  void request() throws Exception {
    OfflineClient c = client(new MemStore());
    Offline.ActivationRequest r = Offline.parseRequest(c.request(T0));
    assertEquals(TENANT, r.tenant());
    assertEquals("acme-db", r.product());
    assertEquals("LF-ABCDE-FGHIJ", r.key());
    assertEquals(MACHINE, r.binding().fingerprint());
    assertEquals(BindingType.MACHINE, r.binding().type());
    assertEquals(FingerprintSource.MACHINE_ID, r.fpSource());
    assertEquals(Optional.of("air-1"), r.hostname());
    assertTrue(r.sdkVersion().orElseThrow().startsWith("java/"));
    assertEquals(T0, r.created());
    assertEquals(16, r.nonce().length);
    assertFalse(Arrays.equals(r.nonce(), Offline.parseRequest(c.request(T0)).nonce()));
  }

  @Test
  void installCurrentDeactivate() throws Exception {
    MemStore store = new MemStore();
    OfflineClient c = client(store);
    assertEquals("NO_LICENSE", code(() -> c.current(T0)));
    String f = F.of().sign();
    LicenseFile.Opened got = c.install(f, T0);
    assertEquals(LicenseFile.Status.VALID, got.status());
    assertEquals("lic_a", got.claims().licenseId());
    // Another client on the same store (another process) sees it.
    OfflineClient c2 = client(store);
    assertEquals(LicenseFile.Status.VALID, c2.current(T0).status());
    assertEquals("EXPIRED", code(() -> c2.current(T0.plus(Duration.ofHours(24)))));
    Offline.DeactivationReceipt r = Offline.parseReceipt(c.deactivate(T0));
    assertEquals(List.of(TENANT, "lic_a", MACHINE, Offline.fileSha256(f)), List.of(r.tenant(), r.licenseId(), r.fingerprint(), r.fileSha256()));
    assertEquals("NO_LICENSE", code(() -> c.current(T0)));
    assertEquals("NO_LICENSE", code(() -> c.deactivate(T0)));
    assertEquals("RETURNED", code(() -> c.install(f, T0)));
    assertEquals("RETURNED", code(() -> c.install(F.of().iat(T0.minus(H).minusSeconds(60)).sign(), T0)));
    assertEquals("ok", code(() -> c.install(F.of().iat(T0.minus(H).plusSeconds(60)).sign(), T0))); // newer
    // Another license's file waits until lic_a is deactivated.
    String b = F.of().lid("lic_b").sign();
    assertEquals("OTHER_LICENSE", code(() -> c.install(b, T0)));
    c.deactivate(T0);
    assertEquals("ok", code(() -> c.install(b, T0)));
    // Deactivate saves before it answers: on a failed write, no receipt and the file stays.
    store.failSave = true;
    assertTrue(code(() -> c.deactivate(T0)).startsWith("IOException"));
    store.failSave = false;
    assertEquals("lic_b", c.current(T0).claims().licenseId());
    // An expired file can still be returned.
    assertEquals("ok", code(() -> c.deactivate(T0.plus(Duration.ofHours(48)))));
  }

  @Test
  void olderFile() throws Exception {
    MemStore store = new MemStore();
    OfflineClient c = client(store);
    String old = F.of().sign();
    String renewed = F.of().iat(T0.minus(H).plusSeconds(60)).sign();
    c.install(renewed, T0);
    assertEquals("OLDER_FILE", code(() -> c.install(old, T0)));
    assertEquals(T0.minus(H).plusSeconds(60), c.current(T0).claims().issuedAt());
    assertEquals("ok", code(() -> c.install(renewed, T0))); // the same file again
    // An installed file that no longer verifies here blocks nothing.
    OfflineClient moved = new OfflineClient(OfflineClient.Config.builder(TENANT, "acme-db", "LF-ABCDE-FGHIJ", KEYS,
        new Fingerprint(OTHER, FingerprintSource.MACHINE_ID, BindingType.MACHINE), store));
    assertEquals("ok", code(() -> moved.install(F.of().bind("{\"type\":\"machine\",\"fp\":\"" + OTHER + "\"}").sign(), T0)));
  }

  @Test
  void graceUpdatesUntilAndBinding() throws Exception {
    MemStore store = new MemStore();
    OfflineClient c = client(store);
    assertEquals(LicenseFile.Status.GRACE, c.install(F.of().exp(T0.minusSeconds(600)).grace("PT1H").sign(), T0).status());
    OfflineClient built = new OfflineClient(cfg(store).buildDate(T0));
    assertEquals("ok", code(() -> built.current(T0)));
    c.install(F.of().iat(T0.minus(H).plusSeconds(1)).updatesUntil(T0.minus(Duration.ofHours(24))).sign(), T0);
    assertEquals("UPDATES_EXPIRED", code(() -> built.current(T0)));
    assertEquals("BAD_FILE", code(() -> c.install(F.of().bind("{\"type\":\"cluster\",\"fp\":\"" + MACHINE + "\"}").sign(), T0)));
  }

  @Test
  void state() throws Exception {
    MemStore store = new MemStore();
    OfflineClient c = client(store);
    for (String s : List.of("{not json", "null", "{}", "[]", "{\"offline\":1,\"file\":5}", "{\"offline\":1,\"returned\":{\"lic_a\":\"x\"}}",
        "{\"offline\":1,\"file\":\"" + F.of().sign() + "\",\"returned\":{\"lic_a\":\"x\"}}")) {
      store.b = s.getBytes(StandardCharsets.UTF_8);
      assertEquals("NO_LICENSE", code(() -> c.current(T0)), s);
    }
    assertEquals("ok", code(() -> c.install(F.of().sign(), T0))); // repairs it
    byte[] guard = "{\"mark\":\"2026-11-09T12:00:00Z\",\"mac\":\"x\"}".getBytes(StandardCharsets.UTF_8); // the clock guard's state
    store.b = guard.clone();
    assertEquals("FOREIGN_STATE", code(() -> c.current(T0)));
    assertEquals("FOREIGN_STATE", code(() -> c.install(F.of().sign(), T0)));
    assertArrayEquals(guard, store.b, "left as it was");
    store.b = "{\"offline\":2}".getBytes(StandardCharsets.UTF_8); // another version's
    assertEquals("FOREIGN_STATE", code(() -> c.current(T0)));
  }

  @Test
  void installRefusalsStoreNothing() throws Exception {
    MemStore store = new MemStore();
    OfflineClient c = client(store);
    assertEquals("BAD_FILE", code(() -> c.install(F.of().bind("{\"type\":\"machine\",\"fp\":\"" + OTHER + "\"}").sign(), T0)), "other machine");
    assertEquals("BAD_FILE", code(() -> c.install(F.of().tenant("tnt_01jcz5b2y3c4d5e6f7g8h9j0k2").sign(), T0)), "other tenant");
    assertEquals("BAD_FILE", code(() -> c.install(F.of().product("other").sign(), T0)), "other product");
    assertEquals("BAD_FILE", code(() -> c.install(F.of().bind("{\"type\":\"none\"}").sign(), T0)), "unbound");
    assertEquals("EXPIRED", code(() -> c.install(F.of().iat(T0.minus(Duration.ofHours(48))).exp(T0.minus(H)).sign(), T0)), "expired");
    byte[] six = new byte[32];
    Arrays.fill(six, (byte) 6);
    assertEquals("BAD_FILE", code(() -> c.install(F.of().seed(six).sign(), T0)), "another key");
    assertEquals("BAD_FILE", code(() -> c.install("not a license", T0)), "garbage");
    assertNull(store.b);
  }

  @Test
  void clockGuard() throws Exception {
    // The vendor's clock an hour ahead, strict claim tolerance: only the guard makes the iat reachable.
    OfflineClient c = withClock(new MemStore(), new Clock.Guard(new MemStore(), "LF-ABCDE-FGHIJ"), Duration.ZERO);
    String ahead = F.of().iat(T0.plus(H)).sign();
    assertEquals(LicenseFile.Status.VALID, c.install(ahead, T0).status());
    assertEquals(LicenseFile.Status.VALID, c.current(T0).status()); // through the raised guard

    // A guard that can't be saved: refused, and nothing stored.
    MemStore unheld = new MemStore();
    unheld.failSave = true;
    MemStore s2 = new MemStore();
    OfflineClient c2 = withClock(s2, new Clock.Guard(unheld, "LF-ABCDE-FGHIJ"), Duration.ZERO);
    assertEquals("CLOCK_NOT_SAVED", code(() -> c2.install(ahead, T0)));
    assertNull(s2.b);
    // Five minutes fast needs no raise (the default claim tolerance).
    OfflineClient c3 = withClock(new MemStore(), new Clock.Guard(unheld, "LF-ABCDE-FGHIJ"), null);
    assertEquals("ok", code(() -> c3.install(F.of().iat(T0.plusSeconds(300)).sign(), T0)));

    // A file 100 h ahead is refused, leaving the installed file as it was.
    OfflineClient c4 = withClock(new MemStore(), new Clock.Guard(new MemStore(), "LF-ABCDE-FGHIJ"), null);
    c4.install(F.of().sign(), T0);
    assertFalse(code(() -> c4.install(F.of().iat(T0.plus(Duration.ofHours(100))).exp(T0.plus(Duration.ofHours(101))).sign(), T0)).equals("ok"));
    assertEquals(LicenseFile.Status.VALID, c4.current(T0).status());

    // A clock turned back past the tolerance stops the license.
    OfflineClient c5 = withClock(new MemStore(), new Clock.Guard(new MemStore(), "LF-ABCDE-FGHIJ", Duration.ZERO), null);
    c5.install(F.of().sign(), T0);
    assertEquals("ROLLBACK", code(() -> c5.current(T0.minus(Duration.ofHours(2)))));
  }

  @Test
  void guardRaiseStopsAtItsTolerance() throws Exception {
    OfflineClient exact = withClock(new MemStore(), new Clock.Guard(new MemStore(), "LF-ABCDE-FGHIJ", H), Duration.ZERO);
    assertEquals("ok", code(() -> exact.install(F.of().iat(T0.plus(H)).sign(), T0))); // exactly local + tolerance
    OfflineClient past = withClock(new MemStore(), new Clock.Guard(new MemStore(), "LF-ABCDE-FGHIJ", H), Duration.ZERO);
    assertEquals("CLOCK_SKEW", code(() -> past.install(F.of().iat(T0.plus(H).plusSeconds(1)).sign(), T0)));
    // A file failing its checks at its own iat doesn't raise the guard.
    Clock.Guard g = new Clock.Guard(new MemStore(), "LF-ABCDE-FGHIJ", H);
    OfflineClient built = new OfflineClient(cfg(new MemStore()).clock(g).clockTolerance(Duration.ZERO).buildDate(T0));
    assertEquals("UPDATES_EXPIRED", code(() -> built.install(F.of().iat(T0.plusSeconds(1800)).updatesUntil(T0.minus(Duration.ofHours(24))).sign(), T0)));
    assertEquals(T0, g.now(T0).now(), "the guard wasn't raised to the file's iat");
  }

  @Test
  void emptyFileCountsAsNone() {
    MemStore store = new MemStore();
    store.b = "{\"offline\":1,\"file\":\"\"}".getBytes(StandardCharsets.UTF_8);
    assertEquals("NO_LICENSE", code(() -> client(store).current(T0)));
  }

  @Test
  void config() {
    assertThrows(IllegalArgumentException.class, () -> OfflineClient.Config.builder(TENANT, "acme-db", "", KEYS, FP, new MemStore()));
    assertThrows(IllegalArgumentException.class, () -> OfflineClient.Config.builder(TENANT, "acme-db", "LF-1", KEYS,
        new Fingerprint(MACHINE, FingerprintSource.MACHINE_ID, BindingType.NONE), new MemStore()));
    // Later changes to the caller's Config don't reach a client.
    OfflineClient.Config c = cfg(new MemStore());
    OfflineClient client = new OfflineClient(c);
    c.buildDate(T0.plus(Duration.ofDays(9999))); // after updates_until: would refuse the file
    assertEquals("ok", code(() -> client.install(F.of().updatesUntil(T0.plus(Duration.ofDays(1))).sign(), T0)));
  }
}

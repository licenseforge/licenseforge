package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.licenseforge.sdk.Claims.BindingType;
import io.licenseforge.sdk.Fingerprints.Fingerprint;
import io.licenseforge.sdk.Online.Client;
import io.licenseforge.sdk.Online.Config;
import io.licenseforge.sdk.Online.Lease;
import io.licenseforge.sdk.Online.OnlineException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The online client: the Go and TypeScript SDKs' online tests, ported to a local server. */
class OnlineTest {
  static final byte[] SEED = "licenseforge-test-vector-seed-01".getBytes(StandardCharsets.US_ASCII);
  static final List<PublicKey> KEYS = List.of(new PublicKey("test:2026-11", "ed25519", Base64.getUrlDecoder().decode("K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k")));
  static final String FP = "sha256:" + "a".repeat(64);
  static final Fingerprint FINGERPRINT = new Fingerprint(FP, FingerprintSource.MACHINE_ID, BindingType.MACHINE);
  static final long NOW = Instant.parse("2026-11-10T12:00:00Z").toEpochMilli();
  static final long DAY = 86_400_000L;

  static String iso(long ms) {
    return Instant.ofEpochMilli(ms).toString();
  }

  record L(long iat, String tenant, String product, String fp, String bind, Long refreshAfter, Long exp, String kid, String maxOffline) {
    static L at(long iat) {
      return new L(iat, "tnt_acme", "acme-db", FP, "machine", null, null, "test:2026-11", null);
    }

    L tenant(String v) {
      return new L(iat, v, product, fp, bind, refreshAfter, exp, kid, maxOffline);
    }

    L product(String v) {
      return new L(iat, tenant, v, fp, bind, refreshAfter, exp, kid, maxOffline);
    }

    L fp(String v) {
      return new L(iat, tenant, product, v, bind, refreshAfter, exp, kid, maxOffline);
    }

    L bind(String v) {
      return new L(iat, tenant, product, fp, v, refreshAfter, exp, kid, maxOffline);
    }

    L refreshAfter(long v) {
      return new L(iat, tenant, product, fp, bind, v, exp, kid, maxOffline);
    }

    L exp(long v) {
      return new L(iat, tenant, product, fp, bind, refreshAfter, v, kid, maxOffline);
    }

    L kid(String v) {
      return new L(iat, tenant, product, fp, bind, refreshAfter, exp, v, maxOffline);
    }

    L maxOffline(String v) {
      return new L(iat, tenant, product, fp, bind, refreshAfter, exp, kid, v);
    }

    String sign() throws Exception {
      String b = bind.equals("none") ? "{\"type\":\"none\"}" : "{\"type\":\"" + bind + "\",\"fp\":\"" + fp + "\"}";
      String payload = "{\"v\":1,\"lid\":\"lic_1\",\"tenant\":\"" + tenant + "\",\"product\":\"" + product + "\",\"iat\":\"" + iso(iat) + "\",\"exp\":\""
          + iso(exp == null ? iat + 7 * DAY : exp) + "\",\"refresh_after\":\"" + iso(refreshAfter == null ? iat + 3_600_000 : refreshAfter) + "\",\"bind\":" + b
          + (maxOffline == null ? "" : ",\"max_offline\":\"" + maxOffline + "\"") + "}";
      String msg = "lf1." + kid + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
      PrivateKey k = KeyFactory.getInstance("Ed25519").generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, SEED));
      Signature s = Signature.getInstance("Ed25519");
      s.initSign(k);
      s.update(msg.getBytes(StandardCharsets.US_ASCII));
      return msg + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign());
    }
  }

  record Answer(int status, String body, String type, Map<String, String> headers, CountDownLatch hold) {
    static Answer of(int status) {
      return new Answer(status, "", "application/json", Map.of(), null);
    }
  }

  record Seen(String path, String auth, String idem, String body) {}

  static Answer ok(String lease) {
    return new Answer(200, "{\"lease\":\"" + lease + "\",\"activation_id\":\"act_1\"}", "application/json", Map.of(), null);
  }

  static Answer problem(int status, String code) {
    return new Answer(status, "{\"code\":\"" + code + "\",\"detail\":\"d\",\"request_id\":\"R1\"}", "application/problem+json", Map.of(), null);
  }

  HttpServer srv;
  String base;
  final ConcurrentLinkedDeque<Answer> answers = new ConcurrentLinkedDeque<>();
  final List<Seen> seen = Collections.synchronizedList(new ArrayList<>());

  @BeforeEach
  void start() throws Exception {
    srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    srv.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
      Thread t = new Thread(r);
      t.setDaemon(true);
      return t;
    }));
    srv.createContext("/", ex -> {
      String b = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      String idem = ex.getRequestHeaders().getFirst("Idempotency-Key");
      seen.add(new Seen(ex.getRequestURI().getRawPath(), ex.getRequestHeaders().getFirst("Authorization"), idem == null ? "" : idem, b));
      Answer a = answers.isEmpty() ? Answer.of(500) : answers.poll();
      if (a.hold() != null) {
        try {
          a.hold().await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      ex.getResponseHeaders().set("Content-Type", a.type());
      a.headers().forEach((k, v) -> ex.getResponseHeaders().set(k, v));
      byte[] out = a.body().getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(a.status(), a.status() == 204 || out.length == 0 ? -1 : out.length);
      if (out.length > 0 && a.status() != 204) {
        try (OutputStream o = ex.getResponseBody()) {
          o.write(out);
        }
      }
      ex.close();
    });
    srv.start();
    base = "http://127.0.0.1:" + srv.getAddress().getPort();
  }

  @AfterEach
  void stop() {
    srv.stop(0);
  }

  Client client(Config cfg) {
    Client c = Client.create(cfg);
    c.now = () -> NOW;
    c.sleeper = bounded(ms -> {}); // no real waits in tests
    return c;
  }

  /** A sleeper that fails after 50 calls: a run that never stops fails instead of hanging the build. */
  static Online.Sleeper bounded(Online.Sleeper inner) {
    int[] n = {0};
    return ms -> {
      if (++n[0] > 50) throw new AssertionError("run didn't stop");
      inner.sleep(ms);
    };
  }

  Config cfg() {
    return Config.builder(base, "tnt_acme", "acme-db", "LF-KEY", KEYS, FINGERPRINT).hostname("db-1").appVersion("2.0");
  }

  interface Call {
    Object run() throws Exception;
  }

  static String code(Call c) {
    try {
      c.run();
      return "ok";
    } catch (OnlineException e) {
      return e.code().spec();
    } catch (LicenseException e) {
      return e.code().spec();
    } catch (Clock.ClockException e) {
      return "clock:" + e.code().name().toLowerCase(java.util.Locale.ROOT);
    } catch (Exception e) {
      return "threw " + e;
    }
  }

  @Test
  void sdkVersionIsThePomVersion() throws Exception {
    String pom = Files.readString(Path.of("pom.xml"));
    String v = pom.substring(pom.indexOf("<version>") + 9, pom.indexOf("</version>"));
    assertEquals("java/" + v, Online.SDK_VERSION);
  }

  @Test
  void activate() throws Exception {
    Client c = client(cfg());
    answers.add(Answer.of(503));
    answers.add(ok(L.at(NOW).sign()));
    Lease l = c.activate();
    assertEquals("act_1", l.activationId());
    assertEquals("acme-db", l.claims().product());
    assertEquals(2, seen.size());
    assertEquals("/api/v1/activation/tenants/tnt_acme/activate", seen.get(0).path());
    assertEquals("License LF-KEY", seen.get(0).auth());
    assertTrue(seen.get(0).idem().length() >= 16 && seen.get(0).idem().equals(seen.get(1).idem()), "retries reuse one Idempotency-Key");
    assertEquals("{\"fingerprint\":\"" + FP + "\",\"fp_source\":\"machine-id\",\"sdk_version\":\"" + Online.SDK_VERSION + "\",\"hostname\":\"db-1\",\"app_version\":\"2.0\"}", seen.get(0).body());
    assertEquals(LicenseFile.Status.VALID, c.current().status());
    answers.add(ok(L.at(NOW + 1000).sign()));
    c.refresh();
    assertEquals("", seen.get(2).idem(), "refresh has no idempotency key");
  }

  @Test
  void aLeaseThatDoesNotVerifyIsNeverUsed() throws Exception {
    Client c = client(cfg());
    String good = L.at(NOW).sign();
    for (String bad : List.of(L.at(NOW).tenant("tnt_other").sign(), L.at(NOW).product("other").sign(), L.at(NOW).fp("sha256:" + "b".repeat(64)).sign(),
        L.at(NOW).bind("cluster").sign(), L.at(NOW).bind("none").sign(), L.at(NOW).kid("test:unknown").sign(), good.substring(0, good.length() - 2) + "AA")) {
      answers.add(ok(bad));
      assertEquals("bad_lease", code(c::activate), bad);
    }
    answers.add(new Answer(200, "not json", "application/json", Map.of(), null));
    answers.add(new Answer(200, "{}", "application/json", Map.of(), null));
    assertEquals("bad_lease", code(c::activate));
    assertEquals("bad_lease", code(c::activate));
    assertEquals("no_lease", code(c::current));
  }

  @Test
  void problemCodesAndRetries() throws Exception {
    Client c = client(cfg().maxAttempts(3));
    answers.add(problem(403, "license_revoked"));
    OnlineException e = assertThrows(OnlineException.class, c::activate);
    assertEquals(List.of(OnlineException.Code.LICENSE_REVOKED, 403, "R1"), List.of(e.code(), e.status(), e.requestId()));
    assertEquals(1, seen.size(), "a refusal isn't retried");
    answers.add(new Answer(403, "{\"code\":\"license_revoked\"}", "text/html", Map.of(), null));
    assertEquals("unexpected_status", code(c::activate), "a proxy page isn't a refusal, even with that text");
    Client once = client(cfg().maxAttempts(1));
    answers.add(new Answer(503, "{\"code\":\"license_revoked\"}", "application/problem+json", Map.of(), null));
    assertEquals("server_error", code(once::activate), "a 5xx problem never reads as revoked");
    answers.add(new Answer(503, "{\"code\":\"no_signing_key\",\"detail\":\"No key.\",\"request_id\":\"R5\"}", "application/problem+json", Map.of(), null));
    OnlineException e5 = assertThrows(OnlineException.class, once::activate);
    assertEquals(List.of(OnlineException.Code.SERVER_ERROR, "R5"), List.of(e5.code(), e5.requestId()));
    assertTrue(e5.getMessage().contains("no_signing_key: No key."), e5.getMessage());
    answers.add(new Answer(503, "{\"code\":\"license_revoked\"}", "application/problem+json", Map.of(), null));
    answers.add(Answer.of(503));
    answers.add(Answer.of(503));
    seen.clear();
    assertEquals("server_error", code(c::activate), "retried to the limit");
    assertEquals(3, seen.size());
    answers.add(problem(409, "idempotency_in_progress"));
    answers.add(problem(429, "rate_limited"));
    answers.add(ok(L.at(NOW).sign()));
    assertEquals("ok", code(c::activate));
    answers.add(new Answer(302, "", "text/html", Map.of("Location", "https://evil.example/"), null));
    assertEquals("unexpected_status", code(c::refresh), "redirects aren't followed");
  }

  @Test
  void retryAfterSetsTheWaitCapped() throws Exception {
    Client c = client(cfg());
    List<Long> waits = new ArrayList<>();
    c.sleeper = waits::add;
    answers.add(new Answer(503, "", "application/json", Map.of("Retry-After", "7"), null));
    answers.add(new Answer(429, "", "application/json", Map.of("Retry-After", "99999"), null));
    answers.add(ok(L.at(NOW).sign()));
    c.activate();
    assertEquals(List.of(7000L, 600_000L), waits);
    assertEquals(0, Online.parseRetryAfter("garbage", NOW));
    assertEquals(30_000, Online.parseRetryAfter("Tue, 10 Nov 2026 12:00:30 GMT", NOW));
  }

  @Test
  void store() throws Exception {
    AtomicReference<String> stored = new AtomicReference<>("");
    Online.LeaseStore s = new Online.LeaseStore() {
      @Override
      public String load() {
        return stored.get();
      }

      @Override
      public void save(String l) {
        stored.set(l);
      }
    };
    Client c = client(cfg().store(s));
    assertEquals(List.of(), c.takeWarnings());
    answers.add(ok(L.at(NOW).sign()));
    Lease l = c.activate();
    assertEquals(l.file(), stored.get());
    assertEquals("lic_1", client(cfg().store(s)).current().claims().licenseId(), "the stored lease, verified again");
    stored.set(L.at(NOW).tenant("tnt_other").sign());
    Client bad = client(cfg().store(s));
    assertEquals("no_lease", code(bad::current));
    assertTrue(bad.takeWarnings().get(0).getMessage().contains("stored lease not used"));
    assertTrue(client(cfg()).takeWarnings().get(0).getMessage().contains("memory only"), "no store: a warning");
    c.forget();
    assertEquals("", stored.get(), "forget clears the store");
  }

  @Test
  void replayAndForget() throws Exception {
    Client c = client(cfg());
    answers.add(ok(L.at(NOW + 30 * DAY).sign()));
    answers.add(ok(L.at(NOW).sign()));
    c.activate();
    assertEquals("bad_lease", code(c::refresh));
    c.forget();
    answers.add(ok(L.at(NOW).sign()));
    assertEquals("ok", code(c::refresh));
  }

  @Test
  void forgetWhileACallIsInFlight() throws Exception {
    Client c = client(cfg());
    CountDownLatch release = new CountDownLatch(1);
    Answer held = ok(L.at(NOW).sign());
    answers.add(new Answer(held.status(), held.body(), held.type(), Map.of(), release));
    AtomicReference<String> result = new AtomicReference<>();
    Thread t = new Thread(() -> result.set(code(c::activate)));
    t.start();
    for (int i = 0; seen.isEmpty(); i++) {
      assertTrue(i < 2000, "the request never arrived");
      Thread.sleep(5);
    }
    c.forget();
    release.countDown();
    t.join(10_000);
    assertEquals("superseded", result.get());
    assertEquals("no_lease", code(c::current));
  }

  @Test
  void deactivate() throws Exception {
    Client c = client(cfg());
    answers.add(ok(L.at(NOW).sign()));
    answers.add(Answer.of(204));
    c.activate();
    c.deactivate();
    assertEquals("{\"fingerprint\":\"" + FP + "\"}", seen.get(1).body());
    assertEquals("no_lease", code(c::current));
    answers.add(problem(404, "not_activated"));
    assertEquals("ok", code(() -> {
      c.deactivate();
      return null;
    }));
    answers.add(problem(401, "unauthenticated"));
    assertEquals("unauthenticated", code(() -> {
      c.deactivate();
      return null;
    }));
  }

  @Test
  void currentUsesTheServerOffset() throws Exception {
    Client c = client(cfg());
    answers.add(ok(L.at(NOW + 3_600_000).exp(NOW + 3_600_000 + 60_000).sign()));
    c.activate(); // the server is an hour ahead of the local clock
    assertEquals(Duration.ofHours(1), c.serverOffset());
    c.now = () -> NOW + 120_000; // two minutes on: past exp by the server's clock
    assertEquals("expired", code(c::current));
  }

  @Test
  void clockGuard() throws Exception {
    Clock.Guard clock = new Clock.Guard(new Clock.MemoryStore(), "LF-KEY");
    clock.now(Instant.ofEpochMilli(NOW + 40 * DAY)); // the local clock once ran a month ahead
    Client c = client(cfg().clock(clock));
    answers.add(ok(L.at(NOW).sign()));
    c.activate(); // the verified iat resets the mark
    assertEquals(LicenseFile.Status.VALID, c.current().status());
    clock.now(Instant.ofEpochMilli(NOW + 10 * DAY));
    assertEquals("clock:rollback", code(c::current));
  }

  @Test
  void runRefreshesThenStopsOnRevocation() throws Exception {
    Client c = client(cfg());
    List<Long> waits = new ArrayList<>();
    c.sleeper = bounded(waits::add);
    c.rand = n -> 0;
    answers.add(ok(L.at(NOW).sign()));
    answers.add(ok(L.at(NOW + 1000).refreshAfter(NOW + 1000).sign()));
    answers.add(Answer.of(503));
    answers.add(problem(403, "license_revoked"));
    c.activate();
    List<Exception> errors = new ArrayList<>();
    OnlineException e = assertThrows(OnlineException.class, () -> c.run(errors::add));
    assertEquals(OnlineException.Code.LICENSE_REVOKED, e.code());
    assertEquals(3_600_000L, waits.get(0), "first refresh at refresh_after");
    assertEquals(60_000L, waits.get(1), "at least MIN_REFRESH_INTERVAL after a success");
    assertTrue(waits.get(2) >= 500 && waits.get(2) <= 1000, "backoff after a failure: " + waits.get(2));
    assertTrue(errors.get(0).getMessage().contains("memory only"), "warnings are reported too");
    assertEquals(List.of(OnlineException.Code.SERVER_ERROR, OnlineException.Code.LICENSE_REVOKED), errors.subList(1, errors.size()).stream().map(x -> ((OnlineException) x).code()).toList());
    assertEquals("no_lease", code(c::current), "the server said: no longer licensed");
  }

  @Test
  void runKeepsTheLeaseOnUnauthenticatedAndStopsOnInterrupt() throws Exception {
    Client c = client(cfg());
    List<Long> waits = new ArrayList<>();
    c.sleeper = bounded(waits::add);
    c.rand = n -> 0;
    answers.add(ok(L.at(NOW).maxOffline("PT0S").sign()));
    answers.add(problem(401, "unauthenticated"));
    c.activate();
    c.now = () -> NOW + 5000; // max_offline PT0S: invalid at once
    assertEquals("unauthenticated", code(() -> {
      c.run(null);
      return null;
    }));
    assertEquals(0L, waits.get(0), "a cached lease failing current: refresh at once");
    c.now = () -> NOW;
    assertEquals("lic_1", c.current().claims().licenseId(), "kept");
    c.sleeper = ms -> {
      throw new InterruptedException("stop");
    };
    assertThrows(InterruptedException.class, () -> c.run(null));
  }

  @Test
  void runStopsOnBindingMismatchAndOfflineSeatKeepingTheLease() throws Exception {
    for (String stop : List.of("binding_mismatch", "offline_seat")) {
      Client c = client(cfg());
      c.rand = n -> 0;
      answers.add(ok(L.at(NOW).sign()));
      answers.add(problem(409, stop));
      c.activate();
      assertEquals(stop, code(() -> {
        c.run(null);
        return null;
      }));
      assertEquals("lic_1", c.current().claims().licenseId(), stop + ": the lease is kept until it ends");
    }
  }

  @Test
  void runWaitsAtMostHalfTheTimeToExp() throws Exception {
    Client c = client(cfg());
    List<Long> waits = new ArrayList<>();
    c.sleeper = bounded(waits::add);
    c.rand = n -> 0;
    answers.add(ok(L.at(NOW).exp(NOW + 600_000).refreshAfter(NOW + 540_000).sign()));
    answers.add(problem(401, "unauthenticated"));
    c.activate();
    assertEquals("unauthenticated", code(() -> {
      c.run(null);
      return null;
    }));
    assertEquals(300_000L, waits.get(0), "half of the 10 minutes to exp, not refresh_after's 9");
  }

  @Test
  void runWakesBeforeTheLeaseFailsLocally() throws Exception {
    Clock.Guard clock = new Clock.Guard(new Clock.MemoryStore(), "LF-KEY");
    Client c = client(cfg().clock(clock));
    List<Long> waits = new ArrayList<>();
    c.sleeper = bounded(waits::add);
    c.rand = n -> 0;
    answers.add(ok(L.at(NOW).maxOffline("PT10M").refreshAfter(NOW + 3_600_000).sign()));
    answers.add(problem(401, "unauthenticated"));
    c.activate();
    clock.now(Instant.ofEpochMilli(NOW + 480_000)); // the trusted time is 8 minutes on: 2 left by it
    assertEquals("unauthenticated", code(() -> {
      c.run(null);
      return null;
    }));
    assertEquals(108_000L, waits.get(0), "2 minutes left, less a tenth: before max_offline runs out locally");
  }

  @Test
  void runForgetsOnNotActivated() throws Exception {
    Client c = client(cfg());
    c.rand = n -> 0;
    answers.add(ok(L.at(NOW).sign()));
    answers.add(problem(404, "not_activated"));
    c.activate();
    assertEquals("not_activated", code(() -> {
      c.run(null);
      return null;
    }));
    assertEquals("no_lease", code(c::current), "the activation is gone");
  }

  @Test
  void forgetIfKeepsANewerCommit() throws Exception {
    Client c = client(cfg());
    answers.add(ok(L.at(NOW).sign()));
    c.activate(); // ver 1
    c.forgetIf(0); // what run does after a refusal, if nothing was committed since it started
    assertEquals("lic_1", c.current().claims().licenseId(), "a newer commit is kept");
    c.forgetIf(1);
    assertEquals("no_lease", code(c::current));
  }

  @Test
  void aServerBehindDoesNotSlowTheLocalClock() throws Exception {
    Client c = client(cfg());
    answers.add(ok(L.at(NOW - 3_600_000).exp(NOW + 30_000).sign()));
    c.activate(); // the server is an hour behind
    c.now = () -> NOW + 60_000;
    assertEquals("expired", code(c::current), "max(local, local + offset): the local clock wins");
  }

  @Test
  void answersAreCappedAndBoundedInTime() throws Exception {
    Client c = client(cfg().maxAttempts(1).timeout(Duration.ofMillis(500)));
    answers.add(new Answer(200, "{\"lease\":\"" + "x".repeat(1 << 20) + "\"}", "application/json", Map.of(), null));
    assertEquals("network", code(c::refresh), "over 1 MiB");
    // A body dripping a byte every 100 ms: the whole request has the deadline.
    srv.createContext("/drip", ex -> {
      ex.sendResponseHeaders(200, 0);
      try (OutputStream o = ex.getResponseBody()) {
        for (int i = 0; i < 50; i++) {
          o.write(' ');
          o.flush();
          Thread.sleep(100);
        }
      } catch (Exception e) {
        // the client went away
      }
    });
    Client drip = client(Config.builder(base + "/drip", "tnt_acme", "acme-db", "LF-KEY", KEYS, FINGERPRINT).maxAttempts(1).timeout(Duration.ofMillis(500)));
    long start = System.nanoTime();
    assertEquals("network", code(drip::refresh));
    assertTrue((System.nanoTime() - start) / 1_000_000 < 3000);
  }

  @Test
  void aStoredLeaseRaisesTheClockMark() throws Exception {
    String file = L.at(NOW).sign();
    Online.LeaseStore s = new Online.LeaseStore() {
      @Override
      public String load() {
        return file;
      }

      @Override
      public void save(String l) {}
    };
    Clock.Guard clock = new Clock.Guard(new Clock.MemoryStore(), "LF-KEY");
    Client c = client(cfg().store(s).clock(clock));
    // Checked before current(), which would raise the mark itself.
    assertEquals("clock:rollback", code(() -> clock.now(Instant.ofEpochMilli(NOW - 2 * DAY))), "observe(iat) on create: an old lease can't pass for new");
    assertEquals("lic_1", c.current().claims().licenseId());
  }

  @Test
  void deactivateReportsAStoreThatWontClear() throws Exception {
    Online.LeaseStore s = new Online.LeaseStore() {
      @Override
      public String load() {
        return "";
      }

      @Override
      public void save(String l) throws java.io.IOException {
        if (l.isEmpty()) throw new java.io.IOException("EROFS");
      }
    };
    Client c = client(cfg().store(s));
    answers.add(ok(L.at(NOW).sign()));
    answers.add(Answer.of(204));
    c.activate();
    assertThrows(java.io.IOException.class, c::deactivate);
    assertEquals("no_lease", code(c::current), "the cache is dropped anyway");
  }

  @Test
  void laterConfigChangesDontReachALiveClient() throws Exception {
    Config cfg = cfg();
    Client c = client(cfg);
    AtomicReference<String> stored = new AtomicReference<>("");
    cfg.store(new Online.LeaseStore() {
      @Override
      public String load() {
        return "";
      }

      @Override
      public void save(String l) {
        stored.set(l);
      }
    });
    answers.add(ok(L.at(NOW).sign()));
    c.activate();
    assertEquals("", stored.get());
  }

  @Test
  void caTrustsAPrivateCAAndOnlyIt(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
    FingerprintTest.Tls tls = FingerprintTest.tls(dir, "ip:127.0.0.1");
    FingerprintTest.Tls other = FingerprintTest.tls(dir, "ip:127.0.0.1");
    java.util.Deque<FingerprintTest.Answer> out = new java.util.ArrayDeque<>();
    com.sun.net.httpserver.HttpsServer s = FingerprintTest.server(tls, out, new ArrayList<>());
    try {
      String https = "https://127.0.0.1:" + s.getAddress().getPort();
      String body = "{\"lease\":\"" + L.at(NOW).sign() + "\",\"activation_id\":\"act_1\"}";
      Config one = Config.builder(https, "tnt_acme", "acme-db", "LF-KEY", KEYS, FINGERPRINT).maxAttempts(1);
      byte[] pem = tls.certPem();
      one.ca(pem);
      java.util.Arrays.fill(pem, (byte) 'A'); // the config keeps its own copy
      Client c = client(one);
      out.add(new FingerprintTest.Answer(200, body));
      assertEquals("act_1", c.activate().activationId());
      assertEquals("network", code(() -> client(Config.builder(https, "tnt_acme", "acme-db", "LF-KEY", KEYS, FINGERPRINT).maxAttempts(1)).activate()), "not in the JVM's trust store");
      assertEquals("network", code(() -> client(Config.builder(https, "tnt_acme", "acme-db", "LF-KEY", KEYS, FINGERPRINT).maxAttempts(1).ca(other.certPem())).activate()), "another CA");
    } finally {
      s.stop(0);
    }
  }

  @Test
  void configIsValidated() {
    for (String bad : List.of("http://api.example", "https://u:p@api.example", "https://api.example?x=1", "not a url", "ftp://localhost")) {
      assertThrows(IllegalArgumentException.class, () -> Config.builder(bad, "t", "p", "k", KEYS, FINGERPRINT), bad);
    }
    assertThrows(IllegalArgumentException.class, () -> Config.builder("https://api.example", "", "p", "k", KEYS, FINGERPRINT));
    assertThrows(IllegalArgumentException.class, () -> Config.builder("https://api.example", "t", "p", "k", List.of(), FINGERPRINT));
    assertThrows(IllegalArgumentException.class, () -> Config.builder("https://api.example", "t", "p", "k", KEYS, new Fingerprint(FP, FingerprintSource.OVERRIDE, BindingType.NONE)));
    for (String key : List.of("S3CRET\r\nX", "LF-S3CRET\u20ac", "LF-S3CRET\u00e9", "LF S3CRET", "LF\u2013S3CRET")) {
      IllegalArgumentException leak = assertThrows(IllegalArgumentException.class, () -> Config.builder("https://api.example", "t", "p", key, KEYS, FINGERPRINT));
      assertFalse(leak.getMessage().contains("S3CRET"), key);
    }
    for (String bad : List.of("https://api.example#x", "https://api.example:99999")) {
      assertThrows(IllegalArgumentException.class, () -> Config.builder(bad, "t", "p", "k", KEYS, FINGERPRINT), bad);
    }
    assertThrows(IllegalArgumentException.class, () -> Config.builder("https://api.example", "t", "p", "k", KEYS, FINGERPRINT).timeout(Duration.ZERO));
    assertThrows(IllegalArgumentException.class, () -> Config.builder("https://api.example", "t", "p", "k", KEYS, FINGERPRINT).maxAttempts(0));
    for (String ca : List.of("", "not pem")) {
      assertThrows(IllegalArgumentException.class, () -> Config.builder("https://api.example", "t", "p", "k", KEYS, FINGERPRINT).ca(ca.getBytes(StandardCharsets.US_ASCII)), ca);
    }
    Config.builder("http://localhost:8080/lf/", "t", "p", "k", KEYS, FINGERPRINT); // loopback http is fine
    Config.builder("http://[::1]:8080", "t", "p", "k", KEYS, FINGERPRINT);
  }

  @Test
  void tenantIsOnePathSegmentAndTheBasePathIsKept() throws Exception {
    Client c = client(Config.builder(base + "/lf/", "tnt a/b", "acme-db", "LF-KEY", KEYS, FINGERPRINT));
    answers.add(Answer.of(503));
    c.sleeper = ms -> {};
    code(c::refresh);
    assertEquals("/lf/api/v1/activation/tenants/tnt%20a%2Fb/refresh", seen.get(0).path());
  }
}

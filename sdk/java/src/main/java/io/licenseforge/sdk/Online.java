package io.licenseforge.sdk;

import io.licenseforge.sdk.Claims.BindingType;
import io.licenseforge.sdk.Fingerprints.Fingerprint;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * The SDK's client for the activation API (ADR-0004, ADR-0034), as the Go and
 * TypeScript SDKs' online clients: activate this machine with a license key,
 * keep its signed lease fresh, deactivate it.
 *
 * <p>Every lease the server returns is verified (signature against the vendor's
 * embedded keys, claims, product, tenant, this machine's fingerprint and
 * binding) before it is used or cached. A cached lease keeps the app running
 * through server outages until max_offline or exp (+ grace) runs out.
 *
 * <p>Time (ADR-0018): each verified lease's iat is server time. The client keeps
 * its offset to the local clock and checks with max(local, local + offset);
 * with a clock guard it also resets the mark to the iat. The HTTP Date header
 * is never trusted.
 */
public final class Online {
  private Online() {}

  // Differences from Go/TS, all failing safe: a problem answer with duplicate keys or a
  // non-string detail reads as no code / "" (strict JSON); Retry-After takes delay-seconds
  // and IMF-fixdate only (the server sends seconds).

  /** Sent with activations and refreshes; kept with the pom's version (OnlineTest). */
  public static final String SDK_VERSION = "java/0.1.0-alpha.1";
  /** The least run waits after a successful refresh, whatever refresh_after says (ADR-0034). */
  public static final Duration MIN_REFRESH_INTERVAL = Duration.ofMinutes(1);

  private static final long BACKOFF_BASE_MS = 1000;
  private static final long BACKOFF_MAX_MS = 5 * 60_000;
  private static final long MAX_RETRY_AFTER_MS = 10 * 60_000;
  private static final long FAIL_MARGIN_MS = 2 * 60_000;
  private static final int MAX_ANSWER = 1 << 20;

  /** A refused or failed call, with the API's stable problem code or the client's own condition. */
  public static final class OnlineException extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Code {
      UNAUTHENTICATED, INVALID_REQUEST, LICENSE_SUSPENDED, LICENSE_REVOKED, LICENSE_EXPIRED, ACTIVATION_LIMIT_REACHED,
      REHOST_LIMIT_REACHED, BINDING_MISMATCH, NOT_ACTIVATED, OFFLINE_SEAT, RATE_LIMITED, IDEMPOTENCY_KEY_REUSED, IDEMPOTENCY_IN_PROGRESS,
      /** A 5xx answer. */
      SERVER_ERROR,
      /** Any other answer the client didn't expect (a redirect, a proxy page). */
      UNEXPECTED_STATUS,
      /** No answer: connection, TLS, timeout. */
      NETWORK,
      /** The answer didn't verify; never cached. */
      BAD_LEASE,
      /** Activate first. */
      NO_LEASE,
      /** forget or deactivate ran while the call was in flight. */
      SUPERSEDED;

      /** The API's name, e.g. "license_revoked". */
      public String spec() {
        return name().toLowerCase(Locale.ROOT);
      }
    }

    private static final Set<Code> API = Set.of(Code.UNAUTHENTICATED, Code.INVALID_REQUEST, Code.LICENSE_SUSPENDED, Code.LICENSE_REVOKED,
        Code.LICENSE_EXPIRED, Code.ACTIVATION_LIMIT_REACHED, Code.REHOST_LIMIT_REACHED, Code.BINDING_MISMATCH, Code.NOT_ACTIVATED,
        Code.OFFLINE_SEAT, Code.RATE_LIMITED, Code.IDEMPOTENCY_KEY_REUSED, Code.IDEMPOTENCY_IN_PROGRESS);

    private final Code code;
    private final int status;
    private final String requestId;
    private final Duration retryAfter;

    OnlineException(Code code, String detail) {
      this(code, detail, 0, "", Duration.ZERO);
    }

    OnlineException(Code code, String detail, int status, String requestId, Duration retryAfter) {
      super("licenseforge online: " + code.spec() + ": " + detail);
      this.code = code;
      this.status = status;
      this.requestId = requestId;
      this.retryAfter = retryAfter;
    }

    public Code code() {
      return code;
    }

    /** The HTTP status, or 0 without an answer. */
    public int status() {
      return status;
    }

    public String requestId() {
      return requestId;
    }

    public Duration retryAfter() {
      return retryAfter;
    }
  }

  /**
   * Keeps the verified lease across restarts; leases are verified again when
   * loaded. "" means none / delete. Report failures as IOException: unchecked
   * exceptions propagate to the caller.
   */
  public interface LeaseStore {
    String load() throws IOException;

    void save(String lease) throws IOException;
  }

  /** A verified lease: the license file, its claims, and the activation's ID. */
  public record Lease(String file, Claims claims, String activationId) {}

  /** The client's settings. Build with {@link #builder}. */
  public static final class Config {
    final URI base; // the fields below the required ones are set by the chained setters; the client copies them
    final String tenantId;
    final String product;
    final String licenseKey;
    final List<PublicKey> keys;
    final Fingerprint fingerprint;
    String hostname = "";
    String appVersion = "";
    LeaseStore store;
    Clock.Guard clock;
    Duration clockTolerance = CheckOptions.DEFAULT_CLOCK_TOLERANCE;
    Optional<Instant> buildDate = Optional.empty();
    int maxAttempts = 4;
    Duration timeout = Duration.ofSeconds(30);
    byte[] ca;

    private Config(URI base, String tenantId, String product, String licenseKey, List<PublicKey> keys, Fingerprint fingerprint) {
      this.base = base;
      this.tenantId = tenantId;
      this.product = product;
      this.licenseKey = licenseKey;
      this.keys = keys;
      this.fingerprint = fingerprint;
    }

    /**
     * The required settings: the API base URL (https; http only for loopback,
     * since the license key travels with each request), the tenant ID (tnt_…,
     * the license's tenant claim), the product slug, the license key, the
     * vendor's trusted keys and this machine's fingerprint.
     */
    public static Config builder(String baseUrl, String tenantId, String product, String licenseKey, List<PublicKey> keys, Fingerprint fingerprint) {
      Objects.requireNonNull(baseUrl, "baseUrl");
      URI u;
      try {
        String b = baseUrl;
        while (b.endsWith("/")) b = b.substring(0, b.length() - 1);
        u = new URI(b);
      } catch (URISyntaxException e) {
        throw new IllegalArgumentException("licenseforge online: baseUrl must be an https URL (http only for loopback hosts)");
      }
      boolean https = "https".equalsIgnoreCase(u.getScheme());
      boolean http = "http".equalsIgnoreCase(u.getScheme()) && u.getHost() != null && loopback(u.getHost());
      if (!(https || http) || u.getHost() == null || u.getPort() > 65535 || u.getRawUserInfo() != null || u.getRawQuery() != null || u.getRawFragment() != null) {
        throw new IllegalArgumentException("licenseforge online: baseUrl must be an https URL (http only for loopback hosts) without credentials, query or fragment: the license key travels with each request");
      }
      if (tenantId == null || tenantId.isEmpty() || product == null || product.isEmpty() || licenseKey == null || licenseKey.isEmpty()
          || keys == null || keys.isEmpty() || fingerprint == null || fingerprint.fingerprint().isEmpty()) {
        throw new IllegalArgumentException("licenseforge online: tenantId, product, licenseKey, keys and fingerprint are required");
      }
      // Keys are printable ASCII (ADR-0004); anything else can't go in a header, and the JDK's error would quote the key.
      if (licenseKey.chars().anyMatch(c -> c < 0x21 || c > 0x7e)) throw new IllegalArgumentException("licenseforge online: licenseKey must be printable ASCII (remove spaces, dashes pasted as en dashes, smart quotes)");
      if (fingerprint.binding() == BindingType.NONE) throw new IllegalArgumentException("licenseforge online: fingerprint binding must be machine or cluster");
      return new Config(u, tenantId, product, licenseKey, List.copyOf(keys), fingerprint);
    }

    Config copy() {
      Config c = new Config(base, tenantId, product, licenseKey, keys, fingerprint);
      c.hostname = hostname;
      c.appVersion = appVersion;
      c.store = store;
      c.clock = clock;
      c.clockTolerance = clockTolerance;
      c.buildDate = buildDate;
      c.maxAttempts = maxAttempts;
      c.timeout = timeout;
      c.ca = ca;
      return c;
    }

    public Config hostname(String v) {
      hostname = Objects.requireNonNull(v);
      return this;
    }

    public Config appVersion(String v) {
      appVersion = Objects.requireNonNull(v);
      return this;
    }

    /** Without one the lease lives in memory only (a warning: nothing survives a restart). */
    public Config store(LeaseStore v) {
      store = v;
      return this;
    }

    /** Reset to each lease's iat (ADR-0018). */
    public Config clock(Clock.Guard v) {
      clock = v;
      return this;
    }

    public Config clockTolerance(Duration v) {
      clockTolerance = Objects.requireNonNull(v);
      return this;
    }

    public Config buildDate(Instant v) {
      buildDate = Optional.of(v);
      return this;
    }

    /** Per call, for network errors, 429, 5xx and idempotency_in_progress. Default 4. */
    public Config maxAttempts(int v) {
      if (v < 1) throw new IllegalArgumentException("licenseforge online: maxAttempts must be ≥ 1");
      maxAttempts = v;
      return this;
    }

    /** Per request, body included. Default 30 s. */
    public Config timeout(Duration v) {
      if (v.isNegative() || v.isZero()) throw new IllegalArgumentException("licenseforge online: timeout must be > 0");
      timeout = v;
      return this;
    }

    /**
     * A server behind a private CA: its certificate(s), PEM. The client then
     * trusts only these, not the JVM's trust store.
     */
    public Config ca(byte[] pem) {
      byte[] v = Objects.requireNonNull(pem, "ca").clone();
      try {
        Fingerprints.trustOnly(v);
      } catch (GeneralSecurityException | IOException e) {
        throw new IllegalArgumentException("licenseforge online: ca must be PEM certificates", e);
      }
      ca = v;
      return this;
    }
  }

  private static final Pattern IPV4_LOOPBACK = Pattern.compile("127(\\.[0-9]{1,3}){3}");

  private static boolean loopback(String host) {
    String h = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    return h.equalsIgnoreCase("localhost") || h.equals("::1") || IPV4_LOOPBACK.matcher(h).matches();
  }

  /** Sleeps, or throws when interrupted: the test hook. */
  interface Sleeper {
    void sleep(long ms) throws InterruptedException;
  }

  /** The client. Safe for concurrent use; run usually has a thread of its own. */
  public static final class Client {
    private final Config cfg;
    private final HttpClient http;
    private final ReentrantLock commit = new ReentrantLock(); // one commit at a time: cache, clock and store end with the same lease
    private volatile String lease = "";
    private volatile Claims claims;
    private volatile long offsetMs; // server time minus local time, from the last lease
    private long gen; // bumped by forget: in-flight calls from before don't commit
    private long ver; // bumped by every commit and forget
    private final List<Exception> warnings = new ArrayList<>();
    LongSupplier now = System::currentTimeMillis;
    Sleeper sleeper = Thread::sleep;
    LongUnaryOperator rand = n -> n <= 0 ? 0 : ThreadLocalRandom.current().nextLong(n);

    private Client(Config cfg) {
      this.cfg = cfg.copy(); // later changes to the caller's Config don't reach a live client
      try {
        SSLContext tls = this.cfg.ca == null ? SSLContext.getInstance("TLS") : Fingerprints.trustOnly(this.cfg.ca);
        if (this.cfg.ca == null) tls.init(null, null, null); // the JVM's trust store
        SSLParameters params = tls.getDefaultSSLParameters();
        params.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
        // No redirects: the license key is in a header.
        http = HttpClient.newBuilder().sslContext(tls).sslParameters(params).followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).connectTimeout(cfg.timeout).build();
      } catch (GeneralSecurityException | IOException e) {
        throw new IllegalStateException(e);
      }
    }

    /** Checks cfg and loads a cached lease from cfg's store if one verifies. */
    public static Client create(Config cfg) {
      Client c = new Client(Objects.requireNonNull(cfg, "cfg"));
      if (cfg.store == null) {
        c.warn(new IllegalStateException("licenseforge online: no store: the lease lives in memory only and is lost on restart (ADR-0018)"));
        return c;
      }
      String s = "";
      try {
        s = cfg.store.load();
      } catch (IOException e) {
        c.warn(new IOException("licenseforge online: loading the stored lease: " + e, e));
      }
      if (s != null && !s.isEmpty()) {
        try {
          Claims cl = c.verifyFresh(s);
          c.lease = s;
          c.claims = cl;
          // A cache starting empty must not let an old lease pass for new.
          if (cfg.clock != null && !cfg.clock.observe(cl.issuedAt(), Instant.ofEpochMilli(c.now.getAsLong()))) {
            c.warn(new IOException("licenseforge online: clock mark not persisted"));
          }
        } catch (OnlineException e) {
          c.warn(new IllegalStateException("licenseforge online: stored lease not used: " + e.getMessage(), e));
        }
      }
      return c;
    }

    private synchronized void warn(Exception e) {
      warnings.add(e);
    }

    /** Returns, and forgets, the non-fatal problems since the last call. run reports them to its onError too. */
    public synchronized List<Exception> takeWarnings() {
      List<Exception> w = List.copyOf(warnings);
      warnings.clear();
      return w;
    }

    /** Activates this machine and returns the verified lease. Retries reuse one Idempotency-Key: never a second seat. */
    public Lease activate() throws OnlineException, InterruptedException {
      byte[] k = new byte[16];
      new SecureRandom().nextBytes(k);
      return leaseCall("activate", Base64.getUrlEncoder().withoutPadding().encodeToString(k), cfg.maxAttempts);
    }

    /** A new lease for this machine (also the SDK's validate). NOT_ACTIVATED: the activation is gone; activate again. */
    public Lease refresh() throws OnlineException, InterruptedException {
      return leaseCall("refresh", "", cfg.maxAttempts);
    }

    /**
     * Frees this machine's seat and drops the cached lease; a machine already
     * not activated is success too. An IOException: the seat is freed and the
     * cache dropped, but the stored lease wasn't cleared (it would load again
     * on restart until a refresh says not_activated): retry forget.
     */
    public void deactivate() throws OnlineException, InterruptedException, IOException {
      try {
        call("deactivate", "{\"fingerprint\":" + quote(cfg.fingerprint.fingerprint()) + "}", "", 204, cfg.maxAttempts);
      } catch (OnlineException e) {
        if (e.code() != OnlineException.Code.NOT_ACTIVATED) throw e;
      }
      forget();
    }

    /**
     * Drops the cached and stored lease without contacting the server: the way
     * out of a lease that can't be replaced (one with a far-future iat makes
     * every later lease look like a replay). Then refresh or activate.
     *
     * @throws IOException from the store; the cache is dropped anyway
     */
    public void forget() throws IOException {
      forgetIf(-1);
    }

    /** Forgets only if nothing was committed or forgotten since ver (-1: always). */
    void forgetIf(long since) throws IOException {
      commit.lock();
      try {
        if (since >= 0 && ver != since) return;
        lease = "";
        claims = null;
        offsetMs = 0;
        gen++;
        ver++;
        if (cfg.store != null) cfg.store.save("");
      } finally {
        commit.unlock();
      }
    }

    private static String quote(String s) {
      try {
        return Offline.quote(s);
      } catch (LicenseException e) {
        throw new IllegalArgumentException("licenseforge online: not valid Unicode");
      }
    }

    private Lease leaseCall(String op, String idemKey, int attempts) throws OnlineException, InterruptedException {
      StringBuilder body = new StringBuilder("{\"fingerprint\":").append(quote(cfg.fingerprint.fingerprint()))
          .append(",\"fp_source\":").append(quote(cfg.fingerprint.source().spec()))
          .append(",\"sdk_version\":").append(quote(SDK_VERSION));
      if (!cfg.hostname.isEmpty()) body.append(",\"hostname\":").append(quote(cfg.hostname));
      if (!cfg.appVersion.isEmpty()) body.append(",\"app_version\":").append(quote(cfg.appVersion));
      body.append('}');
      long g;
      commit.lock();
      try {
        g = gen;
      } finally {
        commit.unlock();
      }
      String raw = call(op, body.toString(), idemKey, 200, attempts);
      String file;
      String activationId;
      try {
        if (!(Json.parseValue(raw) instanceof Map<?, ?> m) || !(m.get("lease") instanceof String l)) throw new OnlineException(OnlineException.Code.BAD_LEASE, "answer has no lease");
        file = l;
        activationId = m.get("activation_id") instanceof String a ? a : "";
      } catch (Json.JsonException e) {
        throw new OnlineException(OnlineException.Code.BAD_LEASE, "answer isn't JSON: " + e.getMessage());
      }
      long local = now.getAsLong();
      Claims cl = verifyFresh(file);
      commit.lock();
      try {
        if (gen != g) throw new OnlineException(OnlineException.Code.SUPERSEDED, "the lease was forgotten while the call ran");
        // An older lease than the one held is a replay: it could wind the clock guard back (ADR-0018).
        Claims held = claims;
        if (held != null && cl.issuedAt().isBefore(held.issuedAt())) throw new OnlineException(OnlineException.Code.BAD_LEASE, "issued before the current lease");
        lease = file;
        claims = cl;
        offsetMs = cl.issuedAt().toEpochMilli() - local;
        ver++;
        // The lease is in use from here; the clock and store failing are warnings.
        if (cfg.clock != null && !cfg.clock.reset(cl.issuedAt())) warn(new IOException("licenseforge online: clock mark not persisted"));
        if (cfg.store != null) {
          try {
            cfg.store.save(file);
          } catch (IOException e) {
            warn(new IOException("licenseforge online: lease not stored: " + e, e));
          }
        }
        return new Lease(file, cl, activationId);
      } finally {
        commit.unlock();
      }
    }

    /** The signature, the claims as of the lease's own iat (server time), the product, this machine, the tenant and the binding. */
    private Claims verifyFresh(String file) throws OnlineException {
      Claims cl;
      try {
        cl = LicenseFile.parseClaims(LicenseFile.verify(file, cfg.keys).payload());
        LicenseFile.check(cl, CheckOptions.of(cl.issuedAt(), cfg.product).withFingerprint(cfg.fingerprint.fingerprint()));
      } catch (LicenseException e) {
        throw new OnlineException(OnlineException.Code.BAD_LEASE, e.getMessage());
      }
      if (!cl.tenant().equals(cfg.tenantId)) throw new OnlineException(OnlineException.Code.BAD_LEASE, "lease for another tenant");
      // An online lease always binds this machine or cluster: an unbound one would run anywhere.
      if (cl.binding().type() != cfg.fingerprint.binding()) throw new OnlineException(OnlineException.Code.BAD_LEASE, "lease binds " + cl.binding().type() + ", not " + cfg.fingerprint.binding());
      return cl;
    }

    private CheckOptions checkOptions() {
      long local = now.getAsLong();
      CheckOptions o = CheckOptions.of(Instant.ofEpochMilli(Math.max(local, local + offsetMs)), cfg.product)
          .withFingerprint(cfg.fingerprint.fingerprint()).withClockTolerance(cfg.clockTolerance);
      return cfg.buildDate.isPresent() ? o.withBuildDate(cfg.buildDate.get()) : o;
    }

    /** The check options current uses: with a clock guard, the time has passed the rollback check. */
    private CheckOptions currentOptions() throws Clock.ClockException {
      CheckOptions o = checkOptions();
      if (cfg.clock == null) return o;
      return new CheckOptions(cfg.clock.now(o.now()).now(), o.product(), o.fingerprint(), o.buildDate(), o.clockTolerance());
    }

    /**
     * Checks the cached lease now: its claims and status (VALID, or GRACE:
     * usable with a warning). Throws when the app must not run as licensed:
     * OnlineException NO_LEASE, a LicenseException from the checks, a
     * ClockException.
     */
    public LicenseFile.Opened current() throws OnlineException, LicenseException, Clock.ClockException {
      Claims cl = claims;
      if (cl == null) throw new OnlineException(OnlineException.Code.NO_LEASE, "no lease: activate first");
      return new LicenseFile.Opened(cl, LicenseFile.check(cl, currentOptions()));
    }

    /** Server time minus local time from the last lease (whole seconds: iat is). */
    public Duration serverOffset() {
      return Duration.ofMillis(offsetMs);
    }

    private static long bound(long b, long d) {
      return d > 0 && (b == 0 || d < b) ? d : b;
    }

    /** How long run may wait with a lease that passes current: half the time to exp and iat+max_offline; a margin before it fails locally. */
    private long[] wakeBounds(Claims cl, long nowMs) {
      long half = 0;
      long beforeFail = 0;
      Long fail = null;
      if (cl.maxOffline().isPresent()) {
        long off = cl.issuedAt().toEpochMilli() + cl.maxOffline().get().toMillis();
        half = bound(half, (off - nowMs) / 2);
        fail = off;
      }
      if (cl.expires().isPresent()) {
        half = bound(half, (cl.expires().get().toEpochMilli() - nowMs) / 2);
        long e = cl.expires().get().toEpochMilli() + cl.grace().toMillis();
        if (fail == null || e < fail) fail = e;
      }
      if (fail != null) {
        try {
          long left = fail - currentOptions().now().toEpochMilli();
          beforeFail = bound(beforeFail, left - Math.min(left / 10, FAIL_MARGIN_MS));
        } catch (Clock.ClockException e) {
          // a clock rollback: no bound from it
        }
      }
      return new long[] {half, beforeFail};
    }

    /**
     * Refreshes the lease until the thread is interrupted: from refresh_after
     * on, at once on the first pass if the cached lease doesn't pass current,
     * never sooner than MIN_REFRESH_INTERVAL after a success, with jitter;
     * failures back off exponentially, not sooner than Retry-After. Every
     * failure and warning goes to onError. Returns only by throwing what the
     * app must act on: NO_LEASE; NOT_ACTIVATED (activate again) and
     * LICENSE_REVOKED, after forgetting the lease when the API said so;
     * UNAUTHENTICATED, BINDING_MISMATCH, OFFLINE_SEAT (the lease is kept until
     * it ends); or InterruptedException.
     */
    public void run(Consumer<Exception> onError) throws OnlineException, InterruptedException {
      Consumer<Exception> report = onError == null ? e -> {} : onError;
      int failures = 0;
      long retryMs = 0;
      boolean refreshed = false;
      for (;;) {
        for (Exception w : takeWarnings()) report.accept(w);
        Claims cl = claims;
        if (cl == null) throw new OnlineException(OnlineException.Code.NO_LEASE, "no lease to keep fresh");
        long nowMs = now.getAsLong() + offsetMs; // refresh_after and exp are server times
        boolean invalid = false;
        try {
          current();
        } catch (Exception e) {
          invalid = true;
        }
        long wait;
        if (failures > 0) wait = Math.max(backoff(failures), retryMs);
        else if (invalid && !refreshed) wait = 0; // a fresh lease may fix it; once refreshed, it can't
        else if (cl.refreshAfter().isPresent()) wait = cl.refreshAfter().get().toEpochMilli() - nowMs;
        else if (cl.expires().isPresent()) wait = Math.min(BACKOFF_MAX_MS, (cl.expires().get().toEpochMilli() - nowMs) / 2);
        else wait = BACKOFF_MAX_MS;
        long half = 0;
        long beforeFail = 0;
        if (failures == 0 && !invalid) {
          long[] b = wakeBounds(cl, nowMs);
          half = b[0];
          beforeFail = b[1];
        }
        if (half > 0) wait = Math.min(wait, half);
        wait = Math.max(wait, 0);
        wait += rand.applyAsLong(wait / 10 + 1); // spread fleets out
        if (beforeFail > 0 && wait > beforeFail) wait = beforeFail - rand.applyAsLong(beforeFail / 10 + 1);
        if (refreshed && failures == 0) wait = Math.max(wait, MIN_REFRESH_INTERVAL.toMillis());
        sleeper.sleep(wait);
        long since;
        commit.lock();
        try {
          since = ver;
        } finally {
          commit.unlock();
        }
        try {
          leaseCall("refresh", "", 1); // one attempt: this loop retries
          failures = 0;
          retryMs = 0;
          refreshed = true;
        } catch (OnlineException e) {
          report.accept(e);
          OnlineException.Code c = e.code();
          if ((e.status() == 403 && c == OnlineException.Code.LICENSE_REVOKED) || (e.status() == 404 && c == OnlineException.Code.NOT_ACTIVATED)) {
            try {
              forgetIf(since);
            } catch (IOException fe) {
              report.accept(fe);
            }
            throw e;
          }
          if (c == OnlineException.Code.LICENSE_REVOKED || c == OnlineException.Code.NOT_ACTIVATED || c == OnlineException.Code.UNAUTHENTICATED
              || c == OnlineException.Code.BINDING_MISMATCH || c == OnlineException.Code.OFFLINE_SEAT) {
            throw e;
          }
          failures++;
          retryMs = e.retryAfter().toMillis();
        }
      }
    }

    /** The wait after n consecutive failures: exponential, jitter in the upper half, until BACKOFF_MAX_MS (never shortened). */
    private long backoff(int n) {
      long d = BACKOFF_BASE_MS << Math.min(n - 1, 20);
      if (d >= BACKOFF_MAX_MS) return BACKOFF_MAX_MS;
      return d / 2 + rand.applyAsLong(d / 2 + 1);
    }

    private URI url(String op) {
      String path = (cfg.base.getRawPath() == null ? "" : cfg.base.getRawPath()) + "/api/v1/activation/tenants/" + segment(cfg.tenantId) + "/" + op;
      String host = cfg.base.getRawAuthority();
      return URI.create(cfg.base.getScheme() + "://" + host + path);
    }

    /** Percent-encodes one path segment (RFC 3986 unreserved characters stay). */
    private static String segment(String s) {
      StringBuilder b = new StringBuilder();
      for (byte x : s.getBytes(StandardCharsets.UTF_8)) {
        int c = x & 0xff;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') b.append((char) c);
        else b.append('%').append(String.format("%02X", c));
      }
      return b.toString();
    }

    /** POSTs body to op; retries network errors, 429, 5xx and idempotency_in_progress up to attempts, honouring Retry-After. */
    private String call(String op, String body, String idemKey, int want, int attempts) throws OnlineException, InterruptedException {
      URI u = url(op);
      for (int attempt = 1; ; attempt++) {
        try {
          return once(u, body, idemKey, want);
        } catch (OnlineException e) {
          boolean retryable = e.code() == OnlineException.Code.NETWORK || e.status() == 429 || e.status() >= 500
              || e.code() == OnlineException.Code.IDEMPOTENCY_IN_PROGRESS;
          if (!retryable || attempt >= attempts) throw e;
          long ra = e.retryAfter().toMillis();
          sleeper.sleep(ra > 0 ? ra : backoff(attempt));
        }
      }
    }

    private record Answer(int status, String body, String type, String retryAfter) {}

    private String once(URI url, String body, String idemKey, int want) throws OnlineException, InterruptedException {
      HttpRequest.Builder rb = HttpRequest.newBuilder(url).timeout(cfg.timeout)
          .header("Authorization", "License " + cfg.licenseKey)
          .header("Content-Type", "application/json")
          .header("User-Agent", "licenseforge-sdk-" + SDK_VERSION)
          .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
      if (!idemKey.isEmpty()) rb.header("Idempotency-Key", idemKey);
      CompletableFuture<Answer> f = http.sendAsync(rb.build(), HttpResponse.BodyHandlers.ofInputStream()).thenApply(res -> {
        try (InputStream in = res.body()) {
          byte[] b = in.readNBytes(MAX_ANSWER + 1);
          if (b.length > MAX_ANSWER) throw new IOException("answer over 1 MiB");
          return new Answer(res.statusCode(), new String(b, StandardCharsets.UTF_8), res.headers().firstValue("Content-Type").orElse(""),
              res.headers().firstValue("Retry-After").orElse(""));
        } catch (IOException e) {
          throw new java.io.UncheckedIOException(e);
        }
      });
      Answer a;
      try {
        a = f.get(cfg.timeout.toMillis(), TimeUnit.MILLISECONDS); // the whole request, body included
      } catch (InterruptedException e) {
        f.cancel(true);
        throw e;
      } catch (TimeoutException e) {
        f.cancel(true);
        throw new OnlineException(OnlineException.Code.NETWORK, "no answer within " + cfg.timeout.toMillis() + " ms");
      } catch (ExecutionException e) {
        Throwable c = e.getCause() instanceof java.io.UncheckedIOException u ? u.getCause() : e.getCause();
        throw new OnlineException(OnlineException.Code.NETWORK, String.valueOf(c));
      }
      if (a.status() == want) return a.body();
      Duration retryAfter = Duration.ofMillis(parseRetryAfter(a.retryAfter(), now.getAsLong()));
      // The stable codes count only in a problem answer with a 4xx status: a
      // proxy's error page or a garbled 5xx must not read as "revoked".
      String type = a.type().split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
      if (type.equals("application/problem+json") && a.status() >= 400 && a.status() < 500) {
        try {
          if (Json.parseValue(a.body()) instanceof Map<?, ?> p && p.get("code") instanceof String code) {
            for (OnlineException.Code c : OnlineException.API) {
              if (c.spec().equals(code)) {
                throw new OnlineException(c, p.get("detail") instanceof String d ? d : "", a.status(), p.get("request_id") instanceof String r ? r : "", retryAfter);
              }
            }
          }
        } catch (Json.JsonException e) {
          // not a problem answer after all
        }
      }
      if (a.status() >= 500) throw new OnlineException(OnlineException.Code.SERVER_ERROR, "status " + a.status(), a.status(), "", retryAfter);
      if (a.status() == 429) throw new OnlineException(OnlineException.Code.RATE_LIMITED, "status 429", a.status(), "", retryAfter);
      throw new OnlineException(OnlineException.Code.UNEXPECTED_STATUS, "status " + a.status(), a.status(), "", retryAfter);
    }
  }

  private static final Pattern DIGITS = Pattern.compile("[0-9]+");

  /** Retry-After as delay-seconds or an HTTP date, in ms, capped at 10 minutes. */
  static long parseRetryAfter(String h, long nowMs) {
    if (h == null || h.isBlank()) return 0;
    String t = h.trim();
    long d = 0;
    if (DIGITS.matcher(t).matches()) {
      d = t.length() > 9 ? MAX_RETRY_AFTER_MS : Long.parseLong(t) * 1000;
    } else {
      try {
        d = ZonedDateTime.parse(t, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli() - nowMs;
      } catch (DateTimeParseException e) {
        d = 0;
      }
    }
    return Math.max(0, Math.min(d, MAX_RETRY_AFTER_MS));
  }
}

package io.licenseforge.sdk;

import io.licenseforge.sdk.Claims.Binding;
import io.licenseforge.sdk.Claims.BindingType;
import io.licenseforge.sdk.Fingerprints.Fingerprint;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A license on an air-gapped machine (ADR-0006, ADR-0043), as the Go SDK's offline package: the app
 * writes an activation request, someone carries it to the vendor's LicenseForge and carries the signed
 * license file back, the app installs it. To give the seat back, the app deletes the file and writes a
 * deactivation receipt for the vendor.
 *
 * <p>The installed file and the files returned are kept in a {@link Clock.Store} of its own ({@link
 * Clock.FileStore}: locked, atomic writes), never the clock guard's. Every use verifies the file again,
 * so a renewed file installed by another process is picked up without a restart. Safe for concurrent
 * use: the store serializes changes.
 */
public final class OfflineClient {
  /** Why the client refused. */
  public static final class OfflineException extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Code {
      /** No license file is installed. */
      NO_LICENSE,
      /** The file doesn't verify, or isn't for this tenant, product or machine. */
      BAD_FILE,
      /** This machine returned the file (or a newer one of its license): request a new one. */
      RETURNED,
      /** A newer file of the same license is installed: installing this one would roll it back. */
      OLDER_FILE,
      /** Another license is installed: deactivate it first, so its seat can be returned. */
      OTHER_LICENSE,
      /** The store holds other state (the clock guard's?): give each its own file. */
      FOREIGN_STATE,
      /** The file's iat is ahead of this machine's clock and the clock guard couldn't be raised to it. */
      CLOCK_NOT_SAVED
    }

    private final Code code;

    OfflineException(Code code, String msg, Throwable cause) {
      super("licenseforge offline: " + code.name().toLowerCase(java.util.Locale.ROOT) + ": " + msg, cause);
      this.code = code;
    }

    public Code code() {
      return code;
    }
  }

  /**
   * The client's configuration: {@link #builder} with the required fields, then the optional ones.
   * The store is its own file, never the clock guard's; on a memory store a returned file could be
   * installed again after a restart. Unreadable or damaged state counts as none (ADR-0014), like
   * deleted state. A clock guard protects the time checks against the clock being turned back
   * (ADR-0018): strongly advised offline, where no server time comes in. Copied when the client is
   * created.
   */
  public static final class Config {
    private final String tenantId;
    private final String product;
    private final String licenseKey;
    private final List<PublicKey> keys;
    private final Fingerprint fingerprint;
    private final Clock.Store store;
    private Optional<String> hostname = Optional.empty();
    private Optional<String> appVersion = Optional.empty();
    private Optional<Clock.Guard> clock = Optional.empty();
    private Duration clockTolerance = CheckOptions.DEFAULT_CLOCK_TOLERANCE;
    private Optional<Instant> buildDate = Optional.empty();

    private Config(String tenantId, String product, String licenseKey, List<PublicKey> keys, Fingerprint fingerprint, Clock.Store store) {
      this.tenantId = tenantId;
      this.product = product;
      this.licenseKey = licenseKey;
      this.keys = keys;
      this.fingerprint = fingerprint;
      this.store = store;
    }

    /**
     * tenantId (tnt_…, the license's tenant claim), the product slug the app expects, the license key
     * as the user typed it (it goes in the request), the trusted keys, this machine's fingerprint (a
     * machine or cluster binding) and the store for the client's state.
     */
    public static Config builder(String tenantId, String product, String licenseKey, List<PublicKey> keys, Fingerprint fingerprint, Clock.Store store) {
      if (tenantId == null || tenantId.isEmpty() || product == null || product.isEmpty() || licenseKey == null || licenseKey.isEmpty() || keys == null
          || keys.isEmpty() || fingerprint == null || fingerprint.fingerprint().isEmpty() || store == null) {
        throw new IllegalArgumentException("licenseforge offline: tenantId, product, licenseKey, keys, fingerprint and store are required");
      }
      if (fingerprint.binding() != BindingType.MACHINE && fingerprint.binding() != BindingType.CLUSTER) {
        throw new IllegalArgumentException("licenseforge offline: the fingerprint's binding must be machine or cluster");
      }
      return new Config(tenantId, product, licenseKey, List.copyOf(keys), fingerprint, store);
    }

    public Config hostname(String v) {
      hostname = Optional.of(v);
      return this;
    }

    public Config appVersion(String v) {
      appVersion = Optional.of(v);
      return this;
    }

    public Config clock(Clock.Guard v) {
      clock = Optional.of(v);
      return this;
    }

    /** How far in the future a file's iat may be (default 24 h); a clock guard can raise its own. */
    public Config clockTolerance(Duration v) {
      clockTolerance = Objects.requireNonNull(v, "clockTolerance");
      return this;
    }

    /** The app's build date, checked against updates_until. */
    public Config buildDate(Instant v) {
      buildDate = Optional.of(v);
      return this;
    }

    Config copy() {
      Config c = new Config(tenantId, product, licenseKey, keys, fingerprint, store);
      c.hostname = hostname;
      c.appVersion = appVersion;
      c.clock = clock;
      c.clockTolerance = clockTolerance;
      c.buildDate = buildDate;
      return c;
    }
  }

  private static final SecureRandom RANDOM = new SecureRandom();
  private final Config cfg;

  public OfflineClient(Config cfg) {
    this.cfg = Objects.requireNonNull(cfg, "cfg").copy(); // later changes to the caller's Config don't reach this client
  }

  /** {@link #request(Instant)} now. */
  public String request() throws LicenseException {
    return request(Instant.now());
  }

  /** {@link #install(String, Instant)} with the system clock. */
  public LicenseFile.Opened install(String file) throws OfflineException, LicenseException, Clock.ClockException, IOException {
    return install(file, Instant.now());
  }

  /** {@link #current(Instant)} with the system clock. */
  public LicenseFile.Opened current() throws OfflineException, LicenseException, Clock.ClockException, IOException {
    return current(Instant.now());
  }

  /** {@link #deactivate(Instant)} now. */
  public String deactivate() throws OfflineException, LicenseException, IOException {
    return deactivate(Instant.now());
  }

  /** An activation request (lfreq1) for this machine, to carry to the vendor. It contains the license key: handle it like the key. */
  public String request(Instant now) throws LicenseException {
    byte[] nonce = new byte[16];
    RANDOM.nextBytes(nonce);
    Fingerprint fp = cfg.fingerprint;
    return Offline.encodeRequest(new Offline.ActivationRequest(cfg.tenantId, cfg.product, cfg.licenseKey, new Binding(fp.binding(), fp.fingerprint()),
        fp.source(), nonce, now, cfg.hostname, cfg.appVersion, Optional.of(Online.SDK_VERSION)));
  }

  /**
   * Verifies file (the vendor's answer to request) and installs it, replacing the installed file of the
   * same license: a renewal, or the same file again. Refused: a file not usable now, one this machine
   * returned (RETURNED), one older than the installed file of its license (OLDER_FILE), another
   * license's while one is installed (OTHER_LICENSE); an installed file that no longer verifies here
   * blocks nothing. With a clock guard, a file whose iat is ahead of this machine's clock raises the
   * guard to it once its checks pass (refused if the guard can't hold it). IOException: the state
   * couldn't be saved (another process holds the store's lock: retry).
   */
  public LicenseFile.Opened install(String file, Instant local) throws OfflineException, LicenseException, Clock.ClockException, IOException {
    Claims claims = verify(file);
    CheckOptions o = options(local);
    LicenseFile.Status status;
    try {
      status = LicenseFile.check(claims, o);
    } catch (LicenseException e) {
      // The vendor's clock may be ahead of this machine's: within the guard's tolerance its iat is a
      // time this machine will accept (ADR-0018), once the guard holds it; if it can't, current()
      // would refuse the file, so install does.
      Optional<Clock.Guard> g = cfg.clock;
      if (e.code() != LicenseException.Code.CLOCK_SKEW || g.isEmpty() || claims.issuedAt().isAfter(local.plus(g.get().tolerance()))) throw e;
      status = LicenseFile.check(claims, new CheckOptions(claims.issuedAt(), o.product(), o.fingerprint(), o.buildDate(), o.clockTolerance()));
      if (!g.get().observe(claims.issuedAt(), local)) {
        throw new OfflineException(OfflineException.Code.CLOCK_NOT_SAVED, "the file's iat is ahead of this machine's clock and the clock guard can't hold it", null);
      }
    }
    update(s -> {
      Instant r = s.returned.get(claims.licenseId());
      if (r != null && !claims.issuedAt().isAfter(r)) throw new OfflineException(OfflineException.Code.RETURNED, "this license file was returned; request a new one", null);
      if (s.file != null) {
        Claims cur;
        try {
          cur = verify(s.file);
        } catch (OfflineException e) {
          cur = null; // an installed file that no longer verifies blocks nothing
        }
        if (cur != null && !cur.licenseId().equals(claims.licenseId())) {
          throw new OfflineException(OfflineException.Code.OTHER_LICENSE, "another license is installed; deactivate it first", null);
        }
        if (cur != null && claims.issuedAt().isBefore(cur.issuedAt())) throw new OfflineException(OfflineException.Code.OLDER_FILE, "a newer license file is installed", null);
      }
      return new State(file, s.returned);
    });
    return new LicenseFile.Opened(claims, status);
  }

  /** The installed file, verified and checked now: its claims and status. Any exception means: don't run as licensed. */
  public LicenseFile.Opened current(Instant local) throws OfflineException, LicenseException, Clock.ClockException, IOException {
    String[] file = new String[1];
    update(s -> {
      file[0] = s.file;
      return null;
    });
    if (file[0] == null) throw new OfflineException(OfflineException.Code.NO_LICENSE, "no license file installed", null);
    Claims claims = verify(file[0]);
    return new LicenseFile.Opened(claims, LicenseFile.check(claims, options(local)));
  }

  /**
   * Gives the seat back: deletes the installed file, remembers it so it can't be installed again, and
   * returns the deactivation receipt (lfrcpt1) for the vendor, once the state is saved. Keep it until the
   * vendor has it: it is the only proof. A file that no longer verifies here (its key dropped from keys,
   * a changed fingerprint) can't be deactivated here (BAD_FILE): the vendor frees the seat from the
   * dashboard.
   */
  public String deactivate(Instant now) throws OfflineException, LicenseException, IOException {
    String[] receipt = new String[1];
    update(s -> {
      if (s.file == null) throw new OfflineException(OfflineException.Code.NO_LICENSE, "no license file installed", null);
      Claims claims = verify(s.file);
      byte[] nonce = new byte[16];
      RANDOM.nextBytes(nonce);
      receipt[0] = Offline.encodeReceipt(new Offline.DeactivationReceipt(cfg.tenantId, claims.licenseId(), cfg.fingerprint.fingerprint(),
          Offline.fileSha256(s.file), nonce, now));
      Map<String, Instant> returned = new LinkedHashMap<>(s.returned);
      Instant r = returned.get(claims.licenseId());
      if (r == null || claims.issuedAt().isAfter(r)) returned.put(claims.licenseId(), claims.issuedAt());
      return new State(null, returned);
    });
    return receipt[0];
  }

  /** The file as issued for this machine: signature, the claim checks at its own iat, tenant, product, binding to this fingerprint. */
  private Claims verify(String file) throws OfflineException {
    try {
      Claims c = LicenseFile.parseClaims(LicenseFile.verify(file, cfg.keys).payload());
      LicenseFile.check(c, CheckOptions.of(c.issuedAt(), cfg.product).withFingerprint(cfg.fingerprint.fingerprint()));
      if (!c.tenant().equals(cfg.tenantId) || c.binding().type() != cfg.fingerprint.binding()) {
        throw new OfflineException(OfflineException.Code.BAD_FILE, "for tenant " + c.tenant() + ", binding " + c.binding().type(), null);
      }
      return c;
    } catch (LicenseException e) {
      throw new OfflineException(OfflineException.Code.BAD_FILE, "license file not valid for this machine", e);
    }
  }

  /** Check options now; with a clock guard, the time has passed its rollback check. */
  private CheckOptions options(Instant local) throws Clock.ClockException {
    Instant now = cfg.clock.isPresent() ? cfg.clock.get().now(local).now() : local;
    return new CheckOptions(now, cfg.product, cfg.fingerprint.fingerprint(), cfg.buildDate, cfg.clockTolerance);
  }

  /** What the store holds: the installed file (null: none), and license ID → iat of the newest file returned. */
  private record State(String file, Map<String, Instant> returned) {}

  private interface Change {
    /** The new state, or null for no change. */
    State apply(State s) throws OfflineException, LicenseException;
  }

  /**
   * Runs fn on the stored state and saves what it returns. The store's update can't throw checked
   * exceptions, so fn's are carried out; a save the store reports as failed is an IOException.
   */
  private void update(Change fn) throws OfflineException, LicenseException, IOException {
    Exception[] err = new Exception[1];
    boolean[] wrote = new boolean[1];
    boolean ok = cfg.store.update(cur -> {
      err[0] = null; // a store may retry fn
      wrote[0] = false;
      try {
        State next = fn.apply(decode(cur));
        if (next == null) return null;
        wrote[0] = true;
        return encode(next);
      } catch (OfflineException | LicenseException | IOException e) {
        err[0] = e;
        return null;
      }
    });
    if (err[0] instanceof OfflineException e) throw e;
    if (err[0] instanceof LicenseException e) throw e;
    if (err[0] instanceof IOException e) throw e;
    if (wrote[0] && !ok) throw new IOException("licenseforge offline: the state couldn't be saved (another process holds it, or the store is read-only)");
  }

  // Unparsable state counts as none, as in the clock guard: corrupting it gains no more than deleting
  // it (ADR-0014). Well-formed state of another kind is FOREIGN_STATE: the stores are mixed up, and
  // writing would destroy it.
  private static State decode(byte[] b) throws OfflineException {
    State none = new State(null, Map.of());
    Object v;
    try {
      v = b == null || b.length == 0 ? null : Json.parseValue(new String(b, java.nio.charset.StandardCharsets.UTF_8));
    } catch (Json.JsonException e) {
      return none;
    }
    if (!(v instanceof Map<?, ?> m) || m.isEmpty()) return none;
    if (!(m.get("offline") instanceof Json.Num n) || !n.token().equals("1")) {
      throw new OfflineException(OfflineException.Code.FOREIGN_STATE, "the store holds other state (shared with the clock guard?); use a store of its own", null);
    }
    Object file = m.get("file");
    if (file != null && !(file instanceof String)) return none; // ours, but damaged: none
    if ("".equals(file)) file = null;
    Map<String, Instant> returned = new LinkedHashMap<>();
    Object r = m.get("returned");
    if (r != null) {
      if (!(r instanceof Map<?, ?> rm)) return none;
      for (Map.Entry<?, ?> e : rm.entrySet()) {
        if (!(e.getValue() instanceof String t)) return none;
        try {
          returned.put((String) e.getKey(), Instant.parse(t));
        } catch (DateTimeParseException x) {
          return none;
        }
      }
    }
    return new State((String) file, returned);
  }

  private static byte[] encode(State s) throws IOException {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("offline", new Json.Num("1"));
    if (s.file() != null) m.put("file", s.file());
    if (!s.returned().isEmpty()) {
      Map<String, Object> r = new LinkedHashMap<>();
      s.returned().forEach((k, t) -> r.put(k, t.toString()));
      m.put("returned", r);
    }
    return LeaseStores.write(m).getBytes(java.nio.charset.StandardCharsets.UTF_8);
  }
}

package io.licenseforge.sdk;

import io.licenseforge.sdk.Claims.Binding;
import io.licenseforge.sdk.Claims.BindingType;
import io.licenseforge.sdk.LicenseException.Code;
import java.math.BigInteger;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * lf1 license files: envelope, signature, claims and claim checks, in the
 * order spec/license-format.md defines, so every SDK reports the same class.
 */
public final class LicenseFile {
  private LicenseFile() {}

  /** The largest input accepted, in UTF-8 bytes. */
  public static final int MAX_SIZE = 64 * 1024;

  private static final String BEGIN = "-----BEGIN LICENSEFORGE LICENSE-----";
  private static final String END = "-----END LICENSEFORGE LICENSE-----";
  private static final Pattern KID = Pattern.compile("[A-Za-z0-9_:-]{1,128}");
  private static final Pattern B64URL = Pattern.compile("[A-Za-z0-9_-]*");

  /** "GRACE": past exp but within grace, usable: warn the user. New values may be added: keep a default branch. */
  public enum Status {
    VALID,
    GRACE
  }

  /** A verified payload and the key ID that signed it. */
  public record Verified(byte[] payload, String kid) {
    public Verified {
      payload = payload.clone();
    }

    @Override
    public byte[] payload() {
      return payload.clone();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof Verified v && kid.equals(v.kid) && java.util.Arrays.equals(payload, v.payload);
    }

    @Override
    public int hashCode() {
      return 31 * kid.hashCode() + java.util.Arrays.hashCode(payload);
    }

    @Override
    public String toString() {
      return "Verified[kid=" + kid + ", payload=" + payload.length + " bytes]";
    }
  }

  /** A usable license: its claims and status. */
  public record Opened(Claims claims, Status status) {}

  /** Decodes canonical base64url (RFC 4648 §5, no padding, no stray bits), or null. */
  static byte[] b64url(String s) {
    if (!B64URL.matcher(s).matches() || s.length() % 4 == 1) return null;
    byte[] b = Base64.getUrlDecoder().decode(s);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b).equals(s) ? b : null;
  }

  private static boolean ws(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  }

  /** Whether s is longer than max bytes in UTF-8 (an unpaired surrogate counts 3, as its replacement). */
  static boolean longerThan(String s, int max) {
    long n = 0;
    for (int k = 0; k < s.length(); k++) {
      char c = s.charAt(k);
      if (c < 0x80) n++;
      else if (c < 0x800) n += 2;
      else if (Character.isHighSurrogate(c) && k + 1 < s.length() && Character.isLowSurrogate(s.charAt(k + 1))) {
        n += 4;
        k++;
      } else n += 3;
      if (n > max) return true;
    }
    return false;
  }

  /** Removes the BOM, armor and whitespace (SP, HT, CR, LF only), returning the bare token. */
  private static String unarmor(String input) throws LicenseException {
    String s = input.startsWith("\uFEFF") ? input.substring(1) : input;
    int a = 0;
    int z = s.length();
    while (a < z && ws(s.charAt(a))) a++;
    while (z > a && ws(s.charAt(z - 1))) z--;
    s = s.substring(a, z);
    if (s.startsWith(BEGIN)) {
      if (!s.endsWith(END) || s.length() < BEGIN.length() + END.length()) throw new LicenseException(Code.MALFORMED, "missing end armor");
      s = s.substring(BEGIN.length(), s.length() - END.length());
    }
    StringBuilder out = new StringBuilder(s.length());
    for (int k = 0; k < s.length(); k++) if (!ws(s.charAt(k))) out.append(s.charAt(k));
    if (out.length() == 0) throw new LicenseException(Code.MALFORMED);
    return out.toString();
  }

  private record Envelope(String token, String kid, String body, byte[] sig, byte[] payload) {}

  /** The spec's envelope checks up to the key lookup. */
  private static Envelope envelope(String license) throws LicenseException {
    Objects.requireNonNull(license, "license");
    if (longerThan(license, MAX_SIZE)) throw new LicenseException(Code.MALFORMED, "too large");
    String token = unarmor(license);
    String[] parts = token.split("\\.", -1); // -1: keep empty parts
    if (parts.length != 4 || !parts[0].equals("lf1") || !KID.matcher(parts[1]).matches() || parts[2].isEmpty()) {
      throw new LicenseException(Code.MALFORMED);
    }
    byte[] sig = b64url(parts[3]);
    if (sig == null) throw new LicenseException(Code.MALFORMED, "signature encoding");
    byte[] payload = b64url(parts[2]);
    if (payload == null) throw new LicenseException(Code.MALFORMED, "payload encoding");
    return new Envelope(token, parts[1], parts[2], sig, payload);
  }

  /** The JDK's Ed25519 provider (ADR-0010). */
  static final String PROVIDER = "SunEC";

  /** The bare token after the envelope checks (armor, BOM and whitespace removed). */
  static String envelopeToken(String license) throws LicenseException {
    return envelope(license).token();
  }

  // SubjectPublicKeyInfo for Ed25519 (RFC 8410) before the 32 key bytes.
  private static final byte[] ED25519_SPKI = HexFormat.of().parseHex("302a300506032b6570032100");

  /**
   * Checks a license's envelope and signature against the trusted keys and
   * returns the verified payload bytes and the key ID. It doesn't look at the
   * claims: use {@link #open} for that.
   */
  public static Verified verify(String license, List<PublicKey> keys) throws LicenseException {
    Envelope e = envelope(license);
    String kid = e.kid();
    List<PublicKey> found = new ArrayList<>(1);
    for (PublicKey k : keys) if (k.kid().equals(kid)) found.add(k);
    if (found.isEmpty()) throw new LicenseException(Code.UNKNOWN_KEY);
    if (found.size() > 1) throw new LicenseException(Code.INVALID_KEY_SET, "duplicate kid " + kid);
    PublicKey key = found.get(0);
    if (!key.alg().equals("ed25519")) throw new LicenseException(Code.UNSUPPORTED_ALG);
    byte[] raw = key.key();
    if (raw.length != 32) throw new LicenseException(Code.INVALID_KEY_SET, "ed25519 key for " + kid + " has length " + raw.length);
    if (weakEd25519(raw) || mixedOrderEd25519(raw)) throw new LicenseException(Code.INVALID_KEY_SET, "ed25519 key for " + kid + " is not a canonical, prime-order point");
    if (e.sig().length != 64) throw new LicenseException(Code.MALFORMED, "signature length");
    // A weak R (spec): with R = identity and S = k·a, cofactorless verification (Go) accepts and OpenSSL refuses.
    if (weakEd25519(java.util.Arrays.copyOf(e.sig(), 32))) throw new LicenseException(Code.BAD_SIGNATURE);
    byte[] spki = new byte[ED25519_SPKI.length + 32];
    System.arraycopy(ED25519_SPKI, 0, spki, 0, ED25519_SPKI.length);
    System.arraycopy(raw, 0, spki, ED25519_SPKI.length, 32);
    boolean ok;
    try {
      // The JDK's own provider, never the first one installed: another (e.g. plain BouncyCastle,
      // not BC FIPS) verifies cofactored or throws unchecked, and the answer must match every SDK's.
      Signature s = Signature.getInstance("Ed25519", PROVIDER);
      s.initVerify(KeyFactory.getInstance("Ed25519", PROVIDER).generatePublic(new X509EncodedKeySpec(spki)));
      s.update(("lf1." + kid + "." + e.body()).getBytes(StandardCharsets.US_ASCII));
      ok = s.verify(e.sig()); // SunEC refuses a non-canonical S (S ≥ L) and verifies cofactorless, like Go and OpenSSL
    } catch (NoSuchAlgorithmException | NoSuchProviderException x) {
      throw new IllegalStateException("licenseforge: no SunEC Ed25519 (a jlinked image on JDK 17-21 needs the jdk.crypto.ec module)", x);
    } catch (GeneralSecurityException | RuntimeException x) {
      // A 32-byte value that isn't a curve point can't verify anything. SunEC throws
      // checked exceptions for it; RuntimeException is defence in depth (no test reaches it).
      ok = false;
    }
    if (!ok) throw new LicenseException(Code.BAD_SIGNATURE);
    return new Verified(e.payload(), kid);
  }

  // The eight small-order points' canonical encodings (spec: weak keys).
  private static final Set<String> SMALL_ORDER = Set.of(
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000080",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

  /** A 32-byte key the spec refuses: a small-order point, or a non-canonical encoding. */
  static boolean weakEd25519(byte[] key) {
    if (SMALL_ORDER.contains(HexFormat.of().formatHex(key))) return true;
    boolean midFF = true;
    boolean mid00 = true;
    for (int k = 1; k < 31; k++) {
      midFF &= key[k] == (byte) 0xff;
      mid00 &= key[k] == 0;
    }
    int first = key[0] & 0xff;
    int top = key[31] & 0x7f;
    // y (little-endian, top bit cleared) ≥ p = 2^255 − 19 (ed ff … ff 7f).
    boolean high = top == 0x7f && midFF;
    if (high && first >= 0xed) return true;
    // Negative zero: the sign bit with x = 0 (y = 1 or y = p − 1).
    if ((key[31] & 0x80) != 0) {
      if (first == 1 && top == 0 && mid00) return true;
      if (first == 0xec && high) return true;
    }
    return false;
  }

  // edwards25519 over p = 2^255 − 19 in extended coordinates {X, Y, Z, T}
  // (x = X/Z, y = Y/Z, x·y = T/Z); L is the base point's prime order.
  private static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
  private static final BigInteger L = BigInteger.TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));
  private static final BigInteger D = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
  private static final BigInteger SQRT_M1 = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);

  /**
   * A canonical curve point outside the prime-order subgroup, [L]·A ≠ identity (spec: weak keys).
   * Its holder can sign so that cofactorless verification accepts, while FIPS 186-5 key validation
   * (Bouncy Castle FIPS) refuses the key. A value that isn't a point is not reported: it can't verify
   * anything (bad_signature). The caller has refused non-canonical encodings. Variable time: keys are public.
   */
  static boolean mixedOrderEd25519(byte[] key) {
    byte[] e = new byte[33]; // big-endian with a zero sign byte
    for (int i = 0; i < 32; i++) e[32 - i] = key[i];
    int sign = (e[1] & 0x80) >> 7;
    e[1] &= 0x7f;
    BigInteger y = new BigInteger(e);
    BigInteger y2 = y.multiply(y).mod(P);
    BigInteger x2 = y2.subtract(BigInteger.ONE).multiply(D.multiply(y2).add(BigInteger.ONE).modInverse(P)).mod(P);
    BigInteger x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
    if (!x.multiply(x).mod(P).equals(x2)) x = x.multiply(SQRT_M1).mod(P);
    if (!x.multiply(x).mod(P).equals(x2)) return false;
    if ((x.testBit(0) ? 1 : 0) != sign) x = x.negate().mod(P);
    BigInteger[] p = {x, y, BigInteger.ONE, x.multiply(y).mod(P)};
    BigInteger[] q = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
    for (int i = L.bitLength() - 1; i >= 0; i--) {
      q = edAdd(q, q);
      if (L.testBit(i)) q = edAdd(q, p);
    }
    return !q[1].equals(q[2]); // y = 1 only at the identity
  }

  // The complete addition for a = −1 (add-2008-hwcd-3); it also doubles.
  private static BigInteger[] edAdd(BigInteger[] p, BigInteger[] q) {
    BigInteger a = p[1].subtract(p[0]).multiply(q[1].subtract(q[0])).mod(P);
    BigInteger b = p[1].add(p[0]).multiply(q[1].add(q[0])).mod(P);
    BigInteger c = p[3].multiply(D).shiftLeft(1).multiply(q[3]).mod(P);
    BigInteger d = p[2].shiftLeft(1).multiply(q[2]).mod(P);
    BigInteger e = b.subtract(a), f = d.subtract(c), g = d.add(c), h = b.add(a);
    return new BigInteger[] {e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P)};
  }

  private static final Pattern INT = Pattern.compile("-?(0|[1-9][0-9]*)");
  private static final Pattern TIME = Pattern.compile("([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z");
  private static final Pattern DURATION = Pattern.compile("P(?:([0-9]{1,6})D)?(?:T(?:([0-9]{1,6})H)?(?:([0-9]{1,6})M)?(?:([0-9]{1,6})S)?)?");
  private static final long MAX_DURATION_SECONDS = 36500L * 86400;
  private static final long MAX_SAFE_INTEGER = (1L << 53) - 1;

  /** Parses exactly YYYY-MM-DDTHH:MM:SSZ, a real date, year 1970–9999. */
  static Instant parseTime(String s) throws LicenseException {
    Matcher m = TIME.matcher(s);
    if (m.matches()) {
      int y = Integer.parseInt(m.group(1));
      try {
        if (y >= 1970) {
          return LocalDateTime.of(y, Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)),
              Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)), Integer.parseInt(m.group(6))).toInstant(ZoneOffset.UTC);
        }
      } catch (DateTimeException e) {
        // an impossible date or time
      }
    }
    throw new LicenseException(Code.MALFORMED, "timestamp");
  }

  /** Parses P[nD][T[nH][nM][nS]], at most 36,500 days. */
  static Duration parseDuration(String s) throws LicenseException {
    Matcher m = DURATION.matcher(s);
    if (!m.matches() || s.equals("P") || s.endsWith("T")) throw new LicenseException(Code.MALFORMED, "duration");
    long[] unit = {86400, 3600, 60, 1};
    long secs = 0;
    for (int k = 0; k < 4; k++) if (m.group(k + 1) != null) secs += Long.parseLong(m.group(k + 1)) * unit[k];
    if (secs > MAX_DURATION_SECONDS) throw new LicenseException(Code.MALFORMED, "duration exceeds 36500 days");
    return Duration.ofSeconds(secs);
  }

  private static String str(Map<String, Object> m, String key) throws LicenseException {
    Object v = m.get(key);
    if (v == null) return null;
    if (!(v instanceof String s)) throw new LicenseException(Code.MALFORMED, key + " must be a string");
    return s;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> obj(Map<String, Object> m, String key) throws LicenseException {
    Object v = m.get(key);
    if (v == null) return null;
    if (!(v instanceof Map)) throw new LicenseException(Code.MALFORMED, key + " must be an object");
    return (Map<String, Object>) v;
  }

  private static String integer(Object v, String key) throws LicenseException {
    if (!(v instanceof Json.Num n) || !INT.matcher(n.token()).matches()) throw new LicenseException(Code.MALFORMED, key + " must be an integer");
    return n.token();
  }

  private static Optional<Instant> optTime(Map<String, Object> m, String key) throws LicenseException {
    String s = str(m, key);
    return s == null ? Optional.empty() : Optional.of(parseTime(s));
  }

  private static String orEmpty(String s) {
    return s == null ? "" : s;
  }

  /** Decodes a verified payload under the spec's strict encoding rules. */
  public static Claims parseClaims(byte[] payload) throws LicenseException {
    Map<String, Object> m;
    try {
      m = Json.parseObject(KeySet.utf8(payload)); // a BOM stays and is refused by the parser
    } catch (CharacterCodingException e) {
      throw new LicenseException(Code.MALFORMED, "not valid UTF-8");
    } catch (Json.JsonException e) {
      throw new LicenseException(Code.MALFORMED, e.getMessage());
    }
    // Version first: a future version may change any other field.
    Object v = m.get("v");
    if (v == null) throw new LicenseException(Code.MALFORMED, "missing v");
    if (!integer(v, "v").equals("1")) throw new LicenseException(Code.UNSUPPORTED_VERSION);

    String lid = str(m, "lid");
    String product = str(m, "product");
    if (lid == null || lid.isEmpty()) throw new LicenseException(Code.MALFORMED, "missing or empty lid");
    if (product == null || product.isEmpty()) throw new LicenseException(Code.MALFORMED, "missing or empty product");
    String tenant = orEmpty(str(m, "tenant"));
    String plan = orEmpty(str(m, "plan"));
    Map<String, Object> cust = obj(m, "customer");
    String customerId = cust == null ? "" : orEmpty(str(cust, "id"));
    String customerName = cust == null ? "" : orEmpty(str(cust, "name"));
    Optional<Instant> issuedAt = optTime(m, "iat");
    if (issuedAt.isEmpty()) throw new LicenseException(Code.MALFORMED, "missing iat");
    Optional<Instant> notBefore = optTime(m, "nbf");
    Optional<Instant> expires = optTime(m, "exp");
    Optional<Instant> refreshAfter = optTime(m, "refresh_after");
    Optional<Instant> updatesUntil = optTime(m, "updates_until");
    String g = str(m, "grace");
    Duration grace = g == null ? Duration.ZERO : parseDuration(g);
    String mo = str(m, "max_offline");
    Optional<Duration> maxOffline = mo == null ? Optional.empty() : Optional.of(parseDuration(mo));
    if (tenant.indexOf('\0') >= 0 || product.indexOf('\0') >= 0) throw new LicenseException(Code.MALFORMED, "tenant and product must not contain NUL");

    Binding binding = Binding.NONE;
    Map<String, Object> bind = obj(m, "bind");
    if (bind != null) {
      String type = str(bind, "type");
      String fp = str(bind, "fp");
      if (type == null || type.equals("none")) {
        if (fp != null) throw new LicenseException(Code.MALFORMED, "bind type none must not have fp");
      } else if (type.equals("machine") || type.equals("cluster")) {
        if (fp == null || fp.isEmpty()) throw new LicenseException(Code.MALFORMED, type + " binding without fp");
        binding = new Binding(type.equals("machine") ? BindingType.MACHINE : BindingType.CLUSTER, fp);
      } else {
        throw new LicenseException(Code.MALFORMED, "unknown binding type");
      }
    }
    // A bound license's fingerprint is derived from tenant and product.
    if (binding.type() != BindingType.NONE && tenant.isEmpty()) throw new LicenseException(Code.MALFORMED, "bound license without tenant");

    Entitlements entitlements = Entitlements.none();
    Map<String, Object> ent = obj(m, "entitlements");
    if (ent != null) {
      List<String> features = new ArrayList<>();
      Object f = ent.get("features");
      if (f != null) {
        if (!(f instanceof List<?> items)) throw new LicenseException(Code.MALFORMED, "features must be an array");
        for (Object it : items) {
          if (!(it instanceof String s)) throw new LicenseException(Code.MALFORMED, "features[] must be a string");
          features.add(s);
        }
      }
      Map<String, Long> limits = new HashMap<>();
      Map<String, Object> lm = obj(ent, "limits");
      if (lm != null) {
        for (Map.Entry<String, Object> l : lm.entrySet()) {
          String tok = integer(l.getValue(), "limits");
          long n;
          try {
            n = Long.parseLong(tok);
          } catch (NumberFormatException x) {
            throw new LicenseException(Code.MALFORMED, "limit out of range");
          }
          if (n < -1 || n > MAX_SAFE_INTEGER) throw new LicenseException(Code.MALFORMED, "limit out of range");
          limits.put(l.getKey(), n);
        }
      }
      entitlements = new Entitlements(features, limits);
    }
    return new Claims(lid, tenant, product, plan, customerId, customerName, issuedAt.get(), notBefore, expires,
        refreshAfter, updatesUntil, grace, maxOffline, binding, entitlements);
  }

  /** Applies the spec's claim checks in order: a usable license's status, or a LicenseException. */
  public static Status check(Claims c, CheckOptions o) throws LicenseException {
    Instant now = o.now();
    if (!c.product().equals(o.product())) throw new LicenseException(Code.WRONG_PRODUCT);
    if (c.binding().type() != BindingType.NONE && (c.binding().fingerprint().isEmpty() || !c.binding().fingerprint().equals(o.fingerprint()))) {
      throw new LicenseException(Code.BINDING_MISMATCH);
    }
    if (c.issuedAt().isAfter(now.plus(o.clockTolerance()))) throw new LicenseException(Code.CLOCK_SKEW);
    if (c.notBefore().isPresent() && now.isBefore(c.notBefore().get())) throw new LicenseException(Code.NOT_YET_VALID);
    if (c.maxOffline().isPresent() && now.isAfter(c.issuedAt().plus(c.maxOffline().get()))) throw new LicenseException(Code.OFFLINE_EXCEEDED);
    if (c.expires().isPresent() && now.isAfter(c.expires().get().plus(c.grace()))) throw new LicenseException(Code.EXPIRED);
    if (c.updatesUntil().isPresent() && o.buildDate().isPresent() && o.buildDate().get().isAfter(c.updatesUntil().get())) {
      throw new LicenseException(Code.UPDATES_EXPIRED);
    }
    return c.expires().isPresent() && now.isAfter(c.expires().get()) ? Status.GRACE : Status.VALID;
  }

  /**
   * Verifies a license, parses its claims and checks them: the usual entry
   * point. Throws a LicenseException when the license can't be used; its
   * claims come back only when everything passed.
   */
  public static Opened open(String license, List<PublicKey> keys, CheckOptions o) throws LicenseException {
    Claims claims = parseClaims(verify(license, keys).payload());
    return new Opened(claims, check(claims, o));
  }
}

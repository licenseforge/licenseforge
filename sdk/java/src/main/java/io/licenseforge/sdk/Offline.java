package io.licenseforge.sdk;

import io.licenseforge.sdk.Claims.Binding;
import io.licenseforge.sdk.Claims.BindingType;
import io.licenseforge.sdk.LicenseException.Code;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Offline activation artifacts (ADR-0043, spec "Offline activation"): the
 * activation request an air-gapped machine writes (lfreq1) and the
 * deactivation receipt it writes when it returns its seat (lfrcpt1). Both are
 * unsigned and carried by hand; the server checks them against what it
 * issued. The lf1 claim strictness, plus: no unknown fields.
 */
public final class Offline {
  private Offline() {}

  /** The largest request or receipt accepted, in UTF-8 bytes. */
  public static final int MAX_SIZE = 4096;

  /**
   * Asks the vendor's LicenseForge for an offline license file for this
   * machine. As sensitive as its key. The binding is MACHINE or CLUSTER.
   */
  public record ActivationRequest(String tenant, String product, String key, Binding binding, FingerprintSource fpSource,
      byte[] nonce, Instant created, Optional<String> hostname, Optional<String> appVersion, Optional<String> sdkVersion) {
    public ActivationRequest {
      Objects.requireNonNull(tenant, "tenant");
      Objects.requireNonNull(product, "product");
      Objects.requireNonNull(key, "key");
      Objects.requireNonNull(binding, "binding");
      Objects.requireNonNull(fpSource, "fpSource");
      nonce = Objects.requireNonNull(nonce, "nonce").clone();
      Objects.requireNonNull(created, "created");
      Objects.requireNonNull(hostname, "hostname");
      Objects.requireNonNull(appVersion, "appVersion");
      Objects.requireNonNull(sdkVersion, "sdkVersion");
    }

    @Override
    public byte[] nonce() {
      return nonce.clone();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof ActivationRequest r && tenant.equals(r.tenant) && product.equals(r.product) && key.equals(r.key)
          && binding.equals(r.binding) && fpSource == r.fpSource && Arrays.equals(nonce, r.nonce) && created.equals(r.created)
          && hostname.equals(r.hostname) && appVersion.equals(r.appVersion) && sdkVersion.equals(r.sdkVersion);
    }

    @Override
    public int hashCode() {
      return Objects.hash(tenant, product, binding, fpSource, Arrays.hashCode(nonce), created);
    }

    @Override
    public String toString() { // never the key
      return "ActivationRequest[tenant=" + tenant + ", product=" + product + ", binding=" + binding + "]";
    }
  }

  /** Returns an offline seat: the file with fileSha256 was deleted on the machine with fingerprint. */
  public record DeactivationReceipt(String tenant, String licenseId, String fingerprint, String fileSha256, byte[] nonce, Instant created) {
    public DeactivationReceipt {
      Objects.requireNonNull(tenant, "tenant");
      Objects.requireNonNull(licenseId, "licenseId");
      Objects.requireNonNull(fingerprint, "fingerprint");
      Objects.requireNonNull(fileSha256, "fileSha256");
      nonce = Objects.requireNonNull(nonce, "nonce").clone();
      Objects.requireNonNull(created, "created");
    }

    @Override
    public byte[] nonce() {
      return nonce.clone();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof DeactivationReceipt r && tenant.equals(r.tenant) && licenseId.equals(r.licenseId)
          && fingerprint.equals(r.fingerprint) && fileSha256.equals(r.fileSha256) && Arrays.equals(nonce, r.nonce) && created.equals(r.created);
    }

    @Override
    public int hashCode() {
      return Objects.hash(tenant, licenseId, fingerprint, fileSha256, Arrays.hashCode(nonce), created);
    }

    @Override
    public String toString() {
      return "DeactivationReceipt[tenant=" + tenant + ", licenseId=" + licenseId + ", fileSha256=" + fileSha256 + "]";
    }
  }

  private static final Pattern FP = Pattern.compile("sha256:[0-9a-f]{64}");
  private static final Pattern HEX = Pattern.compile("[0-9a-f]{64}");
  private static final Pattern HOSTNAME = Pattern.compile("[A-Za-z0-9._-]{1,253}");
  private static final Pattern VERSION = Pattern.compile("[ -~]{1,64}");
  private static final Pattern KEY = Pattern.compile("[!-~]{1,128}");
  private static final Pattern INT = Pattern.compile("-?(0|[1-9][0-9]*)");
  private static final List<String> REQUEST_FIELDS =
      List.of("v", "tenant", "product", "key", "bind", "fp_source", "nonce", "created", "hostname", "app_version", "sdk_version");
  private static final List<String> RECEIPT_FIELDS = List.of("v", "tenant", "license_id", "fp", "file_sha256", "nonce", "created");

  private static LicenseException malformed(String detail) {
    return new LicenseException(Code.MALFORMED, detail);
  }

  /** Removes one leading BOM and every SP, HT, CR and LF. */
  private static String stripSpace(String s) {
    String t = s.startsWith("\uFEFF") ? s.substring(1) : s;
    StringBuilder b = new StringBuilder(t.length());
    for (int i = 0; i < t.length(); i++) {
      char c = t.charAt(i);
      if (c != ' ' && c != '\t' && c != '\r' && c != '\n') b.append(c);
    }
    return b.toString();
  }

  private static Map<String, Object> decode(String version, String input, List<String> known) throws LicenseException {
    Objects.requireNonNull(input, "input");
    if (LicenseFile.longerThan(input, MAX_SIZE)) throw malformed("larger than " + MAX_SIZE + " bytes");
    String token = stripSpace(input); // no armor: an armored token fails the prefix
    if (!token.startsWith(version + ".")) throw malformed("not an " + version + " token");
    byte[] payload = LicenseFile.b64url(token.substring(version.length() + 1));
    if (payload == null) throw malformed("payload encoding");
    Map<String, Object> m;
    try {
      m = Json.parseObject(KeySet.utf8(payload));
    } catch (CharacterCodingException e) {
      throw malformed("not valid UTF-8");
    } catch (Json.JsonException e) {
      throw malformed(e.getMessage());
    }
    Object v = m.get("v");
    if (v == null) throw malformed("missing v");
    if (!(v instanceof Json.Num n) || !INT.matcher(n.token()).matches()) throw malformed("v must be an integer");
    if (!n.token().equals("1")) throw new LicenseException(Code.UNSUPPORTED_VERSION, version + " version");
    for (String k : m.keySet()) if (!known.contains(k)) throw malformed("unknown field");
    return m;
  }

  private static String str(Map<String, Object> m, String key) throws LicenseException {
    Object v = m.get(key);
    if (v == null) return null;
    if (!(v instanceof String s)) throw malformed(key + " must be a string");
    return s;
  }

  private static String req(Map<String, Object> m, String key) throws LicenseException {
    String s = str(m, key);
    if (s == null || s.isEmpty()) throw malformed("missing or empty " + key);
    return s;
  }

  /** A required, non-empty string of at most max UTF-8 bytes, without NUL. */
  private static String name(Map<String, Object> m, String key, int max) throws LicenseException {
    String s = req(m, key);
    if (LicenseFile.longerThan(s, max) || s.indexOf('\0') >= 0) throw malformed(key + " must be at most " + max + " bytes without NUL");
    return s;
  }

  private static byte[] nonce(Map<String, Object> m) throws LicenseException {
    byte[] nonce = LicenseFile.b64url(req(m, "nonce"));
    // Canonical base64url of 16 bytes is always 22 characters (no CR or LF here).
    if (nonce == null || nonce.length != 16) throw malformed("nonce must be 16 bytes, base64url");
    return nonce;
  }

  private static Optional<String> optional(Map<String, Object> m, String key, Pattern p) throws LicenseException {
    String s = str(m, key);
    if (s == null) return Optional.empty();
    if (!p.matcher(s).matches()) throw malformed(key);
    return Optional.of(s);
  }

  /** Reads an lfreq1 token; LicenseException MALFORMED or UNSUPPORTED_VERSION. */
  public static ActivationRequest parseRequest(String input) throws LicenseException {
    Map<String, Object> m = decode("lfreq1", input, REQUEST_FIELDS);
    String tenant = name(m, "tenant", 256);
    String product = name(m, "product", 256);
    String key = req(m, "key");
    if (!KEY.matcher(key).matches()) throw malformed("key must be up to 128 printable ASCII characters");
    // An offline request always binds (a site license needs none): exactly type and fp.
    if (!(m.get("bind") instanceof Map<?, ?> rawBind)) throw malformed("bind must be an object");
    @SuppressWarnings("unchecked")
    Map<String, Object> bind = (Map<String, Object>) rawBind;
    String type = str(bind, "type");
    String fp = str(bind, "fp");
    if (!"machine".equals(type) && !"cluster".equals(type)) throw malformed("bind type must be machine or cluster");
    if (fp == null || !FP.matcher(fp).matches()) throw malformed("fp must be sha256: and 64 lowercase hex digits");
    if (bind.size() != 2) throw malformed("bind has unknown fields");
    FingerprintSource source = FingerprintSource.fromSpec(req(m, "fp_source"));
    if (source == null) throw malformed("fp_source must be machine-id, kubernetes, env or override");
    if ((source == FingerprintSource.KUBERNETES) != type.equals("cluster")) throw malformed("a cluster binding comes from kubernetes, and only it");
    byte[] nonce = nonce(m);
    Instant created = LicenseFile.parseTime(req(m, "created"));
    return new ActivationRequest(tenant, product, key, new Binding(type.equals("machine") ? BindingType.MACHINE : BindingType.CLUSTER, fp),
        source, nonce, created, optional(m, "hostname", HOSTNAME), optional(m, "app_version", VERSION), optional(m, "sdk_version", VERSION));
  }

  /** Reads an lfrcpt1 token, with parseRequest's error classes. */
  public static DeactivationReceipt parseReceipt(String input) throws LicenseException {
    Map<String, Object> m = decode("lfrcpt1", input, RECEIPT_FIELDS);
    String tenant = name(m, "tenant", 256);
    String licenseId = name(m, "license_id", 128);
    String fp = req(m, "fp");
    if (!FP.matcher(fp).matches()) throw malformed("fp must be sha256: and 64 lowercase hex digits");
    String fileSha256 = req(m, "file_sha256");
    if (!HEX.matcher(fileSha256).matches()) throw malformed("file_sha256 must be 64 lowercase hex digits");
    byte[] nonce = nonce(m);
    return new DeactivationReceipt(tenant, licenseId, fp, fileSha256, nonce, LicenseFile.parseTime(req(m, "created")));
  }

  /**
   * A JSON string as Go's encoding/json writes it: \b \f \n \r \t, other
   * controls as lowercase \\u00xx, and <, >, &, U+2028, U+2029 escaped, so
   * every SDK writes the same bytes (and the same offlineSha256).
   */
  static String quote(String s) throws LicenseException {
    StringBuilder b = new StringBuilder(s.length() + 2).append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (Character.isSurrogate(c)) {
        if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
          b.append(c).append(s.charAt(++i));
          continue;
        }
        throw malformed("not valid Unicode (an unpaired surrogate)");
      }
      switch (c) {
        case '"' -> b.append("\\\"");
        case '\\' -> b.append("\\\\");
        case '\b' -> b.append("\\b");
        case '\f' -> b.append("\\f");
        case '\n' -> b.append("\\n");
        case '\r' -> b.append("\\r");
        case '\t' -> b.append("\\t");
        default -> {
          if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == '\u2028' || c == '\u2029') b.append(String.format("\\u%04x", (int) c));
          else b.append(c);
        }
      }
    }
    return b.append('"').toString();
  }

  /** YYYY-MM-DDTHH:MM:SSZ, whole seconds (a year outside 1970-9999 is then refused by the parser). */
  private static String timestamp(Instant t) {
    return t.truncatedTo(ChronoUnit.SECONDS).toString();
  }

  private static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  /** The token for a JSON object whose members are given in sorted key order. */
  private static String token(String version, String json) {
    return version + "." + b64(json.getBytes(StandardCharsets.UTF_8));
  }

  /** An lfreq1 token for r; the key loses the spaces and line breaks pasted with it. Checked by parseRequest. */
  public static String encodeRequest(ActivationRequest r) throws LicenseException {
    if (r.binding().type() == BindingType.NONE) throw malformed("bind type must be machine or cluster");
    StringBuilder j = new StringBuilder("{");
    // An empty optional is left out, as in the Go and TypeScript SDKs.
    Optional<String> appVersion = r.appVersion().filter(s -> !s.isEmpty());
    Optional<String> hostname = r.hostname().filter(s -> !s.isEmpty());
    Optional<String> sdkVersion = r.sdkVersion().filter(s -> !s.isEmpty());
    if (appVersion.isPresent()) j.append("\"app_version\":").append(quote(appVersion.get())).append(',');
    j.append("\"bind\":{\"fp\":").append(quote(r.binding().fingerprint())).append(",\"type\":")
        .append(quote(r.binding().type() == BindingType.MACHINE ? "machine" : "cluster")).append("},"); // NONE refused above
    j.append("\"created\":").append(quote(timestamp(r.created()))).append(',');
    j.append("\"fp_source\":").append(quote(r.fpSource().spec())).append(',');
    if (hostname.isPresent()) j.append("\"hostname\":").append(quote(hostname.get())).append(',');
    j.append("\"key\":").append(quote(stripSpace(r.key()))).append(',');
    j.append("\"nonce\":").append(quote(b64(r.nonce()))).append(',');
    j.append("\"product\":").append(quote(r.product())).append(',');
    if (sdkVersion.isPresent()) j.append("\"sdk_version\":").append(quote(sdkVersion.get())).append(',');
    j.append("\"tenant\":").append(quote(r.tenant())).append(",\"v\":1}");
    String t = token("lfreq1", j.toString());
    parseRequest(t); // an SDK can't write what the server refuses
    return t;
  }

  /** An lfrcpt1 token for r, checked by parseReceipt. */
  public static String encodeReceipt(DeactivationReceipt r) throws LicenseException {
    String t = token("lfrcpt1", "{\"created\":" + quote(timestamp(r.created())) + ",\"file_sha256\":" + quote(r.fileSha256())
        + ",\"fp\":" + quote(r.fingerprint()) + ",\"license_id\":" + quote(r.licenseId()) + ",\"nonce\":" + quote(b64(r.nonce()))
        + ",\"tenant\":" + quote(r.tenant()) + ",\"v\":1}");
    parseReceipt(t);
    return t;
  }

  /**
   * A license file's file_sha256 for a receipt: SHA-256 of its token as
   * verify reads it (armor, BOM and whitespace removed), lowercase hex. A
   * file that fails the envelope checks has none (MALFORMED).
   */
  public static String fileSha256(String file) throws LicenseException {
    return sha256Hex(LicenseFile.envelopeToken(file).getBytes(StandardCharsets.US_ASCII));
  }

  /** A request's or receipt's identity: SHA-256 of the token with the BOM and whitespace removed, lowercase hex. */
  public static String offlineSha256(String input) {
    // An unpaired surrogate hashes as U+FFFD, as Node's and Go's UTF-8 encoders write it (Java's would write "?").
    String s = stripSpace(input);
    StringBuilder b = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) b.append(c).append(s.charAt(++i));
      else b.append(Character.isSurrogate(c) ? '\uFFFD' : c);
    }
    return sha256Hex(b.toString().getBytes(StandardCharsets.UTF_8));
  }

  private static String sha256Hex(byte[] b) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}

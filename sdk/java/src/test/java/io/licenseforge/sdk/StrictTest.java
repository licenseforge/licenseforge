package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** What the shared vectors don't cover: strict JSON and timestamp details, entitlements, check options. */
class StrictTest {
  static final String OK = "{\"v\":1,\"lid\":\"lic_1\",\"product\":\"p\",\"iat\":\"2026-11-01T00:00:00Z\"}";

  static Claims claims(String json) throws LicenseException {
    return LicenseFile.parseClaims(json.getBytes(StandardCharsets.UTF_8));
  }

  static String code(ThrowingRunnable r) {
    try {
      r.run();
      return "ok";
    } catch (LicenseException e) {
      return e.code().spec();
    } catch (Exception e) {
      return "threw " + e;
    }
  }

  interface ThrowingRunnable {
    void run() throws Exception;
  }

  @Test
  void strictJson() throws Exception {
    assertEquals("ok", code(() -> claims(OK)));
    Map<String, String> bad = Map.ofEntries(
        Map.entry("raw tab in a string", OK.replace("\"lic_1\"", "\"lic\t1\"")),
        Map.entry("raw newline in a string", OK.replace("\"lic_1\"", "\"lic\n1\"")),
        Map.entry("bad escape", OK.replace("\"lic_1\"", "\"lic\\x1\"")),
        Map.entry("short \\u escape", OK.replace("\"lic_1\"", "\"lic\\u12\"")),
        Map.entry("non-ASCII hex digit", OK.replace("\"lic_1\"", "\"lic\\u00\u0661\u0661\"")),
        Map.entry("lone low surrogate", OK.replace("\"lic_1\"", "\"\\udc00\"")),
        Map.entry("high surrogate then a non-surrogate", OK.replace("\"lic_1\"", "\"\\ud800\\u0041\"")),
        Map.entry("leading zero", OK.replace("\"v\":1", "\"v\":01")),
        Map.entry("plus sign", OK.replace("\"v\":1", "\"v\":+1")),
        Map.entry("fraction", OK.replace("\"v\":1", "\"v\":1.0")),
        Map.entry("exponent", OK.replace("\"v\":1", "\"v\":1e0")),
        Map.entry("trailing comma", OK.replace("}", ",}")),
        Map.entry("single quotes", OK.replace("\"lic_1\"", "'lic_1'")),
        Map.entry("BOM before the object", "\uFEFF" + OK),
        Map.entry("trailing data", OK + " {}"),
        Map.entry("duplicate key", OK.replace("}", ",\"lid\":\"x\"}")),
        Map.entry("null lid", OK.replace("\"lic_1\"", "null")),
        Map.entry("NUL in tenant", OK.replace("}", ",\"tenant\":\"t\\u0000x\"}")),
        Map.entry("raw 0x1F in a string", OK.replace("\"lic_1\"", "\"lic\u001f1\"")),
        Map.entry("fraction without digits", OK.replace("}", ",\"x\":1.}")),
        Map.entry("fraction without digits, exponent", OK.replace("}", ",\"x\":1.e5}")),
        Map.entry("nesting 33", OK.replace("}", ",\"x\":" + "[".repeat(32) + "]".repeat(32) + "}")));
    for (Map.Entry<String, String> e : bad.entrySet()) assertEquals("malformed", code(() -> claims(e.getValue())), e.getKey());
    assertEquals("ok", code(() -> claims(OK.replace("}", ",\"x\":" + "[".repeat(31) + "]".repeat(31) + "}"))), "nesting 32");
    assertEquals("\uD83D\uDE00é", claims(OK.replace("\"lic_1\"", "\"\\ud83d\\ude00\\u00e9\"")).licenseId(), "a surrogate pair and an escape decode");
    assertEquals("malformed", code(() -> LicenseFile.parseClaims(new byte[] {0x7b, (byte) 0xff, 0x7d})), "invalid UTF-8");
    assertEquals("malformed", code(() -> LicenseFile.parseClaims(new byte[] {0x7b, 0x22, (byte) 0xed, (byte) 0xa0, (byte) 0x80, 0x22, 0x3a, 0x31, 0x7d})), "an encoded surrogate");
    assertEquals("unsupported_version", code(() -> claims(OK.replace("\"v\":1", "\"v\":123456789012345678901234567890"))));
    assertEquals("malformed", code(() -> claims(OK.replace("\"v\":1,", ""))), "missing v");
    assertEquals("malformed", code(() -> claims(OK.replace("\"v\":1", "\"v\":\"1\""))), "string v");
  }

  @Test
  void timestamps() throws Exception {
    assertEquals(Instant.parse("2028-02-29T23:59:59Z"), LicenseFile.parseTime("2028-02-29T23:59:59Z"));
    for (String s : List.of("2026-02-30T00:00:00Z", "2027-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-11-31T00:00:00Z",
        "2026-11-01T24:00:00Z", "2026-11-01T00:60:00Z", "2026-11-01T00:00:60Z", "1969-12-31T23:59:59Z", "2026-11-01t00:00:00Z",
        "2026-11-01T00:00:00z", "2026-11-01T00:00:00.5Z", "2026-11-01T00:00:00+00:00", "\u0662026-11-01T00:00:00Z")) {
      assertEquals("malformed", code(() -> LicenseFile.parseTime(s)), s);
    }
  }

  @Test
  void durations() throws Exception {
    assertEquals(Duration.ofDays(7), LicenseFile.parseDuration("P7D"));
    assertEquals(Duration.ZERO, LicenseFile.parseDuration("PT0S"));
    assertEquals(Duration.ofSeconds(86400 + 3600 + 60 + 1), LicenseFile.parseDuration("P1DT1H1M1S"));
    assertEquals(Duration.ofDays(36500), LicenseFile.parseDuration("P36500D"));
    for (String s : List.of("P", "PT", "P1DT", "P36501D", "P1W", "P1Y", "p1d", "P1234567D", "-P1D", "P1.5D", "PT1S ")) {
      assertEquals("malformed", code(() -> LicenseFile.parseDuration(s)), s);
    }
  }

  @Test
  void entitlements() throws Exception {
    Entitlements e = claims(OK.replace("}", ",\"entitlements\":{\"features\":[\"sso\"],\"limits\":{\"seats\":3,\"nodes\":-1,\"zero\":0,\"neg\":-0}}}")).entitlements();
    assertTrue(e.hasFeature("sso"));
    assertFalse(e.hasFeature("SSO"));
    assertFalse(e.hasFeature("seats"), "never looks at limits");
    assertEquals(3, e.limit("seats"));
    assertEquals(Entitlements.UNLIMITED, e.limit("nodes"));
    assertEquals(0, e.limit("missing"));
    assertEquals(0, e.limit("neg"));
    assertEquals(List.of(true, true, false), List.of(e.allows("seats", 0), e.allows("seats", 3), e.allows("seats", 4)));
    assertTrue(e.allows("nodes", Long.MAX_VALUE));
    assertTrue(e.allows("missing", 0));
    assertFalse(e.allows("missing", 1));
    assertFalse(e.allows("nodes", -1));
    assertFalse(Entitlements.none().hasFeature("x"));
    for (String l : List.of("1.0", "-2", "9007199254740992", "99999999999999999999", "\"1\"", "null")) {
      assertEquals("malformed", code(() -> claims(OK.replace("}", ",\"entitlements\":{\"limits\":{\"x\":" + l + "}}}"))), l);
    }
    assertEquals(9007199254740991L, claims(OK.replace("}", ",\"entitlements\":{\"limits\":{\"x\":9007199254740991}}}")).entitlements().limit("x"));
    assertEquals("malformed", code(() -> claims(OK.replace("}", ",\"entitlements\":{\"features\":[1]}}"))));
  }

  @Test
  void checkOptions() throws Exception {
    Claims c = claims(OK.replace("2026-11-01T00:00:00Z", "2026-11-01T00:00:01Z"));
    Instant now = Instant.parse("2026-11-01T00:00:00Z");
    assertEquals(LicenseFile.Status.VALID, LicenseFile.check(c, CheckOptions.of(now, "p")), "24h default tolerance");
    assertEquals("clock_skew", code(() -> LicenseFile.check(c, CheckOptions.of(now, "p").withClockTolerance(Duration.ZERO))));
    assertThrows(IllegalArgumentException.class, () -> CheckOptions.of(now, "p").withClockTolerance(Duration.ofSeconds(-1)));
    assertThrows(NullPointerException.class, () -> CheckOptions.of(null, "p"));
    assertThrows(IllegalArgumentException.class, () -> CheckOptions.of(now, "p").withClockTolerance(java.time.temporal.ChronoUnit.FOREVER.getDuration()));
    assertEquals(LicenseFile.Status.VALID, LicenseFile.check(c, CheckOptions.of(now, "p").withClockTolerance(CheckOptions.MAX_CLOCK_TOLERANCE)));
  }

  @Test
  void longWhitespaceRunIsCheap() {
    String input = "a" + " \t\r\n".repeat(16000) + "a"; // 64,002 bytes, under the limit
    long start = System.nanoTime();
    assertEquals("malformed", code(() -> LicenseFile.verify(input, List.of())));
    assertTrue(System.nanoTime() - start < 500_000_000L);
  }

  @Test
  @SuppressWarnings("unchecked")
  void sizeLimitCountsUtf8Bytes() throws Exception {
    Map<String, Object> v = VectorsTest.vectors("lf1.json");
    String found = null;
    for (Map<String, Object> c : VectorsTest.cases(v)) if (c.get("expect").equals("valid") && (found == null || ((String) c.get("license")).length() < found.length())) found = (String) c.get("license"); // the shortest
    final String license = found;
    String keys = "[{\"kid\":\"test:2026-11\",\"alg\":\"ed25519\",\"public_key\":\"K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k\"}]";
    List<PublicKey> ks = KeySet.parse(keys);
    int n = license.getBytes(StandardCharsets.UTF_8).length;
    String exact = license + "\n".repeat(LicenseFile.MAX_SIZE - n);
    assertEquals("ok", code(() -> LicenseFile.verify(exact, ks)), "exactly 64 KiB");
    assertEquals("malformed", code(() -> LicenseFile.verify(exact + "\n", ks)), "one byte over");
    // A BOM is one char but three bytes: 64 KiB - 1 chars, 64 KiB + 2 bytes.
    String bom = "\uFEFF" + license + "\n".repeat(LicenseFile.MAX_SIZE - n - 1);
    assertEquals("malformed", code(() -> LicenseFile.verify(bom, ks)), "bytes, not chars");
    assertEquals("ok", code(() -> LicenseFile.verify("\uFEFF" + license, ks)), "one BOM is ignored");
    // Lengths base64 can't have (≡ 1 mod 4) and an alg in the wrong case.
    String[] p = license.split("\\.");
    assertEquals("malformed", code(() -> LicenseFile.verify(p[0] + "." + p[1] + "." + p[2] + ".A", ks)), "signature of length 1");
    assertEquals("malformed", code(() -> LicenseFile.verify(p[0] + "." + p[1] + ".A." + p[3], ks)), "payload of length 1");
    assertEquals("unsupported_alg", code(() -> LicenseFile.verify(license, List.of(new PublicKey("test:2026-11", "ED25519", ks.get(0).key())))));
    // Empty parts count: String.split would drop trailing ones.
    for (String extra : List.of(".", "..", ". ")) assertEquals("malformed", code(() -> LicenseFile.verify(license + extra, ks)), "trailing " + extra);
  }

  @Test
  void weakEd25519() {
    HexFormat hex = HexFormat.of();
    List<byte[]> weak = new ArrayList<>();
    for (String h : List.of(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0100000000000000000000000000000000000000000000000000000000000080", // negative zero
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")) weak.add(hex.parseHex(h));
    for (int k = 0; k < 19; k++) {
      byte[] b = new byte[32];
      java.util.Arrays.fill(b, (byte) 0xff);
      b[0] = (byte) (0xed + k);
      b[31] = 0x7f;
      weak.add(b.clone()); // y = p + k
      b[31] = (byte) 0xff;
      weak.add(b); // and with the sign bit
    }
    for (byte[] k : weak) assertTrue(LicenseFile.weakEd25519(k), hex.formatHex(k));
    for (String h : List.of(
        "eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p − 3: a full-order point
        "0300000000000000000000000000000000000000000000000000000000000000", // y = 3
        "2b57583dbe767c93f76025809070aaf98b68ffc231df60a3df6dba5383ea23a9")) { // the vectors' test key
      assertFalse(LicenseFile.weakEd25519(hex.parseHex(h)), h);
    }
  }
}

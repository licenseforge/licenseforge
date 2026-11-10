package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** KeySet.parse: the same cases as the Go SDK's keyset_test.go and the TS SDK's. */
class KeySetTest {
  static final String VEC = "K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k"; // spec/vectors/lf1.json test:2026-11

  @Test
  void readsTheDashboardsJson() throws Exception {
    List<PublicKey> ks = KeySet.parse("[{\"kid\":\"sk_a\",\"alg\":\"ed25519\",\"public_key\":\"" + VEC + "\"},{\"kid\":\"sk_b\",\"alg\":\"ml-dsa-65\",\"public_key\":\"AAAA\"}]");
    assertEquals(2, ks.size());
    assertEquals(List.of("sk_a", "ed25519", VEC), List.of(ks.get(0).kid(), ks.get(0).alg(), Base64.getUrlEncoder().withoutPadding().encodeToString(ks.get(0).key())));
    assertEquals("ml-dsa-65", ks.get(1).alg());
    assertEquals(3, ks.get(1).key().length);
    assertEquals(1, KeySet.parse("[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]".getBytes(StandardCharsets.UTF_8)).size(), "bytes too");
  }

  @Test
  void whatVerifyDecidesLoadsAsGiven() throws Exception {
    List<PublicKey> ks = KeySet.parse("[{\"kid\":\"d\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"},{\"kid\":\"d\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"},"
        + "{\"kid\":\"x\",\"alg\":\"rsa\",\"public_key\":\"AAAA\"},{\"kid\":\"e\",\"alg\":\"\",\"public_key\":\"AAAA\"},{\"kid\":\"z\",\"alg\":\"ed25519\",\"public_key\":\"\"}]");
    assertEquals(5, ks.size());
    assertEquals(0, ks.get(4).key().length);
  }

  @Test
  void invalidKeySet() {
    Map<String, Object> cases = new LinkedHashMap<>();
    cases.put("not json", "{");
    cases.put("not an array", "{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}");
    cases.put("empty", "[]");
    cases.put("null", "null");
    cases.put("trailing data", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}] []");
    cases.put("typo in field", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"publicKey\":\"AAAA\"}]");
    cases.put("unknown field", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\",\"use\":\"sig\"}]");
    cases.put("missing key", "[{\"kid\":\"a\",\"alg\":\"ed25519\"}]");
    cases.put("missing kid", "[{\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]");
    cases.put("missing alg", "[{\"kid\":\"a\",\"public_key\":\"AAAA\"}]");
    cases.put("padded", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAA=\"}]");
    cases.put("standard alphabet", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AA+/\"}]");
    cases.put("non-canonical bits", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AB\"}]");
    cases.put("bad kid", "[{\"kid\":\"a.b\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]");
    cases.put("upper-case fields", "[{\"KID\":\"a\",\"ALG\":\"ed25519\",\"Public_Key\":\"AAAA\"}]");
    cases.put("kelvin sign", "[{\"\u212Aid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]");
    cases.put("repeated key", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\",\"public_key\":\"" + VEC + "\"}]");
    cases.put("case-variant repeat", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\",\"PUBLIC_KEY\":\"" + VEC + "\"}]");
    cases.put("repeated kid", "[{\"kid\":\"a\",\"kid\":\"b\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]");
    cases.put("null field", "[{\"kid\":\"a\",\"alg\":null,\"public_key\":\"AAAA\"}]");
    cases.put("number field", "[{\"kid\":\"a\",\"alg\":1,\"public_key\":\"AAAA\"}]");
    cases.put("null entry", "[null]");
    cases.put("newline in key", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AA\\nAA\"}]");
    cases.put("CR in key", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AA\\rAA\"}]");
    cases.put("long non-canonical", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"" + VEC.substring(0, VEC.length() - 1) + "l\"}]");
    cases.put("long padded", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"" + VEC + "=\"}]");
    cases.put("lone surrogate escape", "[{\"kid\":\"a\",\"alg\":\"\\ud800\",\"public_key\":\"AAAA\"}]");
    cases.put("lone surrogate in a string", "[{\"kid\":\"a\",\"alg\":\"\uD800\",\"public_key\":\"AAAA\"}]");
    cases.put("lone low surrogate in a string", "[{\"kid\":\"a\",\"alg\":\"\uDC00\",\"public_key\":\"AAAA\"}]");
    cases.put("BOM", "\uFEFF[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]");
    byte[] json = "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]".getBytes(StandardCharsets.UTF_8);
    byte[] bom = new byte[json.length + 3];
    bom[0] = (byte) 0xef;
    bom[1] = (byte) 0xbb;
    bom[2] = (byte) 0xbf;
    System.arraycopy(json, 0, bom, 3, json.length);
    cases.put("BOM in bytes", bom);
    byte[] bad = json.clone();
    bad[20] = (byte) 0xff;
    cases.put("invalid UTF-8", bad);
    for (Map.Entry<String, Object> c : cases.entrySet()) {
      LicenseException e = assertThrows(LicenseException.class, () -> {
        if (c.getValue() instanceof String s) KeySet.parse(s);
        else KeySet.parse((byte[]) c.getValue());
      }, c.getKey());
      assertEquals(LicenseException.Code.INVALID_KEY_SET, e.code(), c.getKey());
    }
  }

  @Test
  void messagesDontEchoTheFile() {
    for (String in : List.of("[{\"kid\":\"a\",\"alg\":\"ed25519\",\"s3cr3t_field\":\"AAAA\"}]", "[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\",\"s3cr3t\":1,\"s3cr3t\":2}]")) {
      LicenseException e = assertThrows(LicenseException.class, () -> KeySet.parse(in));
      assertFalse(e.getMessage().contains("s3cr3t"), in);
    }
  }
}

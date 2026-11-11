package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.licenseforge.sdk.Claims.Binding;
import io.licenseforge.sdk.Claims.BindingType;
import io.licenseforge.sdk.Offline.ActivationRequest;
import io.licenseforge.sdk.Offline.DeactivationReceipt;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** spec/vectors/offline.json, and encoding round trips (an SDK can't write what the server refuses). */
class OfflineTest {
  static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  @Test
  @SuppressWarnings("unchecked")
  void vectors() throws Exception {
    Map<String, Object> v = VectorsTest.vectors("offline.json");
    boolean someWant = false;
    for (Map<String, Object> c : VectorsTest.cases(v)) {
      Map<String, String> got = new HashMap<>();
      String result = "ok";
      try {
        if (c.get("kind").equals("request")) {
          ActivationRequest r = Offline.parseRequest((String) c.get("input"));
          got.putAll(Map.of("tenant", r.tenant(), "product", r.product(), "key", r.key(), "bind_type", r.binding().type().name().toLowerCase(java.util.Locale.ROOT),
              "fp", r.binding().fingerprint(), "fp_source", r.fpSource().spec(), "nonce", b64(r.nonce()), "created", r.created().toString()));
          r.hostname().ifPresent(h -> got.put("hostname", h));
          r.appVersion().ifPresent(h -> got.put("app_version", h));
          r.sdkVersion().ifPresent(h -> got.put("sdk_version", h));
        } else {
          DeactivationReceipt r = Offline.parseReceipt((String) c.get("input"));
          got.putAll(Map.of("tenant", r.tenant(), "license_id", r.licenseId(), "fp", r.fingerprint(), "file_sha256", r.fileSha256(),
              "nonce", b64(r.nonce()), "created", r.created().toString()));
        }
      } catch (LicenseException e) {
        result = e.code().spec();
      }
      assertEquals(c.get("result"), result, (String) c.get("name"));
      if (!result.equals("ok") || !c.containsKey("want")) continue; // some ok cases check only the class
      someWant = true;
      for (Map.Entry<String, Object> w : ((Map<String, Object>) c.get("want")).entrySet()) {
        assertEquals(w.getValue(), got.get(w.getKey()), c.get("name") + ": " + w.getKey());
      }
    }
    assertTrue(someWant, "some cases list fields");
  }

  @Test
  @SuppressWarnings("unchecked")
  void fileHashes() throws Exception {
    List<Map<String, Object>> hashes = (List<Map<String, Object>>) VectorsTest.vectors("offline.json").get("file_hashes");
    assertFalse(hashes.isEmpty());
    for (Map<String, Object> c : hashes) {
      String want = (String) c.get("file_sha256");
      if (want != null && !want.isEmpty()) {
        assertEquals(want, Offline.fileSha256((String) c.get("input")), (String) c.get("name"));
      } else {
        LicenseException e = assertThrows(LicenseException.class, () -> Offline.fileSha256((String) c.get("input")), (String) c.get("name"));
        assertEquals(LicenseException.Code.MALFORMED, e.code());
      }
    }
  }

  static final String FP = "sha256:81fe9b1a2812e068c320c4264f01b6d4d186a83cc0008fe954fd5d1b6e3f3684";
  static final byte[] NONCE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

  static ActivationRequest req(String tenant, String product, FingerprintSource src, byte[] nonce, Optional<String> hostname) {
    return new ActivationRequest(tenant, product, "LF-ABCDE-\nFGHIJ ", new Binding(BindingType.MACHINE, FP), src, nonce,
        Instant.parse("2026-11-08T10:00:00.789Z"), hostname, Optional.of("2.4 <b>&"), Optional.empty());
  }

  @Test
  void encodeRoundTripsAndWritesWhatGoWrites() throws Exception {
    ActivationRequest in = req("tnt_acme", "acme-db", FingerprintSource.MACHINE_ID, NONCE, Optional.of("db-1"));
    String tok = Offline.encodeRequest(in);
    ActivationRequest r = Offline.parseRequest(tok);
    assertEquals(List.of("LF-ABCDE-FGHIJ", "2026-11-08T10:00:00Z", "db-1", "2.4 <b>&"), List.of(r.key(), r.created().toString(), r.hostname().get(), r.appVersion().get()));
    assertTrue(r.sdkVersion().isEmpty());
    // The same bytes as the Go and TypeScript SDKs: sorted keys, <, > and & escaped.
    String json = new String(Base64.getUrlDecoder().decode(tok.substring("lfreq1.".length())), StandardCharsets.UTF_8);
    assertEquals("{\"app_version\":\"2.4 \\u003cb\\u003e\\u0026\",\"bind\":{\"fp\":\"" + FP + "\",\"type\":\"machine\"},\"created\":\"2026-11-08T10:00:00Z\",\"fp_source\":\"machine-id\",\"hostname\":\"db-1\",\"key\":\"LF-ABCDE-FGHIJ\",\"nonce\":\"AAECAwQFBgcICQoLDA0ODw\",\"product\":\"acme-db\",\"tenant\":\"tnt_acme\",\"v\":1}", json);
    for (ActivationRequest bad : List.of(
        req("tnt_acme", "acme-db", FingerprintSource.KUBERNETES, NONCE, Optional.empty()),
        req("tnt_acme", "acme-db", FingerprintSource.MACHINE_ID, NONCE, Optional.of("bad host")),
        req("tnt_acme", "acme-db", FingerprintSource.MACHINE_ID, new byte[15], Optional.empty()),
        req("tnt_acme", "acme-db", FingerprintSource.MACHINE_ID, new byte[17], Optional.empty()),
        new ActivationRequest("t", "p", "k", new Binding(BindingType.NONE, FP), FingerprintSource.KUBERNETES, NONCE, Instant.EPOCH, Optional.empty(), Optional.empty(), Optional.empty()),
        req("t\0x", "acme-db", FingerprintSource.MACHINE_ID, NONCE, Optional.empty()),
        req("tnt_acme", "\uD800", FingerprintSource.MACHINE_ID, NONCE, Optional.empty()),
        new ActivationRequest("t", "p", "k", Binding.NONE, FingerprintSource.MACHINE_ID, NONCE, Instant.EPOCH, Optional.empty(), Optional.empty(), Optional.empty()),
        new ActivationRequest("t", "p", "k", new Binding(BindingType.MACHINE, FP), FingerprintSource.MACHINE_ID, NONCE, Instant.parse("1969-12-31T23:59:59Z"), Optional.empty(), Optional.empty(), Optional.empty()))) {
      assertEquals(LicenseException.Code.MALFORMED, assertThrows(LicenseException.class, () -> Offline.encodeRequest(bad)).code());
    }
    // An empty optional is left out, as Go and TypeScript do.
    ActivationRequest empty = new ActivationRequest("t", "p", "k", new Binding(BindingType.MACHINE, FP), FingerprintSource.MACHINE_ID, NONCE, Instant.EPOCH, Optional.of(""), Optional.of(""), Optional.of(""));
    ActivationRequest back = Offline.parseRequest(Offline.encodeRequest(empty));
    assertTrue(back.hostname().isEmpty() && back.appVersion().isEmpty() && back.sdkVersion().isEmpty());
    DeactivationReceipt rc = new DeactivationReceipt("tnt_acme", "lic_1", FP, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", NONCE, Instant.parse("2026-11-08T10:00:00Z"));
    assertEquals(rc, Offline.parseReceipt(Offline.encodeReceipt(rc)));
    assertThrows(LicenseException.class, () -> Offline.encodeReceipt(new DeactivationReceipt("t", "l", FP, "ABC", NONCE, Instant.EPOCH)));
  }

  @Test
  void quoteLikeGo() throws Exception {
    assertEquals("\"a\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f\\u003c\\u003e\\u0026\\u2028\\u2029\u007fé😀\"", Offline.quote("a\"\\\b\f\n\r\t\u0001\u001f<>&\u2028\u2029\u007fé😀"));
    assertThrows(LicenseException.class, () -> Offline.quote("\uDC00"));
  }

  @Test
  void offlineSha256IgnoresWhatATransferAdds() throws Exception {
    String tok = Offline.encodeReceipt(new DeactivationReceipt("t", "l", FP, "0".repeat(64), NONCE, Instant.EPOCH));
    String h = Offline.offlineSha256(tok);
    assertTrue(h.matches("[0-9a-f]{64}"));
    assertEquals(h, Offline.offlineSha256("\uFEFF" + tok.substring(0, 10) + "\r\n" + tok.substring(10) + "\n"));
    // Node: an unpaired surrogate hashes as U+FFFD.
    assertEquals(Offline.offlineSha256("a\uFFFDb"), Offline.offlineSha256("a\uD800b"));
  }
}

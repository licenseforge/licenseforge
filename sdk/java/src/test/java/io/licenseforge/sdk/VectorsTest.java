package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The shared conformance vectors (spec/vectors): every SDK must give the expected class for every case. */
class VectorsTest {
  @SuppressWarnings("unchecked")
  static Map<String, Object> vectors(String name) throws Exception {
    return (Map<String, Object>) Json.parseValue(Files.readString(Path.of("../../spec/vectors", name)));
  }

  @SuppressWarnings("unchecked")
  static List<Map<String, Object>> cases(Map<String, Object> v) {
    List<Map<String, Object>> c = (List<Map<String, Object>>) v.get("cases");
    assertFalse(c.isEmpty());
    return c;
  }

  @Test
  void lf1EnvelopeAndSignature() throws Exception {
    Map<String, Object> v = vectors("lf1.json");
    // Through KeySet.parse, as an app loads them: a bad alg, key length or a
    // weak key loads as given and surfaces in verify.
    String keysJson = Files.readString(Path.of("../../spec/vectors/lf1.json"));
    int a = keysJson.indexOf("\"keys\":");
    int b = keysJson.indexOf(']', a);
    List<PublicKey> keys = KeySet.parse(keysJson.substring(keysJson.indexOf('[', a), b + 1));
    for (Map<String, Object> c : cases(v)) {
      String got = "valid";
      try {
        LicenseFile.Verified r = LicenseFile.verify((String) c.get("license"), keys);
        if (c.get("expect").equals("valid")) {
          assertEquals(c.get("kid"), r.kid(), (String) c.get("name"));
          assertArrayEquals(((String) c.get("payload")).getBytes(StandardCharsets.UTF_8), r.payload(), (String) c.get("name"));
        }
      } catch (LicenseException e) {
        got = e.code().spec();
      }
      assertEquals(c.get("expect"), got, (String) c.get("name"));
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void lf1ClaimEncodingAndChecks() throws Exception {
    for (Map<String, Object> c : cases(vectors("lf1-claims.json"))) {
      Map<String, Object> o = (Map<String, Object>) c.getOrDefault("options", Map.of());
      String got;
      try {
        Claims claims = LicenseFile.parseClaims(((String) c.get("payload")).getBytes(StandardCharsets.UTF_8));
        CheckOptions opts = CheckOptions.of(LicenseFile.parseTime((String) o.get("now")), (String) o.getOrDefault("product", ""));
        if (o.containsKey("fingerprint")) opts = opts.withFingerprint((String) o.get("fingerprint"));
        if (o.containsKey("build_date")) opts = opts.withBuildDate(LicenseFile.parseTime((String) o.get("build_date")));
        if (o.containsKey("clock_tolerance")) opts = opts.withClockTolerance(LicenseFile.parseDuration((String) o.get("clock_tolerance")));
        got = LicenseFile.check(claims, opts).name().toLowerCase(java.util.Locale.ROOT); // valid or grace
      } catch (LicenseException e) {
        got = e.code().spec();
      }
      assertEquals(c.get("expect"), got, (String) c.get("name"));
    }
  }
}

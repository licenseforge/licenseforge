package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Provider;
import java.security.Security;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** FIPS mode verifies through BCFIPS only (pom.xml runs the suite in both modes). */
class FipsModeTest {
  static final boolean FIPS = Boolean.getBoolean("licenseforge.fips");

  @Test
  void providerFollowsTheMode() {
    assertEquals(FIPS ? "BCFIPS" : "SunEC", LicenseFile.PROVIDER);
    if (FIPS) {
      assertNotNull(Security.getProvider("BCFIPS"));
      assertTrue(org.bouncycastle.crypto.CryptoServicesRegistrar.isInApprovedOnlyMode(), "BC FIPS approved-only mode (ADR-0024)");
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void withoutBcFipsFipsModeFailsClosed() throws Exception {
    if (!FIPS) return;
    Map<String, Object> valid = null;
    for (Map<String, Object> c : VectorsTest.cases(VectorsTest.vectors("lf1.json"))) {
      if (c.get("expect").equals("valid")) valid = c;
    }
    assertNotNull(valid);
    String license = (String) valid.get("license");
    LicenseFile.verify(license, VectorsTest.keys());
    Provider bc = Security.getProvider("BCFIPS");
    int at = java.util.Arrays.asList(Security.getProviders()).indexOf(bc) + 1;
    Security.removeProvider("BCFIPS");
    try {
      // No fallback to SunEC, which is installed.
      IllegalStateException e = assertThrows(IllegalStateException.class, () -> LicenseFile.verify(license, VectorsTest.keys()));
      assertTrue(e.getMessage().contains("BCFIPS"), e.getMessage());
    } finally {
      Security.insertProviderAt(bc, at);
    }
  }
}

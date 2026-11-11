package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureSpi;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** verify uses the JDK's Ed25519, whatever provider an app installs first. */
class ProviderTest {
  /** An Ed25519 Signature that accepts everything. */
  public static final class AcceptAll extends SignatureSpi {
    @Override
    protected void engineInitVerify(java.security.PublicKey k) {}

    @Override
    protected void engineInitSign(PrivateKey k) throws InvalidKeyException {
      throw new InvalidKeyException();
    }

    @Override
    protected void engineUpdate(byte b) {}

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {}

    @Override
    protected byte[] engineSign() {
      return new byte[0];
    }

    @Override
    protected boolean engineVerify(byte[] sig) {
      return true;
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String p, Object v) {}

    @Override
    @Deprecated
    protected Object engineGetParameter(String p) {
      return null;
    }
  }

  static final class Hostile extends Provider {
    private static final long serialVersionUID = 1L;

    Hostile() {
      super("LicenseForgeHostile", "1", "accepts every Ed25519 signature");
      put("Signature.Ed25519", AcceptAll.class.getName());
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void aProviderInstalledFirstIsNotUsed() throws Exception {
    List<PublicKey> keys = VectorsTest.keys();
    Security.insertProviderAt(new Hostile(), 1);
    try {
      int bad = 0;
      for (Map<String, Object> c : VectorsTest.cases(VectorsTest.vectors("lf1.json"))) {
        if (!c.get("expect").equals("bad_signature")) continue;
        bad++;
        String got = "valid";
        try {
          LicenseFile.verify((String) c.get("license"), keys);
        } catch (LicenseException e) {
          got = e.code().spec();
        }
        assertEquals("bad_signature", got, (String) c.get("name"));
      }
      assertEquals(true, bad > 0);
    } finally {
      Security.removeProvider("LicenseForgeHostile");
    }
  }
}

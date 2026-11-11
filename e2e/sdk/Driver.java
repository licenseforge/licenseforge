import io.licenseforge.sdk.Claims;
import io.licenseforge.sdk.Fingerprints;
import io.licenseforge.sdk.KeySet;
import io.licenseforge.sdk.LeaseStores;
import io.licenseforge.sdk.LicenseFile;
import io.licenseforge.sdk.Online;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * One step of a customer's app built on the Java SDK, for the SDK journeys (sdk_test.go):
 * java -cp sdk/java/target/classes e2e/sdk/Driver.java activate|refresh|deactivate|current (current: the saved lease
 * alone, no request). The same contract as driver.mjs: LF_* variables in, one JSON line out. Needs sdk/java compiled.
 */
public class Driver {
  static String env(String k) {
    String v = System.getenv(k);
    return v == null ? "" : v;
  }

  /** A JSON string. */
  static String q(String s) {
    StringBuilder b = new StringBuilder("\"");
    for (char c : String.valueOf(s).toCharArray()) {
      if (c == '"' || c == '\\') b.append('\\').append(c);
      else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
      else b.append(c);
    }
    return b.append('"').toString();
  }

  public static void main(String[] args) throws Exception {
    Fingerprints.Fingerprint fp = Fingerprints.compute(env("LF_TENANT_ID"), env("LF_PRODUCT"), new Fingerprints.Options(() -> env("LF_MACHINE"), false));
    Online.Config cfg = Online.Config.builder(env("LF_BASE_URL"), env("LF_TENANT_ID"), env("LF_PRODUCT"), env("LF_LICENSE_KEY"), KeySet.parse(env("LF_KEYS")), fp)
        .hostname(env("LF_MACHINE"))
        .appVersion("1.0.0")
        .store(new LeaseStores.FileLeaseStore(Path.of(env("LF_STORE"))))
        .maxAttempts(1);
    Online.Client client = Online.Client.create(cfg);
    String out;
    try {
      switch (args[0]) {
        case "activate" -> client.activate();
        case "refresh" -> client.refresh();
        case "deactivate" -> client.deactivate();
        case "current" -> {}
        default -> throw new IllegalArgumentException("unknown step " + args[0]);
      }
      out = "\"ok\":true";
      if (!args[0].equals("deactivate")) {
        LicenseFile.Opened o = client.current();
        Claims c = o.claims();
        out += ",\"lid\":" + q(c.licenseId()) + ",\"tenant\":" + q(c.tenant()) + ",\"product\":" + q(c.product()) + ",\"plan\":" + q(c.plan())
            + ",\"status\":" + q(o.status().name().toLowerCase(Locale.ROOT)) + ",\"sso\":" + c.entitlements().hasFeature("sso")
            + ",\"nope\":" + c.entitlements().hasFeature("nope") + ",\"seats\":" + c.entitlements().limit("seats");
      }
    } catch (Online.OnlineException e) {
      out = "\"ok\":false,\"code\":" + q(e.code().spec()) + ",\"http\":" + e.status() + ",\"detail\":" + q(e.getMessage());
    }
    List<String> w = new ArrayList<>();
    for (Exception x : client.takeWarnings()) w.add(q(x.toString()));
    System.out.println("{" + out + ",\"warnings\":[" + String.join(",", w) + "]}");
  }
}

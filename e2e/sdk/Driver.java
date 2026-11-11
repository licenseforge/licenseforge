import io.licenseforge.sdk.Claims;
import io.licenseforge.sdk.Clock;
import io.licenseforge.sdk.Fingerprints;
import io.licenseforge.sdk.KeySet;
import io.licenseforge.sdk.LeaseStores;
import io.licenseforge.sdk.LicenseException;
import io.licenseforge.sdk.LicenseFile;
import io.licenseforge.sdk.OfflineClient;
import io.licenseforge.sdk.Online;
import io.licenseforge.sdk.PublicKey;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * One step of a customer's app built on the Java SDK, for the SDK journeys (sdk_test.go):
 * java -cp sdk/java/target/classes e2e/sdk/Driver.java <step>, the steps and contract of driver.mjs:
 * LF_* variables in, one JSON line out. Needs sdk/java compiled.
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

  static String claims(LicenseFile.Opened o) {
    Claims c = o.claims();
    return ",\"iat\":" + q(c.issuedAt().toString()) + ",\"lid\":" + q(c.licenseId()) + ",\"tenant\":" + q(c.tenant()) + ",\"product\":" + q(c.product()) + ",\"plan\":" + q(c.plan())
        + ",\"status\":" + q(o.status().name().toLowerCase(Locale.ROOT)) + ",\"sso\":" + c.entitlements().hasFeature("sso")
        + ",\"nope\":" + c.entitlements().hasFeature("nope") + ",\"seats\":" + c.entitlements().limit("seats");
  }

  public static void main(String[] args) throws Exception {
    String op = args[0];
    Fingerprints.Fingerprint fp = Fingerprints.compute(env("LF_TENANT_ID"), env("LF_PRODUCT"), new Fingerprints.Options(() -> env("LF_MACHINE"), false));
    List<PublicKey> keys = KeySet.parse(env("LF_KEYS"));
    String out;
    List<String> w = new ArrayList<>();
    if (op.startsWith("offline-")) {
      OfflineClient client = new OfflineClient(OfflineClient.Config.builder(env("LF_TENANT_ID"), env("LF_PRODUCT"), env("LF_LICENSE_KEY"), keys, fp,
              new Clock.FileStore(Path.of(env("LF_STORE") + ".offline")))
          .hostname(env("LF_MACHINE"))
          .appVersion("1.0.0")
          .clock(new Clock.Guard(new Clock.FileStore(Path.of(env("LF_STORE") + ".clock")), env("LF_LICENSE_KEY"))));
      try {
        out = switch (op) {
          case "offline-request" -> "\"ok\":true,\"text\":" + q(client.request());
          case "offline-install" -> "\"ok\":true" + claims(client.install(env("LF_FILE")));
          case "offline-current" -> "\"ok\":true" + claims(client.current());
          case "offline-deactivate" -> "\"ok\":true,\"text\":" + q(client.deactivate());
          default -> throw new IllegalArgumentException("unknown step " + op);
        };
      } catch (OfflineClient.OfflineException e) {
        out = "\"ok\":false,\"code\":" + q(e.code().name().toLowerCase(Locale.ROOT)) + ",\"detail\":" + q(e.getMessage());
      } catch (LicenseException e) {
        out = "\"ok\":false,\"code\":" + q(e.code().spec()) + ",\"detail\":" + q(e.getMessage());
      } catch (Clock.ClockException e) {
        out = "\"ok\":false,\"code\":" + q(e.code().name().toLowerCase(Locale.ROOT)) + ",\"detail\":" + q(e.getMessage());
      }
    } else {
      Online.Client client = Online.Client.create(Online.Config.builder(env("LF_BASE_URL"), env("LF_TENANT_ID"), env("LF_PRODUCT"), env("LF_LICENSE_KEY"), keys, fp)
          .hostname(env("LF_MACHINE"))
          .appVersion("1.0.0")
          .store(new LeaseStores.FileLeaseStore(Path.of(env("LF_STORE"))))
          .maxAttempts(1));
      try {
        switch (op) {
          case "activate" -> client.activate();
          case "refresh" -> client.refresh();
          case "deactivate" -> client.deactivate();
          case "current" -> {}
          case "run" -> {
            // 30 s at most (the step then fails loudly), or LF_RUN_MS, then the lease it holds.
            long forMs = env("LF_RUN_MS").isEmpty() ? 0 : Long.parseLong(env("LF_RUN_MS"));
            Thread main = Thread.currentThread();
            Thread stop = new Thread(() -> {
              try {
                Thread.sleep(forMs > 0 ? forMs : 30_000);
                main.interrupt();
              } catch (InterruptedException x) {
                // the step ended
              }
            });
            stop.setDaemon(true);
            stop.start();
            try {
              client.run(x -> {});
            } catch (InterruptedException e) {
              if (forMs == 0) throw e;
            } finally {
              stop.interrupt();
            }
          }
          default -> throw new IllegalArgumentException("unknown step " + op);
        }
        out = "\"ok\":true" + (op.equals("deactivate") ? "" : claims(client.current()));
      } catch (Online.OnlineException e) {
        out = "\"ok\":false,\"code\":" + q(e.code().spec()) + ",\"http\":" + e.status() + ",\"detail\":" + q(e.getMessage());
        if (op.equals("run")) {
          boolean forgot;
          try {
            client.current();
            forgot = false;
          } catch (Online.OnlineException x) {
            forgot = x.code() == Online.OnlineException.Code.NO_LEASE;
          }
          out += ",\"forgot\":" + forgot;
        }
      }
      for (Exception x : client.takeWarnings()) w.add(q(x.toString()));
    }
    System.out.println("{" + out + ",\"warnings\":[" + String.join(",", w) + "]}");
  }
}

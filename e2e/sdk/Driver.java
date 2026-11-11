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
import java.nio.file.Files;
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

  /** A file, or with LF_K8S_STORE a ConfigMap or Secret through the API the LF_K8S_* variables name (driver.mjs). */
  static Online.LeaseStore leaseStore() throws Exception {
    String kind = env("LF_K8S_STORE");
    if (kind.isEmpty()) return new LeaseStores.FileLeaseStore(Path.of(env("LF_STORE")));
    LeaseStores.KubernetesApi api = new LeaseStores.KubernetesApi(env("LF_K8S_HOST"), Integer.parseInt(env("LF_K8S_PORT")),
        Files.readAllBytes(Path.of(env("LF_K8S_CA"))), env("LF_K8S_NAMESPACE"), () -> {
          if (env("LF_K8S_TOKEN_FILE").isEmpty()) return env("LF_K8S_TOKEN");
          try {
            return Files.readString(Path.of(env("LF_K8S_TOKEN_FILE"))).trim();
          } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
          }
        });
    return switch (kind) {
      case "secret" -> new LeaseStores.KubernetesSecretStore(env("LF_K8S_NAME"), null, null, api);
      case "configmap" -> new LeaseStores.KubernetesConfigMapStore(env("LF_K8S_NAME"), null, null, api);
      default -> throw new IllegalArgumentException("LF_K8S_STORE " + kind + ": configmap or secret");
    };
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
      Online.Config cfg = Online.Config.builder(env("LF_BASE_URL"), env("LF_TENANT_ID"), env("LF_PRODUCT"), env("LF_LICENSE_KEY"), keys, fp)
          .hostname(env("LF_MACHINE"))
          .appVersion("1.0.0")
          .store(leaseStore())
          .maxAttempts(1);
      if (!env("LF_CA").isEmpty()) cfg.ca(Files.readAllBytes(Path.of(env("LF_CA"))));
      Online.Client client = Online.Client.create(cfg);
      if (!env("LF_READY").isEmpty()) Files.writeString(Path.of(env("LF_READY")), "");
      List<String> errors = new ArrayList<>();
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
              client.run(x -> errors.add(x instanceof Online.OnlineException o ? q(o.code().spec()) : q(x.toString())));
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
      if (op.equals("run")) out += ",\"errors\":[" + String.join(",", errors) + "]";
      for (Exception x : client.takeWarnings()) w.add(q(x.toString()));
    }
    System.out.println("{" + out + ",\"warnings\":[" + String.join(",", w) + "]}");
  }
}

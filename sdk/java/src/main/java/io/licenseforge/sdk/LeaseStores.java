package io.licenseforge.sdk;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Lease stores for the online client (ADR-0004), as the Go and TypeScript
 * SDKs': a file, or one key of a Kubernetes ConfigMap or Secret through the
 * in-cluster API, so every replica of a cluster-bound app shares the lease (it
 * is signed, not secret). A stored lease is verified again when loaded.
 */
public final class LeaseStores {
  private LeaseStores() {}

  /** The lease in a file, written atomically with mode 0600 under a lock; "" empties it. Use a persistent path. */
  public static final class FileLeaseStore implements Online.LeaseStore {
    private final Clock.FileStore file;

    public FileLeaseStore(Path path) {
      this.file = new Clock.FileStore(Objects.requireNonNull(path, "path"));
    }

    @Override
    public String load() throws IOException {
      byte[][] got = {null};
      boolean ok = file.update(cur -> {
        got[0] = cur;
        return null; // no change
      });
      if (!ok) throw new IOException("licenseforge lease store: the lease file can't be read");
      return got[0] == null ? "" : Fingerprints.trim(new String(got[0], StandardCharsets.UTF_8));
    }

    @Override
    public void save(String lease) throws IOException {
      byte[] b = lease.getBytes(StandardCharsets.UTF_8);
      if (file.update(cur -> b)) return;
      // false also means the old file couldn't be read: the write may have worked anyway (as Go's FileStore checks).
      String back;
      try {
        back = load();
      } catch (IOException e) {
        back = null; // still unreadable: report the write
      }
      if (!Fingerprints.trim(lease).equals(back)) throw new IOException("licenseforge lease store: the lease file wasn't written");
    }
  }

  /** Where the Kubernetes API is, as the pod's service account sees it. Tests pass their own. */
  public record KubernetesApi(String host, int port, byte[] ca, String namespace, Supplier<String> token) {
    private static final String SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount";
    private static final Pattern PORT = Pattern.compile("[1-9][0-9]{0,4}");

    public KubernetesApi {
      Objects.requireNonNull(host, "host");
      ca = Objects.requireNonNull(ca, "ca").clone();
      Objects.requireNonNull(namespace, "namespace");
      Objects.requireNonNull(token, "token"); // read on every request: projected tokens rotate
    }

    @Override
    public byte[] ca() {
      return ca.clone();
    }

    /** The pod's own: KUBERNETES_SERVICE_HOST/PORT and the service account's CA, namespace and token. */
    public static KubernetesApi inCluster() throws IOException {
      String host = System.getenv("KUBERNETES_SERVICE_HOST");
      if (host == null || host.isEmpty()) throw new IOException("licenseforge lease store: not in a Kubernetes cluster (no KUBERNETES_SERVICE_HOST)");
      String port = System.getenv("KUBERNETES_SERVICE_PORT");
      if (port == null || port.isEmpty()) port = "443";
      if (!PORT.matcher(port).matches() || Integer.parseInt(port) > 65535) throw new IOException("licenseforge lease store: KUBERNETES_SERVICE_PORT isn't a port");
      byte[] ca;
      String ns;
      try {
        ca = Files.readAllBytes(Path.of(SA_DIR, "ca.crt"));
        ns = Fingerprints.trim(Files.readString(Path.of(SA_DIR, "namespace")));
      } catch (IOException e) {
        throw new IOException("licenseforge lease store: no service account (automountServiceAccountToken?): " + e.getMessage(), e);
      }
      return new KubernetesApi(host, Integer.parseInt(port), ca, ns, () -> {
        try {
          return Fingerprints.trim(Files.readString(Path.of(SA_DIR, "token")));
        } catch (IOException e) {
          throw new java.io.UncheckedIOException(e);
        }
      });
    }
  }

  private static final Pattern DNS_LABEL = Pattern.compile("[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?");
  private static final Pattern DNS_SUBDOMAIN = Pattern.compile("[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*");
  private static final Pattern DATA_KEY = Pattern.compile("[-._a-zA-Z0-9]{1,253}");
  private static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9+/]*={0,2}");
  /** A whole load or save, every attempt: the client holds its commit while saving. */
  private static final Duration API_TIMEOUT = Duration.ofSeconds(15);
  private static final int MAX_ANSWER = 4 << 20; // a near-limit object

  private static final class ApiException extends IOException {
    private static final long serialVersionUID = 1L;
    final int status;

    ApiException(int status, String msg) {
      super("kubernetes API: " + status + " " + msg);
      this.status = status;
    }
  }

  /** One key of a ConfigMap or Secret. */
  private abstract static class KubernetesStore implements Online.LeaseStore {
    private final String resource;
    private final String kind;
    private final String name;
    private final String namespace;
    private final String key;
    private KubernetesApi api;
    private HttpClient http;
    Duration timeout = API_TIMEOUT; // tests shorten it

    KubernetesStore(String resource, String kind, String name, String namespace, String key, KubernetesApi api) {
      this.resource = resource;
      this.kind = kind;
      this.name = Objects.requireNonNull(name, "name");
      this.namespace = namespace;
      this.key = key == null || key.isEmpty() ? "lease" : key;
      this.api = api;
    }

    private record Target(KubernetesApi api, HttpClient http, String path) {}

    private synchronized Target target() throws IOException {
      if (api == null) api = KubernetesApi.inCluster();
      String ns = namespace == null || namespace.isEmpty() ? api.namespace() : namespace;
      if (!DNS_LABEL.matcher(ns).matches()) throw new IOException("licenseforge lease store: the namespace isn't a valid name");
      if (name.length() > 253 || !DNS_SUBDOMAIN.matcher(name).matches()) throw new IOException("licenseforge lease store: the " + kind + " name isn't a valid name");
      if (!DATA_KEY.matcher(key).matches() || key.startsWith("..") || key.equals(".")) throw new IOException("licenseforge lease store: the key isn't a valid " + kind + " key");
      if (http == null) {
        try {
          http = Fingerprints.clusterClient(api.ca(), Duration.ofSeconds(10));
        } catch (GeneralSecurityException e) {
          throw new IOException("licenseforge lease store: unusable service account CA: " + e.getMessage(), e);
        }
      }
      return new Target(api, http, "/api/v1/namespaces/" + ns + "/" + resource + "/" + name);
    }

    private String decode(Object v) throws IOException {
      String s = v instanceof String x ? x : "";
      if (!kind.equals("Secret")) return s;
      s = s.replace("\r", "").replace("\n", ""); // Go's StdEncoding skips CR and LF too
      if (!BASE64.matcher(s).matches() || s.length() % 4 != 0) throw new IOException("the Secret's value isn't base64");
      return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
    }

    private String encode(String lease) {
      return kind.equals("Secret") ? Base64.getEncoder().encodeToString(lease.getBytes(StandardCharsets.UTF_8)) : lease;
    }

    /** "" when the object or the key is missing. */
    @Override
    public String load() throws IOException {
      Target t = target();
      long deadline = System.nanoTime() + timeout.toNanos();
      try {
        Object obj = call(t, "GET", t.path(), null, deadline);
        Object data = obj instanceof Map<?, ?> m ? m.get("data") : null;
        return decode(data instanceof Map<?, ?> d ? d.get(key) : null);
      } catch (ApiException e) {
        if (e.status == 404) return "";
        throw new IOException("licenseforge lease store: loading " + kind + " " + t.path() + ": " + e.getMessage(), e);
      } catch (java.io.InterruptedIOException e) {
        throw e;
      } catch (IOException e) {
        throw new IOException("licenseforge lease store: loading " + kind + " " + t.path() + ": " + e.getMessage(), e);
      }
    }

    /**
     * Sets (or, for "", removes) the key: reads the object and writes it back
     * conditional on its resourceVersion, everything else kept; creates it if
     * missing. A concurrent writer (409) or a deletion meanwhile (404) means
     * another round after a short jittered pause.
     */
    @Override
    public void save(String lease) throws IOException {
      Target t = target();
      long deadline = System.nanoTime() + timeout.toNanos();
      for (int attempt = 0; ; attempt++) {
        try {
          saveOnce(t, lease, deadline);
          return;
        } catch (java.io.InterruptedIOException e) {
          throw e;
        } catch (IOException e) {
          int status = e instanceof ApiException a ? a.status : 0;
          if ((status == 409 || status == 404) && attempt < 4 && System.nanoTime() < deadline) {
            try {
              Thread.sleep(50 + ThreadLocalRandom.current().nextInt(200));
            } catch (InterruptedException ie) {
              Thread.currentThread().interrupt();
              throw new java.io.InterruptedIOException("licenseforge lease store: interrupted");
            }
            continue;
          }
          String hint = status == 403 ? " (create the " + kind + " beforehand and grant get and update on it by name)" : "";
          throw new IOException("licenseforge lease store: saving " + kind + " " + t.path() + ": " + e.getMessage() + hint, e);
        }
      }
    }

    @SuppressWarnings("unchecked")
    private void saveOnce(Target t, String lease, long deadline) throws IOException {
      Map<String, Object> obj;
      try {
        Object got = call(t, "GET", t.path(), null, deadline);
        if (!(got instanceof Map<?, ?> m)) throw new IOException("the API's answer isn't an object");
        obj = (Map<String, Object>) m;
        // Only a PUT carrying the resourceVersion read is conditional: without one it would overwrite a concurrent writer.
        if (!(obj.get("metadata") instanceof Map<?, ?> meta) || !(meta.get("resourceVersion") instanceof String rv) || rv.isEmpty()) {
          throw new IOException("the API's answer has no metadata.resourceVersion");
        }
      } catch (ApiException e) {
        if (e.status != 404) throw e;
        if (lease.isEmpty()) return; // nothing to remove
        Map<String, Object> create = new LinkedHashMap<>();
        create.put("apiVersion", "v1");
        create.put("kind", kind);
        create.put("metadata", Map.of("name", name));
        create.put("data", Map.of(key, encode(lease)));
        call(t, "POST", t.path().substring(0, t.path().lastIndexOf('/')), create, deadline); // 409 if created meanwhile: another round
        return;
      }
      Map<String, Object> data = new LinkedHashMap<>();
      if (obj.get("data") instanceof Map<?, ?> d) data.putAll((Map<String, Object>) d);
      if (lease.isEmpty()) data.remove(key);
      else data.put(key, encode(lease));
      Map<String, Object> next = new LinkedHashMap<>(obj);
      next.put("data", data);
      call(t, "PUT", t.path(), next, deadline); // carries the resourceVersion read: conditional
    }

    private static Object call(Target t, String method, String path, Map<String, Object> body, long deadline) throws IOException {
      long left = (deadline - System.nanoTime()) / 1_000_000;
      if (left <= 0) throw new IOException("timed out");
      String token;
      try {
        token = t.api().token().get();
      } catch (RuntimeException e) {
        throw new IOException("the service account token can't be read", e);
      }
      if (token == null || token.isEmpty()) throw new IOException("the service account token is empty");
      HttpRequest req;
      try {
        HttpRequest.BodyPublisher pub = body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(write(body), StandardCharsets.UTF_8);
        req = HttpRequest.newBuilder(URI.create(Fingerprints.clusterBase(t.api().host(), t.api().port()) + path))
            .header("Authorization", "Bearer " + token).header("Content-Type", "application/json")
            .timeout(Duration.ofMillis(Math.min(left, 10_000))).method(method, pub).build();
      } catch (IllegalArgumentException e) {
        // The JDK's message would quote the header value: never the token.
        throw new IOException("the service account token or the API host can't be sent (a line break?)");
      }
      // The whole exchange, body included, within the budget: on JDK 17 the request timeout
      // doesn't cover the body, and the client holds its commit lock while saving.
      java.util.concurrent.atomic.AtomicReference<InputStream> stream = new java.util.concurrent.atomic.AtomicReference<>();
      java.util.concurrent.CompletableFuture<Object[]> f = t.http().sendAsync(req, HttpResponse.BodyHandlers.ofInputStream()).thenApply(r -> {
        stream.set(r.body());
        try (InputStream in = r.body()) {
          return new Object[] {r.statusCode(), in.readNBytes(MAX_ANSWER + 1)};
        } catch (IOException e) {
          throw new java.io.UncheckedIOException(e);
        }
      });
      Object[] got;
      try {
        got = f.get(Math.max(1, (deadline - System.nanoTime()) / 1_000_000), java.util.concurrent.TimeUnit.MILLISECONDS);
      } catch (InterruptedException e) {
        cancel(f, stream);
        Thread.currentThread().interrupt();
        throw new java.io.InterruptedIOException("interrupted");
      } catch (java.util.concurrent.TimeoutException e) {
        cancel(f, stream);
        throw new IOException("timed out");
      } catch (java.util.concurrent.ExecutionException e) {
        Throwable c = e.getCause() instanceof java.io.UncheckedIOException u ? u.getCause() : e.getCause();
        throw c instanceof IOException io ? io : new IOException(String.valueOf(c), c);
      }
      byte[] raw = (byte[]) got[1];
      if (raw.length > MAX_ANSWER) throw new IOException("answer over 4 MiB");
      String text = new String(raw, StandardCharsets.UTF_8);
      int status = (Integer) got[0];
      if (status < 200 || status > 299) {
        String msg = text.length() > 200 ? text.substring(0, 200) : text;
        try {
          if (Json.parseValue(text) instanceof Map<?, ?> m && m.get("message") instanceof String s && !s.isEmpty()) msg = s;
        } catch (Json.JsonException e) {
          // not a Status object
        }
        throw new ApiException(status, msg);
      }
      if (text.isEmpty()) return null;
      try {
        return Json.parseValue(text);
      } catch (Json.JsonException e) {
        throw new IOException("the API's answer isn't JSON: " + e.getMessage());
      }
    }
  }

  private static void cancel(java.util.concurrent.CompletableFuture<?> f, java.util.concurrent.atomic.AtomicReference<InputStream> stream) {
    f.cancel(true);
    InputStream in = stream.get();
    if (in != null) {
      try {
        in.close(); // unblocks the reader
      } catch (IOException ignored) {
        // closing anyway
      }
    }
  }

  /** Writes a value the strict reader returned (Map, List, String, Num, Boolean, NULL) back as JSON. */
  static String write(Object v) throws IOException {
    StringBuilder b = new StringBuilder();
    write(b, v);
    return b.toString();
  }

  private static void write(StringBuilder b, Object v) throws IOException {
    if (v == null || v == Json.NULL) {
      b.append("null");
    } else if (v instanceof String s) {
      try {
        b.append(Offline.quote(s));
      } catch (LicenseException e) {
        throw new IOException("not valid Unicode");
      }
    } else if (v instanceof Json.Num n) {
      b.append(n.token());
    } else if (v instanceof Boolean x) {
      b.append(x);
    } else if (v instanceof Map<?, ?> m) {
      b.append('{');
      String sep = "";
      for (Map.Entry<?, ?> e : m.entrySet()) {
        b.append(sep);
        write(b, String.valueOf(e.getKey()));
        b.append(':');
        write(b, e.getValue());
        sep = ",";
      }
      b.append('}');
    } else if (v instanceof List<?> l) {
      b.append('[');
      for (int i = 0; i < l.size(); i++) {
        if (i > 0) b.append(',');
        write(b, l.get(i));
      }
      b.append(']');
    } else {
      throw new IOException("can't write " + v.getClass().getSimpleName());
    }
  }

  /**
   * The lease in one key of a ConfigMap (RBAC: get and update on it, by
   * resourceNames; create it beforehand, since create can't be limited to a
   * name). namespace and key may be null: the pod's namespace, "lease"; api
   * null: in-cluster.
   */
  public static final class KubernetesConfigMapStore extends KubernetesStore {
    public KubernetesConfigMapStore(String name, String namespace, String key, KubernetesApi api) {
      super("configmaps", "ConfigMap", name, namespace, key, api);
    }
  }

  /** KubernetesConfigMapStore on a Secret, for clusters whose policy prefers Secrets (ADR-0004, amended). */
  public static final class KubernetesSecretStore extends KubernetesStore {
    public KubernetesSecretStore(String name, String namespace, String key, KubernetesApi api) {
      super("secrets", "Secret", name, namespace, key, api);
    }
  }
}

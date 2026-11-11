package io.licenseforge.sdk;

import io.licenseforge.sdk.Claims.BindingType;
import java.io.ByteArrayInputStream;
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
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * The default machine or cluster fingerprint a license is bound to (ADR-0017,
 * spec/license-format.md "Fingerprints"). Sources, first match wins: the
 * vendor's override, LICENSEFORGE_FINGERPRINT if the vendor allows it,
 * Kubernetes (the kube-system namespace UID), the OS machine ID.
 */
public final class Fingerprints {
  private Fingerprints() {}

  /** The environment variable end users may set, only when the vendor allows it. */
  public static final String ENV_OVERRIDE = "LICENSEFORGE_FINGERPRINT";

  /** A fingerprint, where it came from, and the binding type it gives. */
  public record Fingerprint(String fingerprint, FingerprintSource source, BindingType binding) {}

  /**
   * Set by the vendor embedding the SDK, not by end users.
   *
   * @param override a raw ID chosen by the vendor (hardware serial, cloud instance ID…), or null; wins over every source
   * @param allowEnvOverride let end users set LICENSEFORGE_FINGERPRINT; off by default: anyone who can set it can share one binding
   */
  public record Options(Callable<String> override, boolean allowEnvOverride) {
    public static final Options DEFAULT = new Options(null, false);
  }

  /** Why there's no fingerprint. */
  public static final class FingerprintException extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Code {
      /** No stable, unique ID here: mount the host /etc/machine-id, or have the vendor enable an override. */
      NO_FINGERPRINT,
      /** A source was temporarily unavailable: retry later. */
      TRANSIENT,
      /** Bad tenant, product or override input. */
      INVALID,
      /** A source answered with a permanent error (RBAC, certificate, the override threw). */
      FAILED
    }

    private final Code code;

    FingerprintException(Code code, String detail) {
      super("licenseforge fingerprint: " + detail);
      this.code = code;
    }

    FingerprintException(Code code, String detail, Throwable cause) {
      super("licenseforge fingerprint: " + detail, cause);
      this.code = code;
    }

    public Code code() {
      return code;
    }
  }

  private static FingerprintException err(FingerprintException.Code code, String detail) {
    return new FingerprintException(code, detail);
  }

  /**
   * "sha256:" + hex(SHA-256 of the UTF-8 bytes of "lf-fp-v1", tenant, product
   * and raw ID joined by 0x00). All non-empty and well-formed; no NUL in
   * tenant or product.
   */
  public static String hash(String tenant, String product, String rawId) throws FingerprintException {
    Objects.requireNonNull(tenant, "tenant");
    Objects.requireNonNull(product, "product");
    Objects.requireNonNull(rawId, "rawId");
    if (rawId.isEmpty()) throw err(FingerprintException.Code.INVALID, "empty raw ID");
    if (tenant.isEmpty() || product.isEmpty() || tenant.indexOf('\0') >= 0 || product.indexOf('\0') >= 0) {
      throw err(FingerprintException.Code.INVALID, "tenant and product IDs must be non-empty and contain no NUL");
    }
    for (String s : List.of(tenant, product, rawId)) {
      if (!wellFormed(s)) throw err(FingerprintException.Code.INVALID, "IDs must be valid Unicode");
    }
    try {
      byte[] d = MessageDigest.getInstance("SHA-256").digest(("lf-fp-v1\0" + tenant + "\0" + product + "\0" + rawId).getBytes(StandardCharsets.UTF_8));
      return "sha256:" + HexFormat.of().formatHex(d);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static boolean wellFormed(String s) {
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) i++;
      else if (Character.isSurrogate(c)) return false;
    }
    return true;
  }

  /** Removes only SP, HT, CR and LF at both ends, as every SDK does. */
  static String trim(String s) {
    int a = 0;
    int z = s.length();
    while (a < z && ws(s.charAt(a))) a++;
    while (z > a && ws(s.charAt(z - 1))) z--;
    return s.substring(a, z);
  }

  private static boolean ws(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  }

  /** The sources compute reads, injectable for tests. */
  interface Env {
    String getenv(String name);

    /** Whether the JVM decodes the environment as UTF-8 (sun.jnu.encoding; always on Windows, which has UTF-16). */
    default boolean utf8Environment() {
      return Fingerprints.utf8Environment(System.getProperty("os.name", ""), System.getProperty("sun.jnu.encoding", ""));
    }

    String kubernetes() throws FingerprintException;

    String machineId() throws FingerprintException;
  }

  static boolean utf8Environment(String osName, String jnuEncoding) {
    return osName.startsWith("Windows") || jnuEncoding.equalsIgnoreCase("UTF-8") || jnuEncoding.equalsIgnoreCase("UTF8");
  }

  private static final Env DEFAULT_ENV = new Env() {
    @Override
    public String getenv(String name) {
      return System.getenv(name);
    }

    @Override
    public String kubernetes() throws FingerprintException {
      return kubeSystemUid();
    }

    @Override
    public String machineId() throws FingerprintException {
      return osMachineId();
    }
  };

  /**
   * The default fingerprint for a tenant's product on this machine. tenant and
   * product are the license's claims (the tenant ID such as "tnt_8f2c", not a
   * dashboard slug); {@link #forLicense} takes them from a verified license.
   */
  public static Fingerprint compute(String tenant, String product, Options opts) throws FingerprintException {
    return compute(tenant, product, opts, DEFAULT_ENV);
  }

  /** The fingerprint for a verified, bound license, with its tenant and product. */
  public static Fingerprint forLicense(Claims claims, Options opts) throws FingerprintException {
    Objects.requireNonNull(claims, "claims");
    return compute(claims.tenant(), claims.product(), opts);
  }

  static Fingerprint compute(String tenant, String product, Options opts, Env env) throws FingerprintException {
    Objects.requireNonNull(opts, "opts");
    hash(tenant, product, "-"); // validate the IDs before touching any source
    if (opts.override() != null) {
      String raw;
      try {
        raw = opts.override().call();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new FingerprintException(FingerprintException.Code.FAILED, "override: interrupted", e);
      } catch (Exception e) {
        throw new FingerprintException(FingerprintException.Code.FAILED, "override: " + e, e);
      }
      if (raw == null || (raw = trim(raw)).isEmpty()) throw err(FingerprintException.Code.INVALID, "override returned an empty ID");
      return new Fingerprint(hash(tenant, product, raw), FingerprintSource.OVERRIDE, BindingType.MACHINE);
    }
    if (opts.allowEnvOverride()) {
      String v = env.getenv(ENV_OVERRIDE);
      String raw = trim(v == null ? "" : v);
      // The JVM decodes invalid UTF-8 in the environment as U+FFFD: refused, as Go refuses invalid UTF-8.
      // In a C/POSIX or Latin-1 locale the JVM misreads UTF-8 bytes: a different fingerprint than Go/TS.
      if (!env.utf8Environment() && raw.chars().anyMatch(c -> c > 0x7f)) {
        throw err(FingerprintException.Code.INVALID, ENV_OVERRIDE + " has non-ASCII characters and the JVM's locale isn't UTF-8: set a UTF-8 locale (LANG=C.UTF-8) or use an ASCII value");
      }
      if (raw.indexOf('\uFFFD') >= 0) throw err(FingerprintException.Code.INVALID, ENV_OVERRIDE + " isn't valid UTF-8");
      if (!raw.isEmpty()) return new Fingerprint(hash(tenant, product, raw), FingerprintSource.ENV, BindingType.MACHINE);
    }
    String k8s = env.getenv("KUBERNETES_SERVICE_HOST");
    if (k8s != null && !k8s.isEmpty()) {
      return new Fingerprint(hash(tenant, product, env.kubernetes()), FingerprintSource.KUBERNETES, BindingType.CLUSTER);
    }
    return new Fingerprint(hash(tenant, product, env.machineId()), FingerprintSource.MACHINE_ID, BindingType.MACHINE);
  }

  // --- Kubernetes ---

  private static final String SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount";
  private static final Pattern PORT = Pattern.compile("[1-9][0-9]{0,4}");

  /** Reads the kube-system namespace UID with the pod's service account (RBAC: get namespaces/kube-system). */
  private static String kubeSystemUid() throws FingerprintException {
    String token;
    byte[] ca;
    try {
      token = trim(Files.readString(Path.of(SA_DIR, "token")));
      ca = Files.readAllBytes(Path.of(SA_DIR, "ca.crt"));
    } catch (IOException e) {
      throw new FingerprintException(FingerprintException.Code.FAILED, "kubernetes: no service account token or CA (is automountServiceAccountToken disabled?)", e);
    }
    String host = System.getenv("KUBERNETES_SERVICE_HOST");
    String port = System.getenv("KUBERNETES_SERVICE_PORT");
    if (port == null || port.isEmpty()) port = "443";
    if (!PORT.matcher(port).matches() || Integer.parseInt(port) > 65535) throw err(FingerprintException.Code.FAILED, "kubernetes: KUBERNETES_SERVICE_PORT isn't a port");
    return namespaceUid(host, Integer.parseInt(port), token, ca, List.of(Duration.ofMillis(500), Duration.ofSeconds(2)));
  }

  /** The whole request, body included (a read timeout alone resets on every byte). */
  static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
  private static final int MAX_ANSWER = 1 << 20;

  private record Attempt(String uid, boolean permanent, String detail) {}

  /**
   * An HTTP client for the Kubernetes API: trusts only the cluster's CA (PEM),
   * TLS 1.2 or later, no redirects. Shared with the Kubernetes lease stores.
   */
  static HttpClient clusterClient(byte[] ca, Duration connectTimeout) throws GeneralSecurityException, IOException {
    SSLContext tls = trustOnly(ca);
    javax.net.ssl.SSLParameters params = tls.getDefaultSSLParameters();
    params.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"}); // as Go and TS: never older, whatever java.security allows
    return HttpClient.newBuilder().sslContext(tls).sslParameters(params).connectTimeout(connectTimeout)
        .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).build();
  }

  /** A TLS context that trusts only the CA certificate(s) in ca (PEM); shared with Online's ca option. */
  static SSLContext trustOnly(byte[] ca) throws GeneralSecurityException, IOException {
    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    ks.load(null, null);
    int n = 0;
    for (Certificate c : CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(ca))) ks.setCertificateEntry("ca" + n++, c);
    if (n == 0) throw new GeneralSecurityException("no certificate in the CA file");
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(ks); // only these CAs
    SSLContext tls = SSLContext.getInstance("TLS");
    tls.init(null, tmf.getTrustManagers(), null);
    return tls;
  }

  /** https://host:port, an IPv6 service address bracketed. */
  static String clusterBase(String host, int port) {
    return "https://" + (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + port;
  }

  /** Fetches the UID, retrying transient failures (network, timeout, 429, 5xx) after each backoff. */
  static String namespaceUid(String host, int port, String token, byte[] ca, List<Duration> backoff) throws FingerprintException {
    HttpClient client;
    HttpRequest req;
    try {
      client = clusterClient(ca, REQUEST_TIMEOUT);
      req = HttpRequest.newBuilder(URI.create(clusterBase(host, port) + "/api/v1/namespaces/kube-system"))
          .header("Authorization", "Bearer " + token).timeout(REQUEST_TIMEOUT).GET().build();
    } catch (IllegalArgumentException e) {
      // The JDK's message would quote the header value: never the token, nor a cause carrying it.
      throw err(FingerprintException.Code.FAILED, "kubernetes: the service account token or the API host can't be sent (a line break?)");
    } catch (GeneralSecurityException | IOException e) {
      throw new FingerprintException(FingerprintException.Code.FAILED, "kubernetes: unusable service account CA: " + e.getMessage(), e);
    }
    for (int attempt = 0; ; attempt++) {
      Attempt a = get(client, req);
      if (a.uid() != null) return a.uid();
      if (a.permanent()) throw err(FingerprintException.Code.FAILED, "kubernetes: " + a.detail());
      if (attempt >= backoff.size()) throw err(FingerprintException.Code.TRANSIENT, "kubernetes: " + a.detail());
      try {
        Thread.sleep(backoff.get(attempt).toMillis());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw err(FingerprintException.Code.TRANSIENT, "kubernetes: interrupted");
      }
    }
  }

  private static Attempt get(HttpClient client, HttpRequest req) {
    AtomicReference<InputStream> body = new AtomicReference<>();
    CompletableFuture<Attempt> f = client.sendAsync(req, HttpResponse.BodyHandlers.ofInputStream()).thenApply(res -> {
      body.set(res.body());
      try (InputStream in = res.body()) {
        byte[] b = in.readNBytes(MAX_ANSWER + 1);
        if (b.length > MAX_ANSWER) return new Attempt(null, true, "answer over 1 MiB"); // like a decode error: retrying won't help
        int status = res.statusCode();
        if (status == 429 || status >= 500) return new Attempt(null, false, "GET namespace kube-system: " + status);
        if (status != 200) return new Attempt(null, true, "GET namespace kube-system: " + status + " (needs RBAC get on namespaces/kube-system)");
        return uid(b);
      } catch (IOException e) {
        return new Attempt(null, false, e.toString());
      }
    });
    try {
      return f.get(REQUEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      f.cancel(true);
      InputStream in = body.get();
      if (in != null) {
        try {
          in.close(); // unblocks the reader
        } catch (IOException ignored) {
          // closing anyway
        }
      }
      return new Attempt(null, false, "no answer within " + REQUEST_TIMEOUT.toSeconds() + " s");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return new Attempt(null, false, "interrupted");
    } catch (ExecutionException e) {
      Throwable c = e.getCause();
      // Certificate and name problems are configuration errors: retrying won't help. A handshake
      // cut off by the network (an API server restarting) is transient, as in Go and TS.
      boolean cert = false;
      for (Throwable t = c; t != null && !cert; t = t.getCause()) {
        cert = t instanceof java.security.cert.CertificateException || t instanceof javax.net.ssl.SSLPeerUnverifiedException;
      }
      return new Attempt(null, cert, String.valueOf(c));
    }
  }

  @SuppressWarnings("unchecked")
  private static Attempt uid(byte[] b) {
    try {
      Object v = Json.parseValue(KeySet.utf8(b));
      Object meta = v instanceof Map<?, ?> m ? m.get("metadata") : null;
      Object uid = meta instanceof Map<?, ?> mm ? mm.get("uid") : null;
      if (uid instanceof String s && !s.isEmpty()) return new Attempt(s, false, "");
      return new Attempt(null, true, "kube-system namespace has no uid");
    } catch (Json.JsonException | IOException e) {
      return new Attempt(null, true, "decode namespace: " + e.getMessage());
    }
  }

  // --- OS machine IDs ---

  static String osMachineId() throws FingerprintException {
    String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    if (os.startsWith("linux")) return linuxMachineId(LinuxFs.REAL);
    if (os.startsWith("windows")) return windowsMachineGuid();
    if (os.startsWith("mac")) return macPlatformUuid();
    throw err(FingerprintException.Code.NO_FINGERPRINT, "no machine ID source on " + os + ": have the vendor supply an override");
  }

  private static String run(List<String> cmd) throws FingerprintException {
    try {
      Process p = new ProcessBuilder(cmd).redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(new java.io.File(System.getProperty("os.name", "").startsWith("Windows") ? "NUL" : "/dev/null"))).start();
      CompletableFuture<byte[]> out = CompletableFuture.supplyAsync(() -> {
        try (InputStream in = p.getInputStream()) {
          return in.readNBytes(1 << 20);
        } catch (IOException e) {
          return new byte[0];
        }
      });
      if (!p.waitFor(10, TimeUnit.SECONDS)) {
        p.destroyForcibly();
        throw err(FingerprintException.Code.NO_FINGERPRINT, cmd.get(0) + ": timed out");
      }
      if (p.exitValue() != 0) throw err(FingerprintException.Code.NO_FINGERPRINT, cmd.get(0) + ": exit " + p.exitValue());
      return new String(out.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8);
    } catch (IOException | ExecutionException | TimeoutException e) {
      throw new FingerprintException(FingerprintException.Code.NO_FINGERPRINT, cmd.get(0) + ": " + e, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw err(FingerprintException.Code.NO_FINGERPRINT, cmd.get(0) + ": interrupted");
    }
  }

  private static final Pattern MACHINE_GUID = Pattern.compile("^ {4}MachineGuid {4}REG_SZ {4}(.*?)\\r?$", Pattern.MULTILINE);

  /** HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid, 64-bit view, as stored. */
  private static String windowsMachineGuid() throws FingerprintException {
    String root = System.getenv("SystemRoot");
    if (root == null || root.isEmpty()) root = "C:\\Windows";
    String out = run(List.of(root + "\\System32\\reg.exe", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid", "/reg:64"));
    Matcher m = MACHINE_GUID.matcher(out);
    if (!m.find() || m.group(1).isEmpty()) throw err(FingerprintException.Code.NO_FINGERPRINT, "MachineGuid not found, empty or not a string");
    return m.group(1);
  }

  private static final Pattern PLATFORM_UUID = Pattern.compile("\"IOPlatformUUID\" = \"([0-9A-Fa-f-]{36})\"");

  /** IOPlatformUUID from ioreg, as printed (uppercase). */
  private static String macPlatformUuid() throws FingerprintException {
    Matcher m = PLATFORM_UUID.matcher(run(List.of("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")));
    if (!m.find()) throw err(FingerprintException.Code.NO_FINGERPRINT, "IOPlatformUUID not found");
    return m.group(1);
  }

  /** What linuxMachineId reads, injectable for tests. readFile returns null when absent or unreadable. */
  interface LinuxFs {
    String readFile(String path);

    boolean exists(String path);

    LinuxFs REAL = new LinuxFs() {
      @Override
      public String readFile(String path) {
        try {
          return new String(Files.readAllBytes(Path.of(path)), StandardCharsets.ISO_8859_1); // bytes as chars, like Go's strings
        } catch (IOException | RuntimeException e) {
          return null;
        }
      }

      @Override
      public boolean exists(String path) {
        return Files.exists(Path.of(path));
      }
    };
  }

  /**
   * A stable, unique Linux machine ID, or NO_FINGERPRINT: a machine-id on
   * tmpfs/ramfs is regenerated every boot; in an application container only
   * the host's /etc/machine-id bind-mounted in is trusted; otherwise
   * /etc/machine-id, then /var/lib/dbus/machine-id.
   */
  static String linuxMachineId(LinuxFs fs) throws FingerprintException {
    String info = fs.readFile("/proc/self/mountinfo");
    Mount m = containingMount(info == null ? "" : info, "/etc/machine-id");
    if (m != null && (m.fstype().equals("tmpfs") || m.fstype().equals("ramfs"))) {
      throw err(FingerprintException.Code.NO_FINGERPRINT, "machine-id is on a tmpfs: regenerated every boot");
    }
    if (appContainer(fs)) {
      // Only a bind mount of a file that is itself a machine-id.
      if (m == null || !m.point().equals("/etc/machine-id") || !m.root().endsWith("/etc/machine-id")) {
        throw err(FingerprintException.Code.NO_FINGERPRINT, "in a container: mount the host /etc/machine-id, or have the vendor enable an override");
      }
      String b = fs.readFile("/etc/machine-id");
      if (b == null) throw err(FingerprintException.Code.NO_FINGERPRINT, "no /etc/machine-id");
      return parseMachineId(b);
    }
    String last = "no machine-id";
    for (String p : List.of("/etc/machine-id", "/var/lib/dbus/machine-id")) {
      String b = fs.readFile(p);
      if (b == null) continue;
      try {
        return parseMachineId(b);
      } catch (FingerprintException e) {
        last = "machine-id missing or uninitialized";
      }
    }
    throw err(FingerprintException.Code.NO_FINGERPRINT, last);
  }

  /** Application containers; system containers (lxc, lxc-libvirt, systemd-nspawn) aren't; unknown kinds fail closed. */
  private static boolean appContainer(LinuxFs fs) {
    if (fs.exists("/.dockerenv") || fs.exists("/run/.containerenv")) return true;
    String kind = "";
    String sd = fs.readFile("/run/systemd/container");
    if (sd != null) {
      kind = trim(sd);
    } else {
      String environ = fs.readFile("/proc/1/environ");
      for (String kv : (environ == null ? "" : environ).split("\0", -1)) {
        if (kv.startsWith("container=")) kind = kv.substring("container=".length());
      }
    }
    return !List.of("", "lxc", "lxc-libvirt", "systemd-nspawn").contains(kind);
  }

  record Mount(String root, String point, String fstype) {}

  /** The mount holding path: the longest mount point equal to or above it, the last such entry winning. */
  static Mount containingMount(String mountinfo, String path) {
    Mount best = null;
    for (String line : mountinfo.split("\n", -1)) {
      int at = line.indexOf(" - ");
      if (at < 0) continue;
      // Spaces only: the kernel escapes space, tab, newline and backslash, so
      // any other byte (\v, a Unicode space) belongs to the field.
      List<String> f = fields(line.substring(0, at));
      List<String> g = fields(line.substring(at + 3));
      if (f.size() < 5 || g.isEmpty()) continue;
      Mount m = new Mount(unescapeMount(f.get(3)), unescapeMount(f.get(4)), g.get(0));
      if (!(m.point().equals(path) || m.point().equals("/") || path.startsWith(m.point() + "/"))) continue;
      if (best == null || m.point().length() >= best.point().length()) best = m;
    }
    return best;
  }

  private static List<String> fields(String s) {
    return java.util.Arrays.stream(s.split(" ", -1)).filter(x -> !x.isEmpty()).toList();
  }

  private static final Pattern OCTAL = Pattern.compile("\\\\([0-7]{3})");

  /** Decodes mountinfo's octal escapes (\040 for a space). */
  static String unescapeMount(String s) {
    return OCTAL.matcher(s).replaceAll(r -> {
      int o = Integer.parseInt(r.group(1), 8);
      return Matcher.quoteReplacement(o < 256 ? String.valueOf((char) o) : r.group());
    });
  }

  private static final Pattern MACHINE_ID = Pattern.compile("[0-9a-f]{32}");

  /** The systemd format: 32 lowercase hex characters; empty or "uninitialized" isn't an ID. */
  static String parseMachineId(String s) throws FingerprintException {
    String id = trim(s);
    if (!MACHINE_ID.matcher(id).matches()) throw err(FingerprintException.Code.NO_FINGERPRINT, "machine-id missing or uninitialized");
    return id;
  }
}

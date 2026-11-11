package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.licenseforge.sdk.Claims.BindingType;
import io.licenseforge.sdk.Fingerprints.Fingerprint;
import io.licenseforge.sdk.Fingerprints.FingerprintException;
import io.licenseforge.sdk.Fingerprints.Options;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Fingerprints: the shared vectors, the Go SDK's Linux cases, source order, and Kubernetes against a local TLS server. */
class FingerprintTest {
  interface Call {
    Object run() throws Exception;
  }

  static String code(Call c) {
    try {
      c.run();
      return "ok";
    } catch (FingerprintException e) {
      return e.code().name().toLowerCase(java.util.Locale.ROOT);
    } catch (Exception e) {
      return "threw " + e;
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void vectors() throws Exception {
    for (Map<String, Object> c : VectorsTest.cases(VectorsTest.vectors("fingerprint.json"))) {
      String want = (String) c.get("fingerprint");
      Call h = () -> Fingerprints.hash((String) c.get("tenant"), (String) c.get("product"), (String) c.get("raw_id"));
      if (want != null && !want.isEmpty()) assertEquals(want, h.run(), (String) c.get("name"));
      else assertEquals("invalid", code(h), (String) c.get("name"));
    }
    assertEquals("invalid", code(() -> Fingerprints.hash("tnt", "p", "\uD800")), "lone surrogate");
  }

  static final String VALID = "0123456789abcdef0123456789abcdef";
  static final String ROOT_EXT4 = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n";

  static String bind(String root, String fstype) {
    return "35 22 0:31 " + root + " /etc/machine-id ro,relatime - " + fstype + " src rw\n";
  }

  static Fingerprints.LinuxFs fs(Map<String, String> files) {
    return new Fingerprints.LinuxFs() {
      @Override
      public String readFile(String p) {
        return files.get(p);
      }

      @Override
      public boolean exists(String p) {
        return files.containsKey(p);
      }
    };
  }

  static Map<String, String> m(String... kv) {
    Map<String, String> r = new HashMap<>();
    for (int i = 0; i < kv.length; i += 2) r.put(kv[i], kv[i + 1]);
    return r;
  }

  @Test
  void linuxMachineId() throws Exception {
    record C(String name, Map<String, String> files, String want) {}
    List<C> cases = List.of(
        new C("host", m("/etc/machine-id", VALID + "\n"), VALID),
        new C("dbus fallback when etc is uninitialized", m("/etc/machine-id", "uninitialized\n", "/var/lib/dbus/machine-id", VALID), VALID),
        new C("dbus fallback when etc is missing", m("/var/lib/dbus/machine-id", VALID), VALID),
        new C("transient tmpfs machine-id refused", m("/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/machine-id", "tmpfs")), ""),
        new C("persistent bind mount on host ok", m("/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/persist/etc/machine-id", "btrfs")), VALID),
        new C("root on tmpfs refused", m("/etc/machine-id", VALID, "/proc/self/mountinfo", "22 1 0:5 / / rw - tmpfs none rw\n"), ""),
        new C("etc on ramfs refused", m("/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + "30 22 0:6 / /etc rw - ramfs none rw\n"), ""),
        new C("last stacked mount wins (tmpfs on top)", m("/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/etc/machine-id", "ext4") + bind("/machine-id", "tmpfs")), ""),
        new C("last stacked mount wins (ext4 on top)", m("/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/machine-id", "tmpfs") + bind("/etc/machine-id", "ext4")), VALID),
        new C("docker with image machine-id refused", m("/.dockerenv", "", "/etc/machine-id", VALID), ""),
        new C("docker with host machine-id mounted", m("/.dockerenv", "", "/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/etc/machine-id", "ext4")), VALID),
        new C("docker with ostree-style host path", m("/.dockerenv", "", "/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/ostree/deploy/fedora/deploy/abc/etc/machine-id", "xfs")), VALID),
        new C("docker with arbitrary shared file refused", m("/.dockerenv", "", "/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/home/user/shared-id", "ext4")), ""),
        new C("docker with escaped path", m("/.dockerenv", "", "/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/my\\040disk/etc/machine-id", "ext4")), VALID),
        new C("podman marker", m("/run/.containerenv", "", "/etc/machine-id", VALID), ""),
        new C("systemd container marker docker", m("/run/systemd/container", "docker\n", "/etc/machine-id", VALID), ""),
        new C("unknown container type fails closed", m("/run/systemd/container", "something-new", "/etc/machine-id", VALID), ""),
        new C("nspawn system container uses its own id", m("/run/systemd/container", "systemd-nspawn\n", "/etc/machine-id", VALID), VALID),
        new C("lxc system container uses its own id", m("/proc/1/environ", "PATH=/bin\0container=lxc\0", "/etc/machine-id", VALID), VALID),
        new C("oci container in pid 1 environ", m("/proc/1/environ", "container=oci\0", "/etc/machine-id", VALID), ""),
        new C("the last container= in environ wins", m("/proc/1/environ", "container=lxc\0container=oci\0", "/etc/machine-id", VALID), ""),
        new C("a \\v in a host path is part of the field", m("/.dockerenv", "", "/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/x\u000b/etc/machine-id", "ext4")), VALID),
        new C("a Unicode space in a tmpfs root doesn't hide the tmpfs", m("/etc/machine-id", VALID, "/proc/self/mountinfo", ROOT_EXT4 + bind("/a\u00a0b", "tmpfs")), ""),
        new C("no machine-id at all", m(), ""));
    for (C c : cases) {
      if (!c.want().isEmpty()) assertEquals(c.want(), Fingerprints.linuxMachineId(fs(c.files())), c.name());
      else assertEquals("no_fingerprint", code(() -> Fingerprints.linuxMachineId(fs(c.files()))), c.name());
    }
    for (String bad : List.of("", "uninitialized\n", "0123456789ABCDEF0123456789ABCDEF", "short")) {
      assertEquals("no_fingerprint", code(() -> Fingerprints.parseMachineId(bad)), bad);
    }
    assertEquals("/my disk\\x", Fingerprints.unescapeMount("/my\\040disk\\134x"));
  }

  static Fingerprints.Env env(Map<String, String> vars, boolean[] read) {
    return new Fingerprints.Env() {
      @Override
      public String getenv(String n) {
        return vars.get(n);
      }

      @Override
      public String kubernetes() {
        return "ns-uid";
      }

      @Override
      public String machineId() {
        read[0] = true;
        return VALID;
      }
    };
  }

  @Test
  void computeOrder() throws Exception {
    boolean[] read = {false};
    String t = "tnt_acme";
    String p = "acme-db";
    assertEquals(new Fingerprint(Fingerprints.hash(t, p, VALID), FingerprintSource.MACHINE_ID, BindingType.MACHINE), Fingerprints.compute(t, p, Options.DEFAULT, env(m(), read)));
    assertEquals(new Fingerprint(Fingerprints.hash(t, p, "ns-uid"), FingerprintSource.KUBERNETES, BindingType.CLUSTER),
        Fingerprints.compute(t, p, Options.DEFAULT, env(m("KUBERNETES_SERVICE_HOST", "10.0.0.1"), read)));
    // The env override only when the vendor allows it; trimmed; empty is skipped.
    assertEquals(FingerprintSource.MACHINE_ID, Fingerprints.compute(t, p, Options.DEFAULT, env(m("LICENSEFORGE_FINGERPRINT", "user"), read)).source());
    Options allow = new Options(null, true);
    assertEquals(new Fingerprint(Fingerprints.hash(t, p, "user"), FingerprintSource.ENV, BindingType.MACHINE),
        Fingerprints.compute(t, p, allow, env(m("LICENSEFORGE_FINGERPRINT", " user\n", "KUBERNETES_SERVICE_HOST", "x"), read)));
    assertEquals(FingerprintSource.MACHINE_ID, Fingerprints.compute(t, p, allow, env(m("LICENSEFORGE_FINGERPRINT", " \t"), read)).source());
    // Only SP, HT, CR, LF are trimmed.
    assertEquals(Fingerprints.hash(t, p, "\u000bX\u00a0"), Fingerprints.compute(t, p, allow, env(m("LICENSEFORGE_FINGERPRINT", "\u000bX\u00a0 "), read)).fingerprint());
    assertEquals("invalid", code(() -> Fingerprints.compute(t, p, allow, env(m("LICENSEFORGE_FINGERPRINT", "a\uFFFDb"), read))), "invalid UTF-8 from the environment");
    // The vendor's override wins over everything; empty is an error; a throw is FAILED.
    assertEquals(new Fingerprint(Fingerprints.hash(t, p, "serial-1"), FingerprintSource.OVERRIDE, BindingType.MACHINE),
        Fingerprints.compute(t, p, new Options(() -> "\tserial-1 ", true), env(m("LICENSEFORGE_FINGERPRINT", "user"), read)));
    assertEquals("invalid", code(() -> Fingerprints.compute(t, p, new Options(() -> " \r\n", false), env(m(), read))));
    assertEquals("invalid", code(() -> Fingerprints.compute(t, p, new Options(() -> null, false), env(m(), read))));
    assertEquals("failed", code(() -> Fingerprints.compute(t, p, new Options(() -> {
      throw new IllegalStateException("tpm");
    }, false), env(m(), read))));
    // Bad IDs are refused before any source is read.
    read[0] = false;
    assertEquals("invalid", code(() -> Fingerprints.compute("", p, Options.DEFAULT, env(m(), read))));
    assertEquals("invalid", code(() -> Fingerprints.compute("tnt\0x", p, Options.DEFAULT, env(m(), read))));
    assertFalse(read[0]);
  }

  // --- Kubernetes against a local TLS server (keytool makes a throwaway certificate) ---

  record Tls(SSLContext ctx, byte[] certPem) {}

  static Tls tls(Path dir, String san) throws Exception {
    Path ks = dir.resolve("ks-" + System.nanoTime() + ".p12");
    String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
    run(keytool, "-genkeypair", "-keyalg", "EC", "-groupname", "secp256r1", "-alias", "s", "-dname", "CN=localhost", "-ext", "san=" + san,
        "-validity", "1", "-keystore", ks.toString(), "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit");
    Path pem = dir.resolve("c-" + System.nanoTime() + ".pem");
    run(keytool, "-exportcert", "-rfc", "-alias", "s", "-keystore", ks.toString(), "-storepass", "changeit", "-file", pem.toString());
    KeyStore k = KeyStore.getInstance("PKCS12");
    try (FileInputStream in = new FileInputStream(ks.toFile())) {
      k.load(in, "changeit".toCharArray());
    }
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(k, "changeit".toCharArray());
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(kmf.getKeyManagers(), null, null);
    return new Tls(ctx, Files.readAllBytes(pem));
  }

  static void run(String... cmd) throws Exception {
    Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
    p.getInputStream().readAllBytes();
    assertEquals(0, p.waitFor(), String.join(" ", cmd));
  }

  record Answer(int status, String body) {}

  static HttpsServer server(Tls t, Deque<Answer> answers, List<String> seen) throws Exception {
    HttpsServer s = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    s.setHttpsConfigurator(new HttpsConfigurator(t.ctx()));
    s.createContext("/", ex -> {
      seen.add(ex.getRequestMethod() + " " + ex.getRequestURI() + " " + ex.getRequestHeaders().getFirst("Authorization"));
      Answer a = answers.isEmpty() ? new Answer(500, "") : answers.poll();
      byte[] b = a.body().getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(a.status(), b.length == 0 ? -1 : b.length);
      if (b.length > 0) {
        try (OutputStream o = ex.getResponseBody()) {
          o.write(b);
        }
      }
      ex.close();
    });
    s.start();
    return s;
  }

  static final List<Duration> TWO = List.of(Duration.ofMillis(1), Duration.ofMillis(1));

  @Test
  void kubernetes(@TempDir Path dir) throws Exception {
    Tls t = tls(dir, "dns:localhost,ip:127.0.0.1");
    Deque<Answer> answers = new ArrayDeque<>();
    List<String> seen = new ArrayList<>();
    HttpsServer s = server(t, answers, seen);
    int port = s.getAddress().getPort();
    try {
      answers.add(new Answer(200, "{\"metadata\":{\"uid\":\"5f0c2d8e-1b2a\"}}"));
      assertEquals("5f0c2d8e-1b2a", Fingerprints.namespaceUid("127.0.0.1", port, "sa-token", t.certPem(), List.of()));
      assertEquals(List.of("GET /api/v1/namespaces/kube-system Bearer sa-token"), seen);
      answers.addAll(List.of(new Answer(503, ""), new Answer(429, ""), new Answer(200, "{\"metadata\":{\"uid\":\"u2\"}}")));
      assertEquals("u2", Fingerprints.namespaceUid("127.0.0.1", port, "t", t.certPem(), TWO), "two transient answers, then the UID");
      answers.addAll(List.of(new Answer(503, ""), new Answer(503, "")));
      assertEquals("transient", code(() -> Fingerprints.namespaceUid("127.0.0.1", port, "t", t.certPem(), List.of(Duration.ofMillis(1)))), "retries exhausted");
      for (Answer a : List.of(new Answer(403, ""), new Answer(404, ""), new Answer(200, "not json"), new Answer(200, "{\"metadata\":{}}"))) {
        answers.add(a);
        seen.clear();
        assertEquals("failed", code(() -> Fingerprints.namespaceUid("127.0.0.1", port, "t", t.certPem(), TWO)), a.toString());
        assertEquals(1, seen.size(), "no retry for a permanent answer");
      }
      // Another CA: a configuration error, not retried.
      seen.clear();
      byte[] other = tls(dir, "dns:localhost,ip:127.0.0.1").certPem();
      assertEquals("failed", code(() -> Fingerprints.namespaceUid("127.0.0.1", port, "t", other, TWO)));
      assertEquals(0, seen.size());
      // An answer over 1 MiB is permanent, like a decode error.
      answers.add(new Answer(200, "{\"metadata\":{\"uid\":\"u\"},\"pad\":\"" + "x".repeat(1 << 20) + "\"}"));
      seen.clear();
      assertEquals("failed", code(() -> Fingerprints.namespaceUid("127.0.0.1", port, "t", t.certPem(), TWO)));
      assertEquals(1, seen.size());
      // A token with a line break can't be sent; a CA file without a certificate is unusable.
      assertEquals("failed", code(() -> Fingerprints.namespaceUid("127.0.0.1", port, "a\nb", t.certPem(), TWO)));
      assertEquals("failed", code(() -> Fingerprints.namespaceUid("127.0.0.1", port, "t", "junk".getBytes(StandardCharsets.UTF_8), TWO)));
    } finally {
      s.stop(0);
    }
  }

  @Test
  void kubernetesNameMismatchAndDeadline(@TempDir Path dir) throws Exception {
    Tls onlyDns = tls(dir, "dns:localhost"); // not 127.0.0.1
    HttpsServer s = server(onlyDns, new ArrayDeque<>(List.of(new Answer(200, "{}"))), new ArrayList<>());
    try {
      assertEquals("failed", code(() -> Fingerprints.namespaceUid("127.0.0.1", s.getAddress().getPort(), "t", onlyDns.certPem(), TWO)));
    } finally {
      s.stop(0);
    }
    Tls t = tls(dir, "dns:localhost,ip:127.0.0.1");
    HttpsServer drip = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    drip.setHttpsConfigurator(new HttpsConfigurator(t.ctx()));
    drip.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
      Thread th = new Thread(r);
      th.setDaemon(true);
      return th;
    }));
    drip.createContext("/", ex -> {
      ex.sendResponseHeaders(200, 0);
      try (OutputStream o = ex.getResponseBody()) {
        for (int i = 0; i < 20; i++) { // one byte a second: never idle for 5 s
          o.write(' ');
          o.flush();
          Thread.sleep(1000);
        }
      } catch (Exception e) {
        // the client went away
      }
    });
    drip.start();
    long start = System.nanoTime();
    try {
      assertEquals("transient", code(() -> Fingerprints.namespaceUid("127.0.0.1", drip.getAddress().getPort(), "t", t.certPem(), List.of())));
      long took = (System.nanoTime() - start) / 1_000_000;
      assertTrue(took >= 4500 && took < 8000, "took " + took + " ms");
    } finally {
      drip.stop(0);
    }
  }

  @Test
  void thisMachine() {
    try {
      Fingerprint f = Fingerprints.compute("tnt_acme", "acme-db", Options.DEFAULT, new Fingerprints.Env() {
        @Override
        public String getenv(String n) {
          return n.equals("KUBERNETES_SERVICE_HOST") ? null : System.getenv(n);
        }

        @Override
        public String kubernetes() {
          throw new AssertionError();
        }

        @Override
        public String machineId() throws FingerprintException {
          return Fingerprints.osMachineId();
        }
      });
      assertTrue(f.fingerprint().matches("sha256:[0-9a-f]{64}"));
    } catch (FingerprintException e) {
      assertEquals(FingerprintException.Code.NO_FINGERPRINT, e.code(), e.getMessage());
    }
    assertThrows(NullPointerException.class, () -> Fingerprints.compute("t", "p", null));
  }
}

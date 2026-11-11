package io.licenseforge.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.licenseforge.sdk.LeaseStores.FileLeaseStore;
import io.licenseforge.sdk.LeaseStores.KubernetesApi;
import io.licenseforge.sdk.LeaseStores.KubernetesConfigMapStore;
import io.licenseforge.sdk.LeaseStores.KubernetesSecretStore;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Lease stores: a file, and ConfigMap/Secret keys through a fake Kubernetes API. */
class LeaseStoresTest {
  @Test
  void fileLeaseStore(@TempDir Path dir) throws Exception {
    FileLeaseStore s = new FileLeaseStore(dir.resolve("lease"));
    assertEquals("", s.load());
    s.save("lf1.abc\n");
    assertEquals("lf1.abc", s.load());
    if (!System.getProperty("os.name").startsWith("Windows")) {
      assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve("lease"))));
    }
    s.save("");
    assertEquals("", s.load());
    assertThrows(NullPointerException.class, () -> new FileLeaseStore(null));
    Files.createDirectory(dir.resolve("adir"));
    assertThrows(IOException.class, () -> new FileLeaseStore(dir.resolve("adir")).load(), "unreadable");
    assertThrows(IOException.class, () -> new FileLeaseStore(dir.resolve("adir")).save("lf1.x"), "not written");
    // An unreadable old file that the write replaces anyway: success, as in Go.
    if (!System.getProperty("os.name").startsWith("Windows") && !"root".equals(System.getProperty("user.name"))) {
      Path p = dir.resolve("old");
      FileLeaseStore o = new FileLeaseStore(p);
      o.save("lf1.old");
      Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("---------"));
      o.save("lf1.new");
      assertEquals("lf1.new", o.load());
    }
  }

  record Inject(String method, int status) {}

  HttpsServer srv;
  KubernetesApi api;
  final Map<String, Map<String, Object>> objects = new ConcurrentHashMap<>();
  final List<String> log = Collections.synchronizedList(new ArrayList<>());
  final ConcurrentLinkedDeque<Inject> inject = new ConcurrentLinkedDeque<>();
  int rv;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void fakeApi(@TempDir Path dir) throws Exception {
    FingerprintTest.Tls t = FingerprintTest.tls(dir, "ip:127.0.0.1");
    srv = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    srv.setHttpsConfigurator(new HttpsConfigurator(t.ctx()));
    srv.createContext("/", ex -> {
      String b = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      String method = ex.getRequestMethod();
      String url = ex.getRequestURI().getRawPath();
      log.add(method + " " + url + " " + ex.getRequestHeaders().getFirst("Authorization"));
      int status;
      Object out;
      Inject inj = null;
      for (Inject i : inject) {
        if (i.method().equals(method)) {
          inj = i;
          break;
        }
      }
      try {
        if (inj != null) {
          inject.remove(inj);
          status = inj.status();
          out = Map.of("kind", "Status", "message", "injected");
        } else if (method.equals("GET")) {
          status = objects.containsKey(url) ? 200 : 404;
          out = objects.containsKey(url) ? objects.get(url) : Map.of("message", "not found");
        } else {
          Map<String, Object> obj = new LinkedHashMap<>((Map<String, Object>) Json.parseValue(b));
          Map<String, Object> meta = new LinkedHashMap<>((Map<String, Object>) obj.get("metadata"));
          if (method.equals("POST")) {
            String p = url + "/" + meta.get("name");
            String kind = url.endsWith("/secrets") ? "Secret" : "ConfigMap";
            if (!"v1".equals(obj.get("apiVersion")) || !kind.equals(obj.get("kind"))) {
              status = 400;
              out = Map.of("message", "apiVersion and kind required");
            } else if (objects.containsKey(p)) {
              status = 409;
              out = Map.of("message", "exists");
            } else {
              meta.put("resourceVersion", String.valueOf(++rv));
              obj.put("metadata", meta);
              objects.put(p, obj);
              status = 201;
              out = obj;
            }
          } else {
            Map<String, Object> cur = objects.get(url);
            if (cur == null) {
              status = 404;
              out = Map.of("message", "gone");
            } else if (!((Map<String, Object>) cur.get("metadata")).get("resourceVersion").equals(meta.get("resourceVersion"))) {
              status = 409;
              out = Map.of("message", "conflict");
            } else {
              meta.put("resourceVersion", String.valueOf(++rv));
              obj.put("metadata", meta);
              objects.put(url, obj);
              status = 200;
              out = obj;
            }
          }
        }
        byte[] body = LeaseStores.write(out).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream o = ex.getResponseBody()) {
          o.write(body);
        }
      } catch (Exception e) {
        ex.sendResponseHeaders(500, -1);
      }
      ex.close();
    });
    srv.start();
    api = new KubernetesApi("127.0.0.1", srv.getAddress().getPort(), t.certPem(), "apps", () -> "sa-token");
  }

  @AfterEach
  void stop() {
    srv.stop(0);
  }

  @SuppressWarnings("unchecked")
  Map<String, Object> data(String path) {
    return (Map<String, Object>) objects.get(path).get("data");
  }

  @Test
  @SuppressWarnings("unchecked")
  void configMap() throws Exception {
    KubernetesConfigMapStore s = new KubernetesConfigMapStore("acme-license", null, null, api);
    String path = "/api/v1/namespaces/apps/configmaps/acme-license";
    assertEquals("", s.load());
    s.save("lf1.one");
    assertEquals("lf1.one", s.load());
    assertEquals("lf1.one", data(path).get("lease"));
    assertTrue(log.stream().allMatch(l -> l.endsWith("Bearer sa-token")));
    // Someone else's labels and keys survive our update.
    Map<String, Object> o = new LinkedHashMap<>(objects.get(path));
    Map<String, Object> meta = new LinkedHashMap<>((Map<String, Object>) o.get("metadata"));
    meta.put("labels", Map.of("team", "db"));
    o.put("metadata", meta);
    Map<String, Object> d = new LinkedHashMap<>(data(path));
    d.put("other", "keep");
    o.put("data", d);
    o.put("binaryData", Map.of("blob", "AAAA"));
    objects.put(path, o);
    s.save("lf1.two");
    assertEquals("ConfigMap", objects.get(path).get("kind"), "top-level fields survive");
    assertEquals(Map.of("blob", "AAAA"), objects.get(path).get("binaryData"));
    assertEquals(Map.of("lease", "lf1.two", "other", "keep"), data(path));
    assertEquals(Map.of("team", "db"), ((Map<String, Object>) objects.get(path).get("metadata")).get("labels"));
    s.save("");
    assertEquals(Map.of("other", "keep"), data(path));
    assertEquals("", s.load());
    // Another namespace and key, by name.
    new KubernetesConfigMapStore("x", "other", "lic.txt", api).save("lf1.three");
    assertEquals("lf1.three", data("/api/v1/namespaces/other/configmaps/x").get("lic.txt"));
  }

  @Test
  void secret() throws Exception {
    KubernetesSecretStore s = new KubernetesSecretStore("acme-license", null, null, api);
    s.save("lf1.secret");
    String path = "/api/v1/namespaces/apps/secrets/acme-license";
    assertEquals(Base64.getEncoder().encodeToString("lf1.secret".getBytes(StandardCharsets.UTF_8)), data(path).get("lease"));
    assertEquals("lf1.secret", s.load());
    inject.add(new Inject("PUT", 409));
    s.save("lf1.after-conflict");
    assertEquals("lf1.after-conflict", s.load());
    inject.add(new Inject("PUT", 403));
    assertTrue(assertThrows(IOException.class, () -> s.save("lf1.x")).getMessage().contains("grant get and update on it by name"));
    inject.add(new Inject("GET", 500));
    assertTrue(assertThrows(IOException.class, s::load).getMessage().contains("loading Secret"));
    Map<String, Object> o = new LinkedHashMap<>(objects.get(path));
    for (String bad : List.of("not base64!", "QQ")) { // unpadded: Go's StdEncoding refuses it too
      o.put("data", Map.of("lease", bad));
      objects.put(path, o);
      assertTrue(assertThrows(IOException.class, s::load).getMessage().contains("isn't base64"), bad);
    }
    // A value with line breaks decodes, as in Go.
    String enc = Base64.getEncoder().encodeToString("lf1.abcdef".getBytes(StandardCharsets.UTF_8));
    o.put("data", Map.of("lease", enc.substring(0, 4) + "\r\n" + enc.substring(4)));
    objects.put(path, o);
    assertEquals("lf1.abcdef", s.load());
  }

  @Test
  void retries() throws Exception {
    KubernetesConfigMapStore s = new KubernetesConfigMapStore("race", null, null, api);
    String path = "/api/v1/namespaces/apps/configmaps/race";
    s.save("lf1.a");
    inject.add(new Inject("PUT", 404)); // deleted meanwhile: another round
    s.save("lf1.b");
    assertEquals("lf1.b", s.load());
    objects.remove(path);
    inject.add(new Inject("POST", 409)); // created meanwhile: another round
    s.save("lf1.c");
    assertEquals("lf1.c", s.load());
    objects.remove(path);
    int before = log.size();
    s.save("");
    assertEquals(List.of("GET"), log.subList(before, log.size()).stream().map(l -> l.split(" ")[0]).toList(), "nothing to remove");
    // An endless conflict ends after five rounds.
    s.save("lf1.d");
    for (int i = 0; i < 10; i++) inject.add(new Inject("PUT", 409));
    before = log.size();
    assertThrows(IOException.class, () -> s.save("lf1.e"));
    assertEquals(5, log.subList(before, log.size()).stream().filter(l -> l.startsWith("PUT")).count());
    inject.clear();
  }

  @Test
  void oddAnswersAreErrorsWithNoPut(@TempDir Path dir) throws Exception {
    FingerprintTest.Tls t = FingerprintTest.tls(dir, "ip:127.0.0.1");
    for (String body : List.of("null", "{\"data\":{\"lease\":\"x\"}}", "{\"metadata\":{}}", "{\"metadata\":{\"resourceVersion\":\"\"}}")) {
      int[] puts = {0};
      HttpsServer odd = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      odd.setHttpsConfigurator(new HttpsConfigurator(t.ctx()));
      odd.createContext("/", ex -> {
        if (ex.getRequestMethod().equals("PUT")) puts[0]++;
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream o = ex.getResponseBody()) {
          o.write(b);
        }
        ex.close();
      });
      odd.start();
      try {
        KubernetesApi a = new KubernetesApi("127.0.0.1", odd.getAddress().getPort(), t.certPem(), "apps", () -> "t");
        IOException e = assertThrows(IOException.class, () -> new KubernetesConfigMapStore("x", null, null, a).save("lf1.x"), body);
        assertTrue(e.getMessage().contains("isn't an object") || e.getMessage().contains("resourceVersion"), e.getMessage());
        assertEquals(0, puts[0], body);
      } finally {
        odd.stop(0);
      }
    }
  }

  @Test
  void bigOrStalledAnswersEndWithinTheBudget(@TempDir Path dir) throws Exception {
    FingerprintTest.Tls t = FingerprintTest.tls(dir, "ip:127.0.0.1");
    HttpsServer slow = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    slow.setHttpsConfigurator(new HttpsConfigurator(t.ctx()));
    slow.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
      Thread th = new Thread(r);
      th.setDaemon(true);
      return th;
    }));
    slow.createContext("/api/v1/namespaces/big/", ex -> {
      ex.sendResponseHeaders(200, 0);
      try (OutputStream o = ex.getResponseBody()) {
        o.write(("{\"pad\":\"" + "x".repeat((4 << 20) + 10) + "\"}").getBytes(StandardCharsets.UTF_8));
      } catch (IOException e) {
        // the client stopped reading
      }
      ex.close();
    });
    slow.createContext("/", ex -> {
      ex.sendResponseHeaders(200, 0);
      try (OutputStream o = ex.getResponseBody()) {
        o.write('{');
        o.flush();
        Thread.sleep(30_000); // headers and a byte, then nothing
      } catch (Exception e) {
        // the client went away
      }
    });
    slow.start();
    try {
      KubernetesApi a = new KubernetesApi("127.0.0.1", slow.getAddress().getPort(), t.certPem(), "apps", () -> "t");
      KubernetesConfigMapStore stalled = new KubernetesConfigMapStore("x", null, null, a);
      stalled.timeout = java.time.Duration.ofSeconds(1);
      long start = System.nanoTime();
      assertThrows(IOException.class, stalled::load);
      assertTrue((System.nanoTime() - start) / 1_000_000 < 5000, "the budget bounds a stalled body");
      // An answer over 4 MiB is refused (the namespace "big" routes to that answer).
      IOException e = assertThrows(IOException.class, () -> new KubernetesConfigMapStore("x", "big", null, a).load());
      assertTrue(e.getMessage().contains("4 MiB"), e.getMessage());
    } finally {
      slow.stop(0);
    }
  }

  @Test
  void anEmptyTokenIsNotSent() {
    for (java.util.function.Supplier<String> tok : List.<java.util.function.Supplier<String>>of(() -> null, () -> "")) {
      KubernetesApi bad = new KubernetesApi(api.host(), api.port(), api.ca(), "apps", tok);
      assertThrows(IOException.class, () -> new KubernetesConfigMapStore("x", null, null, bad).load());
    }
    assertEquals(0, log.size());
  }

  @Test
  void aTokenWithALineBreakIsRefusedBeforeAnythingIsSent() {
    KubernetesApi bad = new KubernetesApi(api.host(), api.port(), api.ca(), "apps", () -> "S3CRET\r\nX-Evil: 1");
    IOException e = assertThrows(IOException.class, () -> new KubernetesConfigMapStore("x", null, null, bad).load());
    for (Throwable x = e; x != null; x = x.getCause()) assertTrue(!String.valueOf(x.getMessage()).contains("S3CRET"), x.toString());
    assertEquals(0, log.size());
  }

  @Test
  void namesAreCheckedBeforeAnyRequest() {
    for (String[] o : List.of(new String[] {"Bad_Name", null, null}, new String[] {"ok", "Bad NS", null}, new String[] {"ok", null, ".."},
        new String[] {"ok", null, "a/b"}, new String[] {"ok", null, "."}, new String[] {"x".repeat(254), null, null})) {
      IOException e = assertThrows(IOException.class, () -> new KubernetesConfigMapStore(o[0], o[1], o[2], api).load(), String.join(",", String.valueOf(o[0]), String.valueOf(o[1]), String.valueOf(o[2])));
      assertTrue(e.getMessage().contains("isn't a valid"), e.getMessage());
    }
    assertEquals(0, log.size());
  }

  @Test
  void writeRoundTrips() throws Exception {
    String json = "{\"a\":[1,-2.5e3,true,false,null,\"x\\u003c\\\"\"],\"b\":{}}";
    assertEquals(json, LeaseStores.write(Json.parseValue(json)));
  }
}

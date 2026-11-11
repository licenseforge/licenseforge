# LicenseForge SDK for Java

Verifies LicenseForge license files (`lf1`, [spec](../../spec/license-format.md)) in a Java application, offline: the envelope, the Ed25519 signature against keys built into your app, the claims and the claim checks. Java 17 or later, no runtime dependencies: Ed25519 comes from the JDK (ADR-0010).

Status: in progress, not published yet (Maven Central `io.licenseforge:licenseforge-sdk`, module `io.licenseforge.sdk`). It passes the shared conformance vectors `spec/vectors/lf1.json` and `lf1-claims.json`. Next: fingerprints, offline formats, the clock guard and the online client, as in the Go and TypeScript SDKs.

```java
import io.licenseforge.sdk.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

// Your tenant's trusted key set, as the dashboard shows it (Settings →
// Signing keys → JSON), shipped with your build.
List<PublicKey> keys;
try (var in = Objects.requireNonNull(MyApp.class.getResourceAsStream("/licenseforge-keys.json"), "key set resource")) {
  keys = KeySet.parse(in.readAllBytes());
}

try {
  LicenseFile.Opened lic = LicenseFile.open(Files.readString(Path.of("license.lic")), keys,
      CheckOptions.of(Instant.now(), "acme-db").withFingerprint(fingerprint));
  if (lic.status() == LicenseFile.Status.GRACE) warn("License expired " + lic.claims().expires().orElseThrow() + ": renew it.");
  if (!lic.claims().entitlements().allows("nodes", nodes.size() + 1)) refuse("node limit reached");
} catch (LicenseException e) {
  refuse(e.code().spec()); // malformed, bad_signature, expired, …
}
```

- `KeySet.parse(json)` reads the trusted key set under the spec's rules (exact fields, canonical base64url). A malformed set is `INVALID_KEY_SET`; an unknown alg, a duplicate kid or a weak key loads and surfaces in `verify`.
- `LicenseFile.verify(license, keys)` checks the envelope and the signature, and returns the payload and key ID.
- `LicenseFile.parseClaims(payload)` applies the strict encoding rules with its own JSON reader (no Jackson or Gson: they accept duplicate keys and fold `1.0` into `1`). `LicenseFile.check(claims, options)` runs the claim checks in the spec's order.
- `LicenseFile.open` does all three. `LicenseException.code()` is the spec's class; `code().spec()` its name.
- `Entitlements`: `hasFeature(key)`, `limit(key)` (`UNLIMITED` is -1, absent is 0) and `allows(key, total)`.

- Signatures are checked with the JDK's `SunEC` provider by name, whatever providers your app installs first (BouncyCastle, for example, would give different answers on crafted inputs). A jlinked runtime on JDK 17 to 21 needs the `jdk.crypto.ec` module.
- `LicenseFile.Status` may gain values: keep a `default` branch when you switch on it.

Build and test: `mvn verify` (Maven 3.9; JUnit is a test-only dependency).

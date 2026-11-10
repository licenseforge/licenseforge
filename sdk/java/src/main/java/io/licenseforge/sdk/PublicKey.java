package io.licenseforge.sdk;

import java.util.Arrays;
import java.util.Objects;

/**
 * A trusted verification key. {@code alg} binds the algorithm to the key,
 * never the file. The key bytes are copied in and out.
 */
public record PublicKey(String kid, String alg, byte[] key) {
  public PublicKey {
    Objects.requireNonNull(kid, "kid");
    Objects.requireNonNull(alg, "alg");
    key = Objects.requireNonNull(key, "key").clone();
  }

  @Override
  public byte[] key() {
    return key.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof PublicKey p && kid.equals(p.kid) && alg.equals(p.alg) && Arrays.equals(key, p.key);
  }

  @Override
  public int hashCode() {
    return Objects.hash(kid, alg, Arrays.hashCode(key));
  }

  @Override
  public String toString() {
    return "PublicKey[kid=" + kid + ", alg=" + alg + "]";
  }
}

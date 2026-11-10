package io.licenseforge.sdk;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * A verified lf1 payload ({@link LicenseFile#parseClaims}). Absent optional
 * timestamps are empty; absent strings are "".
 *
 * @param expires empty: perpetual (offline licenses only)
 * @param grace absent: zero
 * @param maxOffline empty: not limited; zero is a real limit
 */
public record Claims(
    String licenseId,
    String tenant,
    String product,
    String plan,
    String customerId,
    String customerName,
    Instant issuedAt,
    Optional<Instant> notBefore,
    Optional<Instant> expires,
    Optional<Instant> refreshAfter,
    Optional<Instant> updatesUntil,
    Duration grace,
    Optional<Duration> maxOffline,
    Binding binding,
    Entitlements entitlements) {

  public Claims {
    Objects.requireNonNull(licenseId);
    Objects.requireNonNull(tenant);
    Objects.requireNonNull(product);
    Objects.requireNonNull(plan);
    Objects.requireNonNull(customerId);
    Objects.requireNonNull(customerName);
    Objects.requireNonNull(issuedAt);
    Objects.requireNonNull(notBefore);
    Objects.requireNonNull(expires);
    Objects.requireNonNull(refreshAfter);
    Objects.requireNonNull(updatesUntil);
    Objects.requireNonNull(grace);
    Objects.requireNonNull(maxOffline);
    Objects.requireNonNull(binding);
    Objects.requireNonNull(entitlements);
  }

  /** What a license is bound to. */
  public enum BindingType {
    NONE,
    MACHINE,
    CLUSTER
  }

  /** The binding; {@code fingerprint} is "" for NONE. */
  public record Binding(BindingType type, String fingerprint) {
    public static final Binding NONE = new Binding(BindingType.NONE, "");

    public Binding {
      Objects.requireNonNull(type);
      Objects.requireNonNull(fingerprint);
    }
  }
}

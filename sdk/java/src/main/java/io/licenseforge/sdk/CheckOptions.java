package io.licenseforge.sdk;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * The local facts a license is checked against.
 *
 * @param now the time to check with (a clock guard's, when there is one)
 * @param product the product this build is
 * @param fingerprint the local machine or cluster fingerprint, "" if none
 * @param buildDate the app's build date; when empty, updates_until isn't checked
 * @param clockTolerance how far in the future iat may be: 24 h by default (ADR-0018), zero is strict
 */
public record CheckOptions(Instant now, String product, String fingerprint, Optional<Instant> buildDate, Duration clockTolerance) {
  public static final Duration DEFAULT_CLOCK_TOLERANCE = Duration.ofHours(24);

  public CheckOptions {
    Objects.requireNonNull(now, "now");
    Objects.requireNonNull(product, "product");
    Objects.requireNonNull(fingerprint, "fingerprint");
    Objects.requireNonNull(buildDate, "buildDate");
    Objects.requireNonNull(clockTolerance, "clockTolerance");
    if (clockTolerance.isNegative()) throw new IllegalArgumentException("licenseforge: clockTolerance must be ≥ 0");
  }

  /** now and product, no fingerprint or build date, the default tolerance. */
  public static CheckOptions of(Instant now, String product) {
    return new CheckOptions(now, product, "", Optional.empty(), DEFAULT_CLOCK_TOLERANCE);
  }

  public CheckOptions withFingerprint(String fingerprint) {
    return new CheckOptions(now, product, fingerprint, buildDate, clockTolerance);
  }

  public CheckOptions withBuildDate(Instant buildDate) {
    return new CheckOptions(now, product, fingerprint, Optional.of(buildDate), clockTolerance);
  }

  public CheckOptions withClockTolerance(Duration clockTolerance) {
    return new CheckOptions(now, product, fingerprint, buildDate, clockTolerance);
  }
}

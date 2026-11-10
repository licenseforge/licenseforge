package io.licenseforge.sdk;

import java.util.List;
import java.util.Map;

/**
 * The features and limits a license grants (ADR-0015). Unknown keys are never
 * an error.
 */
public record Entitlements(List<String> features, Map<String, Long> limits) {
  /** -1: the limit value meaning "no limit". */
  public static final long UNLIMITED = -1;

  public Entitlements {
    features = List.copyOf(features);
    limits = Map.copyOf(limits);
  }

  /** No features, no limits. */
  public static Entitlements none() {
    return new Entitlements(List.of(), Map.of());
  }

  /** Whether the license grants the boolean feature {@code key} (exact, case-sensitive; never looks at limits). */
  public boolean hasFeature(String key) {
    return features.contains(key);
  }

  /** The limit for {@code key}: UNLIMITED (-1), a non-negative value, or 0 when the license doesn't set it. */
  public long limit(String key) {
    return limits.getOrDefault(key, 0L);
  }

  /** Whether a resulting total of {@code n} (after the action, e.g. users + 1) is within the limit {@code key}. */
  public boolean allows(String key, long n) {
    if (n < 0) return false;
    long l = limit(key);
    return l == UNLIMITED || n <= l;
  }
}

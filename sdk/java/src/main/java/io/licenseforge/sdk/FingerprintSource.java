package io.licenseforge.sdk;

import java.util.Locale;

/** Where a fingerprint came from (spec: Offline activation, fp_source). */
public enum FingerprintSource {
  /** The OS machine identity: /etc/machine-id, MachineGuid, IOPlatformUUID. */
  MACHINE_ID,
  /** The cluster ID (kube-system namespace UID). */
  KUBERNETES,
  /** LICENSEFORGE_FINGERPRINT. */
  ENV,
  /** Set by the app. */
  OVERRIDE;

  /** The spec's name, e.g. "machine-id". */
  public String spec() {
    return name().toLowerCase(Locale.ROOT).replace('_', '-');
  }

  static FingerprintSource fromSpec(String s) {
    for (FingerprintSource f : values()) if (f.spec().equals(s)) return f;
    return null;
  }
}

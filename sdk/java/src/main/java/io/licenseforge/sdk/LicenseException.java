package io.licenseforge.sdk;

/** A license that can't be used, with its spec class in {@link #code()}. */
public final class LicenseException extends Exception {
  private static final long serialVersionUID = 1L;

  /** The error classes shared by all SDKs and the conformance vectors. */
  public enum Code {
    MALFORMED,
    UNKNOWN_KEY,
    UNSUPPORTED_ALG,
    BAD_SIGNATURE,
    INVALID_KEY_SET,
    UNSUPPORTED_VERSION,
    WRONG_PRODUCT,
    BINDING_MISMATCH,
    CLOCK_SKEW,
    NOT_YET_VALID,
    OFFLINE_EXCEEDED,
    EXPIRED,
    UPDATES_EXPIRED;

    /** The spec's name, e.g. "bad_signature". */
    public String spec() {
      return name().toLowerCase(java.util.Locale.ROOT);
    }
  }

  private final Code code;

  LicenseException(Code code) {
    this(code, null);
  }

  LicenseException(Code code, String detail) {
    super(detail == null ? "licenseforge: " + code.spec() : "licenseforge: " + code.spec() + ": " + detail);
    this.code = code;
  }

  public Code code() {
    return code;
  }
}

// LicenseForge SDK for Node.js (ADR-0010): server-side, Node 20+, no
// runtime dependencies. spec/license-format.md is the reference.
export {
  check,
  type CheckOptions,
  type Claims,
  DEFAULT_CLOCK_TOLERANCE_SECONDS,
  Entitlements,
  type ErrorCode,
  LicenseError,
  MAX_SIZE,
  open,
  parseClaims,
  type PublicKey,
  type Status,
  UNLIMITED,
  verify,
} from "./licensefile.js";

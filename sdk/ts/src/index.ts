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
export { parseKeySet } from "./keyset.js";
export {
  type ActivationRequest,
  type DeactivationReceipt,
  encodeReceipt,
  encodeRequest,
  fileSHA256,
  MAX_OFFLINE_SIZE,
  offlineSHA256,
  parseReceipt,
  parseRequest,
} from "./offline.js";
export {
  compute,
  ENV_OVERRIDE,
  type Fingerprint,
  FingerprintError,
  type FingerprintEnv,
  type FingerprintOptions,
  type FingerprintSource,
  forLicense,
  hash,
} from "./fingerprint.js";

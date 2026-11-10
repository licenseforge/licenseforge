// The trusted key set's JSON form (spec/license-format.md): what the
// dashboard shows under Settings → Signing keys, and the vectors' "keys".
import { JSONError, parseValue } from "./json.js";
import { b64url, LicenseError, type PublicKey } from "./licensefile.js";

const kidRE = /^[A-Za-z0-9_:-]{1,128}$/;

/**
 * Reads a trusted key set: a non-empty JSON array of objects with exactly
 * "kid", "alg" and "public_key" (case-sensitive, none repeated), string
 * values, kid matching the spec's pattern, public_key canonical base64url.
 * Anything else is a LicenseError with code invalid_key_set. As the spec
 * says, keys load as given: an unknown or empty alg, a duplicate kid, a
 * wrong key length or a weak key surface in verify. A Uint8Array must be
 * UTF-8 without a BOM.
 */
export function parseKeySet(data: string | Uint8Array): PublicKey[] {
  const bad = (msg: string): never => {
    throw new LicenseError("invalid_key_set", msg);
  };
  let text: string;
  if (typeof data === "string") {
    if (!data.isWellFormed()) bad("not valid Unicode (an unpaired surrogate)");
    text = data;
  } else {
    if (!(data instanceof Uint8Array)) throw new TypeError("licenseforge: parseKeySet takes a string or a Uint8Array");
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
    } catch {
      return bad("not valid UTF-8");
    }
  }
  let top;
  try {
    top = parseValue(text); // a BOM is not JSON whitespace: refused here
  } catch (e) {
    if (e instanceof JSONError) return bad("not well-formed JSON (or a repeated field)"); // the reader's text echoes names
    throw e;
  }
  if (top.kind !== "array") return bad("not a JSON array");
  if (top.items.length === 0) bad("no keys");
  return top.items.map((e, i) => {
    // Generic messages: never echo field names or values from the file.
    if (e.kind !== "object") return bad(`key ${i}: not an object`);
    const m = e.entries;
    if (m.size !== 3) bad(`key ${i} needs exactly kid, alg and public_key`);
    const field = (name: string): string => {
      const v = m.get(name);
      if (v === undefined) return bad(`key ${i} needs exactly kid, alg and public_key`);
      if (v.kind !== "string") return bad(`key ${i}: ${name} must be a string`);
      return v.value;
    };
    const kid = field("kid");
    const alg = field("alg");
    const pub = field("public_key");
    if (!kidRE.test(kid)) bad(`key ${i}: kid isn't 1-128 of [A-Za-z0-9_:-]`);
    const key = b64url(pub);
    if (!key) return bad(`key ${i}: public_key isn't canonical base64url without padding`);
    return { kid, alg, key };
  });
}

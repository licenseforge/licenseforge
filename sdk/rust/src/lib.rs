//! LicenseForge SDK for Rust: verify lf1 license files offline
//! (spec/license-format.md, ADR-0050).
//!
//! [`open`] is the usual entry point: it checks a license's envelope and
//! Ed25519 signature against the trusted keys embedded in your build
//! ([`parse_key_set`] reads the dashboard's JSON), decodes its claims and runs
//! the claim checks. [`verify`], [`parse_claims`] and [`check`] are the steps
//! on their own. Every step follows the spec's order, so each SDK reports the
//! same [`Code`] for the same input.

#![forbid(unsafe_code)]

mod claims;
mod error;
mod json;

pub use claims::{
    Binding, BindingType, CheckOptions, Claims, DEFAULT_CLOCK_TOLERANCE, Entitlements, Status,
    check, parse_claims, parse_duration, parse_time,
};
pub use error::{Code, Error};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// The largest license accepted, in UTF-8 bytes.
pub const MAX_SIZE: usize = 64 * 1024;

const BEGIN: &str = "-----BEGIN LICENSEFORGE LICENSE-----";
const END: &str = "-----END LICENSEFORGE LICENSE-----";

/// A trusted verification key. `alg` binds the algorithm to the key, never the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// The key ID licenses name.
    pub kid: String,
    /// The algorithm, e.g. `"ed25519"`.
    pub alg: String,
    /// The raw public key bytes (32 for Ed25519).
    pub key: Vec<u8>,
}

/// A verified payload and the key ID that signed it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Verified {
    /// The payload JSON's bytes, signature checked, not yet parsed.
    pub payload: Vec<u8>,
    /// The key ID that signed it.
    pub kid: String,
}

/// A usable license: its claims and status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub claims: Claims,
    pub status: Status,
}

/// Verifies a license, decodes its claims and checks them. The claims come
/// back only when everything passed; otherwise the first failing step's error.
pub fn open(license: &str, keys: &[PublicKey], options: &CheckOptions) -> Result<Opened, Error> {
    let claims = parse_claims(&verify(license, keys)?.payload)?;
    let status = check(&claims, options)?;
    Ok(Opened { claims, status })
}

/// Reads a trusted key set (the dashboard's Settings → Signing keys JSON, the
/// vectors' `keys`): a non-empty JSON array of objects with exactly `kid`,
/// `alg` and `public_key` (case-sensitive, none repeated), string values, `kid`
/// matching the spec's pattern, `public_key` canonical base64url. Anything else
/// is [`Code::InvalidKeySet`]. Keys load as given: an unknown or empty `alg`, a
/// duplicate `kid`, a wrong key length or a weak key surface in [`verify`].
pub fn parse_key_set(json: &[u8]) -> Result<Vec<PublicKey>, Error> {
    let bad = |m: String| Error::with(Code::InvalidKeySet, m);
    let text = std::str::from_utf8(json).map_err(|_| bad("not valid UTF-8".into()))?;
    // A BOM isn't JSON whitespace, so the parser refuses it.
    let top =
        json::parse(text).map_err(|_| bad("not well-formed JSON (or a repeated field)".into()))?;
    let json::Value::Array(items) = top else {
        return Err(bad("not a JSON array".into()));
    };
    if items.is_empty() {
        return Err(bad("no keys".into()));
    }
    let mut keys = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let json::Value::Object(entries) = item else {
            return Err(bad(format!("key {i}: not an object")));
        };
        if entries.len() != 3 {
            return Err(bad(format!(
                "key {i} needs exactly kid, alg and public_key"
            )));
        }
        let field = |name: &str| match item.get(name) {
            None => Err(bad(format!(
                "key {i} needs exactly kid, alg and public_key"
            ))),
            Some(json::Value::Str(s)) => Ok(s.clone()),
            Some(_) => Err(bad(format!("key {i}: {name} must be a string"))),
        };
        let (kid, alg, public_key) = (field("kid")?, field("alg")?, field("public_key")?);
        if !valid_kid(&kid) {
            return Err(bad(format!("key {i}: kid isn't 1-128 of [A-Za-z0-9_:-]")));
        }
        let key = b64url(&public_key).ok_or_else(|| {
            bad(format!(
                "key {i}: public_key isn't canonical base64url without padding"
            ))
        })?;
        keys.push(PublicKey { kid, alg, key });
    }
    Ok(keys)
}

/// Checks a license's envelope and signature against the trusted keys and
/// returns the verified payload bytes and the key ID. It doesn't look at the
/// claims. A license file is text: read it with `read_to_string`, and treat a
/// file that isn't UTF-8 as malformed.
pub fn verify(license: &str, keys: &[PublicKey]) -> Result<Verified, Error> {
    let e = envelope(license)?;
    let mut found = keys.iter().filter(|k| k.kid == e.kid);
    let key = found.next().ok_or(Error::new(Code::UnknownKey))?;
    if found.next().is_some() {
        return Err(Error::with(
            Code::InvalidKeySet,
            format!("duplicate kid {}", e.kid),
        ));
    }
    if key.alg != "ed25519" {
        return Err(Error::new(Code::UnsupportedAlg));
    }
    let raw: [u8; 32] = key.key.as_slice().try_into().map_err(|_| {
        Error::with(
            Code::InvalidKeySet,
            format!("ed25519 key for {} has length {}", e.kid, key.key.len()),
        )
    })?;
    if weak_ed25519(&raw) || mixed_order_ed25519(&raw) {
        return Err(Error::with(
            Code::InvalidKeySet,
            format!(
                "ed25519 key for {} is not a canonical, prime-order point",
                e.kid
            ),
        ));
    }
    let sig: [u8; 64] = e
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| Error::with(Code::Malformed, "signature length"))?;
    // A weak R (spec): with R = identity and S = k·a, cofactorless verification (Go) accepts and OpenSSL refuses.
    if weak_ed25519(sig[..32].try_into().unwrap()) {
        return Err(Error::new(Code::BadSignature));
    }
    // S < L checked here, not left to ed25519-dalek: its legacy_compatibility feature, which any
    // other crate in the app's build can turn on (Cargo unifies features), skips that check.
    if curve25519_dalek::Scalar::from_canonical_bytes(sig[32..].try_into().unwrap())
        .is_none()
        .into()
    {
        return Err(Error::new(Code::BadSignature));
    }
    // A 32-byte value that isn't a curve point can't verify anything (bad_signature).
    let vk = VerifyingKey::from_bytes(&raw).map_err(|_| Error::new(Code::BadSignature))?;
    let msg = format!("lf1.{}.{}", e.kid, e.body);
    // Cofactorless ([S]B = R + [k]A, compared as encodings) and S < L, like Go, SunEC and OpenSSL.
    vk.verify(msg.as_bytes(), &Signature::from_bytes(&sig))
        .map_err(|_| Error::new(Code::BadSignature))?;
    Ok(Verified {
        payload: e.payload,
        kid: e.kid,
    })
}

struct Envelope {
    kid: String,
    body: String,
    sig: Vec<u8>,
    payload: Vec<u8>,
}

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn valid_kid(kid: &str) -> bool {
    (1..=128).contains(&kid.len())
        && kid
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b':' || c == b'-')
}

/// The bare token: BOM, armor and whitespace (SP, HT, CR, LF only) removed.
fn unarmor(input: &str) -> Result<String, Error> {
    if input.len() > MAX_SIZE {
        return Err(Error::with(Code::Malformed, "too large"));
    }
    let mut s = input
        .strip_prefix('\u{feff}')
        .unwrap_or(input)
        .trim_matches(is_ws);
    if let Some(rest) = s.strip_prefix(BEGIN) {
        s = rest
            .strip_suffix(END)
            .ok_or_else(|| Error::with(Code::Malformed, "missing end armor"))?;
    }
    let token: String = s.chars().filter(|&c| !is_ws(c)).collect();
    if token.is_empty() {
        return Err(Error::new(Code::Malformed));
    }
    Ok(token)
}

/// The spec's envelope checks up to the key lookup.
fn envelope(license: &str) -> Result<Envelope, Error> {
    let token = unarmor(license)?;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 || parts[0] != "lf1" || !valid_kid(parts[1]) || parts[2].is_empty() {
        return Err(Error::new(Code::Malformed));
    }
    let sig = b64url(parts[3]).ok_or_else(|| Error::with(Code::Malformed, "signature encoding"))?;
    let payload =
        b64url(parts[2]).ok_or_else(|| Error::with(Code::Malformed, "payload encoding"))?;
    Ok(Envelope {
        kid: parts[1].to_string(),
        body: parts[2].to_string(),
        sig,
        payload,
    })
}

/// Decodes canonical base64url (RFC 4648 §5, no padding, no stray bits), or None.
fn b64url(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32)
    }
    let b = s.as_bytes();
    if b.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    for chunk in b.chunks(4) {
        let mut n = 0u32;
        for &c in chunk {
            n = (n << 6) | val(c)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]),
            3 => {
                if n & 0x3 != 0 {
                    return None; // non-canonical trailing bits
                }
                out.extend_from_slice(&[(n >> 10) as u8, (n >> 2) as u8]);
            }
            _ => {
                if n & 0xf != 0 {
                    return None;
                }
                out.push((n >> 4) as u8);
            }
        }
    }
    Some(out)
}

// The eight small-order points' canonical encodings (spec: weak keys).
const SMALL_ORDER: [[u8; 32]; 8] = {
    const fn h(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            const fn d(c: u8) -> u8 {
                if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
            }
            out[i] = (d(b[2 * i]) << 4) | d(b[2 * i + 1]);
            i += 1;
        }
        out
    }
    [
        h("0000000000000000000000000000000000000000000000000000000000000000"),
        h("0000000000000000000000000000000000000000000000000000000000000080"),
        h("0100000000000000000000000000000000000000000000000000000000000000"),
        h("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        h("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
        h("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        h("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
        h("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ]
};

/// A 32-byte key the spec refuses: a small-order point, or a non-canonical encoding.
fn weak_ed25519(key: &[u8; 32]) -> bool {
    if SMALL_ORDER.contains(key) {
        return true;
    }
    let mid_ff = key[1..31].iter().all(|&b| b == 0xff);
    let mid_00 = key[1..31].iter().all(|&b| b == 0);
    let top = key[31] & 0x7f;
    // y (little-endian, top bit cleared) ≥ p = 2^255 − 19 (ed ff … ff 7f).
    let high = top == 0x7f && mid_ff;
    if high && key[0] >= 0xed {
        return true;
    }
    // Negative zero: the sign bit with x = 0 (y = 1 or y = p − 1).
    key[31] & 0x80 != 0 && ((key[0] == 1 && top == 0 && mid_00) || (key[0] == 0xec && high))
}

/// A canonical curve point outside the prime-order subgroup, [L]·A ≠ identity
/// (spec: weak keys). A value that isn't a point is not reported: it can't
/// verify anything (bad_signature). The caller has refused non-canonical encodings.
fn mixed_order_ed25519(key: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY(*key)
        .decompress()
        .is_some_and(|p| !p.is_torsion_free())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_is_canonical() {
        assert_eq!(b64url(""), Some(vec![]));
        assert_eq!(b64url("AA"), Some(vec![0]));
        assert_eq!(b64url("AAA"), Some(vec![0, 0]));
        assert_eq!(b64url("_-8"), Some(vec![0xff, 0xef]));
        for bad in ["A", "AB", "AAB", "AA==", "AA+/", "AA AA", "AAAAA"] {
            assert_eq!(b64url(bad), None, "{bad}");
        }
    }

    #[test]
    fn kid_pattern() {
        assert!(valid_kid("test:2026-11_A"));
        assert!(valid_kid(&"a".repeat(128)));
        for bad in ["", "a.b", "a b", "é", &"a".repeat(129)] {
            assert!(!valid_kid(bad), "{bad}");
        }
    }

    fn hex(h: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn weak_keys() {
        let mut weak: Vec<[u8; 32]> = SMALL_ORDER.to_vec();
        weak.push(hex(
            "0100000000000000000000000000000000000000000000000000000000000080",
        )); // negative zero
        weak.push(hex(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ));
        for k in 0..19u8 {
            let mut b = [0xffu8; 32];
            b[0] = 0xed + k;
            b[31] = 0x7f;
            weak.push(b); // y = p + k
            b[31] = 0xff;
            weak.push(b); // and with the sign bit
        }
        for k in &weak {
            assert!(weak_ed25519(k), "{k:02x?}");
        }
        for h in [
            "eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p − 3: a point, not small-order
            "0300000000000000000000000000000000000000000000000000000000000000", // y = 3
            "2b57583dbe767c93f76025809070aaf98b68ffc231df60a3df6dba5383ea23a9", // the vectors' test key
        ] {
            assert!(!weak_ed25519(&hex(h)), "{h}");
        }
    }

    #[test]
    fn mixed_order_keys() {
        for h in [
            "66bc0b83ea748e9e68b3e9e947370667010dcedc6949846f1144d16c77af1166", // the vectors' test key + a point of order 8
            "0000000000000000000000000000000000000000000000000000000000000000",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            assert!(mixed_order_ed25519(&hex(h)), "{h}");
        }
        for h in [
            "2b57583dbe767c93f76025809070aaf98b68ffc231df60a3df6dba5383ea23a9", // the vectors' test key
            "0100000000000000000000000000000000000000000000000000000000000000", // the identity: the weak-key list refuses it
            "0200000000000000000000000000000000000000000000000000000000000000", // y = 2: not a point
        ] {
            assert!(!mixed_order_ed25519(&hex(h)), "{h}");
        }
        for seed in 0..16u8 {
            let a = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes();
            assert!(!mixed_order_ed25519(&a), "{a:02x?}");
        }
    }
}

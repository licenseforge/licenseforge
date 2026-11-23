//! The shared conformance vectors (spec/vectors/lf1.json): every case gives the expected class.

mod common;

use common::{keys, vectors};
use licenseforge::{Code, verify};

#[test]
fn lf1() {
    let v = vectors("lf1.json");
    let keys = keys();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 46);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let r = verify(c["license"].as_str().unwrap(), &keys);
        let got = r.as_ref().map_or_else(|e| e.code().as_str(), |_| "valid");
        assert_eq!(got, c["expect"].as_str().unwrap(), "{name}");
        if let Ok(ok) = r {
            assert_eq!(ok.kid, c["kid"].as_str().unwrap(), "{name}");
            assert_eq!(
                ok.payload,
                c["payload"].as_str().unwrap().as_bytes(),
                "{name}"
            );
        }
    }
}

#[test]
fn errors_name_the_class() {
    let e = verify("nope", &keys()).unwrap_err();
    assert_eq!(e.code(), Code::Malformed);
    assert_eq!(e.to_string(), "licenseforge: malformed");
}

#[test]
fn lf1_claims() {
    use licenseforge::{CheckOptions, check, parse_claims, parse_duration, parse_time};
    let v = vectors("lf1-claims.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 98);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let o = &c["options"];
        let s = |k: &str| o[k].as_str();
        let got = parse_claims(c["payload"].as_str().unwrap().as_bytes()).and_then(|claims| {
            let mut opts = CheckOptions::new(
                parse_time(s("now").unwrap()).unwrap(),
                s("product").unwrap_or(""),
            );
            if let Some(f) = s("fingerprint") {
                opts = opts.with_fingerprint(f);
            }
            if let Some(b) = s("build_date") {
                opts = opts.with_build_date(parse_time(b).unwrap());
            }
            if let Some(t) = s("clock_tolerance") {
                opts = opts.with_clock_tolerance(parse_duration(t).unwrap());
            }
            check(&claims, &opts)
        });
        let got = got.map_or_else(|e| e.code().as_str(), |st| st.as_str());
        assert_eq!(got, c["expect"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn open_runs_every_step() {
    use ed25519_dalek::{Signer, SigningKey};
    use licenseforge::{CheckOptions, Status, open, parse_time};
    let v = vectors("lf1.json");
    let seed: [u8; 32] = v["test_seed"]
        .as_str()
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();
    let b64 = |b: &[u8]| {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for c in b.chunks(3) {
            let n = c
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, &x)| n | ((x as u32) << (16 - 8 * i)));
            for i in 0..=c.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    };
    let payload = r#"{"v":1,"lid":"lic_open","product":"acme-db","iat":"2026-11-01T00:00:00Z","exp":"2026-12-01T00:00:00Z","grace":"P7D"}"#;
    let body = format!("lf1.test:2026-11.{}", b64(payload.as_bytes()));
    let license = format!(
        "{body}.{}",
        b64(&SigningKey::from_bytes(&seed)
            .sign(body.as_bytes())
            .to_bytes())
    );
    let at = |t: &str| parse_time(t).unwrap();
    let lic = open(
        &license,
        &keys(),
        &CheckOptions::new(at("2026-11-15T00:00:00Z"), "acme-db"),
    )
    .unwrap();
    assert_eq!(
        (lic.status, lic.claims.license_id.as_str()),
        (Status::Valid, "lic_open")
    );
    assert_eq!(
        open(
            &license,
            &keys(),
            &CheckOptions::new(at("2026-12-03T00:00:00Z"), "acme-db")
        )
        .unwrap()
        .status,
        Status::Grace
    );
    assert_eq!(
        open(
            &license,
            &keys(),
            &CheckOptions::new(at("2026-12-09T00:00:00Z"), "acme-db")
        )
        .unwrap_err()
        .code(),
        Code::Expired
    );
    assert_eq!(
        open(
            &license,
            &keys(),
            &CheckOptions::new(at("2026-11-15T00:00:00Z"), "other")
        )
        .unwrap_err()
        .code(),
        Code::WrongProduct
    );
    assert_eq!(
        open(
            "lf1.x.y.z",
            &keys(),
            &CheckOptions::new(at("2026-11-15T00:00:00Z"), "acme-db")
        )
        .unwrap_err()
        .code(),
        Code::Malformed
    );
}

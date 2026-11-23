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
    use licenseforge::{CheckOptions, Status, open, parse_time};
    let v = vectors("lf1.json");
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "valid_bare")
        .unwrap();
    let license = c["license"].as_str().unwrap();
    // The valid payload has no iat, so open reports malformed after a good signature.
    let opts = CheckOptions::new(parse_time("2026-11-15T00:00:00Z").unwrap(), "acme-db");
    let payload = c["payload"].as_str().unwrap();
    if payload.contains("\"iat\"") {
        assert_eq!(open(license, &keys(), &opts).unwrap().status, Status::Valid);
    } else {
        assert_eq!(
            open(license, &keys(), &opts).unwrap_err().code(),
            Code::Malformed
        );
    }
    assert_eq!(
        open("lf1.x.y.z", &keys(), &opts).unwrap_err().code(),
        Code::Malformed
    );
}

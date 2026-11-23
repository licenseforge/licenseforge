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

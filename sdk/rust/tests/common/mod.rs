//! Shared test helpers: the conformance vectors from spec/vectors.
#![allow(dead_code)]

use licenseforge::{PublicKey, parse_key_set};
use serde_json::Value;

pub fn vectors(name: &str) -> Value {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).unwrap()
}

/// The vectors' keys, read through parse_key_set like a vendor's build would.
pub fn keys() -> Vec<PublicKey> {
    parse_key_set(vectors("lf1.json")["keys"].to_string().as_bytes()).unwrap()
}

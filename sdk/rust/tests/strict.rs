//! Envelope and key set rules beyond the vectors (the Java and Go SDKs' cases).

mod common;

use licenseforge::{Code, MAX_SIZE, PublicKey, parse_key_set, verify};
use std::time::Instant;

const VEC: &str = "K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k"; // spec/vectors/lf1.json test:2026-11

fn code(r: Result<licenseforge::Verified, licenseforge::Error>) -> &'static str {
    r.map_or_else(|e| e.code().as_str(), |_| "ok")
}

fn shortest_valid() -> String {
    let v = common::vectors("lf1.json");
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["expect"] == "valid")
        .map(|c| c["license"].as_str().unwrap().to_string())
        .min_by_key(|s| s.len())
        .unwrap()
}

#[test]
fn reads_the_dashboards_json() {
    let ks = parse_key_set(format!(r#"[{{"kid":"sk_a","alg":"ed25519","public_key":"{VEC}"}},{{"kid":"sk_b","alg":"ml-dsa-65","public_key":"AAAA"}}]"#).as_bytes()).unwrap();
    assert_eq!(ks.len(), 2);
    assert_eq!(
        (ks[0].kid.as_str(), ks[0].alg.as_str(), ks[0].key.len()),
        ("sk_a", "ed25519", 32)
    );
    assert_eq!((ks[1].alg.as_str(), ks[1].key.len()), ("ml-dsa-65", 3));
}

#[test]
fn what_verify_decides_loads_as_given() {
    let ks = parse_key_set(br#"[{"kid":"d","alg":"ed25519","public_key":"AAAA"},{"kid":"d","alg":"ed25519","public_key":"AAAA"},{"kid":"x","alg":"rsa","public_key":"AAAA"},{"kid":"e","alg":"","public_key":"AAAA"},{"kid":"z","alg":"ed25519","public_key":""}]"#).unwrap();
    assert_eq!(ks.len(), 5);
    assert!(ks[4].key.is_empty());
}

#[test]
fn invalid_key_set() {
    let short = &VEC[..VEC.len() - 1];
    let mut cases: Vec<(String, Vec<u8>)> = [
        ("not json", "{".to_string()),
        (
            "not an array",
            r#"{"kid":"a","alg":"ed25519","public_key":"AAAA"}"#.into(),
        ),
        ("empty", "[]".into()),
        ("null", "null".into()),
        (
            "trailing data",
            r#"[{"kid":"a","alg":"ed25519","public_key":"AAAA"}] []"#.into(),
        ),
        (
            "typo in field",
            r#"[{"kid":"a","alg":"ed25519","publicKey":"AAAA"}]"#.into(),
        ),
        (
            "unknown field",
            r#"[{"kid":"a","alg":"ed25519","public_key":"AAAA","use":"sig"}]"#.into(),
        ),
        ("missing key", r#"[{"kid":"a","alg":"ed25519"}]"#.into()),
        (
            "missing kid",
            r#"[{"alg":"ed25519","public_key":"AAAA"}]"#.into(),
        ),
        ("missing alg", r#"[{"kid":"a","public_key":"AAAA"}]"#.into()),
        (
            "padded",
            r#"[{"kid":"a","alg":"ed25519","public_key":"AAA="}]"#.into(),
        ),
        (
            "standard alphabet",
            r#"[{"kid":"a","alg":"ed25519","public_key":"AA+/"}]"#.into(),
        ),
        (
            "non-canonical bits",
            r#"[{"kid":"a","alg":"ed25519","public_key":"AB"}]"#.into(),
        ),
        (
            "bad kid",
            r#"[{"kid":"a.b","alg":"ed25519","public_key":"AAAA"}]"#.into(),
        ),
        (
            "upper-case fields",
            r#"[{"KID":"a","ALG":"ed25519","Public_Key":"AAAA"}]"#.into(),
        ),
        (
            "kelvin sign",
            "[{\"\u{212A}id\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]".into(),
        ),
        (
            "repeated key",
            format!(r#"[{{"kid":"a","alg":"ed25519","public_key":"AAAA","public_key":"{VEC}"}}]"#),
        ),
        (
            "case-variant repeat",
            format!(r#"[{{"kid":"a","alg":"ed25519","public_key":"AAAA","PUBLIC_KEY":"{VEC}"}}]"#),
        ),
        (
            "repeated kid",
            r#"[{"kid":"a","kid":"b","alg":"ed25519","public_key":"AAAA"}]"#.into(),
        ),
        (
            "null field",
            r#"[{"kid":"a","alg":null,"public_key":"AAAA"}]"#.into(),
        ),
        (
            "number field",
            r#"[{"kid":"a","alg":1,"public_key":"AAAA"}]"#.into(),
        ),
        ("null entry", "[null]".into()),
        (
            "newline in key",
            r#"[{"kid":"a","alg":"ed25519","public_key":"AA\nAA"}]"#.into(),
        ),
        (
            "CR in key",
            r#"[{"kid":"a","alg":"ed25519","public_key":"AA\rAA"}]"#.into(),
        ),
        (
            "long non-canonical",
            format!(r#"[{{"kid":"a","alg":"ed25519","public_key":"{short}l"}}]"#),
        ),
        (
            "long padded",
            format!(r#"[{{"kid":"a","alg":"ed25519","public_key":"{VEC}="}}]"#),
        ),
        (
            "lone surrogate escape",
            r#"[{"kid":"a","alg":"\ud800","public_key":"AAAA"}]"#.into(),
        ),
        (
            "BOM",
            "\u{feff}[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]".into(),
        ),
    ]
    .into_iter()
    .map(|(n, s)| (n.to_string(), s.into_bytes()))
    .collect();
    let mut bad = br#"[{"kid":"a","alg":"ed25519","public_key":"AAAA"}]"#.to_vec();
    bad[20] = 0xff;
    cases.push(("invalid UTF-8".into(), bad));
    for (name, input) in cases {
        let e = parse_key_set(&input).expect_err(&name);
        assert_eq!(e.code(), Code::InvalidKeySet, "{name}");
    }
}

#[test]
fn messages_dont_echo_the_file() {
    for input in [
        r#"[{"kid":"a","alg":"ed25519","s3cr3t_field":"AAAA"}]"#,
        r#"[{"kid":"a","alg":"ed25519","public_key":"AAAA","s3cr3t":1,"s3cr3t":2}]"#,
    ] {
        assert!(
            !parse_key_set(input.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("s3cr3t"),
            "{input}"
        );
    }
}

#[test]
fn long_whitespace_run_is_cheap() {
    let input = format!("a{}a", " \t\r\n".repeat(16000)); // 64,002 bytes, under the limit
    let start = Instant::now();
    assert_eq!(code(verify(&input, &[])), "malformed");
    assert!(start.elapsed().as_millis() < 500);
}

#[test]
fn size_limit_counts_utf8_bytes() {
    let license = shortest_valid();
    let ks = common::keys();
    let exact = license.clone() + &"\n".repeat(MAX_SIZE - license.len());
    assert_eq!(code(verify(&exact, &ks)), "ok", "exactly 64 KiB");
    assert_eq!(
        code(verify(&(exact + "\n"), &ks)),
        "malformed",
        "one byte over"
    );
    // A BOM is one char but three bytes.
    let bom = "\u{feff}".to_string() + &license + &"\n".repeat(MAX_SIZE - license.len() - 1);
    assert_eq!(code(verify(&bom, &ks)), "malformed", "bytes, not chars");
    assert_eq!(
        code(verify(&format!("\u{feff}{license}"), &ks)),
        "ok",
        "one BOM is ignored"
    );
    assert_eq!(
        code(verify(&format!("\u{feff}\u{feff}{license}"), &ks)),
        "malformed",
        "only one BOM"
    );
    let p: Vec<&str> = license.split('.').collect();
    assert_eq!(
        code(verify(&format!("{}.{}.{}.A", p[0], p[1], p[2]), &ks)),
        "malformed",
        "signature of length 1"
    );
    assert_eq!(
        code(verify(&format!("{}.{}.A.{}", p[0], p[1], p[3]), &ks)),
        "malformed",
        "payload of length 1"
    );
    let upper = PublicKey {
        kid: "test:2026-11".into(),
        alg: "ED25519".into(),
        key: ks[0].key.clone(),
    };
    assert_eq!(code(verify(&license, &[upper])), "unsupported_alg");
    for extra in [".", "..", ". "] {
        assert_eq!(
            code(verify(&(license.clone() + extra), &ks)),
            "malformed",
            "trailing {extra:?}"
        );
    }
    let armored =
        format!("-----BEGIN LICENSEFORGE LICENSE-----{license}-----END LICENSEFORGE LICENSE-----");
    assert_eq!(
        code(verify(&armored, &ks)),
        "ok",
        "markers on the token's line"
    );
    assert_eq!(
        code(verify(
            "-----BEGIN LICENSEFORGE LICENSE-----END LICENSEFORGE LICENSE-----",
            &ks
        )),
        "malformed",
        "overlapping markers"
    );
    assert_eq!(
        code(verify(&format!("{license}\u{a0}"), &ks)),
        "malformed",
        "NBSP isn't whitespace"
    );
}

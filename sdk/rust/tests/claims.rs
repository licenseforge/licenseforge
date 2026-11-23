//! Claim encoding beyond the vectors (the Java and Go SDKs' cases).

use licenseforge::{CheckOptions, Claims, Entitlements, Error, Status, check, parse_claims};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const OK: &str = r#"{"v":1,"lid":"lic_1","product":"p","iat":"2026-11-01T00:00:00Z"}"#;

fn claims(s: &str) -> Result<Claims, Error> {
    parse_claims(s.as_bytes())
}

fn code(r: Result<Claims, Error>) -> &'static str {
    r.map_or_else(|e| e.code().as_str(), |_| "ok")
}

fn with(extra: &str) -> String {
    OK.replacen('}', &format!(",{extra}}}"), 1)
}

#[test]
fn strict_json() {
    assert_eq!(code(claims(OK)), "ok");
    let deep = |n: usize| with(&format!("\"x\":{}{}", "[".repeat(n), "]".repeat(n)));
    let bad: Vec<(&str, String)> = vec![
        ("raw tab in a string", OK.replace("\"lic_1\"", "\"lic\t1\"")),
        (
            "raw newline in a string",
            OK.replace("\"lic_1\"", "\"lic\n1\""),
        ),
        ("bad escape", OK.replace("\"lic_1\"", r#""lic\x1""#)),
        ("short \\u escape", OK.replace("\"lic_1\"", r#""lic\u12""#)),
        (
            "non-ASCII hex digit",
            OK.replace("\"lic_1\"", "\"lic\\u00\u{661}\u{661}\""),
        ),
        ("lone low surrogate", OK.replace("\"lic_1\"", r#""\udc00""#)),
        (
            "high surrogate then a non-surrogate",
            OK.replace("\"lic_1\"", r#""\ud800A""#),
        ),
        ("leading zero", OK.replace("\"v\":1", "\"v\":01")),
        ("plus sign", OK.replace("\"v\":1", "\"v\":+1")),
        ("fraction", OK.replace("\"v\":1", "\"v\":1.0")),
        ("exponent", OK.replace("\"v\":1", "\"v\":1e0")),
        ("trailing comma", OK.replace('}', ",}")),
        ("single quotes", OK.replace("\"lic_1\"", "'lic_1'")),
        ("BOM before the object", format!("\u{feff}{OK}")),
        ("trailing data", format!("{OK} {{}}")),
        ("duplicate key", with("\"lid\":\"x\"")),
        ("null lid", OK.replace("\"lic_1\"", "null")),
        ("NUL in tenant", with(r#""tenant":"t\u0000x""#)),
        (
            "raw 0x1F in a string",
            OK.replace("\"lic_1\"", "\"lic\u{1f}1\""),
        ),
        ("fraction without digits", with("\"x\":1.")),
        ("fraction without digits, exponent", with("\"x\":1.e5")),
        ("nesting 33", deep(32)),
        ("an array", format!("[{OK}]")),
        ("empty lid", OK.replace("\"lic_1\"", "\"\"")),
        (
            "bind type empty",
            with(r#""tenant":"t","bind":{"type":"","fp":"x"}"#),
        ),
        (
            "bind none with fp",
            with(r#""bind":{"type":"none","fp":"x"}"#),
        ),
        (
            "machine without tenant",
            with(r#""bind":{"type":"machine","fp":"x"}"#),
        ),
        ("customer not an object", with(r#""customer":"c""#)),
    ];
    for (name, input) in &bad {
        assert_eq!(code(claims(input)), "malformed", "{name}");
    }
    assert_eq!(code(claims(&deep(31))), "ok", "nesting 32");
    assert_eq!(
        claims(&OK.replace("\"lic_1\"", r#""😀é""#))
            .unwrap()
            .license_id,
        "😀é",
        "a surrogate pair and an escape decode"
    );
    assert_eq!(
        code(parse_claims(&[0x7b, 0xff, 0x7d])),
        "malformed",
        "invalid UTF-8"
    );
    assert_eq!(
        code(parse_claims(&[
            0x7b, 0x22, 0xed, 0xa0, 0x80, 0x22, 0x3a, 0x31, 0x7d
        ])),
        "malformed",
        "an encoded surrogate"
    );
    assert_eq!(
        code(claims(
            &OK.replace("\"v\":1", "\"v\":123456789012345678901234567890")
        )),
        "unsupported_version"
    );
    assert_eq!(
        code(claims(&OK.replace("\"v\":1,", ""))),
        "malformed",
        "missing v"
    );
    assert_eq!(
        code(claims(&OK.replace("\"v\":1", "\"v\":\"1\""))),
        "malformed",
        "string v"
    );
    assert_eq!(
        code(claims(
            &OK.replace("\"v\":1", "\"v\":2")
                .replace("\"lid\":\"lic_1\",", "")
        )),
        "unsupported_version",
        "no field rules for v ≠ 1"
    );
}

#[test]
fn entitlements() {
    let e = claims(&with(
        r#""entitlements":{"features":["sso"],"limits":{"seats":3,"nodes":-1,"zero":0,"neg":-0}}"#,
    ))
    .unwrap()
    .entitlements;
    assert!(e.has_feature("sso"));
    assert!(!e.has_feature("SSO"));
    assert!(!e.has_feature("seats"), "never looks at limits");
    assert_eq!(e.limit("seats"), 3);
    assert_eq!(e.limit("nodes"), Entitlements::UNLIMITED);
    assert_eq!(e.limit("missing"), 0);
    assert_eq!(e.limit("neg"), 0);
    assert_eq!(
        [
            e.allows("seats", 0),
            e.allows("seats", 3),
            e.allows("seats", 4)
        ],
        [true, true, false]
    );
    assert!(e.allows("nodes", i64::MAX));
    assert!(e.allows("missing", 0));
    assert!(!e.allows("missing", 1));
    assert!(!e.allows("nodes", -1));
    assert!(!Entitlements::default().has_feature("x"));
    for l in [
        "1.0",
        "-2",
        "9007199254740992",
        "99999999999999999999",
        "\"1\"",
        "null",
    ] {
        assert_eq!(
            code(claims(&with(&format!(
                r#""entitlements":{{"limits":{{"x":{l}}}}}"#
            )))),
            "malformed",
            "{l}"
        );
    }
    assert_eq!(
        claims(&with(r#""entitlements":{"limits":{"x":9007199254740991}}"#))
            .unwrap()
            .entitlements
            .limit("x"),
        9007199254740991
    );
    assert_eq!(
        code(claims(&with(r#""entitlements":{"features":[1]}"#))),
        "malformed"
    );
    assert_eq!(
        code(claims(&with(r#""entitlements":{"features":"sso"}"#))),
        "malformed"
    );
}

#[test]
fn check_options() {
    let c = claims(&OK.replace("2026-11-01T00:00:00Z", "2026-11-01T00:00:01Z")).unwrap();
    let now: SystemTime = UNIX_EPOCH + Duration::from_secs(1_793_491_200); // 2026-11-01T00:00:00Z
    assert_eq!(
        check(&c, &CheckOptions::new(now, "p")),
        Ok(Status::Valid),
        "24h default tolerance"
    );
    assert_eq!(
        check(
            &c,
            &CheckOptions::new(now, "p").with_clock_tolerance(Duration::ZERO)
        )
        .unwrap_err()
        .code()
        .as_str(),
        "clock_skew"
    );
    assert_eq!(
        check(
            &c,
            &CheckOptions::new(now, "p").with_clock_tolerance(Duration::MAX)
        ),
        Ok(Status::Valid)
    );
}

#[test]
fn updates_until_boundary() {
    let c = claims(&with(r#""updates_until":"2027-01-01T00:00:00Z""#)).unwrap();
    let until = c.updates_until.unwrap();
    let now = c.issued_at;
    assert_eq!(
        check(&c, &CheckOptions::new(now, "p").with_build_date(until)),
        Ok(Status::Valid),
        "built at updates_until"
    );
    let late = CheckOptions::new(now, "p").with_build_date(until + Duration::from_millis(1));
    assert_eq!(
        check(&c, &late).unwrap_err().code().as_str(),
        "updates_expired",
        "1 ms later"
    );
    assert_eq!(
        check(&c, &CheckOptions::new(now, "p")),
        Ok(Status::Valid),
        "no build date: not checked"
    );
}

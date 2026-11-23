//! lf1 claims and claim checks (spec/license-format.md, "Claim encoding rules"
//! and "Claim checks"), in the spec's order.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::json::{self, Value};
use crate::{Code, Error};

/// The default for [`CheckOptions::clock_tolerance`] (ADR-0018).
pub const DEFAULT_CLOCK_TOLERANCE: Duration = Duration::from_secs(24 * 3600);

const MAX_DURATION_SECONDS: u64 = 36500 * 86400;
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// What a license is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingType {
    /// A site license: no fingerprint.
    None,
    /// A machine fingerprint.
    Machine,
    /// A Kubernetes cluster fingerprint.
    Cluster,
}

/// A license's binding: its type and, unless `None`, the fingerprint (`"sha256:…"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub kind: BindingType,
    pub fingerprint: String,
}

/// The features and limits a license grants (ADR-0015). Unknown keys are never an error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entitlements {
    pub features: Vec<String>,
    pub limits: HashMap<String, i64>,
}

impl Entitlements {
    /// The limit value meaning "no limit".
    pub const UNLIMITED: i64 = -1;

    /// Whether the license grants the boolean feature `key` (exact, case-sensitive; never looks at limits).
    pub fn has_feature(&self, key: &str) -> bool {
        self.features.iter().any(|f| f == key)
    }

    /// The limit for `key`: [`Self::UNLIMITED`], a non-negative value, or 0 when the license doesn't set it.
    pub fn limit(&self, key: &str) -> i64 {
        self.limits.get(key).copied().unwrap_or(0)
    }

    /// Whether a resulting total of `n` (after the action, e.g. users + 1) is within the limit `key`.
    pub fn allows(&self, key: &str, n: i64) -> bool {
        let l = self.limit(key);
        n >= 0 && (l == Self::UNLIMITED || n <= l)
    }
}

/// A license's decoded payload. Absent optional strings are empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    pub license_id: String,
    pub tenant: String,
    pub product: String,
    pub plan: String,
    pub customer_id: String,
    pub customer_name: String,
    pub issued_at: SystemTime,
    pub not_before: Option<SystemTime>,
    /// None: perpetual.
    pub expires: Option<SystemTime>,
    pub refresh_after: Option<SystemTime>,
    pub updates_until: Option<SystemTime>,
    /// Zero when absent.
    pub grace: Duration,
    /// None: no limit. Zero is set: only usable at `issued_at`.
    pub max_offline: Option<Duration>,
    pub binding: Binding,
    pub entitlements: Entitlements,
}

/// The local facts a license is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckOptions {
    /// The time to check with (a clock guard's, when there is one).
    pub now: SystemTime,
    /// The product this build is.
    pub product: String,
    /// The local machine or cluster fingerprint, empty if none.
    pub fingerprint: String,
    /// The app's build date; when None, `updates_until` isn't checked.
    pub build_date: Option<SystemTime>,
    /// How far in the future `iat` may be; zero is strict.
    pub clock_tolerance: Duration,
}

impl CheckOptions {
    /// `now` and `product`, no fingerprint or build date, the default tolerance.
    pub fn new(now: SystemTime, product: impl Into<String>) -> Self {
        CheckOptions {
            now,
            product: product.into(),
            fingerprint: String::new(),
            build_date: None,
            clock_tolerance: DEFAULT_CLOCK_TOLERANCE,
        }
    }

    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = fingerprint.into();
        self
    }

    pub fn with_build_date(mut self, build_date: SystemTime) -> Self {
        self.build_date = Some(build_date);
        self
    }

    pub fn with_clock_tolerance(mut self, clock_tolerance: Duration) -> Self {
        self.clock_tolerance = clock_tolerance;
        self
    }
}

/// A usable license's status. New values may be added: keep a `_` arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Status {
    Valid,
    /// Past `exp` but within grace: usable, warn the user.
    Grace,
}

impl Status {
    /// The spec's name: `"valid"` or `"grace"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Valid => "valid",
            Status::Grace => "grace",
        }
    }
}

fn malformed(detail: &str) -> Error {
    Error::with(Code::Malformed, detail)
}

/// Nanoseconds since the epoch, negative before it: exact for any SystemTime, no overflow.
fn nanos(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

/// Parses exactly `YYYY-MM-DDTHH:MM:SSZ`: a real date, year 1970–9999, no leap second.
pub fn parse_time(s: &str) -> Result<SystemTime, Error> {
    let b = s.as_bytes();
    let shape = b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z';
    let num = |r: std::ops::Range<usize>| -> Option<u64> {
        b[r].iter().try_fold(0u64, |n, &c| {
            c.is_ascii_digit().then(|| n * 10 + u64::from(c - b'0'))
        })
    };
    let bad = || malformed("timestamp");
    if !shape {
        return Err(bad());
    }
    let (y, mo, d, h, mi, se) = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    );
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) = (y, mo, d, h, mi, se) else {
        return Err(bad());
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(bad()),
    };
    if y < 1970 || d < 1 || d > days_in || h > 23 || mi > 59 || se > 59 {
        return Err(bad());
    }
    // Days since 1970-01-01 (Howard Hinnant's days_from_civil).
    let (yy, m) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = yy / 400;
    let yoe = yy - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Ok(UNIX_EPOCH + Duration::from_secs(days * 86400 + h * 3600 + mi * 60 + se))
}

/// Parses `P[nD][T[nH][nM][nS]]` (each n 1–6 digits, at least one component), at most 36,500 days.
pub fn parse_duration(s: &str) -> Result<Duration, Error> {
    let bad = || malformed("duration");
    /// Takes `<1–6 digits><unit>` from the front of `rest`, if it's there.
    fn take(rest: &mut &str, unit: char) -> Result<Option<u64>, ()> {
        let n = rest.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 || !rest[n..].starts_with(unit) {
            return Ok(None);
        }
        if n > 6 {
            return Err(());
        }
        let v = rest[..n].parse().map_err(|_| ())?;
        *rest = &rest[n + 1..];
        Ok(Some(v))
    }
    let mut rest = s.strip_prefix('P').ok_or_else(bad)?;
    let mut parts = vec![take(&mut rest, 'D').map_err(|_| bad())?.map(|d| d * 86400)];
    if let Some(t) = rest.strip_prefix('T') {
        rest = t;
        let time = [('H', 3600), ('M', 60), ('S', 1)]
            .map(|(u, m)| take(&mut rest, u).map(|v| v.map(|v| v * m)));
        let time: Vec<Option<u64>> = time
            .into_iter()
            .collect::<Result<_, _>>()
            .map_err(|_| bad())?;
        if time.iter().all(Option::is_none) {
            return Err(bad()); // "T" with nothing after it
        }
        parts.extend(time);
    }
    if !rest.is_empty() || parts.iter().all(Option::is_none) {
        return Err(bad());
    }
    let secs: u64 = parts.into_iter().flatten().sum();
    if secs > MAX_DURATION_SECONDS {
        return Err(malformed("duration exceeds 36500 days"));
    }
    Ok(Duration::from_secs(secs))
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<Option<&'a str>, Error> {
    match v.get(key) {
        None => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s)),
        Some(_) => Err(Error::with(
            Code::Malformed,
            format!("{key} must be a string"),
        )),
    }
}

fn obj_field<'a>(v: &'a Value, key: &str) -> Result<Option<&'a Value>, Error> {
    match v.get(key) {
        None => Ok(None),
        Some(o @ Value::Object(_)) => Ok(Some(o)),
        Some(_) => Err(Error::with(
            Code::Malformed,
            format!("{key} must be an object"),
        )),
    }
}

/// An integer token, `-?(0|[1-9][0-9]*)`, as text.
fn integer<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    match v {
        Value::Num(t) if !t.contains(['.', 'e', 'E']) => Ok(t),
        _ => Err(Error::with(
            Code::Malformed,
            format!("{key} must be an integer"),
        )),
    }
}

fn opt_time(v: &Value, key: &str) -> Result<Option<SystemTime>, Error> {
    str_field(v, key)?.map(parse_time).transpose()
}

/// Decodes a verified payload under the spec's strict encoding rules.
pub fn parse_claims(payload: &[u8]) -> Result<Claims, Error> {
    let text = std::str::from_utf8(payload).map_err(|_| malformed("not valid UTF-8"))?;
    // A BOM stays and the parser refuses it.
    let m = json::parse(text).map_err(malformed)?;
    if !matches!(m, Value::Object(_)) {
        return Err(malformed("expected a JSON object"));
    }
    // Version first: a future version may change any other field.
    let v = m.get("v").ok_or_else(|| malformed("missing v"))?;
    if integer(v, "v")? != "1" {
        return Err(Error::new(Code::UnsupportedVersion));
    }

    let lid = str_field(&m, "lid")?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| malformed("missing or empty lid"))?;
    let product = str_field(&m, "product")?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| malformed("missing or empty product"))?;
    let tenant = str_field(&m, "tenant")?.unwrap_or("");
    let plan = str_field(&m, "plan")?.unwrap_or("");
    let (customer_id, customer_name) = match obj_field(&m, "customer")? {
        Some(c) => (
            str_field(c, "id")?.unwrap_or(""),
            str_field(c, "name")?.unwrap_or(""),
        ),
        None => ("", ""),
    };
    let issued_at = opt_time(&m, "iat")?.ok_or_else(|| malformed("missing iat"))?;
    let not_before = opt_time(&m, "nbf")?;
    let expires = opt_time(&m, "exp")?;
    let refresh_after = opt_time(&m, "refresh_after")?;
    let updates_until = opt_time(&m, "updates_until")?;
    let grace = str_field(&m, "grace")?
        .map(parse_duration)
        .transpose()?
        .unwrap_or(Duration::ZERO);
    let max_offline = str_field(&m, "max_offline")?
        .map(parse_duration)
        .transpose()?;
    if tenant.contains('\0') || product.contains('\0') {
        return Err(malformed("tenant and product must not contain NUL"));
    }

    let mut binding = Binding {
        kind: BindingType::None,
        fingerprint: String::new(),
    };
    if let Some(b) = obj_field(&m, "bind")? {
        let fp = str_field(b, "fp")?;
        match str_field(b, "type")? {
            None | Some("none") => {
                if fp.is_some() {
                    return Err(malformed("bind type none must not have fp"));
                }
            }
            Some(t @ ("machine" | "cluster")) => {
                let fp = fp.filter(|f| !f.is_empty()).ok_or_else(|| {
                    Error::with(Code::Malformed, format!("{t} binding without fp"))
                })?;
                let kind = if t == "machine" {
                    BindingType::Machine
                } else {
                    BindingType::Cluster
                };
                binding = Binding {
                    kind,
                    fingerprint: fp.to_string(),
                };
            }
            Some(_) => return Err(malformed("unknown binding type")),
        }
    }
    // A bound license's fingerprint is derived from tenant and product.
    if binding.kind != BindingType::None && tenant.is_empty() {
        return Err(malformed("bound license without tenant"));
    }

    let mut entitlements = Entitlements::default();
    if let Some(e) = obj_field(&m, "entitlements")? {
        match e.get("features") {
            None => {}
            Some(Value::Array(items)) => {
                for it in items {
                    let Value::Str(s) = it else {
                        return Err(malformed("features[] must be a string"));
                    };
                    entitlements.features.push(s.clone());
                }
            }
            Some(_) => return Err(malformed("features must be an array")),
        }
        if let Some(Value::Object(limits)) = obj_field(e, "limits")? {
            for (k, v) in limits {
                let n: i64 = integer(v, "limits")?
                    .parse()
                    .map_err(|_| malformed("limit out of range"))?;
                if !(-1..=MAX_SAFE_INTEGER).contains(&n) {
                    return Err(malformed("limit out of range"));
                }
                entitlements.limits.insert(k.clone(), n);
            }
        }
    }

    Ok(Claims {
        license_id: lid.to_string(),
        tenant: tenant.to_string(),
        product: product.to_string(),
        plan: plan.to_string(),
        customer_id: customer_id.to_string(),
        customer_name: customer_name.to_string(),
        issued_at,
        not_before,
        expires,
        refresh_after,
        updates_until,
        grace,
        max_offline,
        binding,
        entitlements,
    })
}

/// Applies the spec's claim checks in order: a usable license's status, or the first failure.
pub fn check(c: &Claims, o: &CheckOptions) -> Result<Status, Error> {
    let now = nanos(o.now);
    let d = |d: Duration| d.as_nanos() as i128;
    if c.product != o.product {
        return Err(Error::new(Code::WrongProduct));
    }
    if c.binding.kind != BindingType::None
        && (c.binding.fingerprint.is_empty() || c.binding.fingerprint != o.fingerprint)
    {
        return Err(Error::new(Code::BindingMismatch));
    }
    let iat = nanos(c.issued_at);
    if iat > now + d(o.clock_tolerance) {
        return Err(Error::new(Code::ClockSkew));
    }
    if c.not_before.is_some_and(|nbf| now < nanos(nbf)) {
        return Err(Error::new(Code::NotYetValid));
    }
    if c.max_offline.is_some_and(|mo| now > iat + d(mo)) {
        return Err(Error::new(Code::OfflineExceeded));
    }
    if c.expires.is_some_and(|exp| now > nanos(exp) + d(c.grace)) {
        return Err(Error::new(Code::Expired));
    }
    if let (Some(until), Some(build)) = (c.updates_until, o.build_date) {
        if nanos(build) > nanos(until) {
            return Err(Error::new(Code::UpdatesExpired));
        }
    }
    Ok(if c.expires.is_some_and(|exp| now > nanos(exp)) {
        Status::Grace
    } else {
        Status::Valid
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn timestamps() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z").unwrap(), at(0));
        assert_eq!(
            parse_time("2028-02-29T23:59:59Z").unwrap(),
            at(1_835_481_599)
        );
        assert_eq!(parse_time("2000-03-01T00:00:00Z").unwrap(), at(951_868_800));
        assert_eq!(
            parse_time("9999-12-31T23:59:59Z").unwrap(),
            at(253_402_300_799)
        );
        for s in [
            "2026-02-30T00:00:00Z",
            "2027-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-11-00T00:00:00Z",
            "2026-11-31T00:00:00Z",
            "2026-11-01T24:00:00Z",
            "2026-11-01T00:60:00Z",
            "2026-11-01T00:00:60Z",
            "1969-12-31T23:59:59Z",
            "2026-11-01t00:00:00Z",
            "2026-11-01T00:00:00z",
            "2026-11-01T00:00:00.5Z",
            "2026-11-01T00:00:00+00:00",
            "\u{662}026-11-01T00:00:00Z",
            "+026-11-01T00:00:00Z",
            "",
        ] {
            assert_eq!(parse_time(s).unwrap_err().code(), Code::Malformed, "{s}");
        }
    }

    #[test]
    fn durations() {
        assert_eq!(
            parse_duration("P7D").unwrap(),
            Duration::from_secs(7 * 86400)
        );
        assert_eq!(parse_duration("PT0S").unwrap(), Duration::ZERO);
        assert_eq!(
            parse_duration("P1DT1H1M1S").unwrap(),
            Duration::from_secs(86400 + 3600 + 60 + 1)
        );
        assert_eq!(parse_duration("PT1M").unwrap(), Duration::from_secs(60));
        assert_eq!(
            parse_duration("P36500D").unwrap(),
            Duration::from_secs(36500 * 86400)
        );
        assert_eq!(
            parse_duration("PT876000H").unwrap(),
            Duration::from_secs(36500 * 86400)
        );
        for s in [
            "P",
            "PT",
            "P1DT",
            "P36501D",
            "PT876001H",
            "P1W",
            "P1Y",
            "p1d",
            "P1234567D",
            "-P1D",
            "P1.5D",
            "PT1S ",
            "PT1S1M",
            "P1D1D",
            "PTS",
            "P+1D",
            "PT1H1H",
        ] {
            assert_eq!(
                parse_duration(s).unwrap_err().code(),
                Code::Malformed,
                "{s}"
            );
        }
    }

    #[test]
    fn check_compares_below_a_second() {
        let c = parse_claims(br#"{"v":1,"lid":"l","product":"p","iat":"2026-11-01T00:00:00Z","exp":"2026-12-01T00:00:00Z"}"#).unwrap();
        let exp = c.expires.unwrap();
        assert_eq!(
            check(&c, &CheckOptions::new(exp, "p")),
            Ok(Status::Valid),
            "now = exp is valid"
        );
        assert_eq!(
            check(&c, &CheckOptions::new(exp + Duration::from_millis(1), "p"))
                .unwrap_err()
                .code(),
            Code::Expired,
            "1 ms past exp, no grace"
        );
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(
            check(
                &c,
                &CheckOptions::new(before, "p").with_clock_tolerance(Duration::ZERO)
            )
            .unwrap_err()
            .code(),
            Code::ClockSkew,
            "a clock before 1970"
        );
        assert_eq!(
            check(
                &c,
                &CheckOptions::new(before, "p").with_clock_tolerance(Duration::MAX)
            ),
            Ok(Status::Valid),
            "no overflow"
        );
    }
}

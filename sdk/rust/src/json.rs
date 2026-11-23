//! A strict JSON reader for lf1 payloads and key sets (spec/license-format.md,
//! claim encoding rules): no duplicate keys in any object, nesting at most
//! [`MAX_DEPTH`], no unpaired surrogate escapes, no control characters in
//! strings, numbers kept as their source token, nothing after the value.

use std::collections::HashSet;

/// The deepest object/array nesting allowed (the top-level value is depth 1).
pub(crate) const MAX_DEPTH: usize = 32;

#[derive(Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    /// A number, kept as its source token.
    Num(String),
    Str(String),
    Array(Vec<Value>),
    /// Entries in source order; keys are unique.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The value for `key` in an object, if present.
    pub(crate) fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(e) => e.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Parses `text` as exactly one JSON value with nothing but JSON whitespace around it.
pub(crate) fn parse(text: &str) -> Result<Value, &'static str> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    let v = p.value(1)?;
    p.ws();
    if p.i != p.b.len() {
        return Err("trailing data after the value");
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn lit(&mut self, s: &[u8]) -> bool {
        if self.b[self.i..].starts_with(s) {
            self.i += s.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, &'static str> {
        self.ws();
        match self.peek() {
            None => Err("unexpected end"),
            Some(c @ (b'{' | b'[')) => {
                if depth > MAX_DEPTH {
                    return Err("nesting too deep");
                }
                self.i += 1;
                self.ws();
                if c == b'{' {
                    self.object(depth)
                } else {
                    self.array(depth)
                }
            }
            Some(b'"') => self.string().map(Value::Str),
            _ if self.lit(b"true") => Ok(Value::Bool(true)),
            _ if self.lit(b"false") => Ok(Value::Bool(false)),
            _ if self.lit(b"null") => Ok(Value::Null),
            _ => self.number(),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, &'static str> {
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(entries));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err("expected a key");
            }
            let k = self.string()?;
            if !seen.insert(k.clone()) {
                return Err("duplicate key");
            }
            self.ws();
            if self.peek() != Some(b':') {
                return Err("expected :");
            }
            self.i += 1;
            let v = self.value(depth + 1)?;
            entries.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(entries));
                }
                _ => return Err("expected , or }"),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, &'static str> {
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err("expected , or ]"),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, &'static str> {
        let h = self.b.get(self.i..self.i + 4).ok_or("bad \\u escape")?;
        let mut u = 0;
        for &c in h {
            // ASCII hex digits only.
            let d = (c as char)
                .to_digit(16)
                .filter(|_| c.is_ascii_hexdigit())
                .ok_or("bad \\u escape")?;
            u = u * 16 + d;
        }
        self.i += 4;
        Ok(u)
    }

    fn string(&mut self) -> Result<String, &'static str> {
        self.i += 1; // the opening quote
        let mut out = String::new();
        loop {
            let start = self.i;
            // Plain bytes up to a quote, backslash or control character. The input
            // is a &str, so any run between ASCII delimiters is valid UTF-8.
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "invalid UTF-8")?);
            match self.peek() {
                None => return Err("unterminated string"),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {}
                Some(_) => return Err("control character in string"),
            }
            let e = self.b.get(self.i + 1).copied();
            self.i += 2;
            match e {
                Some(b'"') => out.push('"'),
                Some(b'\\') => out.push('\\'),
                Some(b'/') => out.push('/'),
                Some(b'b') => out.push('\u{8}'),
                Some(b'f') => out.push('\u{c}'),
                Some(b'n') => out.push('\n'),
                Some(b'r') => out.push('\r'),
                Some(b't') => out.push('\t'),
                Some(b'u') => {
                    let u = self.hex4()?;
                    let c = match u {
                        0xdc00..=0xdfff => return Err("unpaired surrogate escape"),
                        0xd800..=0xdbff => {
                            if !self.lit(b"\\u") {
                                return Err("unpaired surrogate escape");
                            }
                            let lo = self.hex4()?;
                            if !(0xdc00..=0xdfff).contains(&lo) {
                                return Err("unpaired surrogate escape");
                            }
                            0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00)
                        }
                        _ => u,
                    };
                    out.push(char::from_u32(c).ok_or("bad \\u escape")?);
                }
                _ => return Err("bad escape"),
            }
        }
    }

    /// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`
    fn number(&mut self) -> Result<Value, &'static str> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let s = p.i;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.i += 1;
            }
            p.i > s
        };
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return Err("unexpected character"),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !digits(self) {
                return Err("bad number");
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !digits(self) {
                return Err("bad number");
            }
        }
        // ASCII only, so the slice is valid UTF-8.
        Ok(Value::Num(
            String::from_utf8_lossy(&self.b[start..self.i]).into_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict() {
        for bad in [
            "",
            "{",
            "{} {}",
            r#"{"a":1,"a":2}"#,
            r#"{"a":"\ud800"}"#,
            r#"{"a":"\udc00"}"#,
            r#"{"a":"\ud800A"}"#,
            "{\"a\":\"\u{1}\"}",
            r#"{"a":01}"#,
            r#"{"a":1.}"#,
            r#"{"a":-}"#,
            r#"{"a":"\x"}"#,
            r#"{"a":"\u00g0"}"#,
            "\u{feff}{}",
            "{\"a\":1,}",
            "[1,]",
            "nul",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let deep_ok = "[".repeat(32) + &"]".repeat(32);
        assert!(parse(&deep_ok).is_ok());
        let deep = "[".repeat(33) + &"]".repeat(33);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn values() {
        let v =
            parse(r#" {"s":"aé😀\n","n":-1.5e+3,"z":0,"b":[true,false,null],"o":{}} "#).unwrap();
        assert_eq!(v.get("s"), Some(&Value::Str("aé😀\n".into())));
        assert_eq!(v.get("n"), Some(&Value::Num("-1.5e+3".into())));
        assert_eq!(v.get("z"), Some(&Value::Num("0".into())));
        assert_eq!(
            v.get("b"),
            Some(&Value::Array(vec![
                Value::Bool(true),
                Value::Bool(false),
                Value::Null
            ]))
        );
        assert_eq!(v.get("o"), Some(&Value::Object(vec![])));
        assert_eq!(v.get("missing"), None);
    }
}

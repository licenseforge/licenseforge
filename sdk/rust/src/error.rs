use std::fmt;

/// The error classes shared by all SDKs and the conformance vectors
/// (spec/license-format.md). New classes may be added: keep a `_` arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    Malformed,
    UnknownKey,
    UnsupportedAlg,
    BadSignature,
    InvalidKeySet,
    UnsupportedVersion,
    WrongProduct,
    BindingMismatch,
    ClockSkew,
    NotYetValid,
    OfflineExceeded,
    Expired,
    UpdatesExpired,
}

impl Code {
    /// The spec's name, e.g. `"bad_signature"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Malformed => "malformed",
            Code::UnknownKey => "unknown_key",
            Code::UnsupportedAlg => "unsupported_alg",
            Code::BadSignature => "bad_signature",
            Code::InvalidKeySet => "invalid_key_set",
            Code::UnsupportedVersion => "unsupported_version",
            Code::WrongProduct => "wrong_product",
            Code::BindingMismatch => "binding_mismatch",
            Code::ClockSkew => "clock_skew",
            Code::NotYetValid => "not_yet_valid",
            Code::OfflineExceeded => "offline_exceeded",
            Code::Expired => "expired",
            Code::UpdatesExpired => "updates_expired",
        }
    }
}

/// A license or key set that can't be used, with its spec class in [`Error::code`].
/// Details never echo the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    code: Code,
    detail: Option<String>,
}

impl Error {
    pub(crate) fn new(code: Code) -> Self {
        Error { code, detail: None }
    }

    pub(crate) fn with(code: Code, detail: impl Into<String>) -> Self {
        Error {
            code,
            detail: Some(detail.into()),
        }
    }

    pub fn code(&self) -> Code {
        self.code
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(d) => write!(f, "licenseforge: {}: {}", self.code.as_str(), d),
            None => write!(f, "licenseforge: {}", self.code.as_str()),
        }
    }
}

impl std::error::Error for Error {}

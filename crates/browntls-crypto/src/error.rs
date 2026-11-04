use core::fmt;

/// Errors returned by primitives in this crate.
///
/// Variants are deliberately coarse: they never reveal which internal check
/// failed (for example, which byte of a tag mismatched or which step of
/// signature verification rejected).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A key had the wrong length or was otherwise malformed or invalid
    /// (including points not on the curve, small-order points where rejected,
    /// and inconsistent private-key components).
    InvalidKey,
    /// An input or output buffer had an unsupported length.
    InvalidLength,
    /// An encoding (DER, point, signature) was malformed.
    InvalidEncoding,
    /// A signature did not verify.
    InvalidSignature,
    /// AEAD authentication failed; no plaintext is released.
    DecryptFailed,
    /// A key agreement produced an all-zero or otherwise rejected secret.
    KeyAgreementFailed,
    /// The entropy source failed.
    RandomFailure,
    /// The operation or parameter set is not supported.
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "invalid key",
            Self::InvalidLength => "invalid length",
            Self::InvalidEncoding => "invalid encoding",
            Self::InvalidSignature => "invalid signature",
            Self::DecryptFailed => "decryption failed",
            Self::KeyAgreementFailed => "key agreement failed",
            Self::RandomFailure => "random number generation failed",
            Self::Unsupported => "unsupported operation",
        })
    }
}

impl core::error::Error for Error {}

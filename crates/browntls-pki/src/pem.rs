//! PEM (RFC 7468) decoding for certificates, keys and CRLs.
//!
//! The decoder is strict: it accepts the standard Base64 alphabet with
//! padding, ignores whitespace and explanatory text outside sections, and
//! rejects mismatched labels and malformed Base64.

use alloc::vec::Vec;
use core::fmt;

use crate::types::{
    CertificateDer, CertificateRevocationListDer, CertificateSigningRequestDer, EchConfigListBytes,
    PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    SubjectPublicKeyInfoDer,
};

/// A PEM section kind recognised by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SectionKind {
    /// `CERTIFICATE`.
    Certificate,
    /// `PUBLIC KEY`.
    PublicKey,
    /// `RSA PRIVATE KEY` (PKCS #1).
    RsaPrivateKey,
    /// `PRIVATE KEY` (PKCS #8).
    PrivateKey,
    /// `EC PRIVATE KEY` (SEC 1).
    EcPrivateKey,
    /// `X509 CRL`.
    Crl,
    /// `CERTIFICATE REQUEST`.
    Csr,
    /// `ECHCONFIG`.
    EchConfigList,
}

impl SectionKind {
    fn from_label(label: &[u8]) -> Option<Self> {
        Some(match label {
            b"CERTIFICATE" => Self::Certificate,
            b"PUBLIC KEY" => Self::PublicKey,
            b"RSA PRIVATE KEY" => Self::RsaPrivateKey,
            b"PRIVATE KEY" => Self::PrivateKey,
            b"EC PRIVATE KEY" => Self::EcPrivateKey,
            b"X509 CRL" => Self::Crl,
            b"CERTIFICATE REQUEST" => Self::Csr,
            b"ECHCONFIG" => Self::EchConfigList,
            _ => return None,
        })
    }
}

/// PEM decoding errors.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A `BEGIN` line had no matching `END` line.
    MissingEnd,
    /// `BEGIN` and `END` labels differ.
    LabelMismatch,
    /// The section body is not valid Base64.
    Base64,
    /// No section of the requested kind was found.
    NoItemsFound,
    /// Reading the file failed.
    #[cfg(feature = "std")]
    Io(std::io::ErrorKind),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnd => f.write_str("PEM section is missing its END line"),
            Self::LabelMismatch => f.write_str("PEM BEGIN/END labels differ"),
            Self::Base64 => f.write_str("invalid Base64 in PEM section"),
            Self::NoItemsFound => f.write_str("no matching PEM section found"),
            #[cfg(feature = "std")]
            Self::Io(k) => write!(f, "I/O error reading PEM: {k}"),
        }
    }
}

impl core::error::Error for Error {}

/// Iterates over recognised PEM sections in `input`, yielding the kind and
/// decoded DER. Unrecognised sections are skipped.
pub fn sections(input: &[u8]) -> Sections<'_> {
    Sections { rest: input }
}

/// Iterator returned by [`sections`].
#[derive(Debug)]
pub struct Sections<'a> {
    rest: &'a [u8],
}

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

impl Iterator for Sections<'_> {
    type Item = Result<(SectionKind, Vec<u8>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let start = find(self.rest, BEGIN)?;
            let after = &self.rest[start + BEGIN.len()..];
            let Some(label_end) = find(after, DASHES) else {
                self.rest = &[];
                return Some(Err(Error::MissingEnd));
            };
            let label = &after[..label_end];
            let body_and_rest = &after[label_end + DASHES.len()..];
            let Some(end) = find(body_and_rest, END) else {
                self.rest = &[];
                return Some(Err(Error::MissingEnd));
            };
            let body = &body_and_rest[..end];
            let after_end = &body_and_rest[end + END.len()..];
            let Some(end_label_len) = find(after_end, DASHES) else {
                self.rest = &[];
                return Some(Err(Error::MissingEnd));
            };
            let end_label = &after_end[..end_label_len];
            self.rest = &after_end[end_label_len + DASHES.len()..];
            if label != end_label {
                return Some(Err(Error::LabelMismatch));
            }
            let Some(kind) = SectionKind::from_label(label) else {
                continue;
            };
            return Some(base64_decode(body).map(|der| (kind, der)));
        }
    }
}

/// Decodes standard padded Base64, ignoring ASCII whitespace.
///
/// # Errors
///
/// Returns [`Error::Base64`] for invalid characters, bad padding or length.
pub fn base64_decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    fn val(c: u8) -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut n = 0usize;
    let mut pad = 0usize;
    for &c in input {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            pad += 1;
            if pad > 2 {
                return Err(Error::Base64);
            }
            acc <<= 6;
            n += 1;
        } else {
            if pad > 0 {
                return Err(Error::Base64); // data after padding
            }
            acc = (acc << 6) | val(c).ok_or(Error::Base64)?;
            n += 1;
        }
        if n == 4 {
            let bytes = acc.to_be_bytes();
            out.extend_from_slice(&bytes[1..4 - pad]);
            // Non-canonical encodings (non-zero discarded bits) are rejected.
            let discarded = match pad {
                1 => acc & 0xff,
                2 => acc & 0xffff,
                _ => 0,
            };
            if discarded != 0 {
                return Err(Error::Base64);
            }
            acc = 0;
            n = 0;
            if pad > 0 {
                // Padding terminates the data; only whitespace may follow.
                pad = 3;
            }
        }
    }
    if n != 0 {
        return Err(Error::Base64);
    }
    Ok(out)
}

/// Types that can be decoded from PEM.
pub trait PemObject: Sized {
    /// Builds the object from a section, or returns `None` if the section kind
    /// does not apply.
    fn from_section(kind: SectionKind, der: Vec<u8>) -> Option<Self>;

    /// Decodes the first applicable section in `pem`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed PEM, or [`Error::NoItemsFound`].
    fn from_pem_slice(pem: &[u8]) -> Result<Self, Error> {
        for s in sections(pem) {
            let (kind, der) = s?;
            if let Some(v) = Self::from_section(kind, der) {
                return Ok(v);
            }
        }
        Err(Error::NoItemsFound)
    }

    /// Iterates over all applicable sections in `pem`.
    fn pem_slice_iter(pem: &[u8]) -> impl Iterator<Item = Result<Self, Error>> + '_ {
        sections(pem).filter_map(|s| match s {
            Ok((kind, der)) => Self::from_section(kind, der).map(Ok),
            Err(e) => Some(Err(e)),
        })
    }

    /// Reads and decodes the first applicable section of a file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when reading fails, otherwise as `from_pem_slice`.
    #[cfg(feature = "std")]
    fn from_pem_file(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        let data = std::fs::read(path).map_err(|e| Error::Io(e.kind()))?;
        Self::from_pem_slice(&data)
    }
}

macro_rules! pem_object {
    ($ty:ident, $kind:ident) => {
        impl PemObject for $ty<'static> {
            fn from_section(kind: SectionKind, der: Vec<u8>) -> Option<Self> {
                (kind == SectionKind::$kind).then(|| Self::from(der))
            }
        }
    };
}

pem_object!(CertificateDer, Certificate);
pem_object!(SubjectPublicKeyInfoDer, PublicKey);
pem_object!(CertificateRevocationListDer, Crl);
pem_object!(CertificateSigningRequestDer, Csr);
pem_object!(EchConfigListBytes, EchConfigList);
pem_object!(PrivatePkcs1KeyDer, RsaPrivateKey);
pem_object!(PrivatePkcs8KeyDer, PrivateKey);
pem_object!(PrivateSec1KeyDer, EcPrivateKey);

impl PemObject for PrivateKeyDer<'static> {
    fn from_section(kind: SectionKind, der: Vec<u8>) -> Option<Self> {
        match kind {
            SectionKind::RsaPrivateKey => Some(Self::Pkcs1(der.into())),
            SectionKind::PrivateKey => Some(Self::Pkcs8(der.into())),
            SectionKind::EcPrivateKey => Some(Self::Sec1(der.into())),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn base64() {
        assert_eq!(base64_decode(b"").unwrap(), b"");
        assert_eq!(base64_decode(b"Zg==").unwrap(), b"f");
        assert_eq!(base64_decode(b"Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode(b"Zm9v\n YmFy").unwrap(), b"foobar");
        assert!(base64_decode(b"Zm9").is_err());
        assert!(base64_decode(b"Zh==").is_err()); // non-canonical
        assert!(base64_decode(b"Zg==Zg==").is_err());
        assert!(base64_decode(b"Z===").is_err());
        assert!(base64_decode(b"Zm9v!").is_err());
    }

    #[test]
    fn sections_and_objects() {
        let pem = b"junk\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n\
            -----BEGIN UNKNOWN-----\nAA==\n-----END UNKNOWN-----\n\
            -----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n";
        let cert = CertificateDer::from_pem_slice(pem).unwrap();
        assert_eq!(cert.as_ref(), &[1, 2, 3]);
        let key = PrivateKeyDer::from_pem_slice(pem).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
        assert_eq!(key.secret_der(), &[4, 5, 6]);
        let all: Vec<_> = CertificateDer::pem_slice_iter(pem).collect();
        assert_eq!(all.len(), 1);
        assert_eq!(
            CertificateRevocationListDer::from_pem_slice(pem),
            Err(Error::NoItemsFound)
        );
        let bad = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END PRIVATE KEY-----\n";
        assert_eq!(
            CertificateDer::from_pem_slice(bad),
            Err(Error::LabelMismatch)
        );
        let _ = vec![0u8];
    }
}

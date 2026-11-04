//! DER-encoded certificate, key and revocation-list containers.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use crate::alg_id::AlgorithmIdentifier;

/// Generic DER bytes, borrowed or owned.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Der<'a>(Cow<'a, [u8]>);

impl<'a> Der<'a> {
    /// Borrows `bytes`.
    #[must_use]
    pub const fn from_slice(bytes: &'a [u8]) -> Self {
        Self(Cow::Borrowed(bytes))
    }

    /// Converts into an owned value with a `'static` lifetime.
    #[must_use]
    pub fn into_owned(self) -> Der<'static> {
        Der(Cow::Owned(self.0.into_owned()))
    }
}

impl AsRef<[u8]> for Der<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for Der<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for Der<'a> {
    fn from(b: &'a [u8]) -> Self {
        Self::from_slice(b)
    }
}

impl From<Vec<u8>> for Der<'static> {
    fn from(v: Vec<u8>) -> Self {
        Self(Cow::Owned(v))
    }
}

impl fmt::Debug for Der<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

fn hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    f.write_str("0x")?;
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

macro_rules! der_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name<'a>(Der<'a>);

        impl<'a> $name<'a> {
            /// Borrows `bytes`.
            #[must_use]
            pub const fn from_slice(bytes: &'a [u8]) -> Self {
                Self(Der::from_slice(bytes))
            }

            /// Converts into an owned value with a `'static` lifetime.
            #[must_use]
            pub fn into_owned(self) -> $name<'static> {
                $name(self.0.into_owned())
            }
        }

        impl AsRef<[u8]> for $name<'_> {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl core::ops::Deref for $name<'_> {
            type Target = [u8];
            fn deref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl<'a> From<&'a [u8]> for $name<'a> {
            fn from(b: &'a [u8]) -> Self {
                Self::from_slice(b)
            }
        }

        impl From<Vec<u8>> for $name<'static> {
            fn from(v: Vec<u8>) -> Self {
                Self(Der::from(v))
            }
        }

        impl<'a> From<Der<'a>> for $name<'a> {
            fn from(d: Der<'a>) -> Self {
                Self(d)
            }
        }
    };
}

der_newtype!(
    /// A DER-encoded X.509 certificate (RFC 5280).
    CertificateDer
);
der_newtype!(
    /// A DER-encoded `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7).
    SubjectPublicKeyInfoDer
);
der_newtype!(
    /// A DER-encoded X.509 certificate revocation list (RFC 5280 §5).
    CertificateRevocationListDer
);
der_newtype!(
    /// A DER-encoded PKCS #10 certificate signing request (RFC 2986).
    CertificateSigningRequestDer
);
der_newtype!(
    /// A TLS-encoded `ECHConfigList` (RFC 9849 §4).
    EchConfigListBytes
);

/// Secret DER bytes: redacted in `Debug` and wiped (best effort) on drop.
#[derive(PartialEq, Eq)]
struct SecretDer<'a>(Cow<'a, [u8]>);

impl SecretDer<'_> {
    fn clone_owned(&self) -> SecretDer<'static> {
        SecretDer(Cow::Owned(self.0.to_vec()))
    }
}

impl Drop for SecretDer<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(v) = &mut self.0 {
            v.fill(0);
            core::hint::black_box(v.as_slice());
        }
    }
}

macro_rules! secret_der_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(PartialEq, Eq)]
        pub struct $name<'a>(SecretDer<'a>);

        impl<'a> $name<'a> {
            /// Returns the secret DER bytes.
            #[must_use]
            pub fn secret_der(&self) -> &[u8] {
                &self.0 .0
            }

            /// Copies the key into an owned value. Keys are deliberately not
            /// `Clone`, so copies of secrets are explicit.
            #[must_use]
            pub fn clone_key(&self) -> $name<'static> {
                $name(self.0.clone_owned())
            }
        }

        impl<'a> From<&'a [u8]> for $name<'a> {
            fn from(b: &'a [u8]) -> Self {
                Self(SecretDer(Cow::Borrowed(b)))
            }
        }

        impl From<Vec<u8>> for $name<'static> {
            fn from(v: Vec<u8>) -> Self {
                Self(SecretDer(Cow::Owned(v)))
            }
        }

        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

secret_der_newtype!(
    /// A DER-encoded PKCS #1 `RSAPrivateKey` (RFC 8017 appendix A.1.2).
    PrivatePkcs1KeyDer
);
secret_der_newtype!(
    /// A DER-encoded SEC 1 `ECPrivateKey` (RFC 5915).
    PrivateSec1KeyDer
);
secret_der_newtype!(
    /// A DER-encoded PKCS #8 `OneAsymmetricKey` (RFC 5958).
    PrivatePkcs8KeyDer
);

/// A DER-encoded private key in one of the supported container formats.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivateKeyDer<'a> {
    /// PKCS #1 RSA key.
    Pkcs1(PrivatePkcs1KeyDer<'a>),
    /// SEC 1 EC key.
    Sec1(PrivateSec1KeyDer<'a>),
    /// PKCS #8 key (any algorithm).
    Pkcs8(PrivatePkcs8KeyDer<'a>),
}

impl PrivateKeyDer<'_> {
    /// Returns the secret DER bytes.
    #[must_use]
    pub fn secret_der(&self) -> &[u8] {
        match self {
            Self::Pkcs1(k) => k.secret_der(),
            Self::Sec1(k) => k.secret_der(),
            Self::Pkcs8(k) => k.secret_der(),
        }
    }

    /// Copies the key into an owned value.
    #[must_use]
    pub fn clone_key(&self) -> PrivateKeyDer<'static> {
        match self {
            Self::Pkcs1(k) => PrivateKeyDer::Pkcs1(k.clone_key()),
            Self::Sec1(k) => PrivateKeyDer::Sec1(k.clone_key()),
            Self::Pkcs8(k) => PrivateKeyDer::Pkcs8(k.clone_key()),
        }
    }
}

impl<'a> From<PrivatePkcs1KeyDer<'a>> for PrivateKeyDer<'a> {
    fn from(k: PrivatePkcs1KeyDer<'a>) -> Self {
        Self::Pkcs1(k)
    }
}

impl<'a> From<PrivateSec1KeyDer<'a>> for PrivateKeyDer<'a> {
    fn from(k: PrivateSec1KeyDer<'a>) -> Self {
        Self::Sec1(k)
    }
}

impl<'a> From<PrivatePkcs8KeyDer<'a>> for PrivateKeyDer<'a> {
    fn from(k: PrivatePkcs8KeyDer<'a>) -> Self {
        Self::Pkcs8(k)
    }
}

/// A trust anchor: the subject and public key of a trusted root, with optional
/// name constraints (RFC 5280 §6.1.1 (d)).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrustAnchor<'a> {
    /// The DER contents (without outer tag) of the subject `Name`.
    pub subject: Der<'a>,
    /// The DER contents (without outer tag) of the `SubjectPublicKeyInfo`.
    pub subject_public_key_info: Der<'a>,
    /// The DER contents (without outer tag) of `NameConstraints`, if any.
    pub name_constraints: Option<Der<'a>>,
}

impl TrustAnchor<'_> {
    /// Converts into an owned value with a `'static` lifetime.
    #[must_use]
    pub fn to_owned(&self) -> TrustAnchor<'static> {
        TrustAnchor {
            subject: self.subject.clone().into_owned(),
            subject_public_key_info: self.subject_public_key_info.clone().into_owned(),
            name_constraints: self.name_constraints.clone().map(Der::into_owned),
        }
    }
}

/// The signature over a message was invalid. Deliberately opaque.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidSignature;

impl fmt::Display for InvalidSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid signature")
    }
}

impl core::error::Error for InvalidSignature {}

/// A signature verification algorithm, supplied by a cryptography provider.
///
/// Certificate path validation and TLS handshake signatures both verify through
/// this trait, so the PKI layer has no built-in cryptography.
pub trait SignatureVerificationAlgorithm: Send + Sync + fmt::Debug {
    /// Verifies `signature` over `message` with `public_key`, which is the
    /// content of the `subjectPublicKey` BIT STRING (e.g. an uncompressed EC
    /// point or a PKCS #1 `RSAPublicKey`).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSignature`] for any failure, including malformed keys.
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature>;

    /// The `AlgorithmIdentifier` that must appear in the `SubjectPublicKeyInfo`.
    fn public_key_alg_id(&self) -> AlgorithmIdentifier;

    /// The `AlgorithmIdentifier` that must appear as the signature algorithm.
    fn signature_alg_id(&self) -> AlgorithmIdentifier;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    #[test]
    fn key_debug_is_redacted() {
        let k = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(vec![1, 2, 3]));
        assert_eq!(format!("{k:?}"), "Pkcs8(PrivatePkcs8KeyDer(<redacted>))");
        assert_eq!(k.clone_key().secret_der(), &[1, 2, 3]);
    }

    #[test]
    fn der_owned_roundtrip() {
        let bytes = [0x30u8, 0x00];
        let c = CertificateDer::from(&bytes[..]);
        let owned: CertificateDer<'static> = c.clone().into_owned();
        assert_eq!(owned, c);
        assert_eq!(format!("{c:?}"), "CertificateDer(0x3000)");
    }
}

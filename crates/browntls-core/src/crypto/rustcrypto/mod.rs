//! A [`CryptoProvider`] backed by the RustCrypto crates.
//!
//! This provider exists to exercise the provider interface and to drive the
//! test-suite; it is not the default (`native`) provider. Its limits:
//!
//! * RSA keys can be used for *verification* only:
//!   [`KeyProvider::load_private_key`] rejects RSA keys. The rule dates from
//!   `rsa` releases before 0.10.0, which are affected by RUSTSEC-2023-0071
//!   (the Marvin timing attack on private-key operations).
//! * Nothing here claims FIPS validation.
//!
//! # ML-DSA certificates (opt-in)
//!
//! [`default_provider`] does not verify ML-DSA signatures (RFC 9881): a
//! certificate or CRL signed with an ML-DSA key fails as an unsupported
//! signature algorithm. To accept them in X.509 validation, use
//! [`SUPPORTED_SIG_ALGS_WITH_ML_DSA`], which adds [`verify::ML_DSA_44`],
//! [`verify::ML_DSA_65`] and [`verify::ML_DSA_87`] (backed by the RustCrypto
//! `ml-dsa` crate) to the certificate path algorithms and leaves the TLS
//! signature scheme mapping as it is. This does not enable TLS
//! authentication with ML-DSA keys, which is a separate opt-in (below);
//! [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`] lists exactly which signatures
//! this one covers. The native provider has the same opt-in
//! (`crypto::native::SUPPORTED_SIG_ALGS_WITH_ML_DSA`).
//!
//! ```
//! use std::sync::Arc;
//!
//! use browntls_core::crypto::rustcrypto;
//! use browntls_core::{ClientConfig, RootCertStore};
//!
//! let mut provider = rustcrypto::default_provider();
//! provider.signature_verification_algorithms = rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA;
//! let provider = Arc::new(provider);
//!
//! # let roots = Arc::new(RootCertStore::empty());
//! let config = ClientConfig::builder_with_provider(provider)
//!     .with_safe_default_protocol_versions()?
//!     .with_root_certificates(roots)
//!     .with_no_client_auth();
//! # let _ = config;
//! # Ok::<(), browntls_core::Error>(())
//! ```
//!
//! # ML-DSA in TLS 1.3 (opt-in, experimental)
//!
//! TLS 1.3 authentication with ML-DSA keys follows
//! `draft-ietf-tls-mldsa-06` ("Use of ML-DSA in TLS 1.3"), an
//! Internet-Draft and not a published RFC: the schemes `mldsa44`,
//! `mldsa65` and `mldsa87` (0x0904 to 0x0906, registered with
//! "Recommended: N") sign `CertificateVerify` with pure ML-DSA and the
//! empty context string, under an end-entity key of the same parameter
//! set. [`default_provider`] neither offers nor accepts these schemes and
//! loads no ML-DSA private key. Two independent provider fields opt in, as
//! in the native provider (`crypto::native`), whose items of the same names
//! behave the same way on the wire; the key loader differs in one key form,
//! in its stack use and in what it zeroises (below):
//!
//! * [`SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13`] as
//!   `signature_verification_algorithms` verifies a peer's ML-DSA
//!   `CertificateVerify` (and ML-DSA certificate paths, as above). The
//!   schemes are then listed, after the default ones, in the
//!   `signature_algorithms` of every ClientHello that offers TLS 1.3 and
//!   every TLS 1.3 CertificateRequest the configuration sends: the opt-in
//!   is visible on the wire.
//! * [`KEY_PROVIDER_WITH_ML_DSA`] as `key_provider` loads ML-DSA private
//!   keys (RFC 9881 PKCS #8), so that a certified key can sign with its
//!   scheme when the peer offers it ([`sign::MlDsaSigningKey`], backed by
//!   the `ml-dsa` crate; signing is hedged with the operating system's
//!   random source). It takes the RFC 9881 `seed` and `both` forms; unlike
//!   the native provider it refuses the `expandedKey` form alone, because
//!   the `ml-dsa` crate offers no checked decoding of an expanded key (see
//!   [`sign::any_ml_dsa_type`]). Loading a key needs far more stack than
//!   in the native provider (for ML-DSA-87, up to about 430 KiB in an
//!   optimised build and 1.25 MiB in an unoptimised one, as measured on
//!   x86-64), and the crate does not wipe its signing temporaries: see
//!   [`sign::MlDsaSigningKey`].
//!
//! The schemes are used in TLS 1.3 (and with it QUIC and DTLS 1.3) only:
//! TLS 1.2 handshake signatures never use them, whichever side holds the
//! key, while ML-DSA-signed certificate paths validate in every protocol
//! version (as above). Delegated credentials (RFC 9345) and exported
//! authenticators (RFC 9261), for which no specification defines them,
//! never use them. A peer without
//! the opt-in fails the handshake with an ML-DSA-only peer as it would
//! with any unsupported key type; nothing falls back to another algorithm
//! unless the application configures another certified key.
//!
//! ```
//! use std::sync::Arc;
//!
//! use browntls_core::crypto::rustcrypto;
//!
//! let mut provider = rustcrypto::default_provider();
//! // Verify peers that authenticate with ML-DSA, and say so in
//! // `signature_algorithms`.
//! provider.signature_verification_algorithms =
//!     rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13;
//! // Load our own ML-DSA private keys (`with_single_cert`,
//! // `with_client_auth_cert`, `CertifiedKey::from_der`).
//! provider.key_provider = rustcrypto::KEY_PROVIDER_WITH_ML_DSA;
//! let provider = Arc::new(provider);
//! # let _ = provider;
//! ```

use browntls_pki::PrivateKeyDer;

use crate::Error;
use crate::crypto::{CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SupportedKxGroup};
use crate::enums::SignatureScheme;
use crate::sign::SigningKey;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::webpki::WebPkiSupportedAlgorithms;

pub mod sign;

pub(crate) mod hash;
pub(crate) mod hmac;
pub(crate) mod kx;
pub(crate) mod quic;
pub mod ticketer;
#[cfg(feature = "std")]
pub use ticketer::Ticketer;
#[cfg(feature = "tls12")]
pub(crate) mod tls12;
pub(crate) mod tls13;
pub mod verify;
mod verify_mldsa;

mod sign_mldsa;
pub use sign_mldsa::{
    KEY_PROVIDER_WITH_ML_DSA, ML_DSA_VERIFICATION_ALG_MAPPING, RustCryptoWithMlDsa,
    SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13, VERIFICATION_ALG_MAPPING_WITH_ML_DSA,
};
pub use verify_mldsa::{
    ALL_VERIFICATION_ALGS_WITH_ML_DSA, ML_DSA_VERIFICATION_ALGS, SUPPORTED_SIG_ALGS_WITH_ML_DSA,
};

/// The provider with every supported suite and group enabled.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: DEFAULT_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &RustCrypto,
        key_provider: &RustCrypto,
    }
}

/// SHA-1 of `data` (FIPS 180-4), in one call.
///
/// For the identifiers that older specifications define with SHA-1 and
/// that only name a key or a certificate: OCSP certificate identifiers
/// (RFC 5019) and the hashes of RFC 6066 (`trusted_ca_keys`,
/// `client_certificate_url`). Nothing is signed or authenticated with it.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    use ::sha1::Digest;
    ::sha1::Sha1::digest(data).into()
}

/// The provider's random source and key loader.
#[derive(Debug)]
pub struct RustCrypto;

impl SecureRandom for RustCrypto {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(buf).map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for RustCrypto {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        sign::any_supported_type(&key_der)
    }
}

/// The cipher suites enabled by [`default_provider`], in preference order.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

/// Every cipher suite this provider implements, in preference order.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The individual cipher suites.
pub mod cipher_suite {
    #[cfg(feature = "tls12")]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use super::tls13::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
}

/// The individual key exchange groups.
pub mod kx_group {
    pub use super::kx::{
        MLKEM768, SECP256R1, SECP256R1MLKEM768, SECP384R1, SECP384R1MLKEM1024, SECP521R1, X25519,
        X25519MLKEM768,
    };
}

/// The key exchange groups enabled by [`default_provider`], in preference
/// order.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    #[cfg(feature = "prefer-post-quantum")]
    kx::X25519MLKEM768,
    kx::X25519,
    kx::SECP256R1,
    kx::SECP384R1,
    #[cfg(not(feature = "prefer-post-quantum"))]
    kx::X25519MLKEM768,
];

/// Every key exchange group this provider implements.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx::X25519MLKEM768,
    kx::SECP256R1MLKEM768,
    kx::SECP384R1MLKEM1024,
    kx::MLKEM768,
    kx::X25519,
    kx::SECP256R1,
    kx::SECP384R1,
    kx::SECP521R1,
];

/// The signature verification algorithms and their TLS scheme mapping, as
/// [`default_provider`] uses them. Without ML-DSA: see
/// [`SUPPORTED_SIG_ALGS_WITH_ML_DSA`].
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &verify::ECDSA_P256_SHA256,
        &verify::ECDSA_P256_SHA384,
        &verify::ECDSA_P384_SHA256,
        &verify::ECDSA_P384_SHA384,
        &verify::ECDSA_P521_SHA512,
        &verify::ED25519,
        &verify::RSA_PSS_SHA256,
        &verify::RSA_PSS_SHA384,
        &verify::RSA_PSS_SHA512,
        &verify::RSA_PKCS1_SHA256,
        &verify::RSA_PKCS1_SHA384,
        &verify::RSA_PKCS1_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[&verify::ECDSA_P384_SHA384, &verify::ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&verify::ECDSA_P256_SHA256, &verify::ECDSA_P384_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[&verify::ECDSA_P521_SHA512],
        ),
        (SignatureScheme::ED25519, &[&verify::ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[&verify::RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[&verify::RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[&verify::RSA_PSS_SHA256]),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[&verify::RSA_PKCS1_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[&verify::RSA_PKCS1_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[&verify::RSA_PKCS1_SHA256],
        ),
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 example: SHA-1("abc").
    #[test]
    fn sha1_of_abc() {
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn provider_is_consistent() {
        let p = default_provider();
        assert!(!p.cipher_suites.is_empty());
        assert!(!p.kx_groups.is_empty());
        assert!(!p.fips());
        let mut buf = [0u8; 16];
        p.secure_random.fill(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 16]);
        #[cfg(feature = "prefer-post-quantum")]
        assert_eq!(p.kx_groups[0].name(), crate::NamedGroup::X25519MLKEM768);
    }
}

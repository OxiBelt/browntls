//! The default [`CryptoProvider`], backed by `browntls-crypto`.
//!
//! Everything here is plain static data, so any item can be combined with
//! items from another provider (or an application's own implementation) to
//! build a mixed provider:
//!
//! ```
//! # #[cfg(feature = "rustcrypto")] {
//! use browntls::crypto::{native, rustcrypto};
//!
//! // Native record protection, hashing and key exchange, with RustCrypto
//! // certificate and handshake signature verification and key loading.
//! let mut provider = native::default_provider();
//! provider.signature_verification_algorithms = rustcrypto::SUPPORTED_SIG_ALGS;
//! provider.key_provider = &rustcrypto::RustCrypto;
//! # let _ = provider;
//! # }
//! ```
//!
//! | Item | Backing |
//! |---|---|
//! | [`cipher_suite`] | SHA-2, HMAC, HKDF, the TLS 1.2 PRF, AES-GCM and ChaCha20-Poly1305 from `browntls_crypto::{hash, hmac, hkdf, tls12_prf, gcm, chacha}` |
//! | [`kx_group`] | `browntls_crypto::{curve25519::x25519, nist, mlkem}` |
//! | [`SUPPORTED_SIG_ALGS`] | `browntls_crypto::{nist, curve25519::ed25519, rsa}` |
//! | [`KEY_PROVIDER`] ([`sign`]) | ECDSA, Ed25519 and RSA signing keys from `browntls-crypto` |
//! | [`SECURE_RANDOM`] | `browntls_crypto::rand::OsRng` |
//! | [`ticketer`] | AES-256-GCM from `browntls_crypto::gcm` |
//!
//! The random source, `browntls_crypto::rand::OsRng`, issues `getrandom(2)`
//! directly on Linux x86-64, aarch64 and riscv64. Other targets need
//! `browntls-crypto`'s `getrandom` feature.
//!
//! Nothing here claims FIPS validation.

use browntls_crypto::rand::{OsRng, SecureRandom as _};
use browntls_pki::{PrivateKeyDer, SignatureVerificationAlgorithm};

use crate::Error;
use crate::crypto::{CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SupportedKxGroup};
use crate::enums::SignatureScheme;
use crate::sign::SigningKey;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::webpki::WebPkiSupportedAlgorithms;

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod hmac;
#[cfg(feature = "tls12")]
pub mod prf;
pub mod sign;
pub mod ticketer;
pub mod verify;

pub(crate) mod kx;
#[cfg(feature = "tls12")]
pub(crate) mod tls12;
pub(crate) mod tls13;

/// The provider with [`DEFAULT_CIPHER_SUITES`], [`DEFAULT_KX_GROUPS`],
/// [`SUPPORTED_SIG_ALGS`], [`SECURE_RANDOM`] and [`KEY_PROVIDER`].
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: DEFAULT_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: SECURE_RANDOM,
        key_provider: KEY_PROVIDER,
    }
}

/// The provider's random source and private key loader.
#[derive(Debug)]
pub struct Native;

/// The random source: the operating system's (`browntls_crypto::rand::OsRng`).
pub static SECURE_RANDOM: &dyn SecureRandom = &Native;

/// Loads ECDSA (P-256, P-384, P-521; PKCS #8 or SEC 1), Ed25519 (PKCS #8)
/// and RSA (PKCS #8 or PKCS #1) private keys; see [`sign::any_supported_type`].
pub static KEY_PROVIDER: &dyn KeyProvider = &Native;

impl SecureRandom for Native {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        OsRng.fill(buf).map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for Native {
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
        MLKEM768, MLKEM1024, SECP256R1, SECP256R1MLKEM768, SECP384R1, SECP384R1MLKEM1024,
        SECP384R1MLKEM1024_CODEPOINT, SECP521R1, X25519, X25519MLKEM768,
    };
}

/// The key exchange groups enabled by [`default_provider`], in preference
/// order. With the `prefer-post-quantum` feature X25519MLKEM768 comes first;
/// otherwise it comes last.
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
    kx::MLKEM1024,
    kx::X25519,
    kx::SECP256R1,
    kx::SECP384R1,
    kx::SECP521R1,
];

/// Every signature verification algorithm this provider implements, used
/// for certificate path signatures.
pub static ALL_VERIFICATION_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    &verify::ECDSA_P256_SHA256,
    &verify::ECDSA_P256_SHA384,
    &verify::ECDSA_P256_SHA512,
    &verify::ECDSA_P384_SHA256,
    &verify::ECDSA_P384_SHA384,
    &verify::ECDSA_P384_SHA512,
    &verify::ECDSA_P521_SHA256,
    &verify::ECDSA_P521_SHA384,
    &verify::ECDSA_P521_SHA512,
    &verify::ED25519,
    &verify::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &verify::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &verify::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &verify::RSA_PKCS1_2048_8192_SHA256,
    &verify::RSA_PKCS1_2048_8192_SHA384,
    &verify::RSA_PKCS1_2048_8192_SHA512,
];

/// How each TLS signature scheme maps onto [`ALL_VERIFICATION_ALGS`], in
/// preference order. An ECDSA scheme names a hash; in TLS 1.2 it does not bind
/// the curve, so each maps to every curve with that hash (the key's own curve
/// first).
#[allow(clippy::type_complexity)]
pub static VERIFICATION_ALG_MAPPING: &[(
    SignatureScheme,
    &[&dyn SignatureVerificationAlgorithm],
)] = &[
    (
        SignatureScheme::ECDSA_NISTP384_SHA384,
        &[
            &verify::ECDSA_P384_SHA384,
            &verify::ECDSA_P256_SHA384,
            &verify::ECDSA_P521_SHA384,
        ],
    ),
    (
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &[
            &verify::ECDSA_P256_SHA256,
            &verify::ECDSA_P384_SHA256,
            &verify::ECDSA_P521_SHA256,
        ],
    ),
    (
        SignatureScheme::ECDSA_NISTP521_SHA512,
        &[
            &verify::ECDSA_P521_SHA512,
            &verify::ECDSA_P384_SHA512,
            &verify::ECDSA_P256_SHA512,
        ],
    ),
    (SignatureScheme::ED25519, &[&verify::ED25519]),
    (
        SignatureScheme::RSA_PSS_SHA512,
        &[&verify::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
    ),
    (
        SignatureScheme::RSA_PSS_SHA384,
        &[&verify::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
    ),
    (
        SignatureScheme::RSA_PSS_SHA256,
        &[&verify::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA512,
        &[&verify::RSA_PKCS1_2048_8192_SHA512],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA384,
        &[&verify::RSA_PKCS1_2048_8192_SHA384],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA256,
        &[&verify::RSA_PKCS1_2048_8192_SHA256],
    ),
];

/// The signature verification algorithms and their TLS scheme mapping.
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: ALL_VERIFICATION_ALGS,
    mapping: VERIFICATION_ALG_MAPPING,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NamedGroup;

    #[test]
    fn provider_is_consistent() {
        let p = default_provider();
        assert_eq!(p.cipher_suites.len(), ALL_CIPHER_SUITES.len());
        assert!(!p.kx_groups.is_empty());
        assert!(!p.fips());
        let mut buf = [0u8; 32];
        p.secure_random.fill(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 32]);
        #[cfg(feature = "prefer-post-quantum")]
        assert_eq!(p.kx_groups[0].name(), NamedGroup::X25519MLKEM768);
        #[cfg(not(feature = "prefer-post-quantum"))]
        assert_eq!(p.kx_groups[0].name(), NamedGroup::X25519);
    }

    #[test]
    fn mapping_only_references_listed_algorithms() {
        for (_, algs) in VERIFICATION_ALG_MAPPING {
            for alg in *algs {
                assert!(ALL_VERIFICATION_ALGS.iter().any(|a| core::ptr::addr_eq(
                    *a as *const dyn SignatureVerificationAlgorithm,
                    *alg as *const dyn SignatureVerificationAlgorithm
                )));
            }
        }
        // Every scheme in the TLS 1.2 suite lists has a verifier.
        let schemes = SUPPORTED_SIG_ALGS.supported_schemes();
        #[cfg(feature = "tls12")]
        for scheme in crate::tls12::TLS12_ECDSA_SCHEMES
            .iter()
            .chain(crate::tls12::TLS12_RSA_SCHEMES)
        {
            assert!(schemes.contains(scheme), "{scheme:?}");
        }
        assert_eq!(schemes.len(), 10);
    }

    #[test]
    fn kx_group_names_are_unique() {
        for (i, a) in ALL_KX_GROUPS.iter().enumerate() {
            for b in &ALL_KX_GROUPS[i + 1..] {
                assert_ne!(a.name(), b.name());
            }
        }
    }
}

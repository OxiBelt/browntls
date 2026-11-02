//! A [`CryptoProvider`] backed by the RustCrypto crates.
//!
//! This provider exists to exercise the provider interface and to drive the
//! test-suite; it is not the default (`native`) provider. Its limits:
//!
//! * RSA keys can be used for *verification* only. Every published `rsa`
//!   release is affected by RUSTSEC-2023-0071 (the Marvin timing attack on
//!   private-key operations), so [`KeyProvider::load_private_key`] rejects
//!   RSA keys.
//! * Nothing here claims FIPS validation.

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
pub(crate) mod ticketer;
#[cfg(feature = "tls12")]
pub(crate) mod tls12;
pub(crate) mod tls13;
pub(crate) mod verify;

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
        MLKEM768, SECP256R1, SECP256R1MLKEM768, SECP384R1, SECP521R1, X25519, X25519MLKEM768,
    };
}

/// The key exchange groups enabled by [`default_provider`], in preference order.
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
    kx::MLKEM768,
    kx::X25519,
    kx::SECP256R1,
    kx::SECP384R1,
    kx::SECP521R1,
];

/// The signature verification algorithms and their TLS scheme mapping.
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

//! The legacy RSASSA-PKCS1-v1_5 signature schemes of RFC 9963
//! (`rsa_pkcs1_sha256_legacy`, `rsa_pkcs1_sha384_legacy`,
//! `rsa_pkcs1_sha512_legacy`) in TLS 1.3 client authentication, between
//! browntls peers and against rustls 0.23, with the native provider's
//! opt-in: `native::SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY`.
//!
//! This target runs the cases in `cases/rsa_pkcs1_legacy.rs`, which reach
//! the provider only through the `prov` module below (the contract is at
//! the top of that file), and the cases in
//! `cases/rsa_pkcs1_legacy/native_only.rs`, which need a provider that
//! signs with RSA keys: `native::sign::any_rsa_pkcs1_legacy_type` and the
//! default RSA key loader. `rsa_pkcs1_legacy.rs` runs the shared cases with
//! the RustCrypto provider. Every key is generated at run time, and
//! nothing secret is committed.

#![cfg(all(feature = "native", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod native_prov;

/// The provider under test, with and without the RFC 9963 opt-in.
mod prov {
    #![allow(dead_code, unreachable_pub, unused_imports)]

    pub use crate::native_prov::*;
    use browntls_core::crypto::CryptoProvider;

    /// The provider as it comes: no legacy scheme.
    pub fn provider() -> CryptoProvider {
        default_provider()
    }

    /// The opt-in table as `signature_verification_algorithms`: a client
    /// verifier built with it lists the legacy schemes in TLS 1.3
    /// CertificateRequests and verifies them.
    pub fn provider_with_rsa_pkcs1_legacy() -> CryptoProvider {
        let mut provider = default_provider();
        provider.signature_verification_algorithms = SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY;
        provider
    }
}

mod common;

include!("cases/rsa_pkcs1_legacy.rs");
include!("cases/rsa_pkcs1_legacy/native_only.rs");

//! TLS 1.3 authentication with ML-DSA keys (`draft-ietf-tls-mldsa-06`)
//! between a browntls client and server, with the native provider's
//! opt-in: `native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13` and
//! `native::KEY_PROVIDER_WITH_ML_DSA`.
//!
//! This target runs the cases in `cases/mldsa_tls13.rs`, which reach the
//! provider only through the `prov` module below (the contract is at the
//! top of that file). Certificates are built with
//! `browntls-pki/tests/common/x509_builder.rs` and
//! `native_mldsa/support.rs`; every key is derived at run time from a fixed
//! label, and nothing secret is committed.

#![cfg(all(feature = "native", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod native_prov;

/// The provider under test, with the ML-DSA opt-ins.
mod prov {
    #![allow(dead_code, unreachable_pub, unused_imports)]

    pub use crate::native_prov::*;
    use browntls_core::crypto::CryptoProvider;

    /// The provider as it comes: no ML-DSA.
    pub fn provider() -> CryptoProvider {
        default_provider()
    }

    /// Both ML-DSA opt-ins: TLS 1.3 handshake signatures (and ML-DSA
    /// certificate paths) verified, ML-DSA private keys loaded.
    pub fn provider_with_ml_dsa() -> CryptoProvider {
        let mut provider = default_provider();
        provider.signature_verification_algorithms = SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13;
        provider.key_provider = KEY_PROVIDER_WITH_ML_DSA;
        provider
    }

    /// The X.509-only ML-DSA opt-in: ML-DSA certificate paths verified, no
    /// TLS signature scheme added, no ML-DSA private key loaded.
    pub fn provider_with_ml_dsa_certificates() -> CryptoProvider {
        let mut provider = default_provider();
        provider.signature_verification_algorithms = SUPPORTED_SIG_ALGS_WITH_ML_DSA;
        provider
    }
}

mod common;

#[path = "../../browntls-pki/tests/common/ml_dsa.rs"]
mod ml_dsa;
#[path = "../../browntls-pki/tests/common/x509_builder.rs"]
mod x509;

#[path = "native_mldsa/support.rs"]
mod support;

include!("cases/mldsa_tls13.rs");

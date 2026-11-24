//! ML-DSA (FIPS 204) certificate and CRL signature verification by the
//! RustCrypto provider (RFC 9881), backed by the RustCrypto `ml-dsa` crate,
//! and its opt-in algorithm table `rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA`.
//!
//! The RustCrypto verifiers are checked against signatures made by
//! `browntls_crypto::mldsa` and by the `ml-dsa` crate, against the RFC 9881
//! Appendix C certificates (made by neither), and against the native
//! provider's verifiers on valid and mutated inputs. The keys, issuers and
//! chains are those of `native_mldsa.rs` (`native_mldsa/support.rs`); every
//! key is derived at run time from a fixed label, and nothing secret is
//! committed.

#![cfg(all(feature = "native", feature = "rustcrypto", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

#[path = "../../browntls-pki/tests/common/ml_dsa.rs"]
mod ml_dsa;
#[path = "../../browntls-pki/tests/common/x509_builder.rs"]
mod x509;

#[path = "native_mldsa/support.rs"]
mod support;

#[path = "rustcrypto_mldsa/algorithms.rs"]
mod algorithms;
#[path = "rustcrypto_mldsa/differential.rs"]
mod differential;
#[path = "rustcrypto_mldsa/handshake.rs"]
mod handshake;

use std::sync::Arc;

use browntls_core::crypto::{CryptoProvider, native, rustcrypto};
use browntls_core::pki_types::SignatureVerificationAlgorithm;

use crate::ml_dsa::Set;
pub use crate::support::*;

/// The RustCrypto verification algorithm of `set`.
pub fn rc_alg(set: Set) -> &'static dyn SignatureVerificationAlgorithm {
    match set {
        Set::MlDsa44 => &rustcrypto::verify::ML_DSA_44,
        Set::MlDsa65 => &rustcrypto::verify::ML_DSA_65,
        Set::MlDsa87 => &rustcrypto::verify::ML_DSA_87,
    }
}

/// The native verification algorithm of `set`.
pub fn native_alg(set: Set) -> &'static dyn SignatureVerificationAlgorithm {
    match set {
        Set::MlDsa44 => &native::verify::ML_DSA_44,
        Set::MlDsa65 => &native::verify::ML_DSA_65,
        Set::MlDsa87 => &native::verify::ML_DSA_87,
    }
}

/// The RustCrypto provider with the ML-DSA opt-in table.
pub fn opt_in_provider() -> Arc<CryptoProvider> {
    let mut provider = rustcrypto::default_provider();
    provider.signature_verification_algorithms = rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA;
    Arc::new(provider)
}

/// The RustCrypto provider as it comes.
pub fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(rustcrypto::default_provider())
}

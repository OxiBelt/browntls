//! ML-DSA (FIPS 204) certificate and CRL signature verification by the
//! native provider (RFC 9881), and the opt-in algorithm table
//! `native::SUPPORTED_SIG_ALGS_WITH_ML_DSA`.
//!
//! The RustCrypto `ml-dsa` crate is the independent oracle: certificates and
//! CRLs are signed by it and by `browntls_crypto::mldsa`, and verified by the
//! native algorithms and by the oracle algorithms of
//! `browntls-pki/tests/common/ml_dsa.rs`. The RFC 9881 Appendix C
//! certificates are signatures made by neither. Certificates are built with
//! `browntls-pki/tests/common/x509_builder.rs`; every key is derived at run
//! time from a fixed label, and nothing secret is committed. OCSP responses
//! are encoded with `browntls-pki/tests/common/ocsp_wire.rs`.

#![cfg(all(feature = "native", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

#[path = "../../browntls-pki/tests/common/ml_dsa.rs"]
mod ml_dsa;
#[path = "../../browntls-pki/tests/common/ocsp_wire.rs"]
mod ocsp_wire;
#[path = "../../browntls-pki/tests/common/x509_builder.rs"]
mod x509;

#[path = "native_mldsa/algorithms.rs"]
mod algorithms;
#[path = "native_mldsa/crls.rs"]
mod crls;
#[path = "native_mldsa/handshake.rs"]
mod handshake;
#[path = "native_mldsa/ocsp.rs"]
mod ocsp;
#[path = "native_mldsa/paths.rs"]
mod paths;

#[path = "native_mldsa/support.rs"]
mod support;

use std::sync::Arc;

use browntls_core::crypto::{CryptoProvider, native};
use browntls_core::pki_types::SignatureVerificationAlgorithm;

use crate::ml_dsa::Set;
pub use crate::support::*;

/// The native verification algorithm of `set`.
pub fn native_alg(set: Set) -> &'static dyn SignatureVerificationAlgorithm {
    match set {
        Set::MlDsa44 => &native::verify::ML_DSA_44,
        Set::MlDsa65 => &native::verify::ML_DSA_65,
        Set::MlDsa87 => &native::verify::ML_DSA_87,
    }
}

/// The native provider with the ML-DSA opt-in table.
pub fn opt_in_provider() -> Arc<CryptoProvider> {
    let mut provider = native::default_provider();
    provider.signature_verification_algorithms = native::SUPPORTED_SIG_ALGS_WITH_ML_DSA;
    Arc::new(provider)
}

/// The native provider as it comes.
pub fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(native::default_provider())
}

//! Interoperability with rustls 0.23 (ring provider), in both directions.
//!
//! rustls validates browntls's run-time generated certificates with its real
//! web-PKI verifier (the CA is installed as a root), so these tests also check
//! that the certificates browntls sends are well-formed. browntls pins the
//! rustls peer's certificate because path validation in `browntls-pki` is not
//! implemented yet.
//!
//! This target runs the cases in `cases/interop.rs` with the native provider;
//! `interop.rs` runs them with the RustCrypto provider. The cases in
//! `cases/interop_native_only.rs` cover what only the native provider can
//! do: RSA signing for every scheme in both directions, certificate chains
//! signed by native keys, and the ML-KEM-1024 groups' negotiation.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/interop.rs");
include!("cases/interop_native_only.rs");

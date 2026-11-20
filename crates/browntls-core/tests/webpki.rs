//! Tests of the web-PKI verifiers and the SNI resolver.
//!
//! These exercise `browntls-pki` certificate parsing and path validation with
//! the configurations a real deployment uses.
//!
//! This target runs the cases in `cases/webpki.rs` with the RustCrypto provider;
//! `webpki_native.rs` runs them with the native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/webpki.rs");

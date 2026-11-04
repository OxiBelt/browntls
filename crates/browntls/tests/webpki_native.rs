//! Tests of the web-PKI verifiers and the SNI resolver.
//!
//! These exercise `browntls-pki` certificate parsing and path validation with
//! the configurations a real deployment uses.
//!
//! This target runs the cases in `cases/webpki.rs` with the native provider;
//! `webpki.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/webpki.rs");

//! In-memory TLS 1.2 handshakes between a browntls client and server.
//!
//! The RustCrypto provider refuses RSA private keys (RUSTSEC-2023-0071), so
//! with it the `ECDHE_RSA` suites are only exercised against an RSA-keyed
//! rustls server in `interop.rs` and the server here signs with ECDSA or
//! Ed25519; the native provider also signs with RSA keys.
//!
//! This target runs the cases in `cases/tls12.rs` with the native provider;
//! `tls12.rs` runs them with the RustCrypto provider.

#![cfg(all(feature = "native", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/tls12.rs");

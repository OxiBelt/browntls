//! The connection API around the handshake: `Acceptor`, `Stream` over a real
//! socket, key logging, record sizing, secret extraction, OCSP stapling,
//! half-RTT data and certificate compression.
//!
//! This target runs the cases in `cases/api.rs` with the RustCrypto provider;
//! `api_native.rs` runs them with the native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/api.rs");

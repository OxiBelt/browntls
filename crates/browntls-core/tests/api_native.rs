//! The connection API around the handshake: `Acceptor`, `Stream` over a real
//! socket, key logging, record sizing, secret extraction, OCSP stapling,
//! half-RTT data and certificate compression.
//!
//! This target runs the cases in `cases/api.rs` with the native provider;
//! `api.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/api.rs");

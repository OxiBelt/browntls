//! In-memory TLS 1.3 handshakes between a browntls client and server.
//!
//! This target runs the cases in `cases/tls13.rs` with the RustCrypto provider;
//! `tls13_native.rs` runs them with the native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/tls13.rs");

//! In-memory TLS 1.3 handshakes between a browntls client and server.
//!
//! This target runs the cases in `cases/tls13.rs` with the native provider;
//! `tls13.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/tls13.rs");

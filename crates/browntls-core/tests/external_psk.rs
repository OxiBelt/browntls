//! TLS 1.3 external PSKs, the PSK importer and certificate authentication
//! with an external PSK, between a browntls client and server.
//!
//! This target runs the cases in `cases/external_psk.rs` with the RustCrypto
//! provider; `external_psk_native.rs` runs them with the native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/external_psk.rs");

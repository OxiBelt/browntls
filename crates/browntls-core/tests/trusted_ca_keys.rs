//! The `trusted_ca_keys` extension (RFC 6066 §6): its identifiers, its
//! negotiation in TLS 1.2, and the resolver that follows it.
//!
//! This target runs the cases in `cases/trusted_ca_keys.rs` with the RustCrypto
//! provider; `trusted_ca_keys_native.rs` runs them with the native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/trusted_ca_keys.rs");

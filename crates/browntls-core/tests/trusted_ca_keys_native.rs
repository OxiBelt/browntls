//! The `trusted_ca_keys` extension (RFC 6066 §6): its identifiers, its
//! negotiation in TLS 1.2, and the resolver that follows it.
//!
//! This target runs the cases in `cases/trusted_ca_keys.rs` with the native
//! provider; `trusted_ca_keys.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/trusted_ca_keys.rs");

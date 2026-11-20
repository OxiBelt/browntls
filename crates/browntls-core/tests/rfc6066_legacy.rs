//! The RFC 6066 extensions only TLS 1.2 defines (`client_certificate_url`,
//! `trusted_ca_keys`, `truncated_hmac`), seen by a peer that negotiates none
//! of them.
//!
//! This target runs the cases in `cases/rfc6066_legacy.rs` with the RustCrypto
//! provider; `rfc6066_legacy_native.rs` runs them with the native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/rfc6066_legacy.rs");

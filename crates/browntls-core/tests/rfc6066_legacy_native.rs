//! The RFC 6066 extensions only TLS 1.2 defines (`client_certificate_url`,
//! `trusted_ca_keys`, `truncated_hmac`), seen by a peer that negotiates none
//! of them.
//!
//! This target runs the cases in `cases/rfc6066_legacy.rs` with the native
//! provider; `rfc6066_legacy.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/rfc6066_legacy.rs");

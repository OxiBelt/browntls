//! What a configuration that enables TLS 1.3 only offers, negotiates and
//! refuses, next to the configurations that keep TLS 1.2 (RFC 9852 §4).
//!
//! This target runs the cases in `cases/tls13_only_policy.rs` with the
//! native provider; `tls13_only_policy.rs` runs them with the RustCrypto
//! provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/tls13_only_policy.rs");

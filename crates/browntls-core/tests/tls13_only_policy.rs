//! What a configuration that enables TLS 1.3 only offers, negotiates and
//! refuses, next to the configurations that keep TLS 1.2 (RFC 9852 §4).
//!
//! This target runs the cases in `cases/tls13_only_policy.rs` with the
//! RustCrypto provider; `tls13_only_policy_native.rs` runs them with the
//! native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/tls13_only_policy.rs");

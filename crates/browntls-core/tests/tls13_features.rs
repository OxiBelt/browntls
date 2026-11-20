//! RFC 9846 features beyond the basic TLS 1.3 handshake: post-handshake
//! client authentication, stateless HelloRetryRequest cookies, the early
//! exporter, and the RFC 9266 `tls-exporter` channel binding.
//!
//! This target runs the cases in `cases/tls13_features.rs` with the
//! RustCrypto provider; `tls13_features_native.rs` runs them with the native
//! provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/tls13_features.rs");

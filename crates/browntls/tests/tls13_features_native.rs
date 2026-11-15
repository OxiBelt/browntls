//! RFC 9846 features beyond the basic TLS 1.3 handshake: post-handshake
//! client authentication, stateless HelloRetryRequest cookies, the early
//! exporter, and the RFC 9266 `tls-exporter` channel binding.
//!
//! This target runs the cases in `cases/tls13_features.rs` with the native
//! provider; `tls13_features.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/tls13_features.rs");

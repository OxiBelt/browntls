//! RFC 7924 `cached_info` in TLS 1.2 handshakes, both sides.
//!
//! This target runs the cases in `cases/cached_info.rs` with the RustCrypto
//! provider; `cached_info_native.rs` runs them with the native provider.

#![cfg(all(feature = "rustcrypto", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/cached_info.rs");

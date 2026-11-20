//! RFC 7924 `cached_info` in TLS 1.2 handshakes, both sides.
//!
//! This target runs the cases in `cases/cached_info.rs` with the native
//! provider; `cached_info.rs` runs them with the RustCrypto provider.

#![cfg(all(feature = "native", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/cached_info.rs");

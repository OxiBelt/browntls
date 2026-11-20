//! The built-in certificate compressors (RFC 8879) in handshakes: both
//! directions, algorithm selection, the declared-length and size-limit
//! rejections, and handshakes between the two providers.
//!
//! This target runs the cases in `cases/cert_compression.rs` with the
//! native provider; `cert_compression.rs` runs them with the RustCrypto
//! provider.

#![cfg(all(
    feature = "native",
    any(feature = "zlib", feature = "brotli", feature = "zstd")
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/cert_compression.rs");

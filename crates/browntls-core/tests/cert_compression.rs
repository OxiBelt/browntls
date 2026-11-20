//! The built-in certificate compressors (RFC 8879) in handshakes: both
//! directions, algorithm selection, the declared-length and size-limit
//! rejections, and handshakes between the two providers.
//!
//! This target runs the cases in `cases/cert_compression.rs` with the
//! RustCrypto provider; `cert_compression_native.rs` runs them with the native
//! provider.

#![cfg(all(
    feature = "rustcrypto",
    any(feature = "zlib", feature = "brotli", feature = "zstd")
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/cert_compression.rs");

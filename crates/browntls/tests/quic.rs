//! QUIC-TLS (RFC 9001): Appendix A vectors, in-memory handshakes and rustls
//! interoperability.
//!
//! This target runs the cases in `cases/quic.rs` with the RustCrypto provider;
//! `quic_native.rs` runs them with the native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/quic.rs");

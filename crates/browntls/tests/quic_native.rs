//! QUIC-TLS (RFC 9001): Appendix A vectors, in-memory handshakes and rustls
//! interoperability.
//!
//! This target runs the cases in `cases/quic.rs` with the native provider;
//! `quic.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/quic.rs");

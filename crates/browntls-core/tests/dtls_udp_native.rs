//! The blocking DTLS 1.3 API over loopback UDP sockets.
//!
//! This target runs the cases in `cases/dtls_udp.rs` with the native
//! provider; `dtls_udp.rs` runs them with the RustCrypto provider.

#![cfg(all(feature = "native", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/dtls_udp.rs");

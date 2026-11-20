//! The blocking DTLS 1.3 API over loopback UDP sockets.
//!
//! This target runs the cases in `cases/dtls_udp.rs` with the RustCrypto
//! provider; `dtls_udp_native.rs` runs them with the native provider.

#![cfg(all(feature = "rustcrypto", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/dtls_udp.rs");

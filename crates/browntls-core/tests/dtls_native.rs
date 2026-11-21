//! DTLS 1.3 (RFC 9147) between browntls endpoints over a simulated
//! datagram network.
//!
//! This target runs the cases in `cases/dtls.rs` with the native provider;
//! `dtls.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/dtls.rs");

include!("cases/dtls_attacks.rs");

include!("cases/dtls_cid.rs");

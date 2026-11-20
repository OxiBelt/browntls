//! RFC 7250 raw public keys, in both directions and both protocol versions.
//!
//! This target runs the cases in `cases/rpk.rs` with the native provider;
//! `rpk.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/rpk.rs");

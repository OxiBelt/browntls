//! RFC 7250 raw public keys, in both directions and both protocol versions.
//!
//! This target runs the cases in `cases/rpk.rs` with the RustCrypto provider;
//! `rpk_native.rs` runs them with the native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/rpk.rs");

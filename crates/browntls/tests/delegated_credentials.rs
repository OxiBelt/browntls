//! TLS 1.3 delegated credentials (RFC 9345) between a browntls client and
//! server.
//!
//! This target runs the cases in `cases/delegated_credentials.rs` with the
//! RustCrypto provider; `delegated_credentials_native.rs` runs them with the
//! native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/delegated_credentials.rs");

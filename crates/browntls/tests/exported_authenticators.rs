//! Exported authenticators (RFC 9261) between a browntls client and server.
//!
//! This target runs the cases in `cases/exported_authenticators.rs` with the
//! RustCrypto provider; `exported_authenticators_native.rs` runs them with the other provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/exported_authenticators.rs");

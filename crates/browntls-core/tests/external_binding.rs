//! External session and identity binding (RFC 8844): `external_id_hash` and
//! `external_session_id` between a browntls client and server.
//!
//! This target runs the cases in `cases/external_binding.rs` with the
//! RustCrypto provider; `external_binding_native.rs` runs them with the
//! native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/external_binding.rs");

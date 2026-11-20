//! External session and identity binding (RFC 8844): `external_id_hash` and
//! `external_session_id` between a browntls client and server.
//!
//! This target runs the cases in `cases/external_binding.rs` with the
//! native provider; `external_binding.rs` runs them with the RustCrypto
//! provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/external_binding.rs");

//! Exported authenticators (RFC 9261) between a browntls client and server.
//!
//! This target runs the cases in `cases/exported_authenticators.rs` with the
//! native provider; `exported_authenticators.rs` runs them with the other
//! provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/exported_authenticators.rs");

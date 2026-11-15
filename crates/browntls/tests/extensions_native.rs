//! Optional extensions between a browntls client and server:
//! `record_size_limit` (RFC 8449), `ticket_request` (RFC 9149), GREASE
//! (RFC 8701) and `padding` (RFC 7685).
//!
//! This target runs the cases in `cases/extensions.rs` with the native
//! provider; `extensions.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/extensions.rs");

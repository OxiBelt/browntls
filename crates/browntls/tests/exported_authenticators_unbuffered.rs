//! Exported authenticators (RFC 9261) on unbuffered connections, against
//! buffered and unbuffered peers, over TLS 1.3 and TLS 1.2.
//!
//! This target runs the cases in `cases/exported_authenticators_unbuffered.rs`
//! with the RustCrypto provider; `exported_authenticators_unbuffered_native.rs`
//! runs them with the native provider.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/exported_authenticators_unbuffered.rs");

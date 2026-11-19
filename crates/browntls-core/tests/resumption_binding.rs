//! Client session resumption bound to the configuration that established it.
//!
//! This target runs the cases in `cases/resumption_binding.rs` with the
//! RustCrypto provider; `resumption_binding_native.rs` runs them with the
//! native provider.

#![cfg(all(feature = "rustcrypto", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/resumption_binding.rs");

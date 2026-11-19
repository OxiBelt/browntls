//! Client session resumption bound to the configuration that established it.
//!
//! This target runs the cases in `cases/resumption_binding.rs` with the
//! native provider; `resumption_binding.rs` runs them with the RustCrypto
//! provider.

#![cfg(all(feature = "native", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/resumption_binding.rs");

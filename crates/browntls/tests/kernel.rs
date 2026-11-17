//! Kernel TLS offload support: secret extraction in the form Linux takes.
//!
//! This target runs the cases in `cases/kernel.rs` with the RustCrypto
//! provider; `kernel_native.rs` runs them with the native provider.

#![cfg(all(feature = "rustcrypto", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/kernel.rs");

//! Kernel TLS offload support: secret extraction in the form Linux takes.
//!
//! This target runs the cases in `cases/kernel.rs` with the native
//! provider; `kernel.rs` runs them with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/kernel.rs");

//! PKI types and X.509 certificate path validation for browntls.
//!
//! Implementation pending; see `docs/Architecture.md`.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
#[allow(unused_extern_crates)]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

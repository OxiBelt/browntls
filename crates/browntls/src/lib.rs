//! browntls: a TLS 1.2 and TLS 1.3 library with a pluggable cryptography provider.
//!
//! Implementation pending; see `docs/Architecture.md`.
#![no_std]
#![forbid(unsafe_code)]

#[allow(unused_extern_crates)]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

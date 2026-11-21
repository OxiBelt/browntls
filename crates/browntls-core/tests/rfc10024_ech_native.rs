//! ECH acceptance with RFC 10024 key exchange using the native HPKE suite.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/rfc10024_ech_native.rs");

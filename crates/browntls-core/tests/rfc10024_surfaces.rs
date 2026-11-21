//! RFC 10024 TLS 1.3 key exchange coverage through the public connection
//! surfaces. Shared cases are run with both supported crypto providers.

#![cfg(all(feature = "rustcrypto", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/rfc10024_surfaces.rs");

//! Native-provider half of the RFC 10024 public-surface tests.

#![cfg(all(feature = "native", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/rfc10024_surfaces.rs");

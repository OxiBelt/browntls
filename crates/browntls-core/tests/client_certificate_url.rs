//! Client certificate URLs (RFC 6066 §5, `client_certificate_url` and the
//! CertificateURL message), TLS 1.2 only.
//!
//! This target runs the cases in `cases/client_certificate_url.rs` with the
//! RustCrypto provider; `client_certificate_url_native.rs` runs them with the
//! native provider.

#![cfg(all(feature = "rustcrypto", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

include!("cases/client_certificate_url.rs");

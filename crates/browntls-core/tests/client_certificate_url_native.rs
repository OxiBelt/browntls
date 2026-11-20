//! Client certificate URLs (RFC 6066 §5, `client_certificate_url` and the
//! CertificateURL message), TLS 1.2 only.
//!
//! This target runs the cases in `cases/client_certificate_url.rs` with the
//! native provider; `client_certificate_url.rs` runs them with the RustCrypto
//! provider.

#![cfg(all(feature = "native", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/client_certificate_url.rs");

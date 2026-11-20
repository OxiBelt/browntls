//! Certificate Transparency 2.0 in TLS (RFC 9162 §6.5): the
//! `transparency_info` extension in the ClientHello, the TLS 1.2
//! ServerHello and the TLS 1.3 end-entity CertificateEntry; the client's
//! policy over SCTs from the certificate, a stapled OCSP response and the
//! extension; resumption; malformed and unsolicited extensions; and the
//! unbuffered API.
//!
//! This target runs the cases in `cases/transparency.rs` with the RustCrypto
//! provider; `transparency_native.rs` runs them with the native provider.

#![cfg(all(feature = "rustcrypto", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

#[path = "common/ct_v2.rs"]
mod ct_v2;

fn digests() -> browntls_core::revocation::RevocationDigests {
    browntls_core::revocation::RevocationDigests::rustcrypto()
}

include!("cases/transparency.rs");

//! The legacy RSASSA-PKCS1-v1_5 signature schemes of RFC 9963
//! (`rsa_pkcs1_sha256_legacy`, `rsa_pkcs1_sha384_legacy`,
//! `rsa_pkcs1_sha512_legacy`; 0x0420, 0x0520, 0x0620) are defined for the
//! client's TLS 1.3 CertificateVerify and for nothing else (RFC 9963 §3),
//! whatever a certificate verifier advertises: never in the
//! `signature_algorithms` of any ClientHello, never offered to a server's
//! key, never signed with by a server, never in a TLS 1.2
//! CertificateRequest, never given to a TLS 1.2 client's certificate
//! resolver or key, never accepted in a TLS 1.2 ServerKeyExchange or
//! CertificateVerify, and never used by exported authenticators (RFC 9261)
//! or delegated credentials (RFC 9345). A client key that names one the
//! request did not list is treated as a key that cannot sign.
//!
//! What a TLS 1.3 CertificateRequest lists, and what a TLS 1.3 client
//! gives its resolver, is left out here: that is where the schemes belong,
//! and a later change lets them in.
//!
//! The verifiers are test doubles that add the legacy schemes to
//! `supported_verify_schemes`, and the keys that claim them are doubles
//! whose signers panic if used. So these cases depend only on the protocol
//! rules, not on a provider's support for the legacy schemes.

#![cfg(all(feature = "native", feature = "tls12", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

// Shared with `mldsa_tls13_only_rules`, whose ML-DSA items go unused here.
#[allow(dead_code)]
#[path = "mldsa_tls13_only_rules/doubles.rs"]
mod doubles;
#[path = "rsa_pkcs1_legacy_rules/hello.rs"]
mod hello;
#[path = "rsa_pkcs1_legacy_rules/legacy.rs"]
mod legacy;
#[path = "rsa_pkcs1_legacy_rules/side_mechanisms.rs"]
mod side_mechanisms;
#[path = "rsa_pkcs1_legacy_rules/tls12_client.rs"]
mod tls12_client;
#[path = "rsa_pkcs1_legacy_rules/tls12_server.rs"]
mod tls12_server;
#[path = "rsa_pkcs1_legacy_rules/tls12_wire.rs"]
mod tls12_wire;
#[path = "rsa_pkcs1_legacy_rules/tls13_server.rs"]
mod tls13_server;

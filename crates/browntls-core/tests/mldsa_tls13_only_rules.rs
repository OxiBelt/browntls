//! The ML-DSA signature schemes (`draft-ietf-tls-mldsa-06`: `mldsa44`,
//! `mldsa65`, `mldsa87`) are for the TLS 1.3 handshake only, whatever a
//! certificate verifier advertises: never in a TLS 1.2 CertificateRequest,
//! never given to a TLS 1.2 client's certificate resolver or key, never in
//! the `signature_algorithms` of a ClientHello that does not offer TLS 1.3,
//! never seen by the certificate resolver of a server that negotiated
//! TLS 1.2, never used by exported authenticators (RFC 9261) or delegated
//! credentials (RFC 9345), and never signed with in TLS 1.2, even by a key
//! that chooses one anyway or under a suite that lists one.
//!
//! No provider table here maps the ML-DSA schemes: the verifiers are test
//! doubles that add them to `supported_verify_schemes`, and the keys that
//! claim them are doubles that are never asked to sign. So these cases
//! depend only on the protocol rules, not on a provider's ML-DSA support.

#![cfg(all(feature = "native", feature = "tls12", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

#[path = "mldsa_tls13_only_rules/doubles.rs"]
mod doubles;
#[path = "mldsa_tls13_only_rules/side_mechanisms.rs"]
mod side_mechanisms;
#[path = "mldsa_tls13_only_rules/tls12.rs"]
mod tls12;
#[path = "mldsa_tls13_only_rules/tls12_signing.rs"]
mod tls12_signing;
#[path = "mldsa_tls13_only_rules/tls12_wire.rs"]
mod tls12_wire;

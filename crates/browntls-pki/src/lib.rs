//! PKI types and X.509 certificate path validation for browntls.
//!
//! This crate is the browntls counterpart of a "PKI types + WebPKI" layer:
//!
//! * [`types`]: DER containers for certificates, public keys, private keys,
//!   CRLs and trust anchors; [`server_name`]: TLS server names; [`time`]:
//!   validation time; [`pem`]: PEM decoding; [`alg_id`]: standard
//!   `AlgorithmIdentifier`s.
//! * [`EndEntityCert`]: certificate parsing, path building to a
//!   [`TrustAnchor`] (RFC 5280 §6), server name matching (RFC 6125) and
//!   handshake signature verification; [`crl`]: certificate revocation lists.
//! * [`SignatureVerificationAlgorithm`]: the seam through which a
//!   cryptography provider verifies signatures. This crate contains no
//!   cryptographic primitives.
//!
//! All input is treated as untrusted: parsing is strict DER with eager
//! validation, work is bounded by explicit budgets, and nothing here panics
//! on malformed input.
//!
//! The crate forbids `unsafe` code and requires `alloc`.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

pub mod alg_id;
mod asn1_time;
mod cert;
pub mod crl;
mod crl_der;
mod der;
mod error;
mod extensions;
mod name;
mod path;
pub mod pem;
mod revocation;
mod rsassa_pss;
pub mod server_name;
mod signed_data;
pub mod time;
pub mod types;
mod verify;

pub use alg_id::AlgorithmIdentifier;
pub use crl::{
    BorrowedCertRevocationList, BorrowedRevokedCert, CertRevocationList, CrlsRequired,
    ExpirationPolicy, OwnedCertRevocationList, OwnedRevokedCert, RevocationCheckDepth,
    RevocationOptions, RevocationOptionsBuilder, RevocationReason, RevokedCerts,
    UnknownStatusPolicy,
};
pub use error::Error;
pub use server_name::{DnsName, InvalidDnsNameError, IpAddr, ServerName};
pub use time::UnixTime;
pub use types::{
    CertificateDer, CertificateRevocationListDer, CertificateSigningRequestDer, Der,
    EchConfigListBytes, InvalidSignature, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
    PrivateSec1KeyDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, TrustAnchor,
};
pub use verify::{
    EndEntityCert, KeyUsage, PathVerifier, RawPublicKeyEntity, VerifiedPath,
    anchor_from_trusted_cert,
};

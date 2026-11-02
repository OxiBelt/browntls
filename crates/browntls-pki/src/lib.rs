//! PKI types and X.509 certificate path validation for browntls.
//!
//! This crate is the browntls counterpart of a "PKI types + WebPKI" layer:
//!
//! * [`types`]: DER containers for certificates, public keys, private keys,
//!   CRLs and trust anchors; [`server_name`]: TLS server names; [`time`]:
//!   validation time; [`pem`]: PEM decoding; [`alg_id`]: standard
//!   `AlgorithmIdentifier`s.
//! * [`SignatureVerificationAlgorithm`]: the seam through which a
//!   cryptography provider verifies signatures. This crate contains no
//!   cryptographic primitives.
//!
//! The crate forbids `unsafe` code and requires `alloc`.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

pub mod alg_id;
pub mod crl;
mod error;
pub mod pem;
pub mod server_name;
pub mod time;
pub mod types;
mod verify;

pub use alg_id::AlgorithmIdentifier;
pub use crl::{
    BorrowedCertRevocationList, CertRevocationList, ExpirationPolicy, OwnedCertRevocationList,
    RevocationCheckDepth, RevocationOptions, RevocationOptionsBuilder, UnknownStatusPolicy,
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

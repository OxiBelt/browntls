//! browntls: a TLS 1.2 and TLS 1.3 library with a pluggable cryptography provider.
//!
//! The crate is `#![no_std]` with `alloc`; the `std` feature (default) adds the
//! buffered I/O helpers, `KeyLogFile`, the in-memory session caches and the
//! process-wide default [`crypto::CryptoProvider`].
//!
//! # Layout
//!
//! * [`crypto`]: the provider mount point (cipher suites, key exchange, signing,
//!   randomness) and the providers shipped with the crate.
//! * [`Error`] and its sub-enums describe every failure the library reports.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

/// Logging macros: forwarded to the `log` crate, or no-ops.
#[cfg(feature = "logging")]
mod log {
    pub(crate) use ::log::{debug, trace, warn};
}

#[cfg(not(feature = "logging"))]
mod log {
    macro_rules! trace ( ($($tt:tt)*) => {{}} );
    macro_rules! debug ( ($($tt:tt)*) => {{}} );
    macro_rules! warn ( ($($tt:tt)*) => {{}} );
    pub(crate) use {debug, trace, warn};
}

pub(crate) mod sync {
    pub(crate) use alloc::sync::Arc;
}

#[macro_use]
mod msgs;
mod common_state;
pub mod crypto;
mod enums;
mod error;
mod hash_hs;
mod key_log;
mod rand;
mod record_layer;
mod suites;
#[cfg(feature = "tls12")]
mod tls12;
mod tls13;
mod vecbuf;
mod verify;
mod versions;
mod webpki;
mod x509;

pub use crate::common_state::{CommonState, HandshakeKind, IoState, Side};
pub use crate::enums::{
    AlertDescription, CertificateCompressionAlgorithm, CertificateType, CipherSuite, ContentType,
    HandshakeType, ProtocolVersion, SignatureAlgorithm, SignatureScheme,
};
pub use crate::error::{
    CertRevocationListError, CertificateError, Error, InconsistentKeys, InvalidMessage,
    OtherError, PeerIncompatible, PeerMisbehaved,
};
pub use crate::key_log::{KeyLog, NoKeyLog};
pub use crate::msgs::enums::NamedGroup;
pub use crate::msgs::handshake::DistinguishedName;
pub use crate::suites::{
    CipherSuiteCommon, ConnectionTrafficSecrets, ExtractedSecrets, SupportedCipherSuite,
};
#[cfg(feature = "tls12")]
pub use crate::tls12::Tls12CipherSuite;
pub use crate::tls13::Tls13CipherSuite;
pub use crate::verify::DigitallySignedStruct;
pub use crate::versions::{ALL_VERSIONS, DEFAULT_VERSIONS, SupportedProtocolVersion};
pub use crate::webpki::RootCertStore;

/// All defined protocol versions appear in this module.
pub mod version {
    #[cfg(feature = "tls12")]
    pub use crate::versions::TLS12;
    pub use crate::versions::TLS13;
}

/// Re-exports the PKI types this crate's public API is expressed in.
pub mod pki_types {
    #[doc(no_inline)]
    pub use browntls_pki::*;
}

/// Message signing interfaces.
pub mod sign {
    pub use crate::crypto::signer::{CertifiedKey, Signer, SigningKey, public_key_to_spki};
}

/// APIs for implementing a time source.
pub mod time_provider;

/// Low-level access to the message codec, for fuzzing and interop tooling.
#[doc(hidden)]
pub mod internal {
    pub mod msgs {
        pub mod codec {
            pub use crate::msgs::codec::{Codec, Reader};
        }
        pub mod handshake {
            pub use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload};
        }
        pub mod message {
            pub use crate::msgs::message::OutboundOpaqueMessage;
        }
        pub mod deframer {
            pub use crate::msgs::deframer::fuzz_deframer;
        }
    }
}

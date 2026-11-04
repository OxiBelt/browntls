//! browntls: a TLS 1.2 and TLS 1.3 library with a pluggable cryptography provider.
//!
//! The crate is `#![no_std]` with `alloc`; the `std` feature (default) adds the
//! buffered I/O helpers ([`Stream`], [`StreamOwned`], `read_tls`/`write_tls`),
//! [`KeyLogFile`], the in-memory session caches and the process-wide default
//! [`crypto::CryptoProvider`].
//!
//! # Layout
//!
//! * [`crypto`]: the provider mount point (cipher suites, key exchange, signing,
//!   randomness) and the providers shipped with the crate.
//! * [`client`] / [`server`]: configuration ([`ClientConfig`], [`ServerConfig`])
//!   and connections ([`ClientConnection`], [`ServerConnection`]).
//! * [`ConnectionCommon`]: the buffered connection API shared by both sides.
//! * [`Error`] and its sub-enums describe every failure the library reports.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Without `std` the buffered connections are absent and nothing drives the
// handshake state machines yet (the unbuffered API is not implemented), so
// most of the protocol code is unreachable in that configuration.  Without
// `tls12` the TLS 1.2 message types, which are compiled unconditionally to
// keep the wire-format module uniform, have no users.  The all-features build
// is the one that must be free of dead code.
#![cfg_attr(not(all(feature = "std", feature = "tls12")), allow(dead_code))]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

/// Logging macros: forwarded to the `log` crate, or no-ops.
#[cfg(feature = "logging")]
mod log {
    pub(crate) use ::log::{debug, trace};

    // Named `warning` rather than `warn` because a `macro_rules!` item called
    // `warn` collides with the built-in `#[warn]` attribute when imported.
    macro_rules! warning ( ($($tt:tt)*) => { ::log::warn!($($tt)*) } );
    pub(crate) use warning;
}

#[cfg(not(feature = "logging"))]
mod log {
    // The arguments are still type-checked and "used", so a logging-off
    // build raises the same warnings as a logging build.
    macro_rules! trace ( ($($tt:tt)*) => {{ let _ = format_args!($($tt)*); }} );
    macro_rules! debug ( ($($tt:tt)*) => {{ let _ = format_args!($($tt)*); }} );
    macro_rules! warning ( ($($tt:tt)*) => {{ let _ = format_args!($($tt)*); }} );
    pub(crate) use {debug, trace, warning};
}

pub(crate) mod sync {
    pub(crate) use alloc::sync::Arc;
}

#[macro_use]
mod msgs;
#[macro_use]
mod check;
mod builder;
mod common_state;
pub mod compress;
mod conn;
pub mod crypto;
mod ct;
mod enums;
mod error;
mod hash_hs;
mod key_log;
#[cfg(feature = "std")]
mod key_log_file;
#[cfg(feature = "std")]
mod limited_cache;
mod rand;
mod record_layer;
#[cfg(feature = "std")]
mod stream;
mod suites;
#[cfg(feature = "std")]
pub mod ticketer;
#[cfg(feature = "tls12")]
mod tls12;
mod tls13;
mod vecbuf;
mod verify;
mod versions;
mod webpki;
mod x509;

pub use crate::builder::{ConfigBuilder, ConfigSide, WantsVerifier, WantsVersions};
pub use crate::common_state::{CommonState, HandshakeKind, IoState, Side};
#[cfg(feature = "std")]
pub use crate::conn::{Connection, Reader, Writer};
pub use crate::conn::{ConnectionCommon, SideData};
pub use crate::enums::{
    AlertDescription, CertificateCompressionAlgorithm, CertificateType, CipherSuite, ContentType,
    HandshakeType, ProtocolVersion, SignatureAlgorithm, SignatureScheme,
};
pub use crate::error::{
    CertRevocationListError, CertificateError, Error, InconsistentKeys, InvalidMessage, OtherError,
    PeerIncompatible, PeerMisbehaved,
};
pub use crate::key_log::{KeyLog, NoKeyLog};
#[cfg(feature = "std")]
pub use crate::key_log_file::KeyLogFile;
pub use crate::msgs::enums::NamedGroup;
pub use crate::msgs::handshake::DistinguishedName;
#[cfg(feature = "std")]
pub use crate::stream::{Stream, StreamOwned};
pub use crate::suites::{
    CipherSuiteCommon, ConnectionTrafficSecrets, ExtractedSecrets, SupportedCipherSuite,
};
#[cfg(feature = "tls12")]
pub use crate::tls12::Tls12CipherSuite;
pub use crate::tls13::Tls13CipherSuite;
pub use crate::verify::DigitallySignedStruct;
pub use crate::versions::{ALL_VERSIONS, DEFAULT_VERSIONS, SupportedProtocolVersion};
pub use crate::webpki::RootCertStore;

/// Items for use by TLS clients.
pub mod client {
    pub(super) mod builder;
    mod client_conn;
    mod common;
    pub(super) mod handy;
    mod hs;
    #[cfg(feature = "tls12")]
    mod tls12;
    pub(crate) mod tls13;

    pub use builder::WantsClientCert;
    pub use client_conn::{
        ClientConfig, ClientConnectionData, ClientSessionStore, ResolvesClientCert, Resumption,
        Tls12Resumption,
    };
    #[cfg(feature = "std")]
    pub use client_conn::{ClientConnection, WriteEarlyData};
    #[cfg(feature = "std")]
    pub use handy::ClientSessionMemoryCache;
    pub use handy::NoClientSessionStorage;

    /// Dangerous configuration that must be audited and used with extreme care.
    pub mod danger {
        pub use super::builder::danger::DangerousClientConfigBuilder;
        pub use super::client_conn::danger::DangerousClientConfig;
        pub use crate::verify::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    }

    #[cfg(feature = "tls12")]
    pub use crate::msgs::persist::Tls12ClientSessionValue;
    pub use crate::msgs::persist::Tls13ClientSessionValue;
    pub use crate::webpki::{
        ServerCertVerifierBuilder, VerifierBuilderError, WebPkiServerVerifier,
        verify_server_cert_signed_by_trust_anchor, verify_server_name,
    };
}

pub use client::ClientConfig;
#[cfg(feature = "std")]
pub use client::ClientConnection;

/// Items for use by TLS servers.
pub mod server {
    pub(crate) mod builder;
    mod common;
    pub(crate) mod handy;
    mod hs;
    mod server_conn;
    #[cfg(feature = "tls12")]
    mod tls12;
    mod tls13;

    pub use builder::WantsServerCert;
    pub use handy::NoServerSessionStorage;
    #[cfg(feature = "std")]
    pub use handy::{ResolvesServerCertUsingSni, ServerSessionMemoryCache};
    #[cfg(feature = "std")]
    pub use server_conn::{Accepted, AcceptedAlert, Acceptor, ReadEarlyData, ServerConnection};
    pub use server_conn::{
        ClientHello, ProducesTickets, ResolvesServerCert, ServerConfig, ServerConnectionData,
        StoresServerSessions,
    };

    pub use crate::verify::NoClientAuth;
    pub use crate::webpki::{
        ClientCertVerifierBuilder, ParsedCertificate, VerifierBuilderError, WebPkiClientVerifier,
    };

    /// Dangerous configuration that must be audited and used with extreme care.
    pub mod danger {
        pub use crate::verify::{ClientCertVerified, ClientCertVerifier};
    }
}

pub use server::ServerConfig;
#[cfg(feature = "std")]
pub use server::ServerConnection;

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
    pub use crate::crypto::signer::{
        CertifiedKey, Signer, SigningKey, SingleCertAndKey, public_key_to_spki,
    };
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

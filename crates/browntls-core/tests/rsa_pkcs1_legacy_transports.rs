//! The legacy RSASSA-PKCS1-v1_5 schemes of RFC 9963 (0x0420, 0x0520,
//! 0x0620) in TLS 1.3 client authentication on the transports other than
//! the buffered TLS connection, with the native provider's opt-in: the
//! unbuffered connection API, DTLS 1.3 (RFC 9147, with a lost datagram
//! retransmitted) and DTLS 1.2 (which never uses a legacy scheme), QUIC-TLS
//! (RFC 9001), and a connection handed to kernel TLS
//! (`browntls_core::kernel`, through a userspace stand-in).
//!
//! The client's key is `native::sign::any_rsa_pkcs1_legacy_type`, which
//! signs with RSASSA-PKCS1-v1_5 only. Every handshake checks the scheme of
//! the client's `CertificateVerify` through a recording verifier. The
//! buffered connection is covered by `rsa_pkcs1_legacy_native.rs`. Keys and
//! certificates are generated at run time; nothing secret is committed.

#![cfg(all(feature = "native", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

#[path = "rsa_pkcs1_legacy_transports/identity.rs"]
mod identity;

#[path = "rsa_pkcs1_legacy_transports/dtls.rs"]
mod dtls;
#[cfg(feature = "tls12")]
#[path = "rsa_pkcs1_legacy_transports/kernel.rs"]
mod kernel;
#[path = "rsa_pkcs1_legacy_transports/quic.rs"]
mod quic;
#[cfg(feature = "tls12")]
#[path = "cases/kernel/sim.rs"]
mod sim;
#[path = "rsa_pkcs1_legacy_transports/unbuffered.rs"]
mod unbuffered;

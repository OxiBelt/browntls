//! ML-DSA TLS 1.3 authentication (`draft-ietf-tls-mldsa-06`, the native
//! provider's opt-in) on the transports other than the buffered TLS
//! connection: QUIC-TLS (RFC 9001), DTLS 1.3 (RFC 9147, with fragmentation,
//! loss and retransmission of the large flights) and DTLS 1.2 (which never
//! uses ML-DSA), the unbuffered connection API, and a connection handed to
//! kernel TLS (`browntls_core::kernel`, through a userspace stand-in).
//!
//! Every handshake checks the `CertificateVerify` scheme through a
//! recording verifier. Certificates and keys are derived at run time from
//! fixed labels (`native_mldsa/support.rs`); nothing secret is committed.

#![cfg(all(feature = "native", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

#[path = "../../browntls-pki/tests/common/ml_dsa.rs"]
mod ml_dsa;
#[path = "../../browntls-pki/tests/common/x509_builder.rs"]
mod x509;

#[path = "native_mldsa/support.rs"]
mod support;

#[path = "mldsa_transports/identity.rs"]
mod identity;

#[path = "mldsa_transports/dtls.rs"]
mod dtls;
#[cfg(feature = "tls12")]
#[path = "mldsa_transports/kernel.rs"]
mod kernel;
#[path = "mldsa_transports/quic.rs"]
mod quic;
#[cfg(feature = "tls12")]
#[path = "cases/kernel/sim.rs"]
mod sim;
#[path = "mldsa_transports/unbuffered.rs"]
mod unbuffered;

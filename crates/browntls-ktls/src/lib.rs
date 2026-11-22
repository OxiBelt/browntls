//! Linux kernel TLS offload for browntls connections.
//!
//! The handshake runs in userspace with browntls; afterwards
//! [`KtlsStream::new`] gives the connection's traffic keys to the kernel
//! (`setsockopt(TCP_ULP, "tls")`, `TLS_TX`, `TLS_RX`), which then encrypts
//! and decrypts application data itself, so that `sendfile`, `splice` and
//! plain `read`/`write` on the socket carry TLS ([`KtlsStream::sendfile`]
//! sends a file that way and keeps the stream's counts). Every record that is
//! not application data (TLS 1.3 KeyUpdate and NewSessionTicket messages,
//! post-handshake authentication, alerts) comes back to the stream, which
//! hands it to the connection's [`browntls_core::kernel::KernelConnection`] and
//! carries out what that asks for: records to send, new keys to install.
//!
//! Supported: TLS 1.2 and TLS 1.3 with AES-128-GCM, AES-256-GCM and
//! ChaCha20-Poly1305, TLS 1.3 AES-128-CCM. TLS 1.3 key updates need Linux
//! 6.14; transmitting records smaller than the protocol maximum (a peer's
//! `record_size_limit`, or the configured `max_fragment_size`) needs Linux
//! 6.19 (`TLS_TX_MAX_PAYLOAD_LEN`). Linux kernel TLS cannot enforce a
//! negotiated receive `record_size_limit` below the protocol maximum, so
//! those connections remain in userspace. The `tls` kernel module must be
//! available (`modprobe tls`).
//!
//! Applications normally reach this crate through the `browntls` crate,
//! whose `ktls` feature re-exports it as the module `browntls::ktls`
//! (`browntls::ktls::KtlsStream` is [`KtlsStream`]):
//!
//! ```toml
//! [dependencies]
//! browntls = { git = "https://github.com/OxiBelt/browntls", features = ["ktls"] }
//! ```
//!
//! The example here names the items through this crate and `browntls_core`.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let config: std::sync::Arc<browntls_core::ClientConfig> = unimplemented!();
//! use std::io::{Read, Write};
//!
//! // `config` has `enable_secret_extraction` set.
//! let tcp = std::net::TcpStream::connect("example.com:443")?;
//! let conn = browntls_core::ClientConnection::new(config, "example.com".try_into()?)?;
//! // Completes the handshake, then hands the connection to the kernel.
//! let mut tls = browntls_ktls::KtlsStream::new(conn, tcp).map_err(|e| e.into_io_error())?;
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")?;
//! let mut response = Vec::new();
//! tls.read_to_end(&mut response)?;
//! # Ok(())
//! # }
//! ```
//!
//! Without the `tls` module, or with a cipher suite that has no kernel
//! form, [`KtlsStream::new`] returns the connection and the socket
//! unharmed ([`HandoffError::Refused`]), so the caller can go on in
//! userspace. A running kernel that lacks the suite's cipher (built
//! without it, or restricted to approved algorithms) says so only once it
//! is given keys, after the secrets were taken out of the connection: that
//! is [`HandoffError::Failed`], and the connection is lost. The
//! [load-aware routing](routing) asks the kernel about each cipher on a
//! loopback socket first; a direct caller can do the same.
//!
//! # Load-aware routing
//!
//! With the `native` feature, the `routing` module makes kernel TLS the
//! first place for a connection's records under the native provider's
//! load-aware routing: `routing::RoutedStream::new` hands a connection to
//! the kernel or leaves it in userspace, as the routing places it.
//!
//! # Tokio
//!
//! With the `tokio` feature, `AsyncKtlsStream` is the same offload on a
//! `tokio::net::TcpStream`, with `AsyncRead` and `AsyncWrite`. Its
//! `from_client` and `from_server` take a `browntls-tokio` stream, ready it
//! (`into_kernel_handoff`: handshake and 0-RTT phase completed, queued
//! records written, input read up to a record boundary) and hand it to the
//! kernel; a refusal returns the stream with the application data already
//! taken from it.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod crypto_info;
pub use crypto_info::{CryptoInfo, UnsupportedCipher};

pub mod ech;

#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod ledger;
#[cfg(target_os = "linux")]
mod meter;
#[cfg(target_os = "linux")]
mod outputs;
#[cfg(target_os = "linux")]
mod quiet_close;
#[cfg(all(
    test,
    target_os = "linux",
    any(feature = "native", feature = "rustcrypto")
))]
mod sigpipe_tests;
#[cfg(target_os = "linux")]
mod stream;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "linux")]
pub use stream::{HandoffError, KtlsStream, Offload};

#[cfg(all(target_os = "linux", feature = "native"))]
#[cfg_attr(docsrs, doc(cfg(feature = "native")))]
pub mod routing;

#[cfg(all(target_os = "linux", feature = "tokio"))]
mod drain;
#[cfg(all(target_os = "linux", feature = "tokio"))]
mod tokio_stream;
#[cfg(all(target_os = "linux", feature = "tokio"))]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub use tokio_stream::{AsyncKtlsStream, StreamHandoffError};

#[cfg(all(test, target_os = "linux"))]
mod backpressure_tests;
// The integration tests' helpers, loaded once for the tests in the crate.
#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/common/mod.rs"]
mod common;

//! browntls: a TLS 1.2 and TLS 1.3 library with a pluggable cryptography
//! provider, optional asynchronous streams for Tokio and optional Linux
//! kernel TLS offload.
//!
//! This is the crate an application depends on. It has no code of its own:
//! its root is `browntls-core` (the protocol, the provider mount point and
//! the built-in providers), and two features add the project's other library
//! crates as modules.
//!
//! | Feature | Module | Crate | What it adds |
//! |---|---|---|---|
//! | (always) | the crate root | `browntls-core` | [`ClientConfig`], [`ServerConfig`], connections, [`crypto`], [`unbuffered`], [`kernel`] |
//! | `tokio` | `browntls::tokio` | `browntls-tokio` | `TlsConnector`, `TlsAcceptor` and their streams over Tokio's I/O traits |
//! | `ktls` | `browntls::ktls` | `browntls-ktls` | `KtlsStream`: Linux kernel TLS offload; with `tokio` also `AsyncKtlsStream` |
//!
//! ```toml
//! [dependencies]
//! browntls = { git = "https://github.com/OxiBelt/browntls", features = ["tokio", "ktls"] }
//! # The runtime stays the application's own dependency.
//! tokio = { version = "1.53", features = ["rt-multi-thread", "macros", "net", "io-util"] }
//! ```
//!
//! The items are the same ones the crates behind them define, not copies:
//! `browntls::ClientConfig` is `browntls_core::ClientConfig`, and
//! `browntls::tokio::TlsConnector` is `browntls_tokio::TlsConnector`. A
//! library that names one path works with an application that names the
//! other.
//!
//! # Layout of the root
//!
//! * [`crypto`]: the provider mount point (cipher suites, key exchange,
//!   signing, randomness) and the providers shipped with the library.
//! * [`client`] / [`server`]: configuration ([`ClientConfig`],
//!   [`ServerConfig`]) and connections (`ClientConnection`,
//!   `ServerConnection`).
//! * [`ConnectionCommon`]: the buffered connection API shared by both sides.
//! * [`unbuffered`]: the caller-buffer-driven API, also available without
//!   `std`.
//! * [`kernel`]: what a kernel TLS implementation needs from a connection
//!   (the `ktls` feature's module drives Linux with it).
//! * [`Error`] and its sub-enums describe every failure the library reports.
//!
//! Without the `std` feature the crate is `#![no_std]` with `alloc`, as
//! `browntls-core` is.
//!
//! # A client on a blocking socket
//!
#![cfg_attr(all(feature = "std", feature = "native"), doc = "```no_run")]
#![cfg_attr(not(all(feature = "std", feature = "native")), doc = "```ignore")]
//! use std::io::{Read, Write};
//! use std::sync::Arc;
//!
//! use browntls::pki_types::ServerName;
//! use browntls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
//!
//! # fn run(roots: RootCertStore) -> Result<(), Box<dyn std::error::Error>> {
//! let config = ClientConfig::builder()
//!     .with_root_certificates(roots)
//!     .with_no_client_auth();
//! let name = ServerName::try_from("example.com")?;
//! let conn = ClientConnection::new(Arc::new(config), name)?;
//! let tcp = std::net::TcpStream::connect("example.com:443")?;
//! let mut tls = StreamOwned::new(conn, tcp);
//!
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
//! let mut response = Vec::new();
//! tls.read_to_end(&mut response)?;
//! # Ok(())
//! # }
//! ```
//!
//! # A TLS 1.3-only policy
//!
//! RFC 9852 requires a new protocol that uses TLS to make TLS 1.3 its
//! default. The default version list ([`DEFAULT_VERSIONS`]) prefers TLS 1.3
//! and also enables TLS 1.2 where the `tls12` feature is built, for the
//! deployed protocols that still meet peers without TLS 1.3. An application
//! of a new protocol lists the version itself, and can check what a
//! connection negotiated:
//!
#![cfg_attr(all(feature = "std", feature = "native"), doc = "```no_run")]
#![cfg_attr(not(all(feature = "std", feature = "native")), doc = "```ignore")]
//! use browntls::pki_types::{CertificateDer, PrivateKeyDer};
//! use browntls::{
//!     ClientConfig, ClientConnection, ProtocolVersion, RootCertStore, ServerConfig, version,
//! };
//!
//! # fn configure(
//! #     roots: RootCertStore,
//! #     chain: Vec<CertificateDer<'static>>,
//! #     key: PrivateKeyDer<'static>,
//! # ) -> Result<(ClientConfig, ServerConfig), browntls::Error> {
//! let client = ClientConfig::builder_with_protocol_versions(&[&version::TLS13])
//!     .with_root_certificates(roots)
//!     .with_no_client_auth();
//! let server = ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
//!     .with_no_client_auth()
//!     .with_single_cert(chain, key)?;
//! # Ok((client, server))
//! # }
//!
//! # fn check(conn: &ClientConnection) {
//! // After the handshake, on either side:
//! assert_eq!(conn.protocol_version(), Some(ProtocolVersion::TLSv1_3));
//! # }
//! ```
//!
//! [`ClientConfig::builder_tls13_only`], [`ServerConfig::builder_tls13_only`]
//! and [`ConfigBuilder::with_tls13_only`] are the same list under a name,
//! and [`ClientConfig::supports_version`] tells whether a configuration
//! built elsewhere still enables TLS 1.2.
//!
//! A handshake with a peer that has TLS 1.2 alone then fails, and nothing
//! falls back: a browntls server answers with a `protocol_version` alert,
//! and a client reports the alert of the server that refused it. The list is
//! the policy: turning the `tls12` feature off is not one, because another
//! crate of the application can turn it on again (Cargo builds one
//! `browntls-core` with the features of every crate that depends on it).
//!
//! # A client on Tokio (`tokio` feature)
//!
//! The module `browntls::tokio` has the name of the Tokio crate. Name its
//! items by path, as below, or import it under another name
//! (`use browntls::tokio as tls;`). After `use browntls::tokio;` or
//! `use browntls::*;` the name `tokio` means this module in that scope, and
//! `tokio::net::TcpStream` or `#[tokio::main]` no longer compile there.
//!
#![cfg_attr(all(feature = "tokio", feature = "native"), doc = "```no_run")]
#![cfg_attr(not(all(feature = "tokio", feature = "native")), doc = "```ignore")]
//! use std::sync::Arc;
//!
//! use browntls::pki_types::ServerName;
//! use browntls::tokio::TlsConnector;
//! use browntls::{ClientConfig, RootCertStore};
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use tokio::net::TcpStream;
//!
//! # async fn run(roots: RootCertStore) -> std::io::Result<()> {
//! let config = ClientConfig::builder()
//!     .with_root_certificates(roots)
//!     .with_no_client_auth();
//! let connector = TlsConnector::from(Arc::new(config));
//!
//! let tcp = TcpStream::connect("example.com:443").await?;
//! let name = ServerName::try_from("example.com").expect("valid DNS name");
//! let mut tls = connector.connect(name, tcp).await?;
//!
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await?;
//! tls.flush().await?;
//! let mut response = Vec::new();
//! tls.read_to_end(&mut response).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Kernel TLS on Linux (`ktls` feature)
//!
//! The handshake runs in userspace; afterwards the kernel encrypts and
//! decrypts application data. The configuration must set
//! `enable_secret_extraction`. A kernel without the `tls` module, or a
//! cipher suite without a kernel form, returns the connection and the
//! socket unharmed.
//!
#![cfg_attr(
    all(feature = "ktls", feature = "native", target_os = "linux"),
    doc = "```no_run"
)]
#![cfg_attr(
    not(all(feature = "ktls", feature = "native", target_os = "linux")),
    doc = "```ignore"
)]
//! use std::io::{Read, Write};
//! use std::sync::Arc;
//!
//! use browntls::ktls::KtlsStream;
//! use browntls::{ClientConfig, ClientConnection};
//!
//! # fn run(config: Arc<ClientConfig>) -> Result<(), Box<dyn std::error::Error>> {
//! let tcp = std::net::TcpStream::connect("example.com:443")?;
//! let conn = ClientConnection::new(config, "example.com".try_into()?)?;
//! // Completes the handshake, then hands the connection to the kernel.
//! let mut tls = KtlsStream::new(conn, tcp).map_err(|e| e.into_io_error())?;
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
//! let mut response = Vec::new();
//! tls.read_to_end(&mut response)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! Every feature turns on the feature of the same name in the crates behind
//! this one that have it. The default set is `browntls-core`'s (`std`,
//! `native`, `tls12`, `logging`, `prefer-post-quantum`) plus `coop`.
//!
//! | Feature | Default | Effect |
//! |---|---|---|
//! | `std` | yes | Buffered I/O helpers, `KeyLogFile`, in-memory session caches, the process-wide default provider |
//! | `alloc` | with `std` | Present for symmetry with `browntls-core`, which always needs `alloc` |
//! | `native` | yes | The built-in provider backed by `browntls-crypto` (`crypto::native`) |
//! | `rustcrypto` | no | A provider backed by the RustCrypto crates (`crypto::rustcrypto`). Together with `native` there is no implicit process default: install or pass a provider |
//! | `tls12` | yes | TLS 1.2 |
//! | `logging` | yes | Debug logging through the `log` crate |
//! | `key-log` | no | RFC 9850 callbacks and a Linux diagnostic file sink |
//! | `prefer-post-quantum` | yes | X25519MLKEM768 first in the default key exchange groups |
//! | `zlib`, `brotli`, `zstd` | no | Built-in certificate compression (RFC 8879), one feature per algorithm; `brotli` enables `std` |
//! | `tokio` | no | `browntls::tokio`; enables `std` |
//! | `coop` | yes | With `tokio`: take part in Tokio's cooperative scheduling. Without `tokio` it does nothing |
//! | `ocsp` | no | `browntls::tokio::revocation`: fetching certificate status responses; enables `tokio` |
//! | `ktls` | no | `browntls::ktls`; enables `std`. Linux only: on other systems the module holds the kernel-independent types alone |
//!
//! `browntls-core`'s `fuzzing` feature (unstable entry points for the
//! project's fuzz targets) is deliberately not offered here. Cargo builds one
//! `browntls-core` for a whole dependency graph, so its items appear at this
//! crate's root as well if another package enables that feature.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[doc(inline)]
pub use browntls_core::*;

/// Linux kernel TLS offload for browntls connections: the `browntls-ktls`
/// crate.
#[cfg(feature = "ktls")]
#[cfg_attr(docsrs, doc(cfg(feature = "ktls")))]
#[doc(inline)]
pub use browntls_ktls as ktls;
/// Asynchronous TLS streams for Tokio: the `browntls-tokio` crate.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
#[doc(inline)]
pub use browntls_tokio as tokio;

/// Compiles the README's examples as doctests.
#[cfg(all(
    doctest,
    feature = "tokio",
    feature = "ktls",
    feature = "native",
    target_os = "linux"
))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

//! Linux kernel TLS offload for browntls connections.
//!
//! The handshake runs in userspace with browntls; afterwards
//! [`KtlsStream::new`] gives the connection's traffic keys to the kernel
//! (`setsockopt(TCP_ULP, "tls")`, `TLS_TX`, `TLS_RX`), which then encrypts
//! and decrypts application data itself, so that `sendfile`, `splice` and
//! plain `read`/`write` on the socket carry TLS. Every record that is not
//! application data (TLS 1.3 KeyUpdate and NewSessionTicket messages,
//! post-handshake authentication, alerts) comes back to the stream, which
//! hands it to the connection's [`browntls::kernel::KernelConnection`] and
//! carries out what that asks for: records to send, new keys to install.
//!
//! Supported: TLS 1.2 and TLS 1.3 with AES-128-GCM, AES-256-GCM and
//! ChaCha20-Poly1305, TLS 1.3 AES-128-CCM. TLS 1.3 key updates need Linux
//! 6.14; a peer's `record_size_limit` below the protocol maximum needs
//! Linux 6.18 (`TLS_TX_MAX_PAYLOAD_LEN`). The `tls` kernel module must be
//! available (`modprobe tls`).
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let config: std::sync::Arc<browntls::ClientConfig> = unimplemented!();
//! use std::io::{Read, Write};
//!
//! // `config` has `enable_secret_extraction` set.
//! let tcp = std::net::TcpStream::connect("example.com:443")?;
//! let conn = browntls::ClientConnection::new(config, "example.com".try_into()?)?;
//! // Completes the handshake, then hands the connection to the kernel.
//! let mut tls = browntls_ktls::KtlsStream::new(conn, tcp).map_err(|e| e.into_io_error())?;
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")?;
//! let mut response = Vec::new();
//! tls.read_to_end(&mut response)?;
//! # Ok(())
//! # }
//! ```
//!
//! Without the `tls` module, or with a cipher suite the kernel cannot
//! take, [`KtlsStream::new`] returns the connection and the socket
//! unharmed ([`HandoffError::Refused`]), so the caller can go on in
//! userspace.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod crypto_info;
pub use crypto_info::{CryptoInfo, UnsupportedCipher};

#[cfg(target_os = "linux")]
mod stream;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "linux")]
pub use stream::{HandoffError, KtlsStream, Offload};

//! DTLS 1.3 (RFC 9147): TLS 1.3 over datagrams.
//!
//! [`ClientConnection`] and [`ServerConnection`] are the low-level API: they
//! take and produce whole datagrams and leave the transport, and the
//! clock, to the caller. They run the TLS 1.3 handshake with the DTLS
//! record layer: records that carry their own epoch and sequence number,
//! encrypted record numbers, a replay window per epoch, handshake messages
//! that are fragmented, reordered and retransmitted, and acknowledgements.
//!
//! With `std`, [`UdpClient`] and [`UdpServer`] are the high-level API: they
//! drive those connections over a `std::net::UdpSocket`, blocking, with
//! the clock and the retransmissions taken care of. A [`UdpServer`] serves
//! many clients on one socket and keeps no state for a client before it
//! returns the cookie.
//!
//! A server answers a ClientHello without a cookie with a HelloRetryRequest
//! carrying one, bound to the client's address (RFC 9147 §5.1), unless the
//! cookie exchange is turned off. Over DTLS this version supports neither
//! 0-RTT, Encrypted Client Hello, post-handshake client authentication nor
//! connection IDs.
//!
//! Internally: records and their headers are in `wire`, record protection
//! in `keys`, replay windows in `replay`, handshake reassembly in
//! `reassembly`, epochs and incoming records in `state`, and flights,
//! acknowledgements and timers in `flight`.

mod acceptor;
mod connection;
mod flight;
mod keys;
mod reassembly;
mod replay;
mod send;
mod state;
#[cfg(feature = "std")]
mod udp;
mod wire;

pub use acceptor::{Accepted, Acceptor};
pub use connection::{ClientConnection, ConnectionCommon, Received, ServerConnection};
pub(crate) use state::Dtls;
#[cfg(test)]
pub(crate) use state::Settings;
#[cfg(feature = "std")]
pub use udp::{ServerEvent, UdpClient, UdpServer};

/// The `HKDF-Expand-Label` prefix of DTLS 1.3 (RFC 9147 §5.9). It has no
/// trailing space, unlike that of TLS 1.3.
pub(crate) const LABEL_PREFIX: &[u8] = b"dtls13";

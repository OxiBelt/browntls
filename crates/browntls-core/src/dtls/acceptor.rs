//! Accepting DTLS 1.3 clients without keeping state for unverified
//! addresses (RFC 9147 §5.1).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use super::connection::ServerConnection;
use super::wire::{self, HandshakeHeader, Header};
use crate::enums::{ContentType, HandshakeType};
use crate::error::Error;
use crate::sync::Arc;

/// Answers the datagrams of clients a server has no connection for.
///
/// A ClientHello without a cookie gets a HelloRetryRequest carrying one,
/// bound to the client's address, and nothing is kept: a spoofed source
/// address costs the server one small datagram and no memory. Only a
/// ClientHello that comes back with the cookie (`message_seq` 1, RFC 9147
/// §5.2) gets a [`ServerConnection`].
///
/// The cookie of a second ClientHello split over several datagrams can
/// only be checked once the whole message arrived. Until its handshake
/// progresses such a connection is unverified: bound how many of those a
/// server keeps, and drop those that make no progress.
pub struct Acceptor {
    config: Arc<crate::ServerConfig>,
}

/// What [`Acceptor::accept`] made of a datagram.
#[derive(Debug)]
pub enum Accepted {
    /// Nothing that starts a handshake: drop the datagram.
    Ignored,
    /// A first ClientHello, answered by the HelloRetryRequest datagram in
    /// `out`; nothing was kept.
    Retry,
    /// A ClientHello that answers our HelloRetryRequest: its connection,
    /// which has processed the datagram. Keep it for this address.
    Connection(Box<ServerConnection>),
}

impl Acceptor {
    /// An acceptor for servers with `config`, which must set
    /// `hello_retry_cookies`, allow TLS 1.3 and contain a cipher suite
    /// usable with DTLS 1.3.
    pub fn new(config: Arc<crate::ServerConfig>) -> Result<Self, Error> {
        // Validates the configuration once, up front.
        ServerConnection::new(config.clone(), &[])?;
        Ok(Self { config })
    }

    /// Handles `datagram` from `peer_address`, for which the server has no
    /// connection. A HelloRetryRequest to send back is appended to `out`.
    pub fn accept(
        &self,
        datagram: &mut [u8],
        peer_address: &[u8],
        out: &mut Vec<u8>,
        now: Duration,
    ) -> Result<Accepted, Error> {
        let Some(message_seq) = client_hello_seq(datagram) else {
            return Ok(Accepted::Ignored);
        };
        let mut conn = ServerConnection::new(self.config.clone(), peer_address)?;
        if message_seq == 1 {
            conn.continue_after_stateless_retry();
        } else if message_seq != 0 {
            return Ok(Accepted::Ignored);
        }
        // A broken ClientHello fails the connection; its alert is not
        // worth sending to an address nobody verified.
        if conn.read_datagram(datagram, now).is_err() {
            return Ok(Accepted::Ignored);
        }
        if message_seq == 1 {
            return Ok(Accepted::Connection(Box::new(conn)));
        }
        if !conn.answered_with_retry() {
            // Part of a first ClientHello, or a cookie exchange turned off
            // in a configuration it cannot be (`new` requires cookies).
            return Ok(Accepted::Ignored);
        }
        conn.write_datagram(out, now)?;
        Ok(Accepted::Retry)
    }
}

/// The `message_seq` of the ClientHello fragment that starts `datagram`,
/// if it starts with an unprotected handshake record holding one.
fn client_hello_seq(datagram: &[u8]) -> Option<u16> {
    let record = wire::parse_record(datagram, 0)?;
    let Header::Plaintext {
        typ: ContentType::Handshake,
        epoch: 0,
        ..
    } = record.header
    else {
        return None;
    };
    let (header, ..) = HandshakeHeader::read(datagram.get(record.body)?)?;
    (header.typ == u8::from(HandshakeType::ClientHello)).then_some(header.message_seq)
}

impl fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls::Acceptor").finish_non_exhaustive()
    }
}

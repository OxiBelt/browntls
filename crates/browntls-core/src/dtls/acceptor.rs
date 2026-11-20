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
use crate::msgs::codec::Reader;
use crate::msgs::enums::ExtensionType;
use crate::sync::Arc;

/// Answers the datagrams of clients a server has no connection for.
///
/// A ClientHello without a cookie gets a HelloRetryRequest carrying one,
/// bound to the client's address, and nothing is kept: a spoofed source
/// address costs the server one small datagram and no memory. Only a
/// ClientHello that comes back with the cookie (`message_seq` 1, RFC 9147
/// §5.2) gets a [`ServerConnection`].
///
/// The cookie is checked before anything is kept, also for a second
/// ClientHello split over several datagrams: its first fragment, which
/// starts with the cookie, must arrive first. Clients that complete no
/// handshake still cost a connection each: bound how many a server keeps,
/// and drop those that make no progress.
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
        let Some((header, fragment)) = first_client_hello(datagram) else {
            return Ok(Accepted::Ignored);
        };
        let retried = match header.message_seq {
            0 => false,
            // Nothing is kept for a second ClientHello unless it starts
            // with a valid cookie for this address.
            1 => match cookie_of(&header, fragment) {
                Some(cookie)
                    if crate::server::cookie::dtls_cookie_is_valid(
                        &self.config,
                        cookie,
                        peer_address,
                    ) =>
                {
                    true
                }
                _ => return Ok(Accepted::Ignored),
            },
            _ => return Ok(Accepted::Ignored),
        };
        let mut conn = ServerConnection::new(self.config.clone(), peer_address)?;
        if retried {
            conn.continue_after_stateless_retry();
        }
        // A broken ClientHello fails the connection; its alert is not
        // worth sending to an address nobody verified.
        if conn.read_datagram(datagram, now).is_err() {
            return Ok(Accepted::Ignored);
        }
        if retried {
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

/// The ClientHello fragment that starts `datagram`, if it starts with an
/// unprotected handshake record holding one.
fn first_client_hello(datagram: &[u8]) -> Option<(HandshakeHeader, &[u8])> {
    let record = wire::parse_record(datagram, 0)?;
    let Header::Plaintext {
        typ: ContentType::Handshake,
        epoch: 0,
        ..
    } = record.header
    else {
        return None;
    };
    let (header, fragment, _) = HandshakeHeader::read(datagram.get(record.body)?)?;
    (header.typ == u8::from(HandshakeType::ClientHello)).then_some((header, fragment))
}

/// The cookie of a ClientHello from its first fragment: browntls clients,
/// as RFC 9147 §5.1 suggests, send the `cookie` extension first so that it
/// arrives in that fragment. `None` for any other fragment, or when the
/// first extension is not a cookie.
fn cookie_of<'a>(header: &HandshakeHeader, fragment: &'a [u8]) -> Option<&'a [u8]> {
    if header.fragment_offset != 0 {
        return None;
    }
    let mut r = Reader::init(fragment);
    // legacy_version, random
    r.take(2 + 32)?;
    // legacy_session_id, legacy_cookie, cipher_suites,
    // legacy_compression_methods
    for len_bytes in [1, 1, 2, 1] {
        let len = r.take(len_bytes)?;
        let len = len.iter().fold(0usize, |acc, b| acc << 8 | usize::from(*b));
        r.take(len)?;
    }
    // extensions<8..2^16-1>, then the first extension's type and length
    let _extensions_len = r.take(2)?;
    let typ = r.take(2)?;
    if typ != u16::from(ExtensionType::Cookie).to_be_bytes() {
        return None;
    }
    let ext_len = r.take(2)?;
    let ext = r.take(usize::from(u16::from_be_bytes([ext_len[0], ext_len[1]])))?;
    // struct { opaque cookie<1..2^16-1>; } Cookie;
    let (len, cookie) = ext.split_first_chunk::<2>()?;
    (usize::from(u16::from_be_bytes(*len)) == cookie.len() && !cookie.is_empty()).then_some(cookie)
}

impl fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls::Acceptor").finish_non_exhaustive()
    }
}

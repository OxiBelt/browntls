//! Buffered or unbuffered connection ends for the exported-authenticator
//! operation: a small driver for the unbuffered API, an in-memory
//! handshake between any two ends, and the authenticator methods forwarded
//! to whichever connection type an end is.

use std::ops::DerefMut;

use browntls_core::client::UnbufferedClientConnection;
use browntls_core::exported_authenticator::AuthenticatorRequestExtensions;
use browntls_core::pki_types::CertificateDer;
use browntls_core::server::UnbufferedServerConnection;
use browntls_core::sign::CertifiedKey;
use browntls_core::unbuffered::{
    ConnectionState, EncodeError, InsufficientSizeError, UnbufferedConnectionCommon,
};
use browntls_core::{ClientConnection, ConnectionCommon, Error, ServerConnection, SideData};

/// One end of an in-memory connection.
pub(super) enum End<B, U> {
    Buffered(B),
    Unbuffered {
        conn: U,
        /// Received TLS bytes not yet discarded.
        incoming: Vec<u8>,
        /// Encoded TLS bytes not yet sent.
        outgoing: Vec<u8>,
    },
}

pub(super) type Client = End<ClientConnection, UnbufferedClientConnection>;
pub(super) type Server = End<ServerConnection, UnbufferedServerConnection>;

impl<B, U> End<B, U> {
    pub(super) fn unbuffered(conn: U) -> Self {
        Self::Unbuffered {
            conn,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }
    }
}

impl<B, U, D> End<B, U>
where
    B: DerefMut<Target = ConnectionCommon<D>>,
    U: DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: SideData,
{
    /// The TLS bytes this end has to send.
    pub(super) fn take_output(&mut self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Buffered(conn) => {
                let mut out = Vec::new();
                while conn.wants_write() {
                    if conn.write_tls(&mut out).is_err() {
                        break;
                    }
                }
                Ok(out)
            }
            Self::Unbuffered {
                conn,
                incoming,
                outgoing,
            } => {
                drive(conn, incoming, outgoing)?;
                Ok(std::mem::take(outgoing))
            }
        }
    }

    /// Processes TLS bytes from the peer.
    fn give_input(&mut self, bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::Buffered(conn) => {
                let mut rest = bytes;
                while !rest.is_empty() {
                    match conn.read_tls(&mut rest) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    conn.process_new_packets()?;
                }
                Ok(())
            }
            Self::Unbuffered {
                conn,
                incoming,
                outgoing,
            } => {
                incoming.extend_from_slice(bytes);
                drive(conn, incoming, outgoing)
            }
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            Self::Buffered(conn) => conn.is_handshaking(),
            Self::Unbuffered { conn, .. } => conn.is_handshaking(),
        }
    }
}

/// Runs an unbuffered connection until it needs input, appending what it
/// has to send to `outgoing`.
fn drive<D: SideData>(
    conn: &mut UnbufferedConnectionCommon<D>,
    incoming: &mut Vec<u8>,
    outgoing: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut size = 512;
    for _ in 0..256 {
        let status = conn.process_tls_records(&mut incoming[..]);
        let discard = status.discard;
        let settled = match status.state? {
            ConnectionState::EncodeTlsData(mut encode) => {
                let mut buf = vec![0u8; size];
                match encode.encode(&mut buf) {
                    Ok(n) => outgoing.extend_from_slice(&buf[..n]),
                    Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                        size = required_size
                    }
                    Err(e) => panic!("encode: {e:?}"),
                }
                false
            }
            ConnectionState::TransmitTlsData(transmit) => {
                transmit.done();
                false
            }
            // Only handshake messages and tickets are exchanged here.
            ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => true,
            other => panic!("unexpected state {other:?}"),
        };
        incoming.drain(..discard);
        if settled {
            return Ok(());
        }
    }
    panic!("an unbuffered connection did not settle");
}

/// Runs the handshake between `client` and `server`, and delivers what
/// follows it (tickets); returns the first error.
pub(super) fn connect(client: &mut Client, server: &mut Server) -> Result<(), Error> {
    for _ in 0..16 {
        let to_server = client.take_output()?;
        server.give_input(&to_server)?;
        let to_client = server.take_output()?;
        client.give_input(&to_client)?;
        if to_server.is_empty() && to_client.is_empty() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    Ok(())
}

impl Client {
    pub(super) fn request_authenticator(
        &mut self,
        context: &[u8],
        extensions: &AuthenticatorRequestExtensions,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Buffered(conn) => conn.request_authenticator(context, extensions),
            Self::Unbuffered { conn, .. } => conn.request_authenticator(context, extensions),
        }
    }

    pub(super) fn authenticator(
        &mut self,
        request: &[u8],
        certified_key: Option<&CertifiedKey>,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Buffered(conn) => conn.authenticator(request, certified_key),
            Self::Unbuffered { conn, .. } => conn.authenticator(request, certified_key),
        }
    }

    pub(super) fn validate_authenticator(
        &mut self,
        request: Option<&[u8]>,
        authenticator: &[u8],
    ) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
        match self {
            Self::Buffered(conn) => conn.validate_authenticator(request, authenticator),
            Self::Unbuffered { conn, .. } => conn.validate_authenticator(request, authenticator),
        }
    }
}

impl Server {
    pub(super) fn request_authenticator(
        &mut self,
        context: &[u8],
        extensions: &AuthenticatorRequestExtensions,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Buffered(conn) => conn.request_authenticator(context, extensions),
            Self::Unbuffered { conn, .. } => conn.request_authenticator(context, extensions),
        }
    }

    pub(super) fn authenticator(
        &mut self,
        request: Option<&[u8]>,
        certified_key: Option<&CertifiedKey>,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Buffered(conn) => conn.authenticator(request, certified_key),
            Self::Unbuffered { conn, .. } => conn.authenticator(request, certified_key),
        }
    }

    pub(super) fn validate_authenticator(
        &mut self,
        request: &[u8],
        authenticator: &[u8],
    ) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
        match self {
            Self::Buffered(conn) => conn.validate_authenticator(request, authenticator),
            Self::Unbuffered { conn, .. } => conn.validate_authenticator(request, authenticator),
        }
    }
}

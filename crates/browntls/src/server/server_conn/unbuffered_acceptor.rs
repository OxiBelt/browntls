//! The unbuffered acceptor (no `std` needed): reads a ClientHello from the
//! caller's buffer before a [`ServerConfig`] is chosen, then hands over an
//! [`UnbufferedServerConnection`].

use core::fmt;

use super::accept::{self, AcceptedHello};
use super::{ClientHello, ServerConfig, ServerConnectionData, UnbufferedServerConnection};
use crate::conn::ConnectionCore;
use crate::error::Error;
use crate::msgs::deframer::DeframerSliceBuffer;
use crate::sync::Arc;
use crate::unbuffered::{EncodeError, UnbufferedConnectionCommon, encode_queued};
use crate::vecbuf::ChunkVecBuffer;

/// Reads a ClientHello from the caller's buffer before a [`ServerConfig`] is
/// chosen: the [`crate::unbuffered`] counterpart of
/// [`Acceptor`](super::Acceptor), available without `std`.
///
/// Call [`Self::accept`] with the bytes received so far, remove
/// [`UnbufferedAcceptStatus::discard`] bytes from the front of the buffer,
/// and repeat with more bytes until it returns an [`UnbufferedAccepted`]
/// (choose a configuration from its [`ClientHello`], then
/// [`UnbufferedAccepted::into_connection`]) or an error (send the
/// [`UnbufferedAcceptedAlert`] and close).
///
/// Nothing is decrypted before a configuration is chosen. Only plaintext
/// `change_cipher_spec` records may come before the ClientHello (a client
/// continuing a stateless HelloRetryRequest, RFC 9846 §4.3.2; the handshake
/// refuses them unless the ClientHello carries a valid cookie). The
/// ClientHello may span records; its bytes are copied into the connection's
/// handshake joiner, which holds at most one maximum-size handshake message,
/// as [`UnbufferedConnectionCommon::process_tls_records`] does.
pub struct UnbufferedAcceptor {
    inner: Option<ConnectionCore<ServerConnectionData>>,
}

impl UnbufferedAcceptor {
    /// An acceptor that has read nothing yet.
    pub fn new() -> Self {
        Self {
            inner: Some(accept::accepting_core()),
        }
    }

    /// Reads records from the front of `incoming_tls` until the ClientHello
    /// is complete.
    ///
    /// `incoming_tls` holds the received bytes not yet discarded, oldest
    /// first; it may be empty, and may end in the middle of a record. Once
    /// the returned status has been handled, remove
    /// [`UnbufferedAcceptStatus::discard`] bytes from its front and keep the
    /// rest: after a ClientHello, the rest (0-RTT data, for instance) belongs
    /// to the connection, through
    /// [`UnbufferedConnectionCommon::process_tls_records`].
    ///
    /// Returns `Ok(None)` while the ClientHello is incomplete. A record other
    /// than a handshake or `change_cipher_spec` record, a malformed record or
    /// message (a server name that is not a valid DNS name included), a first
    /// handshake message that is not a ClientHello, and a ClientHello that
    /// fails the checks that need no configuration (duplicate key shares or
    /// certificate compression algorithms, QUIC transport parameters, no
    /// `signature_algorithms` where certificates may be used) are refused
    /// with the error and the alert to send. Once a ClientHello or an error
    /// was returned, every call fails with an empty alert and discards
    /// nothing.
    pub fn accept(&mut self, incoming_tls: &mut [u8]) -> UnbufferedAcceptStatus {
        let Some(mut core) = self.inner.take() else {
            return UnbufferedAcceptStatus {
                discard: 0,
                state: Err((
                    Error::general("UnbufferedAcceptor polled after completion"),
                    UnbufferedAcceptedAlert(ChunkVecBuffer::new(None)),
                )),
            };
        };
        let mut buffer = DeframerSliceBuffer::new(incoming_tls);
        let result = accept::read_client_hello(&mut core, &mut buffer);
        let discard = buffer.discarded();
        let state = match result {
            Ok(Some(hello)) => Ok(Some(UnbufferedAccepted { core, hello })),
            Ok(None) => {
                self.inner = Some(core);
                Ok(None)
            }
            Err(err) => Err((err, UnbufferedAcceptedAlert::from(core))),
        };
        UnbufferedAcceptStatus { discard, state }
    }
}

impl Default for UnbufferedAcceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UnbufferedAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnbufferedAcceptor")
            .field("done", &self.inner.is_none())
            .finish_non_exhaustive()
    }
}

/// The result of [`UnbufferedAcceptor::accept`].
#[must_use]
#[derive(Debug)]
pub struct UnbufferedAcceptStatus {
    /// How many bytes to remove from the front of the `incoming_tls` buffer
    /// before the next call (to the acceptor, or to the connection made from
    /// the ClientHello).
    pub discard: usize,

    /// The ClientHello once complete (`None` until then), or the error that
    /// ended the acceptor with the alert to send to the client.
    pub state: Result<Option<UnbufferedAccepted>, (Error, UnbufferedAcceptedAlert)>,
}

/// A ClientHello read by an [`UnbufferedAcceptor`], waiting for a
/// configuration.
pub struct UnbufferedAccepted {
    core: ConnectionCore<ServerConnectionData>,
    hello: AcceptedHello,
}

impl UnbufferedAccepted {
    /// The ClientHello, as the client sent it: nothing in it is
    /// authenticated yet.
    ///
    /// With Encrypted Client Hello this is the outer ClientHello (its server
    /// name is the public name): the inner one is only decrypted by
    /// [`Self::into_connection`], with the keys of the configuration chosen.
    pub fn client_hello(&self) -> ClientHello<'_> {
        self.hello.client_hello(&self.core.data)
    }

    /// Continues the handshake with `config`.
    ///
    /// `config` is checked as [`UnbufferedServerConnection::new`] checks it
    /// (cookie sealer, ECH role, `max_fragment_size`, `record_size_limit`).
    /// An encrypted ClientHello is then decrypted with `config`'s ECH keys,
    /// and the ClientHello handled with `config` (a stateless HelloRetryRequest
    /// cookie is opened with its sealer). The connection returned behaves as
    /// an `UnbufferedServerConnection::new(config)` that read the same bytes:
    /// pass the bytes not discarded to
    /// [`process_tls_records`](UnbufferedConnectionCommon::process_tls_records),
    /// which offers the server's first flight. Accepted 0-RTT data is reported
    /// in place, and is replayable by an attacker (see
    /// [`ServerConfig::max_early_data_size`]).
    ///
    /// On error the alert to send is returned too: the handshake's own, or
    /// `internal_error` when `config` itself is refused.
    pub fn into_connection(
        mut self,
        config: Arc<ServerConfig>,
    ) -> Result<UnbufferedServerConnection, (Error, UnbufferedAcceptedAlert)> {
        match accept::configure(&mut self.core, self.hello, config) {
            Ok(()) => Ok(UnbufferedServerConnection::from_core(self.core)),
            Err(err) => Err((err, UnbufferedAcceptedAlert::from(self.core))),
        }
    }
}

impl fmt::Debug for UnbufferedAccepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnbufferedAccepted").finish_non_exhaustive()
    }
}

/// The records an [`UnbufferedAcceptor`] or [`UnbufferedAccepted`] wants to
/// send after a failure: a fatal alert, after anything the handshake queued
/// before it failed. Empty for a call after completion.
pub struct UnbufferedAcceptedAlert(ChunkVecBuffer);

impl UnbufferedAcceptedAlert {
    /// Copies as many whole queued records as fit into `outgoing_tls` and
    /// returns the bytes written (zero once everything was copied), like
    /// [`EncodeTlsData::encode`](crate::unbuffered::EncodeTlsData::encode).
    ///
    /// Fails, writing and consuming nothing, when not even the next record
    /// fits; the error carries that record's length. Send what was written,
    /// then close the transport.
    pub fn encode(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncodeError> {
        encode_queued(&mut self.0, outgoing_tls)
    }

    /// Whether nothing (more) is to be sent.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<ConnectionCore<ServerConnectionData>> for UnbufferedAcceptedAlert {
    fn from(core: ConnectionCore<ServerConnectionData>) -> Self {
        Self(core.common_state.sendable_tls)
    }
}

impl fmt::Debug for UnbufferedAcceptedAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnbufferedAcceptedAlert")
            .field("queued", &self.0.len())
            .finish()
    }
}

impl UnbufferedServerConnection {
    /// Wraps a server core for the unbuffered API: accepted 0-RTT data, like
    /// application data, stays in the caller's buffer. Every
    /// `UnbufferedServerConnection` is made here, by
    /// [`UnbufferedServerConnection::new`] or
    /// [`UnbufferedAccepted::into_connection`].
    pub(super) fn from_core(mut core: ConnectionCore<ServerConnectionData>) -> Self {
        core.data.early_data.set_in_place();
        Self {
            inner: UnbufferedConnectionCommon::new(core),
        }
    }
}

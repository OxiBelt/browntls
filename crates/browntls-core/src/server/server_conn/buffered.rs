//! The buffered server API (`std` only): the connection, its early data
//! reader, and the acceptor that reads a ClientHello before a configuration
//! is chosen.

use core::fmt;

use super::accept::{self, AcceptedHello};
use super::{
    ClientHello, EarlyDataState, PostHandshakeAuthStatus, ServerConfig, ServerConnectionData,
};
use crate::conn::ConnectionCore;
use crate::delegated_credential::DelegatedCredential;
use crate::error::Error;
use crate::sync::Arc;
use crate::vecbuf::ChunkVecBuffer;

/// An [`std::io::Read`] for accepted early data; see
/// [`ServerConnection::early_data`].
#[cfg(feature = "std")]
pub struct ReadEarlyData<'a> {
    early_data: &'a mut EarlyDataState,
}

#[cfg(feature = "std")]
impl fmt::Debug for ReadEarlyData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadEarlyData")
            .field("state", self.early_data)
            .finish()
    }
}

#[cfg(feature = "std")]
impl std::io::Read for ReadEarlyData<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.early_data.read(buf)
    }
}

/// A server-side TLS connection.
#[cfg(feature = "std")]
pub struct ServerConnection {
    inner: crate::conn::ConnectionCommon<ServerConnectionData>,
}

#[cfg(feature = "std")]
impl ServerConnection {
    /// Prepares to accept a connection with `config`.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self {
            inner: ConnectionCore::for_server(config)?.into(),
        })
    }

    /// The server name the client indicated, once its ClientHello was
    /// processed.
    pub fn server_name(&self) -> Option<&str> {
        self.inner.core.data.sni.as_ref().map(|n| n.as_ref())
    }

    /// Application data stored with a resumed session, once resumed.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        self.inner.core.data.received_resumption_data.as_deref()
    }

    /// Application data to store with the session for later resumption.
    ///
    /// Call before the handshake completes; it is written into the tickets.
    pub fn set_resumption_data(&mut self, data: &[u8]) {
        self.inner.core.data.resumption_data = data.to_vec();
    }

    /// Refuses any 0-RTT data on this connection.
    ///
    /// Must be called before the handshake has processed the ClientHello
    /// (right after [`Self::new`], or from a certificate resolver); a later
    /// call has no effect on data already accepted.
    pub fn reject_early_data(&mut self) {
        debug_assert!(
            self.inner.core.common_state.is_handshaking(),
            "cannot retroactively reject early data"
        );
        self.inner.core.data.early_data.reject();
    }

    /// A reader for the client's 0-RTT ("early") data, if any was accepted.
    ///
    /// Early data is enabled by a non-zero
    /// [`ServerConfig::max_early_data_size`] with stateful (non-ticket)
    /// resumption, or under an external PSK created with
    /// `ExternalPsk::with_early_data`. It is **replayable** by an attacker: the
    /// application must only act on it when a replay is harmless, and the
    /// library offers no anti-replay store. Returns `None` until the
    /// ClientHello has been processed, or if early data was not offered or not
    /// accepted.
    pub fn early_data(&mut self) -> Option<ReadEarlyData<'_>> {
        let data = &mut self.inner.core.data;
        if data.early_data.was_accepted() {
            Some(ReadEarlyData {
                early_data: &mut data.early_data,
            })
        } else {
            None
        }
    }

    /// Whether the connection only uses FIPS-validated components.
    pub fn fips(&self) -> bool {
        self.inner.core.common_state.fips()
    }

    /// The delegated credential (RFC 9345 §4.1.2) the client authenticated
    /// with, once its CertificateVerify has been verified with the
    /// credential's key (and, after the handshake, once the Finished of
    /// that answer has verified); `None` when the client signed with its
    /// certificate key, sent no certificate, or the session was resumed.
    /// It belongs to the certificate `peer_certificates` returns.
    pub fn client_delegated_credential(&self) -> Option<&DelegatedCredential> {
        self.inner.core.data.client_delegated_credential.as_ref()
    }

    /// What was decided about Encrypted Client Hello. With
    /// [`EchStatus::Accepted`](crate::ech::EchStatus::Accepted), the
    /// handshake used the client's encrypted ClientHello, and
    /// [`Self::server_name`] is the name it carried.
    pub fn ech_status(&self) -> crate::ech::EchStatus {
        self.inner.core.data.ech.status()
    }

    /// Whether the client offered TLS 1.3 post-handshake authentication
    /// (`post_handshake_auth`, RFC 9846 §4.3.6), once its ClientHello has
    /// been processed.
    pub fn post_handshake_auth_offered(&self) -> bool {
        self.inner.core.data.post_handshake_auth_offered
    }

    /// Asks the client for a certificate after the handshake (RFC 9846
    /// §4.7.2): queues a CertificateRequest with a fresh, unpredictable
    /// `certificate_request_context`.
    ///
    /// Requires a completed TLS 1.3 handshake with a client that offered
    /// `post_handshake_auth`, a client certificate verifier that offers
    /// client authentication, no request still unanswered, and no
    /// `close_notify` sent or received (the client would never answer). The
    /// answer
    /// arrives through
    /// [`Self::process_new_packets`](crate::ConnectionCommon::process_new_packets)
    /// and is checked with the configured verifier: follow it with
    /// [`Self::post_handshake_auth_status`]. A client may take its time and
    /// send application data first; a certificate the verifier refuses, a bad
    /// signature or Finished, a missing certificate when the verifier makes it
    /// mandatory, or messages interleaved with the answer end the connection
    /// with the corresponding alert.
    pub fn request_client_auth(&mut self) -> Result<(), Error> {
        self.inner.core.request_client_auth()
    }

    /// The state of the most recent [`Self::request_client_auth`], or
    /// `None` if none was made.
    pub fn post_handshake_auth_status(&self) -> Option<PostHandshakeAuthStatus> {
        self.inner.core.data.post_handshake_auth
    }

    /// See [`crate::ConnectionCommon::dangerous_extract_secrets`].
    pub fn dangerous_extract_secrets(self) -> Result<crate::suites::ExtractedSecrets, Error> {
        self.inner.dangerous_extract_secrets()
    }

    /// See [`crate::ConnectionCommon::dangerous_into_kernel_connection`].
    pub fn dangerous_into_kernel_connection(
        self,
    ) -> Result<
        (
            crate::suites::ExtractedSecrets,
            crate::kernel::KernelConnection<ServerConnectionData>,
        ),
        Error,
    > {
        self.inner.dangerous_into_kernel_connection()
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConnection").finish_non_exhaustive()
    }
}

#[cfg(feature = "std")]
impl core::ops::Deref for ServerConnection {
    type Target = crate::conn::ConnectionCommon<ServerConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(feature = "std")]
impl core::ops::DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(feature = "std")]
impl From<ServerConnection> for crate::conn::Connection {
    fn from(conn: ServerConnection) -> Self {
        Self::Server(conn)
    }
}

/// Reads a ClientHello before choosing a [`ServerConfig`].
#[cfg(feature = "std")]
pub struct Acceptor {
    inner: Option<crate::conn::ConnectionCommon<ServerConnectionData>>,
}

#[cfg(feature = "std")]
impl Default for Acceptor {
    fn default() -> Self {
        Self {
            inner: Some(accept::accepting_core().into()),
        }
    }
}

#[cfg(feature = "std")]
impl Acceptor {
    /// Reads TLS bytes from `rd`.
    pub fn read_tls(&mut self, rd: &mut dyn std::io::Read) -> Result<usize, std::io::Error> {
        match &mut self.inner {
            Some(conn) => conn.read_tls(rd),
            None => Err(std::io::Error::other(
                "acceptor cannot read after successful acceptance",
            )),
        }
    }

    /// Returns the ClientHello once it has been read in full.
    ///
    /// Before it, only `change_cipher_spec` records are allowed (a stateless
    /// HelloRetryRequest, RFC 9846 §4.3.2). Anything else, a malformed
    /// record, or a ClientHello that fails the checks that do not depend on
    /// the configuration, is refused; so is a call after the acceptor
    /// returned a ClientHello or an error. A refusal comes with the alert to
    /// send to the client (empty for a call after completion).
    ///
    /// These checks see the ClientHello as sent. With Encrypted Client
    /// Hello that is the outer one, so a defect only there is refused here,
    /// although a connection created with the ECH keys, which checks only the
    /// inner ClientHello it decrypts, would go on.
    pub fn accept(&mut self) -> Result<Option<Accepted>, (Error, AcceptedAlert)> {
        let Some(mut connection) = self.inner.take() else {
            return Err((
                Error::general("Acceptor polled after completion"),
                AcceptedAlert::empty(),
            ));
        };
        match accept::read_client_hello(&mut connection.core, &mut connection.deframer_buffer) {
            Ok(Some(hello)) => Ok(Some(Accepted { connection, hello })),
            Ok(None) => {
                self.inner = Some(connection);
                Ok(None)
            }
            Err(err) => Err((err, AcceptedAlert::from(connection))),
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acceptor").finish_non_exhaustive()
    }
}

/// The alert an [`Acceptor`] or [`Accepted`] wants to send after a failure,
/// or a [`ServerConnection`] that failed.
#[cfg(feature = "std")]
pub struct AcceptedAlert(ChunkVecBuffer);

#[cfg(feature = "std")]
impl AcceptedAlert {
    fn empty() -> Self {
        Self(ChunkVecBuffer::new(None))
    }

    /// Writes as much of the alert as `wr` accepts.
    pub fn write(&mut self, wr: &mut dyn std::io::Write) -> Result<usize, std::io::Error> {
        self.0.write_to(wr)
    }

    /// Writes the whole alert.
    pub fn write_all(&mut self, wr: &mut dyn std::io::Write) -> Result<(), std::io::Error> {
        while self.write(wr)? != 0 {}
        Ok(())
    }
}

#[cfg(feature = "std")]
impl From<crate::conn::ConnectionCommon<ServerConnectionData>> for AcceptedAlert {
    fn from(conn: crate::conn::ConnectionCommon<ServerConnectionData>) -> Self {
        Self(conn.core.common_state.sendable_tls)
    }
}

/// Everything the connection has queued to send. Meant for a connection
/// that failed right after an [`Accepted`] became it, when that is its
/// alert, behind what was left of its flight; a connection that had
/// application data queued would have that written too.
#[cfg(feature = "std")]
impl From<ServerConnection> for AcceptedAlert {
    fn from(conn: ServerConnection) -> Self {
        Self::from(conn.inner)
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for AcceptedAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptedAlert").finish_non_exhaustive()
    }
}

/// A ClientHello read by an [`Acceptor`], waiting for a configuration.
#[cfg(feature = "std")]
pub struct Accepted {
    connection: crate::conn::ConnectionCommon<ServerConnectionData>,
    hello: AcceptedHello,
}

#[cfg(feature = "std")]
impl Accepted {
    /// The ClientHello.
    ///
    /// With Encrypted Client Hello this is the outer ClientHello: the inner
    /// one is only decrypted by [`Self::into_connection`], with the keys of
    /// the configuration chosen.
    pub fn client_hello(&self) -> ClientHello<'_> {
        self.hello.client_hello(&self.connection.core.data)
    }

    /// Continues the handshake with `config`.
    ///
    /// The connection then behaves as a [`ServerConnection::new`] with
    /// `config` that read the same bytes. One refusal differs in its error,
    /// not its alert: a `change_cipher_spec` record ahead of the ClientHello,
    /// with no cookie sealer in `config`, is
    /// [`PeerMisbehaved::IllegalMiddleboxChangeCipherSpec`](crate::PeerMisbehaved::IllegalMiddleboxChangeCipherSpec)
    /// here and [`Error::InappropriateMessage`] there (`unexpected_message`
    /// both). `config` is checked as there
    /// (cookie sealer, ECH role, `max_fragment_size`, `record_size_limit`);
    /// ECH is processed with its keys; the ClientHello is then handled with
    /// it. On error the alert to send is returned too: the handshake's own,
    /// or `internal_error` when `config` itself is refused.
    ///
    /// Records the [`Acceptor`] read after the ClientHello (0-RTT data, say)
    /// stay unprocessed until the connection's next
    /// [`process_new_packets`](crate::ConnectionCommon::process_new_packets):
    /// call it before waiting for more input.
    pub fn into_connection(
        mut self,
        config: Arc<ServerConfig>,
    ) -> Result<ServerConnection, (Error, AcceptedAlert)> {
        match accept::configure(&mut self.connection.core, self.hello, config) {
            Ok(()) => Ok(ServerConnection {
                inner: self.connection,
            }),
            Err(err) => Err((err, AcceptedAlert::from(self.connection))),
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted").finish_non_exhaustive()
    }
}

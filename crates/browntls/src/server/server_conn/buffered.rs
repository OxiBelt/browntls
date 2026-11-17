//! The buffered server API (`std` only): the connection, its early data
//! reader, and the acceptor that reads a ClientHello before a configuration
//! is chosen.

use alloc::vec::Vec;
use core::fmt;

use super::{
    ClientHello, EarlyDataState, PostHandshakeAuthStatus, ServerConfig, ServerConnectionData,
};
use crate::common_state::{CommonState, Side};
use crate::conn::ConnectionCore;
use crate::enums::{ProtocolVersion, SignatureScheme};
use crate::error::Error;
use crate::msgs::handshake::ClientHelloPayload;
use crate::server::hs;
use crate::sync::Arc;
use crate::vecbuf::ChunkVecBuffer;

/// An [`std::io::Read`] for accepted early data; see [`ServerConnection::early_data`].
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

    /// The server name the client indicated, once its ClientHello was processed.
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
    /// Early data is enabled by a non-zero [`ServerConfig::max_early_data_size`]
    /// with stateful (non-ticket) resumption. It is **replayable** by an
    /// attacker: the application must only act on it when a replay is
    /// harmless, and the library offers no anti-replay store. Returns `None`
    /// until the ClientHello has been processed, or if early data was not
    /// offered or not accepted.
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
    /// arrives through [`Self::process_new_packets`](crate::ConnectionCommon::process_new_packets)
    /// and is checked with the configured verifier: follow it with
    /// [`Self::post_handshake_auth_status`]. A client may take its time and
    /// send application data first; a certificate the verifier refuses, a
    /// bad signature or Finished, a missing certificate when the verifier
    /// makes it mandatory, or messages interleaved with the answer end the
    /// connection with the corresponding alert.
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
            inner: Some(
                ConnectionCore::new(
                    alloc::boxed::Box::new(Accepting),
                    ServerConnectionData::default(),
                    CommonState::new(Side::Server),
                )
                .into(),
            ),
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
    /// On error, the alert to send to the client is returned too.
    pub fn accept(&mut self) -> Result<Option<Accepted>, (Error, AcceptedAlert)> {
        let Some(mut connection) = self.inner.take() else {
            return Err((
                Error::general("Acceptor polled after completion"),
                AcceptedAlert::empty(),
            ));
        };

        let message = match connection
            .core
            .first_handshake_message(&mut connection.deframer_buffer)
        {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                self.inner = Some(connection);
                return Ok(None);
            }
            Err(err) => {
                // Every refusal comes with an alert the caller can send.
                let err = ConnectionCore::<ServerConnectionData>::ensure_alert_sent(
                    &mut connection.core.common_state,
                    err,
                );
                return Err((err, AcceptedAlert::from(connection)));
            }
        };

        let mut cx = crate::conn::Context {
            common: &mut connection.core.common_state,
            data: &mut connection.core.data,
        };
        let sig_schemes = match hs::process_client_hello(&message, false, &mut cx) {
            Ok((_, sig_schemes)) => sig_schemes,
            Err(err) => {
                let err = ConnectionCore::<ServerConnectionData>::ensure_alert_sent(
                    &mut connection.core.common_state,
                    err,
                );
                return Err((err, AcceptedAlert::from(connection)));
            }
        };

        Ok(Some(Accepted {
            connection,
            message,
            sig_schemes,
        }))
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acceptor").finish_non_exhaustive()
    }
}

/// The alert an [`Acceptor`] or [`Accepted`] wants to send after a failure.
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
    message: crate::msgs::message::Message<'static>,
    sig_schemes: Vec<SignatureScheme>,
}

#[cfg(feature = "std")]
impl Accepted {
    /// The ClientHello.
    pub fn client_hello(&self) -> ClientHello<'_> {
        ClientHello::new(
            self.connection.core.data.sni.as_ref(),
            &self.sig_schemes,
            Self::client_hello_payload(&self.message),
        )
    }

    /// Continues the handshake with `config`.
    pub fn into_connection(
        mut self,
        config: Arc<ServerConfig>,
    ) -> Result<ServerConnection, (Error, AcceptedAlert)> {
        if let Err(err) = config
            .check_cookie_sealer()
            .and_then(|()| config.check_ech_role())
            .and_then(|()| {
                self.connection
                    .set_max_fragment_size(config.max_fragment_size)
            })
            .and_then(|()| {
                crate::common_state::check_record_size_limit_config(config.record_size_limit)
            })
        {
            return Err((err, AcceptedAlert::from(self.connection)));
        }
        self.connection.enable_secret_extraction = config.enable_secret_extraction;
        self.connection.fips = config.fips();

        let mut cx = crate::conn::Context {
            common: &mut self.connection.core.common_state,
            data: &mut self.connection.core.data,
        };
        // RFC 9849 §7.1: with ECH keys in `config`, an encrypted ClientHello
        // replaces the one the acceptor saw.
        let inner = match crate::ech::server::process_client_hello(
            config.ech_role(),
            &mut cx.data.ech,
            cx.common,
            &self.message,
            false,
        ) {
            Ok(inner) => inner,
            Err(err) => return Err((err, AcceptedAlert::from(self.connection))),
        };
        let (message, sig_schemes) = match inner {
            Some(inner) => match hs::process_client_hello(&inner, false, &mut cx) {
                Ok((_, sig_schemes)) => (inner, sig_schemes),
                Err(err) => return Err((err, AcceptedAlert::from(self.connection))),
            },
            None => (self.message, self.sig_schemes),
        };
        let state = hs::ExpectClientHello::new(config);
        let payload = Self::client_hello_payload(&message);
        let new = match state.with_certified_key(sig_schemes, payload, &message, &mut cx) {
            Ok(new) => new,
            Err(err) => return Err((err, AcceptedAlert::from(self.connection))),
        };
        self.connection.replace_state(new);
        Ok(ServerConnection {
            inner: self.connection,
        })
    }

    fn client_hello_payload<'a>(
        message: &'a crate::msgs::message::Message<'_>,
    ) -> &'a ClientHelloPayload {
        match &message.payload {
            crate::msgs::message::MessagePayload::Handshake {
                parsed:
                    crate::msgs::handshake::HandshakeMessagePayload(
                        crate::msgs::handshake::HandshakePayload::ClientHello(ch),
                    ),
                ..
            } => ch,
            // `Acceptor::accept` only constructs `Accepted` from a ClientHello.
            _ => unreachable_client_hello(),
        }
    }
}

#[cfg(feature = "std")]
#[cold]
fn unreachable_client_hello() -> &'static ClientHelloPayload {
    // `Accepted` is only built after `process_client_hello` accepted the
    // message as a ClientHello, so this cannot be reached. Returning a leaked
    // minimal payload keeps the function free of panics.
    static EMPTY: std::sync::OnceLock<ClientHelloPayload> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: crate::msgs::handshake::Random::from([0u8; 32]),
        session_id: crate::msgs::handshake::SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: Default::default(),
    })
}

#[cfg(feature = "std")]
impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted").finish_non_exhaustive()
    }
}

/// The state an [`Acceptor`] parks in: it never handles messages itself.
#[cfg(feature = "std")]
struct Accepting;

#[cfg(feature = "std")]
impl crate::conn::State<ServerConnectionData> for Accepting {
    fn handle(
        self: alloc::boxed::Box<Self>,
        _cx: &mut crate::conn::Context<'_, ServerConnectionData>,
        _message: crate::msgs::message::Message<'_>,
    ) -> Result<alloc::boxed::Box<dyn crate::conn::State<ServerConnectionData>>, Error> {
        Err(Error::general(
            "Acceptor connections cannot process messages",
        ))
    }
}

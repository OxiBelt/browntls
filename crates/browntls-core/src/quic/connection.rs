//! The QUIC-TLS connection types.

use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut};

use browntls_pki::ServerName;

use super::{DirectionalKeys, KeyChange, Quic, Version};
use crate::common_state::CommonState;
use crate::conn::{ConnectionCore, SideData};
use crate::enums::AlertDescription;
use crate::error::Error;
use crate::sync::Arc;

/// A QUIC-TLS connection, client or server.
///
/// It dereferences to [`CommonState`] for the negotiated parameters (ALPN
/// protocol, cipher suite, peer certificates, handshake progress).
pub struct ConnectionCommon<Data> {
    core: ConnectionCore<Data>,
}

impl<Data: SideData> ConnectionCommon<Data> {
    fn new(core: ConnectionCore<Data>) -> Self {
        Self { core }
    }

    fn quic(&self) -> &Quic {
        // Every QUIC connection is created with its QUIC state.
        match &self.core.common_state.quic {
            Some(quic) => quic,
            None => unreachable!("QUIC connection without QUIC state"),
        }
    }

    fn quic_mut(&mut self) -> &mut Quic {
        match &mut self.core.common_state.quic {
            Some(quic) => quic,
            None => unreachable!("QUIC connection without QUIC state"),
        }
    }

    /// The peer's transport parameters, once received (RFC 9001 §8.2).
    ///
    /// They are authenticated only once the handshake completes. A client
    /// that offered 0-RTT sees the parameters remembered with its ticket
    /// until the server's EncryptedExtensions replaces them (RFC 9000
    /// §7.4.1).
    pub fn quic_transport_parameters(&self) -> Option<&[u8]> {
        self.quic().peer_params.as_deref()
    }

    /// The 0-RTT keys: on a client offering early data, for sending; on a
    /// server that accepted early data, for receiving.
    ///
    /// A client has them from its first ClientHello until a
    /// HelloRetryRequest or the server's refusal of early data; a QUIC
    /// implementation that took them earlier stops using them once
    /// `is_early_data_accepted` stays false at the end of the handshake.
    pub fn zero_rtt_keys(&self) -> Option<DirectionalKeys> {
        self.quic().zero_rtt_keys()
    }

    /// Processes in-order handshake bytes received in CRYPTO frames.
    ///
    /// Bytes of one encryption level must not be mixed with another's:
    /// when a message changes the level the peer sends at, nothing may be
    /// left over (RFC 9001 §4.1.3). Which level a CRYPTO frame may arrive
    /// at otherwise is for the QUIC implementation to check: this call
    /// takes no level, so for example Handshake-level data arriving after
    /// the handshake is read as post-handshake messages.
    pub fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        self.core.read_quic_handshake(plaintext)
    }

    /// Supplies the result of the current OCSP query and processes buffered
    /// CRYPTO data.
    pub fn resolve_peer_revocation(
        &mut self,
        id: u64,
        response: crate::revocation::RevocationResponse,
    ) -> Result<(), Error> {
        self.core.resolve_peer_revocation(id, response)?;
        self.read_hs(&[])
    }

    /// Appends the handshake bytes to send at the current sending level to
    /// `buf`, and returns the keys of the next level once they exist.
    ///
    /// The bytes appended by a call returning [`KeyChange`] go out under the
    /// previous level's keys. Call this until it returns `None`.
    pub fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<KeyChange> {
        let side = self.core.common_state.side;
        self.quic_mut().write_hs(buf, side)
    }

    /// The TLS alert that ended the connection, if this side raised one.
    ///
    /// Send it as the QUIC CRYPTO_ERROR
    /// [`crypto_error_code`](super::crypto_error_code) of the alert in a
    /// CONNECTION_CLOSE frame (RFC 9001 §4.8). When a call failed and
    /// this is `None`, the peer broke a rule RFC 9001 makes a QUIC
    /// PROTOCOL_VIOLATION (for example
    /// [`PeerMisbehaved::KeyEpochWithPendingFragment`](crate::PeerMisbehaved::KeyEpochWithPendingFragment),
    /// [`PeerMisbehaved::InvalidMaxEarlyDataSize`](crate::PeerMisbehaved::InvalidMaxEarlyDataSize)
    /// or
    /// [`PeerMisbehaved::NonEmptySessionIdInQuicClientHello`](crate::PeerMisbehaved::NonEmptySessionIdInQuicClientHello)).
    pub fn alert(&self) -> Option<AlertDescription> {
        self.quic().alert
    }

    /// Derives keying material bound to this session (RFC 9846 §7.5).
    pub fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        mut output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<T, Error> {
        self.core
            .export_keying_material(output.as_mut(), label, context)?;
        Ok(output)
    }
}

impl<Data> Deref for ConnectionCommon<Data> {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.core.common_state
    }
}

impl<Data> DerefMut for ConnectionCommon<Data> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core.common_state
    }
}

impl<Data> fmt::Debug for ConnectionCommon<Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("quic::ConnectionCommon")
            .field("common", &self.core.common_state)
            .finish_non_exhaustive()
    }
}

/// A QUIC-TLS client connection.
pub struct ClientConnection {
    inner: ConnectionCommon<crate::client::ClientConnectionData>,
}

impl ClientConnection {
    /// Starts a QUIC handshake with `name`, offering `params` (the encoded
    /// transport parameters of the QUIC `version` in use).
    ///
    /// The configuration must allow TLS 1.3 and contain a cipher suite usable
    /// with QUIC; only those are offered. ALPN is mandatory with QUIC
    /// (RFC 9001 §8.1): if `config.alpn_protocols` is not empty and the server
    /// selects none of them, the handshake fails with
    /// `no_application_protocol`.
    pub fn new(
        config: Arc<crate::ClientConfig>,
        version: Version,
        name: ServerName<'static>,
        params: Vec<u8>,
    ) -> Result<Self, Error> {
        let alpn = config.alpn_protocols.clone();
        Self::new_with_alpn(config, version, name, params, alpn)
    }

    /// Like [`Self::new`] with ALPN protocols overriding the configuration's.
    pub fn new_with_alpn(
        config: Arc<crate::ClientConfig>,
        version: Version,
        name: ServerName<'static>,
        params: Vec<u8>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        let core = ConnectionCore::for_quic_client(
            config,
            name,
            alpn_protocols,
            Quic::new(version, params),
        )?;
        Ok(Self {
            inner: ConnectionCommon::new(core),
        })
    }

    /// Whether the server accepted 0-RTT.
    pub fn is_early_data_accepted(&self) -> bool {
        self.inner.core.data.early_data_accepted()
    }

    /// How many TLS 1.3 tickets the server has sent so far.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.inner.core.data.tls13_tickets_received
    }
}

impl Deref for ClientConnection {
    type Target = ConnectionCommon<crate::client::ClientConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("quic::ClientConnection")
            .finish_non_exhaustive()
    }
}

/// A QUIC-TLS server connection.
pub struct ServerConnection {
    inner: ConnectionCommon<crate::server::ServerConnectionData>,
}

impl ServerConnection {
    /// Prepares to accept a QUIC handshake, answering with `params` (the
    /// encoded transport parameters of the QUIC `version` in use).
    ///
    /// The configuration must allow TLS 1.3 and contain a cipher suite usable
    /// with QUIC, and its `max_early_data_size` must be 0 (no 0-RTT) or
    /// `u32::MAX` (RFC 9001 §4.6.1).
    pub fn new(
        config: Arc<crate::ServerConfig>,
        version: Version,
        params: Vec<u8>,
    ) -> Result<Self, Error> {
        let core = ConnectionCore::for_quic_server(config, Quic::new(version, params))?;
        Ok(Self {
            inner: ConnectionCommon::new(core),
        })
    }

    /// The server name the client indicated, once its ClientHello was
    /// processed.
    pub fn server_name(&self) -> Option<&str> {
        self.inner.core.data.server_name()
    }

    /// Application data stored with a resumed session, once resumed.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        self.inner.core.data.received_resumption_data()
    }

    /// Application data to store with the session for later resumption,
    /// for example what the QUIC layer needs to judge 0-RTT acceptable
    /// (RFC 9001 §4.6.3). Call before the handshake completes.
    pub fn set_resumption_data(&mut self, data: &[u8]) {
        self.inner.core.data.set_resumption_data(data);
    }

    /// Refuses 0-RTT on this connection; call before the ClientHello is read.
    pub fn reject_early_data(&mut self) {
        self.inner.core.data.reject_early_data();
    }

    /// Whether 0-RTT was accepted, once the ClientHello was processed.
    pub fn is_early_data_accepted(&self) -> bool {
        self.inner.core.data.early_data_accepted()
    }
}

impl Deref for ServerConnection {
    type Target = ConnectionCommon<crate::server::ServerConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl fmt::Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("quic::ServerConnection")
            .finish_non_exhaustive()
    }
}

/// A QUIC-TLS connection of either side.
#[derive(Debug)]
pub enum Connection {
    /// A client connection.
    Client(ClientConnection),
    /// A server connection.
    Server(ServerConnection),
}

impl Connection {
    /// See [`ConnectionCommon::quic_transport_parameters`].
    pub fn quic_transport_parameters(&self) -> Option<&[u8]> {
        match self {
            Self::Client(conn) => conn.quic_transport_parameters(),
            Self::Server(conn) => conn.quic_transport_parameters(),
        }
    }

    /// See [`ConnectionCommon::zero_rtt_keys`].
    pub fn zero_rtt_keys(&self) -> Option<DirectionalKeys> {
        match self {
            Self::Client(conn) => conn.zero_rtt_keys(),
            Self::Server(conn) => conn.zero_rtt_keys(),
        }
    }

    /// See [`ConnectionCommon::read_hs`].
    pub fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        match self {
            Self::Client(conn) => conn.read_hs(plaintext),
            Self::Server(conn) => conn.read_hs(plaintext),
        }
    }

    /// Supplies the result of the current OCSP query and processes buffered
    /// CRYPTO data.
    pub fn resolve_peer_revocation(
        &mut self,
        id: u64,
        response: crate::revocation::RevocationResponse,
    ) -> Result<(), Error> {
        match self {
            Self::Client(conn) => conn.resolve_peer_revocation(id, response),
            Self::Server(conn) => conn.resolve_peer_revocation(id, response),
        }
    }

    /// See [`ConnectionCommon::write_hs`].
    pub fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<KeyChange> {
        match self {
            Self::Client(conn) => conn.write_hs(buf),
            Self::Server(conn) => conn.write_hs(buf),
        }
    }

    /// See [`ConnectionCommon::alert`].
    pub fn alert(&self) -> Option<AlertDescription> {
        match self {
            Self::Client(conn) => conn.alert(),
            Self::Server(conn) => conn.alert(),
        }
    }

    /// See [`ConnectionCommon::export_keying_material`].
    pub fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<T, Error> {
        match self {
            Self::Client(conn) => conn.export_keying_material(output, label, context),
            Self::Server(conn) => conn.export_keying_material(output, label, context),
        }
    }
}

impl Deref for Connection {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Client(conn) => conn,
            Self::Server(conn) => conn,
        }
    }
}

impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Client(conn) => conn,
            Self::Server(conn) => conn,
        }
    }
}

impl From<ClientConnection> for Connection {
    fn from(conn: ClientConnection) -> Self {
        Self::Client(conn)
    }
}

impl From<ServerConnection> for Connection {
    fn from(conn: ServerConnection) -> Self {
        Self::Server(conn)
    }
}

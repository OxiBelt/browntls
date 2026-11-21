//! The buffered client API (`std` only): the connection and its early data
//! writer.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::ServerName;

use super::{ClientConfig, ClientConnectionData};
use crate::conn::ConnectionCore;
use crate::delegated_credential::DelegatedCredential;
use crate::error::Error;
use crate::sync::Arc;

/// A client-side TLS connection.
pub struct ClientConnection {
    inner: crate::conn::ConnectionCommon<ClientConnectionData>,
}

impl ClientConnection {
    /// Starts a connection to `name` with `config`; the ClientHello is queued
    /// immediately.
    pub fn new(config: Arc<ClientConfig>, name: ServerName<'static>) -> Result<Self, Error> {
        let alpn = config.alpn_protocols.clone();
        Self::new_with_alpn(config, name, alpn)
    }

    /// Like [`Self::new`] with ALPN protocols overriding the configuration's.
    pub fn new_with_alpn(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: ConnectionCore::for_client(config, name, None, alpn_protocols)?.into(),
        })
    }

    /// Starts a connection for an explicit service identity.
    pub fn new_with_identity(
        config: Arc<ClientConfig>,
        identity: crate::ClientServerIdentity,
    ) -> Result<Self, Error> {
        let alpn = config.alpn_protocols.clone();
        Self::new_with_identity_and_alpn(config, identity, alpn)
    }

    /// Starts a connection for an explicit identity and per-connection ALPN.
    pub fn new_with_identity_and_alpn(
        config: Arc<ClientConfig>,
        identity: crate::ClientServerIdentity,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        let (name, identity) = identity.into_parts();
        Ok(Self {
            inner: ConnectionCore::for_client(config, name, Some(identity), alpn_protocols)?.into(),
        })
    }

    /// How many valid TLS 1.3 tickets this connection accepted for storage.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.inner.core.data.tls13_tickets_received
    }

    /// The `extension_data` of the server's `transparency_info` extension
    /// (RFC 9162 §6.5) from a full handshake: a `TransItemList`, or empty
    /// or an empty list, which §6.5 allows. It is well formed but **not
    /// verified**; see [`Self::peer_transparency_status`].
    pub fn peer_transparency_info(&self) -> Option<&[u8]> {
        self.inner.core.data.transparency.info.as_deref()
    }

    /// What the certificate verifier established about the server
    /// certificate's Certificate Transparency 2.0 evidence, once the
    /// certificate is verified; `None` when the verifier reports nothing,
    /// and after resumption. See [`crate::transparency`].
    pub fn peer_transparency_status(&self) -> Option<crate::transparency::TransparencyStatus> {
        self.inner.core.data.transparency.status
    }

    /// The delegated credential (RFC 9345) the server authenticated with,
    /// once its CertificateVerify has been verified with the credential's
    /// key; `None` when the server signed with its certificate key.
    pub fn delegated_credential(&self) -> Option<&DelegatedCredential> {
        self.inner.core.data.delegated_credential.as_ref()
    }

    /// A writer for TLS 1.3 0-RTT ("early") data, while that is possible.
    ///
    /// Returns `None` unless the configuration enables early data, the
    /// resumed session's ticket permits it, and the server has not yet
    /// declined it. Writes beyond the ticket's `max_early_data_size` are
    /// refused. Early data is **replayable** by an attacker and must only
    /// carry idempotent requests; the server may also silently discard it, so
    /// check [`Self::is_early_data_accepted`] after the handshake and resend
    /// if needed.
    pub fn early_data(&mut self) -> Option<WriteEarlyData<'_>> {
        if self.inner.core.data.early_data.is_enabled() {
            Some(WriteEarlyData { conn: self })
        } else {
            None
        }
    }

    /// How many post-handshake CertificateRequests (RFC 9846 §4.7.2) this
    /// connection has answered, with or without a certificate.
    pub fn post_handshake_auth_responses(&self) -> u32 {
        self.inner.core.data.post_handshake_auth_responses
    }

    /// Whether the server accepted the early data sent so far.
    ///
    /// Meaningful once the handshake has finished (and only if
    /// [`Self::early_data`] was used).
    pub fn is_early_data_accepted(&self) -> bool {
        self.inner.core.data.early_data.is_accepted()
    }

    fn write_early_data(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let Some(take) = self.inner.core.data.early_data.check_write(data.len()) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        let sent = self
            .inner
            .core
            .common_state
            .send_early_plaintext(&data[..take]);
        // Give back budget the record layer did not use (RFC 9846 §5.5:
        // early data stops short of the key usage limit).
        self.inner.core.data.early_data.left += take - sent;
        Ok(sent)
    }

    /// Whether the connection only uses FIPS-validated components.
    pub fn fips(&self) -> bool {
        self.inner.core.common_state.fips()
    }

    /// Where Encrypted Client Hello stands. A rejection also ends the
    /// handshake with [`Error::RejectedEch`].
    pub fn ech_status(&self) -> crate::ech::EchStatus {
        self.inner.core.data.ech_status
    }

    /// Whether the server acknowledged our `trusted_ca_keys` (RFC 6066 §6):
    /// it negotiated TLS 1.2 in a full handshake and says the list guided
    /// its choice of certificate chain. Always false in TLS 1.3, and after
    /// resuming a session. Meaningful once the ServerHello is processed.
    pub fn trusted_ca_keys_acknowledged(&self) -> bool {
        self.inner.core.data.trusted_ca_keys_acknowledged
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
            crate::kernel::KernelConnection<ClientConnectionData>,
        ),
        Error,
    > {
        self.inner.dangerous_into_kernel_connection()
    }
}

/// An [`std::io::Write`] for early data; see [`ClientConnection::early_data`].
pub struct WriteEarlyData<'a> {
    conn: &'a mut ClientConnection,
}

impl WriteEarlyData<'_> {
    /// How many more bytes of early data the server allows.
    pub fn bytes_left(&self) -> usize {
        self.conn.inner.core.data.early_data.left
    }
}

impl fmt::Debug for WriteEarlyData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteEarlyData")
            .field("bytes_left", &self.bytes_left())
            .finish()
    }
}

impl std::io::Write for WriteEarlyData<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.conn.write_early_data(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConnection").finish_non_exhaustive()
    }
}

impl core::ops::Deref for ClientConnection {
    type Target = crate::conn::ConnectionCommon<ClientConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl core::ops::DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl From<ClientConnection> for crate::conn::Connection {
    fn from(conn: ClientConnection) -> Self {
        Self::Client(conn)
    }
}

//! The low-level DTLS connection API: datagrams in, datagrams out,
//! and timers, with no I/O of its own.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut, Range};
use core::time::Duration;

use browntls_pki::ServerName;

use super::cid::{AuthenticatedRecord, ConnectionIdUsage};
use super::state::{Dtls, Incoming, Settings};
use crate::common_state::{CommonState, Side};
use crate::conn::{ConnectionCore, SideData};
use crate::enums::{AlertDescription, ProtocolVersion};
use crate::error::Error;
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::Payload;
use crate::msgs::codec::Reader;
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::message::{Message, MessagePayload};
use crate::sync::Arc;

/// What [`ConnectionCommon::read_datagram`] found in a datagram.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Received {
    app_data: Vec<Range<usize>>,
    authenticated_records: Vec<AuthenticatedRecord>,
}

impl Received {
    /// The application data the datagram carried: one range of the
    /// datagram buffer per record, where it was decrypted, in order.
    pub fn app_data(&self) -> &[Range<usize>] {
        &self.app_data
    }

    /// Records checked for this association, traffic-key authentication
    /// and replay. Unprotected, replayed and rejected records never appear.
    /// This metadata does not authorize a change of peer address.
    pub fn authenticated_records(&self) -> &[AuthenticatedRecord] {
        &self.authenticated_records
    }
}

/// A DTLS connection, client or server, without I/O.
///
/// Feed it each datagram received from the peer with
/// [`Self::read_datagram`], send what [`Self::write_datagram`] produces
/// until it returns `false` (after every call that may queue something:
/// reads, sends, timeouts, closing), and call [`Self::handle_timeout`] once
/// [`Self::next_timeout`] has passed. Times are durations since any fixed
/// origin of a monotonic clock the caller chooses, used consistently.
///
/// It dereferences to [`CommonState`] for the negotiated parameters and
/// handshake progress; [`CommonState::protocol_version`] reports
/// [`ProtocolVersion::DTLSv1_3`] or [`ProtocolVersion::DTLSv1_2`].
pub struct ConnectionCommon<Data> {
    core: ConnectionCore<Data>,
}

impl<Data: SideData> ConnectionCommon<Data> {
    fn new(mut core: ConnectionCore<Data>) -> Self {
        // Application data stays in the caller's datagram.
        core.common_state.unbuffered = true;
        Self { core }
    }

    fn dtls(&self) -> &Dtls {
        match &self.core.common_state.dtls {
            Some(dtls) => dtls,
            None => unreachable!("DTLS connection without DTLS state"),
        }
    }

    fn dtls_mut(&mut self) -> &mut Dtls {
        dtls_of(&mut self.core.common_state)
    }

    /// Processes one datagram received from the peer, decrypting it in
    /// place.
    ///
    /// Records that do not authenticate, are replayed or cannot be
    /// delimited are dropped silently (RFC 9147 §4.5.2). An error means the
    /// connection failed: send what [`Self::write_datagram`] still produces
    /// (the alert), then stop.
    pub fn read_datagram(&mut self, datagram: &mut [u8], now: Duration) -> Result<Received, Error> {
        let mut state = self.core.take_state()?;
        let mut received = Received::default();
        self.dtls_mut().begin_input();
        let mut at = 0;
        loop {
            let common = &mut self.core.common_state;
            // RFC 9846 §6.1: nothing after close_notify is processed.
            if common.has_received_close_notify {
                break;
            }
            let handshaking = common.is_handshaking();
            let incoming = match dtls_of(common).read_record(datagram, &mut at, handshaking) {
                Ok(incoming) => incoming,
                Err(err) => {
                    let desc = match &err {
                        Error::InvalidMessage(e) => AlertDescription::from(*e),
                        Error::DecryptError => AlertDescription::BadRecordMac,
                        _ => AlertDescription::UnexpectedMessage,
                    };
                    let err = common.send_fatal_alert(desc, err);
                    return Err(self.fail(err));
                }
            };
            if let Some(record) = dtls_of(common).authenticated_record.take() {
                received.authenticated_records.push(record);
            }
            let message = match incoming {
                Incoming::End => break,
                Incoming::Handled => None,
                #[cfg(feature = "tls12")]
                Incoming::ChangeCipherSpec => None,
                Incoming::Alert(level, description) => Some(Message {
                    version: ProtocolVersion::TLSv1_3,
                    payload: MessagePayload::Alert(AlertMessagePayload { level, description }),
                }),
                Incoming::ApplicationData(range) => {
                    let message = Message {
                        version: ProtocolVersion::TLSv1_3,
                        payload: MessagePayload::ApplicationData(Payload::Borrowed(
                            &datagram[range.clone()],
                        )),
                    };
                    state = match ConnectionCore::process_msg(
                        &mut self.core.common_state,
                        &mut self.core.data,
                        state,
                        message,
                    ) {
                        Ok(next) => next,
                        Err(err) => return Err(self.fail(err)),
                    };
                    if core::mem::take(&mut self.core.common_state.app_data_in_place) {
                        received.app_data.push(range);
                    }
                    None
                }
            };
            if let Some(message) = message {
                state = match ConnectionCore::process_msg(
                    &mut self.core.common_state,
                    &mut self.core.data,
                    state,
                    message,
                ) {
                    Ok(next) => next,
                    Err(err) => return Err(self.fail(err)),
                };
            }
            state = self.deliver_handshake(state)?;
        }
        self.core.state = Ok(state);
        self.after_input(now)?;
        if self.core.common_state.has_received_close_notify {
            // Nothing the peer sends is processed any more, its ACKs
            // included.
            self.dtls_mut().peer_closed();
        }
        Ok(received)
    }

    /// Fails the connection with `err`: from now on it only sends the
    /// alerts already queued.
    fn fail(&mut self, err: Error) -> Error {
        self.dtls_mut().abandon();
        self.core.fail(err)
    }

    /// Hands the peer's complete handshake messages, in order, to the
    /// state machine.
    fn deliver_handshake(
        &mut self,
        mut state: Box<dyn crate::conn::State<Data>>,
    ) -> Result<Box<dyn crate::conn::State<Data>>, Error> {
        loop {
            let common = &mut self.core.common_state;
            if common.pending_revocation.is_some()
                || common.pending_certificate_url.is_some()
                || common.has_received_close_notify
            {
                return Ok(state);
            }
            #[cfg(feature = "tls12")]
            if state.expects_dtls12_ccs() && dtls_of(common).take_v12_ccs() {
                state = match ConnectionCore::process_msg(
                    common,
                    &mut self.core.data,
                    state,
                    Message {
                        version: ProtocolVersion::TLSv1_2,
                        payload: MessagePayload::ChangeCipherSpec(
                            crate::msgs::ccs::ChangeCipherSpecPayload,
                        ),
                    },
                ) {
                    Ok(next) => next,
                    Err(err) => return Err(self.fail(err)),
                };
                continue;
            }
            let Some((epoch, bytes)) = dtls_of(common).next_message() else {
                return Ok(state);
            };
            let handshaking = common.is_handshaking();
            match dtls_of(common).handle_cid_message(epoch, &bytes, handshaking) {
                Ok(true) => continue,
                Ok(false) => {}
                Err((alert, err)) => {
                    let err = common.send_fatal_alert(alert, err);
                    return Err(self.fail(err));
                }
            }
            let version = common
                .negotiated_version
                .unwrap_or(ProtocolVersion::TLSv1_2);
            let result =
                match HandshakeMessagePayload::read_dtls(&mut Reader::init(&bytes), version) {
                    Ok(parsed) => {
                        #[cfg(feature = "tls12")]
                        let canonical;
                        let encoded = &bytes;
                        #[cfg(feature = "tls12")]
                        let encoded = if dtls_of(common).is_v12()
                            && bytes.first()
                                != Some(&u8::from(crate::enums::HandshakeType::ClientHello))
                        {
                            canonical = super::v12::canonical(&bytes, dtls_of(common).received_seq);
                            &canonical
                        } else {
                            encoded
                        };
                        ConnectionCore::process_msg(
                            common,
                            &mut self.core.data,
                            state,
                            Message {
                                version,
                                payload: MessagePayload::Handshake {
                                    parsed,
                                    encoded: Payload::Borrowed(encoded),
                                },
                            },
                        )
                    }
                    Err(err) => {
                        Err(common.send_fatal_alert(AlertDescription::from(err), Error::from(err)))
                    }
                };
            state = match result {
                Ok(next) => next,
                Err(err) => return Err(self.fail(err)),
            };
        }
    }

    /// What follows every input: a KeyUpdate owed to the peer or due for
    /// the confidentiality limit, and the acknowledgement decisions.
    fn after_input(&mut self, now: Duration) -> Result<(), Error> {
        if let Err(err) = self.dtls_mut().answer_cid_request() {
            let err = self
                .core
                .common_state
                .send_fatal_alert(AlertDescription::InternalError, err);
            return Err(self.fail(err));
        }
        if !self.dtls().key_update_pending() && self.core.common_state.pending_revocation.is_none()
        {
            self.core.maybe_send_key_update()?;
        }
        let handshaking = self.core.common_state.is_handshaking();
        self.dtls_mut().end_input(handshaking, now);
        Ok(())
    }

    /// Appends the next datagram to send to `out`; returns whether there
    /// was one. Call it until it returns `false`.
    ///
    /// This works after the connection failed too, to send its alert.
    pub fn write_datagram(&mut self, out: &mut Vec<u8>, now: Duration) -> Result<bool, Error> {
        let result = self.dtls_mut().write_datagram(out, now);
        // An ACK may have released the keys of our KeyUpdate; a KeyUpdate
        // that waited for that can go now.
        if result.is_ok()
            && !self.dtls().key_update_pending()
            && self.core.state.is_ok()
            && (self.core.common_state.key_update_owed
                || self.core.common_state.refresh_traffic_keys_pending)
        {
            self.core.maybe_send_key_update()?;
        }
        result
    }

    /// Whether the peer sent `close_notify`; nothing it sends afterwards
    /// is processed.
    pub fn peer_has_closed(&self) -> bool {
        self.core.common_state.has_received_close_notify
    }

    /// Whether [`Self::write_datagram`] has something to send at `now`.
    pub fn wants_write(&self, now: Duration) -> bool {
        self.dtls().wants_write(now)
    }

    /// Seals `data` as one application data record, appended to `out` as
    /// a datagram of its own. Application data is never fragmented: it
    /// must fit one datagram ([`Self::max_application_data`]).
    pub fn send(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        if let Err(err) = &self.core.state {
            return Err(err.clone());
        }
        let common = &mut self.core.common_state;
        if !common.may_send_application_data || common.has_sent_close_notify() {
            return Err(Error::HandshakeNotComplete);
        }
        if dtls_of(common).seal_application_data(out, data)? {
            common.refresh_traffic_keys_pending = true;
        }
        Ok(())
    }

    /// The most application data one [`Self::send`] takes, once the
    /// handshake is complete.
    pub fn max_application_data(&self) -> Option<usize> {
        self.dtls().max_application_data()
    }

    /// The locally issued, nonempty receiving CIDs for wrapper lookup.
    /// All remain valid for this association's lifetime, including IDs in
    /// unacknowledged updates. A lookup match still requires
    /// [`Self::read_datagram`] and its checked metadata before use.
    pub fn local_connection_ids(&self) -> impl Iterator<Item = &[u8]> {
        self.dtls().cid.local_ids()
    }

    /// Issues up to `count` fresh, fixed-length receiving IDs. Returns the
    /// number actually issued; the lifetime cap includes the initial ID.
    /// Only one NewConnectionId may await ACK. An immediate update requires
    /// at least one fresh ID; an exhausted spare response may contain none.
    pub fn issue_connection_ids(
        &mut self,
        count: u8,
        usage: ConnectionIdUsage,
    ) -> Result<usize, Error> {
        self.check_cid_ready()?;
        self.dtls_mut().issue_cids(count, usage)
    }

    /// Requests at most [`super::MAX_CONNECTION_IDS`] peer IDs. A new
    /// request waits for both the previous ACK and a NewConnectionId
    /// response, which may contain fewer IDs, including none.
    pub fn request_connection_ids(&mut self, count: u8) -> Result<(), Error> {
        self.check_cid_ready()?;
        self.dtls_mut().request_cids(count)
    }

    fn check_cid_ready(&self) -> Result<(), Error> {
        if let Err(err) = &self.core.state {
            return Err(err.clone());
        }
        if self.dtls().is_v12() {
            return Err(Error::General(
                "DTLS 1.2 connection IDs do not rotate".into(),
            ));
        }
        if self.core.common_state.is_handshaking() {
            return Err(Error::HandshakeNotComplete);
        }
        if self.core.common_state.has_sent_close_notify()
            || self.core.common_state.has_received_close_notify
        {
            return Err(Error::General("DTLS connection is closed".into()));
        }
        Ok(())
    }

    /// When [`Self::handle_timeout`] is next due, if anything waits on a
    /// timer.
    pub fn next_timeout(&self) -> Option<Duration> {
        self.dtls().next_timeout()
    }

    /// Acts on the timers that expired by `now`: retransmissions and
    /// delayed acknowledgements. Then call [`Self::write_datagram`].
    ///
    /// Fails when the peer acknowledged nothing through repeated
    /// retransmissions.
    pub fn handle_timeout(&mut self, now: Duration) -> Result<(), Error> {
        if let Err(err) = self.dtls_mut().handle_timeout(now) {
            return Err(self.fail(err));
        }
        Ok(())
    }

    /// The largest datagram this connection sends.
    pub fn mtu(&self) -> usize {
        self.dtls().mtu()
    }

    /// Sets the largest datagram this connection sends: the path MTU less
    /// the IP and UDP headers. The default, 1200 bytes, suits any IPv6
    /// path; 256 to 65507 bytes are accepted, provided a selected peer CID
    /// leaves room for a handshake fragment and a one-record ACK. A later
    /// selection of a longer CID can also make `write_datagram` fail until
    /// this limit is raised.
    pub fn set_mtu(&mut self, mtu: usize) -> Result<(), Error> {
        self.dtls_mut().set_mtu(mtu)
    }

    /// Derives keying material bound to this session (RFC 9846 §7.5, with
    /// the DTLS 1.3 label prefix).
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

    /// Updates our sending keys and asks the peer to update theirs
    /// (RFC 9147 §8). While an earlier KeyUpdate of ours awaits its
    /// acknowledgement the update waits for it.
    pub fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        if self.dtls().key_update_pending() {
            self.core.common_state.refresh_traffic_keys_pending = true;
            return Ok(());
        }
        self.core.refresh_traffic_keys()
    }

    /// Supplies the result of the current OCSP query and continues the
    /// handshake with the messages already received.
    pub fn resolve_peer_revocation(
        &mut self,
        id: u64,
        response: crate::revocation::RevocationResponse,
        now: Duration,
    ) -> Result<(), Error> {
        self.core.resolve_peer_revocation(id, response)?;
        let state = self.core.take_state()?;
        self.dtls_mut().begin_input();
        let state = self.deliver_handshake(state)?;
        self.core.state = Ok(state);
        self.after_input(now)
    }
}

fn dtls_of(common: &mut CommonState) -> &mut Dtls {
    match &mut common.dtls {
        Some(dtls) => dtls,
        None => unreachable!("DTLS connection without DTLS state"),
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
        f.debug_struct("dtls::ConnectionCommon")
            .field("common", &self.core.common_state)
            .finish_non_exhaustive()
    }
}

/// A DTLS client connection, using DTLS 1.3 by default.
pub struct ClientConnection {
    inner: ConnectionCommon<crate::client::ClientConnectionData>,
}

impl ClientConnection {
    /// Starts a DTLS 1.3 handshake with `name`. The first ClientHello is
    /// ready for [`ConnectionCommon::write_datagram`] at once.
    ///
    /// The configuration must allow TLS 1.3 and contain a cipher suite
    /// usable with DTLS 1.3 (every TLS 1.3 suite but
    /// TLS_AES_128_CCM_8_SHA256); only those are offered. 0-RTT, Encrypted
    /// Client Hello and post-handshake client authentication are not
    /// supported over DTLS.
    pub fn new(config: Arc<crate::ClientConfig>, name: ServerName<'static>) -> Result<Self, Error> {
        Self::new_with_settings(config, name, Settings::default())
    }

    /// Starts a handshake under an explicit endpoint version policy.
    pub fn new_with_versions(
        config: Arc<crate::ClientConfig>,
        name: ServerName<'static>,
        versions: super::Versions,
    ) -> Result<Self, Error> {
        Self::new_with_settings(config, name, Settings::default().with_versions(versions))
    }

    /// Starts a DTLS client with explicit DTLS-only settings.
    pub fn new_with_settings(
        config: Arc<crate::ClientConfig>,
        name: ServerName<'static>,
        settings: Settings,
    ) -> Result<Self, Error> {
        let mut dtls = Dtls::new(Side::Client, settings);
        dtls.initialize_cids(config.crypto_provider().secure_random)?;
        let core = ConnectionCore::for_dtls_client(config, name, dtls)?;
        Ok(Self {
            inner: ConnectionCommon::new(core),
        })
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
        f.debug_struct("dtls::ClientConnection")
            .finish_non_exhaustive()
    }
}

/// A DTLS server connection, using DTLS 1.3 by default.
pub struct ServerConnection {
    inner: ConnectionCommon<crate::server::ServerConnectionData>,
}

impl ServerConnection {
    /// Prepares to accept a DTLS 1.3 handshake from the client at
    /// `peer_address` (any stable encoding of its transport address).
    ///
    /// A ClientHello without a valid cookie is answered with a
    /// HelloRetryRequest carrying one, bound to `peer_address`, before the
    /// server commits any state or sends anything large (RFC 9147 §5.1).
    /// The configuration must therefore set `hello_retry_cookies`, allow
    /// TLS 1.3 and contain a cipher suite usable with DTLS 1.3.
    pub fn new(config: Arc<crate::ServerConfig>, peer_address: &[u8]) -> Result<Self, Error> {
        Self::new_with_settings(config, peer_address, Settings::default())
    }

    /// Accepts certificate handshakes under an explicit version policy.
    pub fn new_with_versions(
        config: Arc<crate::ServerConfig>,
        peer_address: &[u8],
        versions: super::Versions,
    ) -> Result<Self, Error> {
        Self::new_with_settings(
            config,
            peer_address,
            Settings::default().with_versions(versions),
        )
    }

    /// Prepares a server with DTLS-only settings and cookie exchange.
    /// The caller must keep the transport path pinned at this stage.
    pub fn new_with_settings(
        config: Arc<crate::ServerConfig>,
        peer_address: &[u8],
        mut settings: Settings,
    ) -> Result<Self, Error> {
        settings.peer_address = peer_address.to_vec();
        let mut dtls = Dtls::new(Side::Server, settings);
        dtls.initialize_cids(config.crypto_provider().secure_random)?;
        let core = ConnectionCore::for_dtls_server(config, dtls)?;
        Ok(Self {
            inner: ConnectionCommon::new(core),
        })
    }

    /// Like [`Self::new`], but without the cookie exchange: for paths
    /// where the client's address is already known to be genuine (for
    /// example after ICE, RFC 9147 §5.1). Such a server can be used to
    /// amplify traffic towards a spoofed address otherwise.
    pub fn new_without_cookie_exchange(
        config: Arc<crate::ServerConfig>,
        peer_address: &[u8],
    ) -> Result<Self, Error> {
        Self::new_without_cookie_exchange_with_settings(config, peer_address, Settings::default())
    }

    /// Combines explicit DTLS settings with the already-verified-path
    /// requirement of [`Self::new_without_cookie_exchange`]. The caller
    /// must keep the path pinned; CID authentication does not verify a new
    /// source address.
    pub fn new_without_cookie_exchange_with_settings(
        config: Arc<crate::ServerConfig>,
        peer_address: &[u8],
        mut settings: Settings,
    ) -> Result<Self, Error> {
        settings.require_cookie = false;
        Self::new_with_settings(config, peer_address, settings)
    }

    /// Before anything is processed: the client's ClientHello answers a
    /// HelloRetryRequest that another (stateless) connection sent.
    pub(crate) fn continue_after_stateless_retry(&mut self) {
        dtls_of(&mut self.inner.core.common_state).continue_after_stateless_retry();
    }

    /// Whether all this server has to say is a HelloRetryRequest.
    pub(crate) fn answered_with_retry(&self) -> bool {
        self.inner.dtls().is_hrr_only()
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

    /// Application data to store with the session for later resumption.
    /// Call before the handshake completes.
    pub fn set_resumption_data(&mut self, data: &[u8]) {
        self.inner.core.data.set_resumption_data(data);
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
        f.debug_struct("dtls::ServerConnection")
            .finish_non_exhaustive()
    }
}

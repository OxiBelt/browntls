//! The connection core: feeding records to the handshake state machine and
//! the buffered I/O API around it.

mod buffered;
#[cfg(all(test, feature = "std", feature = "native"))]
mod control_backlog_tests;

use alloc::boxed::Box;
use core::fmt::Debug;
use core::mem;
use core::ops::Range;

pub use buffered::ConnectionCommon;
#[cfg(feature = "std")]
pub use buffered::{Connection, Reader, Writer};

use crate::common_state::{CommonState, IoState};
use crate::enums::{AlertDescription, ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
use crate::msgs::codec::Reader as CodecReader;
use crate::msgs::deframer::{Deframed, DeframerBuffer, DeframerVecBuffer, MessageDeframer};
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{InboundPlainMessage, Message, MessagePayload};
use crate::suites::{ExtractedSecrets, PartiallyExtractedSecrets};

/// One position in the handshake state machine.
pub(crate) trait State<Data>: Send + Sync {
    /// Handles `message`, returning the next state.
    fn handle(
        self: Box<Self>,
        cx: &mut Context<'_, Data>,
        message: Message<'_>,
    ) -> Result<Box<dyn State<Data>>, Error>;

    /// RFC 5705 / RFC 8446 §7.5 keying material export.
    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    /// The current traffic secrets, for kernel offload.
    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        Err(Error::HandshakeNotComplete)
    }

    /// Sends a KeyUpdate carrying `request` under the current write key,
    /// then rotates to the next one (TLS 1.3). The caller has already
    /// applied the RFC 9846 §4.7.3 sending rules.
    fn send_key_update(
        &mut self,
        _common: &mut CommonState,
        _request: KeyUpdateRequest,
    ) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    /// Sends a post-handshake CertificateRequest (TLS 1.3 servers only,
    /// RFC 9846 §4.7.2).
    fn request_client_auth(&mut self, _cx: &mut Context<'_, Data>) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    /// Hook called when a record failed to decrypt.
    fn handle_decrypt_error(&self) {}
}

/// What a state handler sees besides the message.
pub(crate) struct Context<'a, Data> {
    pub(crate) common: &'a mut CommonState,
    pub(crate) data: &'a mut Data,
}

/// Per-side connection data.
///
/// `Send + Sync` so that a [`Writer`], which borrows the whole connection,
/// stays `Send + Sync` like the connection itself.
pub trait SideData: Debug + Send + Sync {
    /// Called once when the connection fails for good, with the version
    /// negotiated so far.
    ///
    /// RFC 5246 §7.2.2: sessions corresponding to a connection that ended
    /// with a fatal alert cannot be resumed.
    #[doc(hidden)]
    fn on_fatal_error(&mut self, _negotiated_version: Option<ProtocolVersion>) {}

    /// Whether the record just processed was 0-RTT data that an unbuffered
    /// server left in place (clears the flag).
    #[doc(hidden)]
    fn take_early_data_in_place(&mut self) -> bool {
        false
    }
}

/// What [`ConnectionCore::process_one`] consumed.
#[derive(Debug)]
pub(crate) enum Processed {
    /// A message that the state machine dealt with entirely.
    Message,
    /// An application data record that an unbuffered connection left in
    /// place: its plaintext, as a range into the buffer's underlying storage
    /// (see [`DeframerBuffer::position`]).
    AppData(Range<usize>),
    /// Like [`Self::AppData`], for 0-RTT data accepted by a server.
    EarlyData(Range<usize>),
}

/// The state after [`ConnectionCore::process_one`], and what it consumed
/// (`None`: no complete unit was buffered).
pub(crate) type Step<Data> = (Box<dyn State<Data>>, Option<Processed>);

/// The state machine plus everything it needs.
pub(crate) struct ConnectionCore<Data> {
    pub(crate) state: Result<Box<dyn State<Data>>, Error>,
    pub(crate) data: Data,
    pub(crate) common_state: CommonState,
    pub(crate) deframer: MessageDeframer,
}

impl<Data: SideData> ConnectionCore<Data> {
    pub(crate) fn new(state: Box<dyn State<Data>>, data: Data, common_state: CommonState) -> Self {
        Self {
            state: Ok(state),
            data,
            common_state,
            deframer: MessageDeframer::default(),
        }
    }

    /// Processes every complete record in `buffer`.
    pub(crate) fn process_new_packets(
        &mut self,
        buffer: &mut DeframerVecBuffer,
    ) -> Result<IoState, Error> {
        let mut state = self.take_state()?;

        if self.common_state.encrypt_failed {
            return Err(self.fail(Error::EncryptError));
        }

        loop {
            if self.common_state.has_received_close_notify {
                // RFC 8446 §6.1: everything after close_notify is ignored.
                break;
            }

            let (next, processed) = self.process_one(state, buffer)?;
            state = next;
            if processed.is_none() {
                break;
            }
        }

        self.state = Ok(state);

        self.maybe_send_key_update()?;

        Ok(self.common_state.current_io_state())
    }

    /// QUIC (RFC 9001 §4.1.3): processes in-order handshake bytes taken from
    /// CRYPTO frames. There is no record layer; the bytes are TLS handshake
    /// messages, possibly fragmented or coalesced.
    pub(crate) fn read_quic_handshake(&mut self, mut data: &[u8]) -> Result<(), Error> {
        let mut state = match mem::replace(&mut self.state, Err(Error::HandshakeNotComplete)) {
            Ok(state) => state,
            Err(e) => {
                self.state = Err(e.clone());
                return Err(e);
            }
        };

        loop {
            let take = data.len().min(self.deframer.joiner.room());
            if take > 0 {
                if let Err(err) = self.deframer.joiner.push(&data[..take]) {
                    let err = match err {
                        Error::InvalidMessage(e) => self
                            .common_state
                            .send_fatal_alert(AlertDescription::from(e), err),
                        other => other,
                    };
                    return Err(self.fail(err));
                }
                data = &data[take..];
            }

            let mut progressed = false;
            while let Some(len) = self.deframer.joiner.complete_message_len() {
                progressed = true;
                let read_level = self.common_state.quic.as_ref().map(|q| q.read_level);
                let version = self
                    .common_state
                    .negotiated_version
                    .unwrap_or(ProtocolVersion::TLSv1_2);
                let bytes = &self.deframer.joiner.buffered()[..len];
                let result = match HandshakeMessagePayload::read_version(
                    &mut CodecReader::init(bytes),
                    version,
                ) {
                    Ok(parsed) => {
                        let msg = Message {
                            version,
                            payload: MessagePayload::Handshake {
                                parsed,
                                encoded: Payload::Borrowed(bytes),
                            },
                        };
                        Self::process_msg(&mut self.common_state, &mut self.data, state, msg)
                    }
                    Err(err) => Err(self
                        .common_state
                        .send_fatal_alert(AlertDescription::from(err), Error::from(err))),
                };
                self.deframer.joiner.consume(len);
                state = match result {
                    Ok(next) => next,
                    Err(err) => return Err(self.fail(err)),
                };

                // RFC 9001 §4.1.3: once the peer moves to a new encryption
                // level, no data of the previous level may remain
                // unconsumed. That is a QUIC PROTOCOL_VIOLATION, not a TLS
                // alert.
                let level_changed =
                    self.common_state.quic.as_ref().map(|q| q.read_level) != read_level;
                if level_changed && (!self.deframer.joiner.is_empty() || !data.is_empty()) {
                    return Err(self.fail(PeerMisbehaved::KeyEpochWithPendingFragment.into()));
                }
            }

            if data.is_empty() {
                break;
            }
            if take == 0 && !progressed {
                // Unreachable: the joiner rejects a declared length that
                // does not fit before it fills up.
                let err = self.common_state.send_fatal_alert(
                    AlertDescription::DecodeError,
                    InvalidMessage::HandshakePayloadTooLarge,
                );
                return Err(self.fail(err));
            }
        }

        self.state = Ok(state);
        Ok(())
    }

    /// Takes the state machine out of `self.state` for processing, or
    /// returns the error that ended the connection.
    pub(crate) fn take_state(&mut self) -> Result<Box<dyn State<Data>>, Error> {
        match mem::replace(&mut self.state, Err(Error::HandshakeNotComplete)) {
            Ok(state) => Ok(state),
            Err(e) => {
                self.state = Err(e.clone());
                Err(e)
            }
        }
    }

    /// Deframes and processes one unit of `buffer`: a whole handshake
    /// message, or one non-handshake record.
    ///
    /// Returns the next state, and `None` instead of a [`Processed`] when
    /// `buffer` holds no complete unit. On error the connection has failed
    /// ([`Self::fail`]) and the state is gone.
    pub(crate) fn process_one(
        &mut self,
        state: Box<dyn State<Data>>,
        buffer: &mut impl DeframerBuffer,
    ) -> Result<Step<Data>, Error> {
        let item = match self.deframer.pop(
            &mut self.common_state.record_layer,
            self.common_state.negotiated_version,
            buffer,
        ) {
            Ok(Some(item)) => item,
            Ok(None) => return Ok((state, None)),
            Err(err) => {
                let err = self.handle_deframe_error(err, &*state);
                return Err(self.fail(err));
            }
        };

        let mut processed = Processed::Message;
        let result = match item {
            Deframed::Handshake { len, version } => {
                let decrypt_epoch = self.common_state.record_layer.read_seq();
                let was_decrypting = self.common_state.record_layer.is_decrypting();
                let bytes = &self.deframer.joiner.buffered()[..len];
                let parse_version = self.common_state.negotiated_version.unwrap_or(version);
                let result = match HandshakeMessagePayload::read_version(
                    &mut CodecReader::init(bytes),
                    parse_version,
                ) {
                    Ok(parsed) => {
                        let msg = Message {
                            version,
                            payload: MessagePayload::Handshake {
                                parsed,
                                encoded: Payload::Borrowed(bytes),
                            },
                        };
                        Self::process_msg(&mut self.common_state, &mut self.data, state, msg)
                    }
                    Err(err) => {
                        let err = self
                            .common_state
                            .send_fatal_alert(AlertDescription::from(err), Error::from(err));
                        Err(err)
                    }
                };
                self.deframer.joiner.consume(len);
                // RFC 8446 §5.1: a handshake message that changes the read
                // key must end its record; nothing may follow it under the
                // old key.
                let key_changed = self.common_state.record_layer.is_decrypting() != was_decrypting
                    || (self.common_state.record_layer.is_decrypting()
                        && self.common_state.record_layer.read_seq() < decrypt_epoch);
                match result {
                    Ok(_) if key_changed && !self.deframer.joiner.is_empty() => {
                        Err(self.common_state.send_fatal_alert(
                            AlertDescription::UnexpectedMessage,
                            PeerMisbehaved::KeyEpochWithPendingFragment,
                        ))
                    }
                    other => other,
                }
            }
            Deframed::Record {
                typ,
                version,
                plaintext,
                consumed,
                want_close_before_decrypt,
            } => {
                if want_close_before_decrypt {
                    self.common_state.send_close_notify();
                }
                // `plaintext` is relative to the buffer as `pop` left it.
                let position = buffer.position();
                let in_storage = position + plaintext.start..position + plaintext.end;
                let payload = &buffer.filled()[plaintext];
                let result = match Message::try_from(InboundPlainMessage {
                    typ,
                    version,
                    payload,
                }) {
                    Ok(msg) => {
                        Self::process_msg(&mut self.common_state, &mut self.data, state, msg)
                    }
                    Err(err) => Err(self
                        .common_state
                        .send_fatal_alert(AlertDescription::from(err), Error::from(err))),
                };
                // Unbuffered connections leave application data where it was
                // decrypted; the state machine only flagged that it took it.
                let app_data = mem::take(&mut self.common_state.app_data_in_place);
                let early_data = self.data.take_early_data_in_place();
                if result.is_ok() {
                    if app_data {
                        processed = Processed::AppData(in_storage);
                    } else if early_data {
                        processed = Processed::EarlyData(in_storage);
                    }
                }
                buffer.discard(consumed);
                result
            }
        };

        match result {
            Ok(new_state) => Ok((new_state, Some(processed))),
            Err(err) => Err(self.fail(err)),
        }
    }

    /// Records `err` as the connection's final state and lets the side data
    /// forget any session the failed connection was using.
    pub(crate) fn fail(&mut self, err: Error) -> Error {
        self.data
            .on_fatal_error(self.common_state.negotiated_version);
        self.state = Err(err.clone());
        err
    }

    fn process_msg(
        common: &mut CommonState,
        data: &mut Data,
        state: Box<dyn State<Data>>,
        msg: Message<'_>,
    ) -> Result<Box<dyn State<Data>>, Error> {
        match &msg.payload {
            MessagePayload::Alert(alert) => {
                common.process_alert(alert)?;
                return Ok(state);
            }
            // Unprotected ChangeCipherSpec records in TLS 1.3 are middlebox
            // compatibility noise (RFC 8446 appendix D.4).
            MessagePayload::ChangeCipherSpec(_)
                if common.is_tls13()
                    || (common.side == crate::common_state::Side::Client
                        && common.negotiated_version.is_none()) =>
            {
                common.process_middlebox_ccs()?;
                return Ok(state);
            }
            // RFC 5246 §7.4.1.1: a client ignores HelloRequest while it is
            // negotiating; once the handshake is done the state machine
            // answers it (with no_renegotiation).
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::HelloRequest),
                ..
            } if common.side == crate::common_state::Side::Client
                && common.is_handshaking()
                && !common.is_tls13() =>
            {
                common.process_hello_request_during_handshake()?;
                return Ok(state);
            }
            // Application data during the handshake is for the state machine
            // to judge: a server may be skipping or reading 0-RTT data, and
            // every other state refuses it with unexpected_message.
            _ => {}
        }

        let mut cx = Context { common, data };
        match state.handle(&mut cx, msg) {
            Ok(next) => Ok(next),
            Err(err) => Err(Self::ensure_alert_sent(cx.common, err)),
        }
    }

    /// Makes sure every fatal error is accompanied by an alert.
    pub(crate) fn ensure_alert_sent(common: &mut CommonState, err: Error) -> Error {
        if common.sent_fatal_alert {
            return err;
        }
        // RFC 9001 makes these a QUIC PROTOCOL_VIOLATION, which has no TLS
        // alert: `quic::ConnectionCommon::alert` stays `None`.
        if common.is_quic()
            && matches!(
                err,
                Error::PeerMisbehaved(
                    PeerMisbehaved::InvalidMaxEarlyDataSize
                        | PeerMisbehaved::NonEmptySessionIdInQuicClientHello
                        | PeerMisbehaved::KeyEpochWithPendingFragment
                        | PeerMisbehaved::UnsolicitedPostHandshakeCertificateRequest
                )
            )
        {
            return err;
        }
        let desc = match &err {
            Error::InvalidMessage(e) => AlertDescription::from(*e),
            Error::InappropriateMessage { .. } | Error::InappropriateHandshakeMessage { .. } => {
                AlertDescription::UnexpectedMessage
            }
            Error::PeerMisbehaved(_) => AlertDescription::IllegalParameter,
            Error::PeerIncompatible(_) => AlertDescription::HandshakeFailure,
            Error::InvalidCertificate(e) => AlertDescription::from(e.clone()),
            Error::InvalidCertRevocationList(_) => AlertDescription::BadCertificate,
            Error::NoCertificatesPresented if common.is_tls13() => {
                AlertDescription::CertificateRequired
            }
            Error::NoCertificatesPresented => AlertDescription::HandshakeFailure,
            Error::DecryptError => AlertDescription::BadRecordMac,
            Error::PeerSentOversizedRecord => AlertDescription::RecordOverflow,
            Error::NoApplicationProtocol => AlertDescription::NoApplicationProtocol,
            Error::AlertReceived(_) => return err,
            _ => AlertDescription::InternalError,
        };
        common.send_fatal_alert(desc, err)
    }

    fn handle_deframe_error(&mut self, err: Error, state: &dyn State<Data>) -> Error {
        match &err {
            Error::DecryptError => {
                state.handle_decrypt_error();
                self.common_state
                    .send_fatal_alert(AlertDescription::BadRecordMac, err)
            }
            Error::PeerSentOversizedRecord => self
                .common_state
                .send_fatal_alert(AlertDescription::RecordOverflow, err),
            Error::InvalidMessage(e) => {
                let desc = AlertDescription::from(*e);
                self.common_state.send_fatal_alert(desc, err)
            }
            Error::PeerMisbehaved(_) => self
                .common_state
                .send_fatal_alert(AlertDescription::UnexpectedMessage, err),
            _ => err,
        }
    }

    pub(crate) fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        if output.is_empty() {
            return Err(Error::general(
                "export_keying_material: output buffer is empty",
            ));
        }
        if context.is_some_and(|c| c.len() > usize::from(u16::MAX)) {
            return Err(Error::general("export_keying_material: context too long"));
        }
        match &self.state {
            Ok(state) => state.export_keying_material(output, label, context),
            Err(err) => Err(err.clone()),
        }
    }

    /// The early exporter (RFC 9846 §7.5); the body of the buffered and
    /// unbuffered `export_early_keying_material`.
    pub(crate) fn export_early_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        if output.is_empty() {
            return Err(Error::general(
                "export_early_keying_material: output buffer is empty",
            ));
        }
        if context.is_some_and(|c| c.len() > usize::from(u16::MAX)) {
            return Err(Error::general(
                "export_early_keying_material: context too long",
            ));
        }
        // Like the regular exporter, nothing is exported once the
        // connection has failed.
        if let Err(err) = &self.state {
            return Err(err.clone());
        }
        match &self.common_state.early_exporter {
            Some(exporter) => exporter.export_keying_material(output, label, context),
            None => Err(Error::General(
                "early exporter unavailable: 0-RTT was not offered, or was rejected".into(),
            )),
        }
    }

    pub(crate) fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        if !self.common_state.enable_secret_extraction {
            return Err(Error::general("Secret extraction is disabled"));
        }
        let st = self.state?;
        let record_layer = &self.common_state.record_layer;
        let PartiallyExtractedSecrets { tx, rx } = st.extract_secrets()?;
        Ok(ExtractedSecrets {
            tx: (record_layer.write_seq(), tx),
            rx: (record_layer.read_seq(), rx),
        })
    }

    /// The public key refresh: rotates our write key and asks the peer to
    /// rotate theirs, unless an earlier request of ours is still unanswered
    /// (then only our key rotates). Fails once the RFC 9846 §4.7.3 epoch
    /// limit is reached.
    pub(crate) fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        let st = match &mut self.state {
            Ok(st) => st,
            Err(e) => return Err(e.clone()),
        };
        // RFC 9846 §6.1: nothing follows our close_notify.
        if self.common_state.has_sent_close_notify() {
            return Ok(());
        }
        let Some(request) = self
            .common_state
            .key_update_to_send(KeyUpdateRequest::UpdateRequested)
        else {
            return Err(Error::EncryptError);
        };
        st.send_key_update(&mut self.common_state, request)?;
        self.common_state.refresh_traffic_keys_pending = false;
        self.common_state.flush_plaintext();
        Ok(())
    }

    /// Sends the KeyUpdate that is due, if any: the single response owed to
    /// the peer's `update_requested` (RFC 9846 §4.7.3), or the refresh that
    /// the confidentiality limit asked for (RFC 9846 §5.5). Neither needs the
    /// peer to update its own key.
    ///
    /// At the epoch limit nothing is sent: the peer's flag is ignored as
    /// RFC 9846 §4.7.3 recommends, and a pending refresh turns into closure
    /// when the confidentiality limit is hit.
    ///
    /// Nothing is sent after our close_notify (RFC 9846 §6.1). A refresh
    /// that comes due before our state can send a KeyUpdate (a server's
    /// half-RTT data) stays pending until the handshake completes.
    pub(crate) fn maybe_send_key_update(&mut self) -> Result<(), Error> {
        let common = &mut self.common_state;
        if !common.key_update_owed && !common.refresh_traffic_keys_pending {
            return Ok(());
        }
        if common.has_sent_close_notify() {
            common.key_update_owed = false;
            common.refresh_traffic_keys_pending = false;
            return Ok(());
        }
        let Some(request) = common.key_update_to_send(KeyUpdateRequest::UpdateNotRequested) else {
            common.key_update_owed = false;
            common.refresh_traffic_keys_pending = false;
            return Ok(());
        };
        match &mut self.state {
            Ok(st) => match st.send_key_update(common, request) {
                Ok(()) => {
                    common.refresh_traffic_keys_pending = false;
                    // Plaintext held back for the refresh can go now.
                    common.flush_plaintext();
                    Ok(())
                }
                Err(Error::HandshakeNotComplete) => Ok(()),
                Err(e) => Err(e),
            },
            Err(e) => Err(e.clone()),
        }
    }

    /// Reads one plaintext handshake message out of `buffer` without
    /// advancing the state machine; used by the server acceptors (buffered
    /// and unbuffered).
    pub(crate) fn first_handshake_message(
        &mut self,
        buffer: &mut impl DeframerBuffer,
    ) -> Result<Option<Message<'static>>, Error> {
        loop {
            match self.deframer.pop(
                &mut self.common_state.record_layer,
                self.common_state.negotiated_version,
                buffer,
            ) {
                Ok(Some(Deframed::Handshake { len, version })) => {
                    let bytes = &self.deframer.joiner.buffered()[..len];
                    let parsed = HandshakeMessagePayload::read_version(
                        &mut CodecReader::init(bytes),
                        ProtocolVersion::TLSv1_2,
                    )
                    .map_err(|e| {
                        self.common_state
                            .send_fatal_alert(AlertDescription::from(e), Error::from(e))
                    })?;
                    let msg = Message {
                        version,
                        payload: MessagePayload::Handshake {
                            parsed,
                            encoded: Payload::Borrowed(bytes),
                        },
                    }
                    .into_owned();
                    self.deframer.joiner.consume(len);
                    return Ok(Some(msg));
                }
                // RFC 9846 §4.3.2: a stateless server may receive the
                // client's compatibility change_cipher_spec ahead of a second
                // ClientHello. It is set aside here, within the usual bound;
                // the handshake refuses it unless the ClientHello continues
                // a stateless HelloRetryRequest.
                Ok(Some(Deframed::Record {
                    typ: ContentType::ChangeCipherSpec,
                    version,
                    plaintext,
                    consumed,
                    ..
                })) => {
                    let payload = &buffer.filled()[plaintext];
                    let result = match Message::try_from(InboundPlainMessage {
                        typ: ContentType::ChangeCipherSpec,
                        version,
                        payload,
                    }) {
                        Ok(_) => self.common_state.process_middlebox_ccs(),
                        Err(err) => Err(self
                            .common_state
                            .send_fatal_alert(AlertDescription::from(err), Error::from(err))),
                    };
                    buffer.discard(consumed);
                    result?;
                }
                Ok(Some(Deframed::Record { typ, .. })) => {
                    return Err(self.common_state.send_fatal_alert(
                        AlertDescription::UnexpectedMessage,
                        Error::InappropriateMessage {
                            expect_types: alloc::vec![ContentType::Handshake],
                            got_type: typ,
                        },
                    ));
                }
                Ok(None) => return Ok(None),
                Err(err) => return Err(self.handle_deframe_error(err, &NoState)),
            }
        }
    }
}

struct NoState;

impl<Data> State<Data> for NoState {
    fn handle(
        self: Box<Self>,
        _cx: &mut Context<'_, Data>,
        _message: Message<'_>,
    ) -> Result<Box<dyn State<Data>>, Error> {
        Err(Error::HandshakeNotComplete)
    }
}

#[allow(dead_code)]
fn log_unused() {
    trace!("");
    debug!("");
    let _ = InvalidMessage::MessageTooShort;
}

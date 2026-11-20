//! TLS 1.3 server early data (RFC 8446 §4.2.10): the decision to accept it
//! and the states that read or skip it.

use alloc::boxed::Box;

use super::traffic::ExpectFinished;
use crate::conn::State;
use crate::enums::{AlertDescription, ContentType, HandshakeType};
use crate::error::PeerMisbehaved;
use crate::hash_hs::HandshakeHash;
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::ServerSessionValue;
use crate::psk::ExternalPskCandidate;
use crate::server::hs::{self, NextStateOrError, ServerContext};
use crate::server::server_conn::{ServerConfig, ServerConnectionData};
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::KeyScheduleTrafficWithClientFinishedPending;

/// The outcome of the client's `early_data` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EarlyDataDecision {
    /// Not requested.
    Disabled,
    /// Requested, but we will not read it.
    RequestedButRejected,
    /// Requested and accepted.
    Accepted,
}

/// How much rejected early data to skip: the configured limit, or one
/// maximum-sized record when early data is off (a client may hold a ticket
/// from when it was on).
pub(super) fn max_early_data_size(configured: u32) -> usize {
    if configured != 0 {
        configured as usize
    } else {
        16384
    }
}

/// RFC 8446 §4.2.10: early data is accepted only with a fresh, first-listed
/// PSK that reproduces the version, suite and ALPN protocol it was issued
/// under, and only with stateful resumption (RFC 8446 §8.1 anti-replay).
pub(super) fn decide_if_early_data_allowed(
    cx: &mut ServerContext<'_>,
    early_data_requested: bool,
    resuming: Option<(usize, &ServerSessionValue)>,
    suite: &'static Tls13CipherSuite,
    config: &ServerConfig,
) -> EarlyDataDecision {
    let rejected_or_disabled = if early_data_requested {
        EarlyDataDecision::RequestedButRejected
    } else {
        EarlyDataDecision::Disabled
    };

    let Some((psk_index, resume)) = resuming else {
        return rejected_or_disabled;
    };

    let early_data_configured = config.max_early_data_size > 0 && !config.ticketer.enabled();
    let early_data_possible = early_data_requested
        && psk_index == 0
        && resume.is_fresh()
        && Some(resume.version) == cx.common.negotiated_version
        && resume.cipher_suite == suite.common.suite
        && resume.alpn.as_ref().map(|p| p.0.as_slice()) == cx.common.alpn_protocol.as_deref();

    if early_data_configured && early_data_possible && !cx.data.early_data.was_rejected() {
        EarlyDataDecision::Accepted
    } else {
        rejected_or_disabled
    }
}

/// RFC 9846 §4.3.10 for an external PSK: early data is accepted only when
/// the key allows it (it is off by default, RFC 9257), was the client's
/// first PSK, and was provisioned with the suite and ALPN protocol now
/// negotiated. There is no anti-replay protection for external PSKs.
pub(super) fn decide_if_external_early_data_allowed(
    cx: &mut ServerContext<'_>,
    early_data_requested: bool,
    candidate: &ExternalPskCandidate,
    suite: &'static Tls13CipherSuite,
    cert_with_extern_psk: bool,
) -> EarlyDataDecision {
    if !early_data_requested {
        return EarlyDataDecision::Disabled;
    }
    let psk = &candidate.psk;
    let possible = candidate.index == 0
        && psk.max_early_data_size() > 0
        && psk.cipher_suite() == Some(suite.common.suite)
        && psk.alpn_protocol() == cx.common.alpn_protocol.as_deref()
        && !cert_with_extern_psk
        // RFC 9000 §7.4.1: QUIC 0-RTT runs under transport parameters
        // remembered from a ticket, which an external PSK does not have.
        && !cx.common.is_quic();
    if possible && !cx.data.early_data.was_rejected() {
        EarlyDataDecision::Accepted
    } else {
        EarlyDataDecision::RequestedButRejected
    }
}

/// Discards a client's early data records (unreadable because its PSK was
/// not taken) up to a limit, then hands everything else to `next`.
pub(super) struct ExpectAndSkipRejectedEarlyData {
    pub(super) skip_data_left: usize,
    pub(super) next: Box<hs::ExpectClientHello>,
}

impl State<ServerConnectionData> for ExpectAndSkipRejectedEarlyData {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        // RFC 8446 §4.2.10: "skipping all records with an external content
        // type of application_data ... up to the configured
        // max_early_data_size". Each record costs at least one byte, so the
        // limit also bounds how many (empty) records are skipped.
        if let MessagePayload::ApplicationData(skip_data) = &m.payload {
            let cost = skip_data.bytes().len().max(1);
            if cost <= self.skip_data_left {
                self.skip_data_left -= cost;
                return Ok(self);
            }
        }
        self.next.handle(cx, m)
    }
}

/// Reads accepted early data until EndOfEarlyData.
pub(super) struct ExpectEarlyData {
    pub(super) config: Arc<ServerConfig>,
    pub(super) transcript: HandshakeHash,
    pub(super) suite: &'static Tls13CipherSuite,
    pub(super) key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    pub(super) send_tickets: usize,
}

impl State<ServerConnectionData> for ExpectEarlyData {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        match &m.payload {
            MessagePayload::ApplicationData(payload) => {
                if cx.data.early_data.take_received_plaintext(payload.bytes()) {
                    Ok(self)
                } else {
                    Err(cx.common.send_fatal_alert(
                        AlertDescription::UnexpectedMessage,
                        PeerMisbehaved::TooMuchEarlyDataReceived,
                    ))
                }
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::EndOfEarlyData),
                ..
            } => {
                let mut st = *self;
                // RFC 8446 §4.5: the client's next records use its handshake
                // key.
                st.key_schedule.update_decrypter(cx.common);
                st.transcript.add_message(&m);
                Ok(Box::new(ExpectFinished {
                    config: st.config,
                    transcript: st.transcript,
                    suite: st.suite,
                    key_schedule: st.key_schedule,
                    send_tickets: st.send_tickets,
                }))
            }
            payload => Err(crate::check::inappropriate_handshake_message(
                payload,
                &[ContentType::ApplicationData, ContentType::Handshake],
                &[HandshakeType::EndOfEarlyData],
            )),
        }
    }
}

//! TLS 1.3 session tickets: their lifetime and NewSessionTicket (RFC 9846
//! §4.7.1).

use browntls_pki::UnixTime;

use crate::enums::ProtocolVersion;
use crate::error::Error;
use crate::hash_hs::HandshakeHash;
use crate::log::{trace, warning};
use crate::msgs::codec::Codec;
use crate::msgs::grease::ServerGreaseValues;
use crate::msgs::handshake::{
    HandshakeMessagePayload, HandshakePayload, NewSessionTicketPayloadTls13,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::ServerSessionValue;
use crate::server::hs::ServerContext;
use crate::server::server_conn::ServerConfig;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::KeyScheduleTraffic;

/// How long a TLS 1.3 session record stays usable, in seconds, when the
/// session cache rather than a ticketer holds it.
const STATEFUL_TICKET_LIFETIME: u32 = 24 * 60 * 60;

/// The `ticket_lifetime` we announce, and honour on resumption: the
/// ticketer's for stateless tickets, [`STATEFUL_TICKET_LIFETIME`] for
/// session-cache lookups, never above seven days (RFC 9846 §4.7.1).
pub(super) fn tls13_ticket_lifetime(config: &ServerConfig) -> u32 {
    let lifetime = if config.ticketer.enabled() {
        config.ticketer.lifetime()
    } else {
        STATEFUL_TICKET_LIFETIME
    };
    lifetime.min(crate::msgs::persist::MAX_TICKET_LIFETIME)
}

fn bound_ticket_lifetime_by_delegated_credential(
    configured_lifetime: u32,
    now: UnixTime,
    delegated_credential_expiry: Option<UnixTime>,
) -> u32 {
    let Some(expiry) = delegated_credential_expiry else {
        return configured_lifetime;
    };
    if now >= expiry {
        return 0;
    }
    let remaining = expiry.as_secs().saturating_sub(now.as_secs());
    configured_lifetime.min(u32::try_from(remaining).unwrap_or(u32::MAX))
}

/// The version a ticket issued on this connection records: TLS 1.3, or
/// DTLS 1.3 so that the ticket only resumes over DTLS (the binder and the
/// key schedule take another label prefix there, RFC 9147 §5.9).
pub(super) fn ticket_version(common: &crate::common_state::CommonState) -> ProtocolVersion {
    match common.is_dtls() {
        true => ProtocolVersion::DTLSv1_3,
        false => ProtocolVersion::TLSv1_3,
    }
}

/// Issues one NewSessionTicket.
pub(super) fn emit_ticket(
    transcript: &HandshakeHash,
    suite: &'static Tls13CipherSuite,
    cx: &mut ServerContext<'_>,
    key_schedule: &KeyScheduleTraffic,
    config: &ServerConfig,
) -> Result<(), Error> {
    // RFC 9846 §4.7.1: a zero lifetime tells the client to discard the
    // ticket at once, so such a ticket is not worth sending.
    let configured_lifetime = tls13_ticket_lifetime(config);
    // RFC 9846 §6.1: nothing follows our close_notify.
    if configured_lifetime == 0 || cx.common.has_sent_close_notify() {
        return Ok(());
    }
    let rng = config.provider.secure_random;
    let nonce = crate::rand::random_vec(rng, 32)?;
    let age_add = crate::rand::random_u32(rng)?;
    // RFC 8701 §4.1: GREASE extensions, fresh for every ticket. Drawn with
    // the other random values, before the session is stored: nothing that
    // can fail follows the store.
    let grease = config
        .enable_grease
        .then(|| ServerGreaseValues::random(rng))
        .transpose()?;
    let secret = key_schedule
        .resumption_master_secret_and_derive_ticket_psk(transcript.current_hash().as_ref(), &nonce);

    let now = config.current_time()?;
    // The session must not outlive a delegated credential that
    // authenticated either side (RFC 9345).
    let lifetime = [
        cx.data.delegated_credential_expiry,
        cx.data.client_delegated_credential_expiry,
    ]
    .into_iter()
    .fold(configured_lifetime, |lifetime, expiry| {
        bound_ticket_lifetime_by_delegated_credential(lifetime, now, expiry)
    });
    if lifetime == 0 {
        return Ok(());
    }
    let mut value = ServerSessionValue::new(
        cx.data.sni.as_ref(),
        ticket_version(cx.common),
        suite.common.suite,
        &secret,
        cx.common.peer_certificates.clone(),
        cx.common.alpn_protocol.clone(),
        cx.data.resumption_data.clone(),
        now,
        age_add,
    );
    value.set_external_psk(
        cx.common
            .external_psk_binding(&config.provider.cipher_suites, &secret)?,
    );
    value.set_delegated_credential_expiry(cx.data.delegated_credential_expiry);
    value.client_delegated_credential_expiry = cx.data.client_delegated_credential_expiry;
    value.certificate_free = cx.data.certificate_free;
    if config.max_early_data_size > 0
        && !config.ticketer.enabled()
        && !cx.common.is_quic()
        && !cx.common.is_dtls()
    {
        value.early_data_record_size_limit = Some(
            cx.common
                .negotiated_receive_record_size_limit()
                .unwrap_or(crate::common_state::max_record_size_limit(true)),
        );
    }
    let plain = value.get_encoding();

    let ticket = if config.ticketer.enabled() {
        match config.ticketer.encrypt(&plain) {
            Some(t) => t,
            None => return Ok(()),
        }
    } else if config.session_storage.can_cache() {
        let id = crate::rand::random_vec(rng, 32)?;
        if !config.session_storage.put(id.clone(), plain) {
            return Ok(());
        }
        id
    } else {
        return Ok(());
    };

    let mut payload = NewSessionTicketPayloadTls13::new(lifetime, age_add, nonce, ticket);
    if config.max_early_data_size > 0 {
        if config.ticketer.enabled() {
            // RFC 8446 §8.1: without a server-side session record there is no
            // single-use guarantee, so 0-RTT is never offered on such tickets.
            warning!("early_data with stateless resumption is not allowed");
        } else {
            payload.exts.max_early_data_size = Some(config.max_early_data_size);
        }
    }
    if let Some(grease) = grease {
        payload.exts.grease_first = Some(grease.first_extension);
        payload.exts.grease_last = Some(grease.last_extension);
    }
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::NewSessionTicketTls13(payload),
        )),
    };
    trace!("sending new ticket {:?}", m);
    cx.common.send_msg(m, true);
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;

    fn at(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    #[test]
    fn delegated_credential_bounds_ticket_lifetime() {
        assert_eq!(
            bound_ticket_lifetime_by_delegated_credential(100, at(1_000), None),
            100
        );
        assert_eq!(
            bound_ticket_lifetime_by_delegated_credential(100, at(1_000), Some(at(1_200))),
            100
        );
        assert_eq!(
            bound_ticket_lifetime_by_delegated_credential(100, at(1_000), Some(at(1_050))),
            50
        );
        assert_eq!(
            bound_ticket_lifetime_by_delegated_credential(100, at(1_000), Some(at(1_000))),
            0
        );
        assert_eq!(
            bound_ticket_lifetime_by_delegated_credential(100, at(1_001), Some(at(1_000))),
            0
        );
    }
}

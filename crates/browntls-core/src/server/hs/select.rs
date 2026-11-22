//! Choices the server makes from a ClientHello: the key exchange group, the
//! certificate types, and what it answers `record_size_limit` and
//! `ticket_request` with.

use alloc::vec::Vec;

use super::ServerContext;
use crate::common_state::CommonState;
use crate::crypto::SupportedKxGroup;
use crate::enums::{AlertDescription, CertificateType, ProtocolVersion};
use crate::error::{Error, PeerIncompatible};
use crate::msgs::enums::{NamedGroup, PskKeyExchangeMode};
use crate::msgs::handshake::ClientHelloPayload;
use crate::server::server_conn::ServerConfig;

/// The `record_size_limit` to send for `version` (RFC 8449 §4): our
/// configured value, clamped to the protocol maximum, when the client sent
/// the extension and the configuration has one.
pub(in crate::server) fn record_size_limit_ack(
    common: &CommonState,
    config: &ServerConfig,
    client_hello: &ClientHelloPayload,
    version: ProtocolVersion,
) -> Option<u16> {
    client_hello.extensions.record_size_limit?;
    common.local_record_size_limit(
        config.record_size_limit,
        version == ProtocolVersion::TLSv1_3,
    )
}

/// How many TLS 1.3 tickets to send, and the RFC 9149 `expected_count` to
/// announce in EncryptedExtensions when the client sent `ticket_request`.
///
/// RFC 9846 §4.7.1: tickets go only to a client whose ClientHello carried a
/// suitable `psk_key_exchange_modes`; `psk_dhe_ke` is the only mode we
/// resume with. RFC 9149 §3: no more tickets than the client asked for, for
/// a resumed session (`resumption_count`) or a new one
/// (`new_session_count`, also when we declined the offered PSK), and never
/// more than `send_tls13_tickets`, our own maximum.
pub(in crate::server) fn tls13_tickets_to_send(
    config: &ServerConfig,
    client_hello: &ClientHelloPayload,
    resumed: bool,
) -> (usize, Option<u8>) {
    let client_takes_tickets = client_hello
        .extensions
        .psk_modes
        .as_ref()
        .is_some_and(|modes| modes.contains(&PskKeyExchangeMode::PSK_DHE_KE));
    let ours = if client_takes_tickets {
        config.send_tls13_tickets
    } else {
        0
    };
    match client_hello.extensions.ticket_request {
        Some(request) => {
            let wanted = match resumed {
                true => request.resumption_count,
                false => request.new_session_count,
            };
            let count = ours.min(usize::from(wanted));
            // `count` is at most `wanted`, a u8.
            (count, u8::try_from(count).ok())
        }
        None => (ours, None),
    }
}

/// The RFC 7250 certificate types to announce, one per direction; `None`
/// when the client did not raise the question.
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::server) struct NegotiatedCertTypes {
    pub(in crate::server) client: Option<CertificateType>,
    pub(in crate::server) server: Option<CertificateType>,
}

/// Picks a certificate type from what the client supports. A side configured
/// for raw public keys only accepts a client that offers them; otherwise X.509
/// is used (and the client must allow it when it sent the extension at all).
pub(super) fn negotiate_cert_type(
    client_supports: &[CertificateType],
    requires_raw_keys: bool,
    cx: &mut ServerContext<'_>,
) -> Result<Option<CertificateType>, Error> {
    let raw = client_supports.contains(&CertificateType::RawPublicKey);
    let x509 = client_supports.contains(&CertificateType::X509);
    match (requires_raw_keys, raw, x509) {
        (true, true, _) => Ok(Some(CertificateType::RawPublicKey)),
        (false, _, true) => Ok(Some(CertificateType::X509)),
        (false, false, false) => Ok(None),
        (true, false, _) | (false, true, false) => Err(cx.common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            PeerIncompatible::IncorrectCertificateTypeExtension,
        )),
    }
}

/// Picks the key exchange group, preferred groups before the non-preferred
/// tier ([`NamedGroup::is_non_preferred`]): within a tier, for TLS 1.3 the
/// first of our groups the client sent a key share for, otherwise the first
/// group both support (a HelloRetryRequest will ask for its share). A key
/// share for a non-preferred group is therefore not accepted while a
/// preferred group is mutually supported.
pub(super) fn choose_kx_group(
    ours: &[&'static dyn SupportedKxGroup],
    theirs: &[NamedGroup],
    client_hello: &ClientHelloPayload,
    version: ProtocolVersion,
) -> Option<&'static dyn SupportedKxGroup> {
    let usable = |g: &&'static dyn SupportedKxGroup| {
        theirs.contains(&g.name()) && g.usable_for_version(version)
    };
    for non_preferred in [false, true] {
        let in_tier = |g: &&'static dyn SupportedKxGroup| {
            usable(g) && g.name().is_non_preferred() == non_preferred
        };
        if version == ProtocolVersion::TLSv1_3
            && let Some(shares) = client_hello.key_shares()
            && let Some(with_share) = ours
                .iter()
                .copied()
                .find(|g| in_tier(g) && shares.iter().any(|s| s.group == g.name()))
        {
            return Some(with_share);
        }
        if let Some(group) = ours.iter().copied().find(in_tier) {
            return Some(group);
        }
    }
    None
}

/// Our groups usable with `version`, in preference order: the preferred
/// tier, then the non-preferred one, each in configuration order.
pub(in crate::server) fn kx_groups_by_preference(
    ours: &[&'static dyn SupportedKxGroup],
    version: ProtocolVersion,
) -> Vec<&'static dyn SupportedKxGroup> {
    [false, true]
        .into_iter()
        .flat_map(|non_preferred| {
            ours.iter().copied().filter(move |g| {
                g.usable_for_version(version) && g.name().is_non_preferred() == non_preferred
            })
        })
        .collect()
}

//! The messages of the TLS 1.3 server's handshake flight: ServerHello or
//! HelloRetryRequest through Finished.

use alloc::vec::Vec;

use super::client_auth::ClientAuthOffer;
use crate::common_state::{CommonState, ConnectionRandoms, Side};
use crate::delegated_credential::DelegatedCredentialKey;
use crate::enums::{AlertDescription, CertificateType, ProtocolVersion, SignatureScheme};
use crate::error::{Error, PeerIncompatible};
use crate::hash_hs::HandshakeHash;
use crate::log::trace;
use crate::msgs::base::{Payload, PayloadU8, PayloadU16};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{Compression, NamedGroup};
use crate::msgs::grease::ServerGreaseValues;
use crate::msgs::handshake::{
    CertificatePayloadTls13, CertificateRequestExtensions, CertificateRequestPayloadTls13,
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, HelloRetryRequest,
    HelloRetryRequestExtensions, KeyShareEntry, ServerExtensions, ServerHelloPayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::server::common::{ActiveCertifiedKey, transparency_info_for};
use crate::server::hs::{self, ServerContext};
use crate::server::server_conn::ServerConfig;
use crate::sign::CertifiedKey;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::{
    KeyScheduleHandshake, KeyScheduleTrafficWithClientFinishedPending,
};
use crate::verify::DigitallySignedStruct;

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_server_hello(
    transcript: &mut HandshakeHash,
    randoms: &mut ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    common: &mut CommonState,
    session_id: &SessionId,
    chosen_psk_index: Option<usize>,
    key_share: KeyShareEntry,
    ech_accepted: bool,
    cert_with_extern_psk: bool,
) {
    let extensions = ServerExtensions {
        key_share: Some(key_share),
        pre_shared_key: chosen_psk_index.and_then(|i| u16::try_from(i).ok()),
        supported_versions: Some(ProtocolVersion::TLSv1_3),
        cert_with_extern_psk: cert_with_extern_psk.then_some(()),
        ..Default::default()
    };
    let mut payload = ServerHelloPayload {
        legacy_version: ProtocolVersion::TLSv1_2,
        random: randoms.server.into(),
        session_id: *session_id,
        cipher_suite: suite.common.suite,
        compression_method: Compression::Null,
        extensions,
    };
    // RFC 9849 §7.2: confirm ECH in the last 8 bytes of the random,
    // computed over the inner transcript with those bytes zeroed. The
    // client random is the inner ClientHello's.
    if ech_accepted {
        payload.random.0[24..].fill(0);
        let zeroed = HandshakeMessagePayload(HandshakePayload::ServerHello(payload.clone()));
        let hash = transcript.hash_with(&zeroed.get_encoding());
        let confirmation = crate::ech::accept_confirmation(
            suite.hkdf_provider,
            &randoms.client,
            crate::ech::ACCEPT_LABEL,
            hash.as_ref(),
        );
        payload.random.0[24..].copy_from_slice(&confirmation);
        randoms.server = payload.random.0;
    }
    let sh = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ServerHello(
            payload,
        ))),
    };
    trace!("sending server hello {:?}", sh);
    transcript.add_message(&sh);
    common.send_msg(sh, false);
}

/// Sends the middlebox-compatibility ChangeCipherSpec (RFC 8446 appendix D.4);
/// never on QUIC, which has no such record (RFC 9001 §8.4).
pub(super) fn emit_fake_ccs(common: &mut CommonState) {
    if common.is_quic() {
        return;
    }
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload),
    };
    common.send_msg(m, false);
}

/// The HelloRetryRequest selecting `suite` and `group`, with `cookie` and
/// no ECH extension.
pub(super) fn hello_retry_request(
    suite: &'static Tls13CipherSuite,
    session_id: SessionId,
    group: NamedGroup,
    cookie: Option<Vec<u8>>,
) -> HelloRetryRequest {
    HelloRetryRequest {
        legacy_version: ProtocolVersion::TLSv1_2,
        session_id,
        cipher_suite: suite.common.suite,
        compression_method: Compression::Null,
        extensions: HelloRetryRequestExtensions {
            key_share: Some(group),
            cookie: cookie.map(PayloadU16::new),
            supported_versions: Some(ProtocolVersion::TLSv1_3),
            encrypted_client_hello: None,
            unknown: Vec::new(),
        },
    }
}

/// The HelloRetryRequest selecting `suite` and `group`, with `cookie`, as
/// a stateless retry sends it (never with ECH). Also used to rebuild it for
/// the transcript.
pub(in crate::server) fn hello_retry_request_message(
    suite: &'static Tls13CipherSuite,
    session_id: SessionId,
    group: NamedGroup,
    cookie: Option<Vec<u8>>,
) -> Message<'static> {
    Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::HelloRetryRequest(hello_retry_request(
                suite, session_id, group, cookie,
            )),
        )),
    }
}

/// What a HelloRetryRequest says about ECH (RFC 9849 §7).
pub(super) enum HrrEch {
    /// Nothing: the client sent no ECH extension, or we have no keys.
    None,
    /// ECH is rejected: 8 random bytes, so the message looks the same as
    /// an acceptance (§7.1, §10.10.4).
    Random,
    /// ECH is accepted: the confirmation, keyed by the first inner
    /// ClientHello's random (§7.2.1).
    Confirm([u8; 32]),
}

/// Sends `hrr` with the ECH extension `ech` calls for.
pub(super) fn emit_hello_retry_request(
    transcript: &mut HandshakeHash,
    mut hrr: HelloRetryRequest,
    suite: &'static Tls13CipherSuite,
    ech: HrrEch,
    common: &mut CommonState,
    rng: &dyn crate::crypto::SecureRandom,
) -> Result<(), Error> {
    match ech {
        HrrEch::None => {}
        HrrEch::Random => {
            let mut random = [0u8; 8];
            rng.fill(&mut random)?;
            hrr.extensions.encrypted_client_hello = Some(random);
        }
        HrrEch::Confirm(inner_random) => {
            hrr.extensions.encrypted_client_hello = Some([0; 8]);
            let zeroed = HandshakeMessagePayload(HandshakePayload::HelloRetryRequest(hrr.clone()));
            let hash = transcript.hash_with(&zeroed.get_encoding());
            hrr.extensions.encrypted_client_hello = Some(crate::ech::accept_confirmation(
                suite.hkdf_provider,
                &inner_random,
                crate::ech::HRR_ACCEPT_LABEL,
                hash.as_ref(),
            ));
        }
    }
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::HelloRetryRequest(hrr),
        )),
    };
    trace!("Requesting retry {:?}", m);
    transcript.add_message(&m);
    common.send_msg(m, false);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_encrypted_extensions(
    transcript: &mut HandshakeHash,
    cx: &mut ServerContext<'_>,
    config: &ServerConfig,
    client_hello: &ClientHelloPayload,
    early_data_accepted: bool,
    cert_types: hs::NegotiatedCertTypes,
    supported_groups: Option<Vec<NamedGroup>>,
    retry_configs: Option<Vec<u8>>,
    expected_tickets: Option<u8>,
) {
    let mut exts = ServerExtensions {
        supported_groups,
        encrypted_client_hello: retry_configs,
        alpn: cx
            .common
            .alpn_protocol
            .clone()
            .map(crate::msgs::handshake::ProtocolName::from),
        server_name_ack: client_hello.sni().map(|_| ()),
        early_data: early_data_accepted.then_some(()),
        client_certificate_type: cert_types.client,
        server_certificate_type: cert_types.server,
        // RFC 9001 §8.2: our transport parameters, on QUIC connections only.
        transport_parameters: cx
            .common
            .quic
            .as_ref()
            .map(|q| Payload::new(q.local_params.clone())),
        // RFC 8449 §4: the TLS 1.3 server answers in EncryptedExtensions.
        // QUIC has no TLS records: never acknowledged there.
        record_size_limit: hs::record_size_limit_ack(
            config,
            client_hello,
            ProtocolVersion::TLSv1_3,
        )
        .filter(|_| !cx.common.is_quic()),
        // RFC 9149 §3: `expected_count`.
        ticket_request: expected_tickets,
        ..Default::default()
    };
    // RFC 8844 §3.2, §4.3: answered in EncryptedExtensions.
    crate::external_binding::handshake::server_answer(
        config.external_binding.as_ref(),
        &client_hello.extensions,
        &mut exts,
    );
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::EncryptedExtensions(exts),
        )),
    };
    trace!("sending encrypted extensions {:?}", m);
    transcript.add_message(&m);
    cx.common.send_msg(m, true);
}

/// Sends a CertificateRequest if the configuration wants client authentication.
pub(super) fn emit_certificate_req_tls13(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    config: &ServerConfig,
) -> Result<Option<ClientAuthOffer>, Error> {
    if !config.verifier.offer_client_auth() {
        return Ok(None);
    }
    let (m, offer) = certificate_request_message(config, Vec::new())?;
    trace!("Sending CertificateRequest {:?}", m);
    transcript.add_message(&m);
    common.send_msg(m, true);
    Ok(Some(offer))
}

/// A CertificateRequest with `context` (empty during the handshake, RFC
/// 9846 §4.4.2) listing the verifier's TLS 1.3 schemes and authorities,
/// and GREASE values (RFC 8701 §4.1) when the configuration enables them.
/// Also returns the schemes the server may accept in the answer.
pub(super) fn certificate_request_message(
    config: &ServerConfig,
    context: Vec<u8>,
) -> Result<(Message<'static>, ClientAuthOffer), Error> {
    let offer = ClientAuthOffer::from_config(config);
    let mut schemes = offer.signature_schemes.clone();
    if schemes.is_empty() {
        return Err(Error::general(
            "client certificate verifier supports no TLS 1.3 signature schemes",
        ));
    }
    // GREASE is only in the message. CertificateVerify uses the real
    // signature schemes recorded in the offer.
    let grease = config
        .enable_grease
        .then(|| ServerGreaseValues::random(config.provider.secure_random))
        .transpose()?;
    if let Some(grease) = &grease {
        schemes.insert(0, SignatureScheme::Unknown(grease.signature_scheme));
    }
    let authorities = config.verifier.root_hint_subjects();
    // RFC 8446 §4.4.2.1: ask for the client's OCSP responses, and its SCTs,
    // when its certificate's revocation status is evaluated.
    let evidence = crate::server::common::client_revocation_enabled(config).then_some(());
    let cr = CertificateRequestPayloadTls13 {
        context: PayloadU8::new(context),
        extensions: CertificateRequestExtensions {
            signature_algorithms: Some(schemes),
            authorities: (!authorities.is_empty()).then(|| authorities.to_vec()),
            certificate_compression: crate::compress::offered_cert_compression(
                &config.cert_decompressors,
                config.cert_decompression_limit,
            ),
            // RFC 9345 §4.1.2: the schemes accepted for a client's
            // delegated credential, when those are enabled.
            delegated_credential: offer.delegated_schemes.clone(),
            status_request: evidence,
            sct_request: evidence,
            grease_first: grease.map(|g| g.first_extension),
            grease_last: grease.map(|g| g.last_extension),
            ..Default::default()
        },
    };
    let message = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateRequestTls13(cr),
        )),
    };
    Ok((message, offer))
}

/// The first delegated credential (RFC 9345) of `server_key` that the
/// client accepts, if it offered the extension: its scheme must be in the
/// client's `delegated_credential` list, the credential's signature scheme
/// in `signature_algorithms` (§4.1.1), and it must be valid for at most
/// seven more days (§4.1.3). Only for X.509 certificates.
pub(super) fn choose_delegated_credential<'a>(
    config: &ServerConfig,
    server_key: &ActiveCertifiedKey<'a>,
    client_hello: &ClientHelloPayload,
    sigschemes: &[SignatureScheme],
    cert_types: hs::NegotiatedCertTypes,
) -> Option<&'a DelegatedCredentialKey> {
    let offered = client_hello.extensions.delegated_credential.as_ref()?;
    if cert_types.server == Some(CertificateType::RawPublicKey) {
        return None;
    }
    let now = config.current_time().ok()?;
    server_key
        .certified_key()
        .choose_delegated_credential(Side::Server, offered, sigschemes, now)
        .map(|dc| &**dc)
}

/// The server's Certificate message for `certified_key`, with what
/// `client_hello` asked for: the OCSP response configured for each entry if
/// it sent `status_request` (RFC 8446 §4.4.2.1), and the end entity's SCT
/// list if it sent `signed_certificate_timestamp` (RFC 6962 §3.3.1).
fn certificate_body<'a>(
    certified_key: &'a CertifiedKey,
    client_hello: &ClientHelloPayload,
    delegated: Option<&DelegatedCredentialKey>,
    server_cert_type: Option<CertificateType>,
) -> CertificatePayloadTls13<'a> {
    let mut cert_body = CertificatePayloadTls13::from_certified_key(
        certified_key,
        client_hello.extensions.certificate_status_request.is_some(),
        client_hello.extensions.sct_request.is_some(),
    );
    // RFC 9162 §6.5: the TransItemList goes on the end entity's entry.
    if let Some(list) = transparency_info_for(certified_key, client_hello, server_cert_type) {
        cert_body.set_transparency_info(list);
    }
    // RFC 9345 §4.1.1: the credential goes on the end entity's entry.
    if let (Some(dc), Some(first)) = (delegated, cert_body.entries.first_mut()) {
        first.delegated_credential = Some(dc.credential().clone());
    }
    cert_body
}

/// Sends the Certificate (or CompressedCertificate) message for
/// `certified_key`, the credential `server_key` was made from.
pub(super) fn emit_certificate_tls13(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    config: &ServerConfig,
    certified_key: &CertifiedKey,
    client_hello: &ClientHelloPayload,
    delegated: Option<&DelegatedCredentialKey>,
    server_cert_type: Option<CertificateType>,
) {
    let cert_body = certificate_body(certified_key, client_hello, delegated, server_cert_type);

    // RFC 8879 §4: compress when the client offered an algorithm we have.
    if let Some(offered) = &client_hello.extensions.certificate_compression
        && let Some(compressed) = crate::compress::compress_certificate(
            &config.cert_compressors,
            &config.cert_compression_cache,
            offered,
            &cert_body.get_encoding(),
        )
    {
        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::CompressedCertificate(compressed),
            )),
        };
        transcript.add_message(&m);
        common.send_msg(m, true);
        return;
    }

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateTls13(cert_body),
        )),
    };
    trace!("sending certificate {:?}", m);
    transcript.add_message(&m);
    common.send_msg(m, true);
}

pub(super) fn emit_certificate_verify_tls13(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    server_key: &ActiveCertifiedKey<'_>,
    schemes: &[SignatureScheme],
    delegated: Option<&DelegatedCredentialKey>,
) -> Result<(), Error> {
    let message = crate::client::tls13::construct_server_verify_message(&transcript.current_hash());
    // RFC 9345 §4.1.1: with a delegated credential, its key signs with the
    // credential's scheme (checked to be possible when it was attached).
    let signer = match delegated {
        Some(dc) => dc
            .key()
            .choose_scheme(&[dc.credential().credential.dc_cert_verify_algorithm]),
        None => server_key.get_key().choose_scheme(schemes),
    };
    let signer = signer.ok_or_else(|| {
        common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            PeerIncompatible::NoSignatureSchemesInCommon,
        )
    })?;
    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let cv = DigitallySignedStruct::new(scheme, sig);
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateVerify(cv),
        )),
    };
    trace!("sending certificate-verify {:?}", m);
    transcript.add_message(&m);
    common.send_msg(m, true);
    Ok(())
}

pub(super) fn emit_finished_tls13(
    transcript: &mut HandshakeHash,
    randoms: &ConnectionRandoms,
    cx: &mut ServerContext<'_>,
    key_schedule: KeyScheduleHandshake,
    config: &ServerConfig,
) -> KeyScheduleTrafficWithClientFinishedPending {
    let handshake_hash = transcript.current_hash();
    let verify_data = key_schedule.sign_server_finish(handshake_hash.as_ref());
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Finished(
            Payload::new(verify_data.as_ref().to_vec()),
        ))),
    };
    trace!("sending finished {:?}", m);
    transcript.add_message(&m);
    let hash_at_server_fin = transcript.current_hash();
    cx.common.send_msg(m, true);

    // The server starts sending application data under the application
    // traffic secret right away.
    key_schedule.into_traffic_with_client_finished_pending(
        hash_at_server_fin.as_ref(),
        &*config.key_log,
        &randoms.client,
        cx.common,
    )
}

#[cfg(test)]
mod tests;

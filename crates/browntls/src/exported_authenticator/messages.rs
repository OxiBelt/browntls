//! The wire format of authenticator requests and authenticators: framing,
//! parsing and building requests, and the bytes a CertificateVerify signs.

use alloc::vec::Vec;

use super::{
    AuthenticatorRequestExtensions, CERTIFICATE_REQUEST, CLIENT_CERTIFICATE_REQUEST,
    SIGNATURE_CONTEXT,
};
use crate::common_state::Side;
use crate::enums::SignatureScheme;
use crate::error::{Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::msgs::base::PayloadU8;
use crate::msgs::codec::{Codec, Reader, u24};
use crate::msgs::handshake::{
    CertificateRequestExtensions, CertificateRequestPayloadTls13, MAX_HANDSHAKE_SIZE,
};

/// The bytes a CertificateVerify signs (RFC 9261 §5.2.2).
pub(super) fn signed_message(transcript_hash: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64 + SIGNATURE_CONTEXT.len() + 1 + transcript_hash.len());
    msg.resize(64, 0x20);
    msg.extend_from_slice(SIGNATURE_CONTEXT);
    msg.push(0);
    msg.extend_from_slice(transcript_hash);
    msg
}

/// A handshake message: type, 24-bit length, body.
pub(super) fn frame(typ: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u24::from_usize(body.len())
        .filter(|len| len.0 <= MAX_HANDSHAKE_SIZE)
        .ok_or_else(|| Error::General("exported authenticator message too large".into()))?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(typ);
    len.encode(&mut out);
    out.extend_from_slice(body);
    Ok(out)
}

/// Reads one handshake message: (type, body).
pub(super) fn read_message<'a>(r: &mut Reader<'a>) -> Result<(u8, &'a [u8]), InvalidMessage> {
    let typ = u8::read(r)?;
    let len = u24::read(r)?.0;
    if len > MAX_HANDSHAKE_SIZE {
        return Err(InvalidMessage::HandshakePayloadTooLarge);
    }
    let body = r.take(len as usize).ok_or(InvalidMessage::MissingData(
        "exported authenticator message",
    ))?;
    Ok((typ, body))
}

/// A parsed authenticator request.
pub(super) struct Request<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) context: Vec<u8>,
    pub(super) schemes: Vec<SignatureScheme>,
}

pub(super) fn parse_request(bytes: &[u8], expected_type: u8) -> Result<Request<'_>, Error> {
    let mut r = Reader::init(bytes);
    let (typ, body) = read_message(&mut r)?;
    r.expect_empty("authenticator request")?;
    if typ != expected_type {
        return Err(InvalidMessage::UnexpectedMessage("authenticator request type").into());
    }
    let req = CertificateRequestPayloadTls13::read_bytes(body)?;
    // RFC 9846 §4.3 applies to the extensions as in a CertificateRequest.
    if crate::tls13::extensions::first_disallowed(
        req.extensions.unknown.iter().copied(),
        crate::tls13::extensions::Tls13Message::CertificateRequest,
    )
    .is_some()
    {
        return Err(PeerMisbehaved::DisallowedCertificateRequestExtension.into());
    }
    // RFC 9261 §4: signature_algorithms MUST be present.
    let Some(schemes) = req.extensions.signature_algorithms else {
        return Err(PeerIncompatible::SignatureAlgorithmsExtensionRequired.into());
    };
    if req.context.0.is_empty() {
        return Err(PeerMisbehaved::IllegalCertificateRequestContext.into());
    }
    Ok(Request {
        bytes,
        context: req.context.0,
        schemes: tls13_schemes(&schemes),
    })
}

pub(super) fn tls13_schemes(schemes: &[SignatureScheme]) -> Vec<SignatureScheme> {
    schemes
        .iter()
        .copied()
        .filter(SignatureScheme::supported_in_tls13)
        .collect()
}

/// Builds a request from `requester` (RFC 9261 §4).
pub(super) fn make_request(
    requester: Side,
    context: &[u8],
    extensions: &AuthenticatorRequestExtensions,
    default_schemes: Vec<SignatureScheme>,
) -> Result<Vec<u8>, Error> {
    if context.is_empty() || context.len() > 255 {
        return Err(Error::General(
            "certificate_request_context must be 1 to 255 bytes".into(),
        ));
    }
    let schemes = tls13_schemes(
        extensions
            .signature_schemes
            .as_deref()
            .unwrap_or(&default_schemes),
    );
    if schemes.is_empty() {
        return Err(Error::General(
            "an authenticator request needs a TLS 1.3 signature scheme".into(),
        ));
    }
    let payload = CertificateRequestPayloadTls13 {
        context: PayloadU8::new(context.to_vec()),
        extensions: CertificateRequestExtensions {
            signature_algorithms: Some(schemes),
            authorities: extensions.certificate_authorities.clone(),
            ..Default::default()
        },
    };
    let typ = match requester {
        Side::Client => CLIENT_CERTIFICATE_REQUEST,
        Side::Server => CERTIFICATE_REQUEST,
    };
    frame(typ, &payload.get_encoding())
}

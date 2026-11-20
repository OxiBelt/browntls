//! The server side of RFC 7924 in a full TLS 1.2 handshake: deciding which
//! messages to replace by their fingerprint.

use super::{
    CachedInformationType, CachedInformationTypes, ClientHelloCachedInfo, FINGERPRINT_LEN,
    ServerCachedInfoPolicy, ServerHelloCachedInfo, codec, fingerprint,
};
use crate::crypto::CryptoProvider;
use crate::log::debug;
use crate::msgs::codec::Codec;
use crate::msgs::handshake::HandshakeMessagePayload;

/// The Certificate and CertificateRequest messages of a full TLS 1.2
/// handshake, each in full or replaced by its fingerprint, and the
/// ServerHello answer saying which.
pub(crate) struct ServerCachedInfo {
    /// The Certificate message to send.
    pub(crate) certificate: HandshakeMessagePayload<'static>,
    /// The CertificateRequest message to send, if any.
    pub(crate) certificate_request: Option<HandshakeMessagePayload<'static>>,
    replaced: CachedInformationTypes,
}

impl ServerCachedInfo {
    /// Replaces `certificate` and `certificate_request` (the full messages
    /// the server is about to send) by their fingerprint where `policy`
    /// allows it and the client's `offer` holds exactly that fingerprint
    /// (RFC 7924 §4.1, §4.2). Any other offer, an unknown type or a hash of
    /// another length included, leaves the message in full (§4: a stale
    /// cache falls back).
    pub(crate) fn new(
        policy: &ServerCachedInfoPolicy,
        provider: &CryptoProvider,
        offer: Option<&ClientHelloCachedInfo>,
        certificate: HandshakeMessagePayload<'static>,
        certificate_request: Option<HandshakeMessagePayload<'static>>,
    ) -> Self {
        let mut out = Self {
            certificate,
            certificate_request,
            replaced: CachedInformationTypes::default(),
        };
        let Some(offer) = offer else {
            return out;
        };
        if let Some(short) = replace(
            policy,
            provider,
            offer,
            CachedInformationType::Cert,
            &out.certificate,
        ) {
            out.certificate = short;
            out.replaced.insert(CachedInformationType::Cert);
        }
        if let Some(full) = &out.certificate_request
            && let Some(short) = replace(
                policy,
                provider,
                offer,
                CachedInformationType::CertReq,
                full,
            )
        {
            out.certificate_request = Some(short);
            out.replaced.insert(CachedInformationType::CertReq);
        }
        out
    }

    /// The ServerHello extension: the replaced types, or `None`.
    pub(crate) fn extension(&self) -> Option<ServerHelloCachedInfo> {
        ServerHelloCachedInfo::from_types(self.replaced)
    }

    /// The types replaced by their fingerprint.
    pub(crate) fn replaced(&self) -> CachedInformationTypes {
        self.replaced
    }
}

/// The hash form of `full` when the client offered its fingerprint.
fn replace(
    policy: &ServerCachedInfoPolicy,
    provider: &CryptoProvider,
    offer: &ClientHelloCachedInfo,
    typ: CachedInformationType,
    full: &HandshakeMessagePayload<'_>,
) -> Option<HandshakeMessagePayload<'static>> {
    if !policy.allows(typ) {
        return None;
    }
    let mut offered = offer
        .entries()
        .filter(|(code, hash)| *code == typ.code() && hash.len() == FINGERPRINT_LEN)
        .peekable();
    offered.peek()?;
    let ours = fingerprint(provider, &full.get_encoding()).ok()?;
    if offered.any(|(_, hash)| hash == ours.as_slice()) {
        debug!("Sending {:?} as its cached_info fingerprint", typ);
        Some(codec::hash_form_message(typ.handshake_type(), &ours))
    } else {
        debug!("Client's cached {:?} is stale; sending it in full", typ);
        None
    }
}

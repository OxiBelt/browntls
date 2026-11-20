//! The client side of RFC 7924 in a TLS 1.2 handshake: the offer, the
//! server's acknowledgement, restoring replaced messages, and storing
//! messages received in full once the handshake completed.

use alloc::vec::Vec;

use browntls_pki::ServerName;

use super::{
    CachedInformationType, CachedInformationTypes, CachedObject, ClientCachedInfoStore,
    ClientHelloCachedInfo, MAX_OFFERED_PER_TYPE, ServerHelloCachedInfo, codec,
};
use crate::client::ClientConfig;
use crate::common_state::CommonState;
use crate::enums::{AlertDescription, ContentType, HandshakeType};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::log::debug;
use crate::msgs::handshake::{
    CertificateChain, CertificateRequestPayload, HandshakeMessagePayload, HandshakePayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::sync::Arc;

/// One handshake's use of the client's store: what the ClientHello offered,
/// what the server acknowledged, and the messages received in full.
#[derive(Debug)]
pub(crate) struct ClientCachedInfo {
    store: Arc<dyn ClientCachedInfoStore>,
    offered_cert: Vec<Arc<CachedObject>>,
    offered_cert_req: Vec<Arc<CachedObject>>,
    acknowledged: CachedInformationTypes,
    /// Complete messages received in this handshake, for the store once it
    /// completes.
    received: Vec<(CachedInformationType, Vec<u8>)>,
}

impl ClientCachedInfo {
    /// The store's objects for `server_name`, when the configuration has a
    /// store and the ClientHello offers TLS 1.2 (`tls12_offered`, false with
    /// an ECH offer or on QUIC).
    pub(crate) fn offer(
        config: &ClientConfig,
        server_name: &ServerName<'_>,
        tls12_offered: bool,
    ) -> Option<Self> {
        let store = config.cached_info.clone().filter(|_| tls12_offered)?;
        let lookup = |typ| {
            let mut objects = store.lookup(server_name, typ);
            // Only what we can match: our type and a SHA-256 fingerprint
            // (an application's store may hold anything).
            objects.retain(|object| object.typ() == typ);
            objects.truncate(MAX_OFFERED_PER_TYPE);
            objects
        };
        let offered_cert = lookup(CachedInformationType::Cert);
        let offered_cert_req = lookup(CachedInformationType::CertReq);
        Some(Self {
            store,
            offered_cert,
            offered_cert_req,
            acknowledged: CachedInformationTypes::default(),
            received: Vec::new(),
        })
    }

    /// The ClientHello extension, or `None` when there is nothing to offer.
    pub(crate) fn extension(&self) -> Option<ClientHelloCachedInfo> {
        ClientHelloCachedInfo::from_objects(
            self.offered_cert
                .iter()
                .chain(&self.offered_cert_req)
                .map(|object| &**object),
        )
    }

    fn offered(&self, typ: CachedInformationType) -> &[Arc<CachedObject>] {
        match typ {
            CachedInformationType::Cert => &self.offered_cert,
            CachedInformationType::CertReq => &self.offered_cert_req,
        }
    }

    /// The offered object whose fingerprint a hash-form message `body`
    /// carries (RFC 7924 §4.1, §4.2).
    fn restore(
        &self,
        common: &mut CommonState,
        typ: CachedInformationType,
        body: &[u8],
    ) -> Result<Arc<CachedObject>, Error> {
        let hash = codec::read_hash_form(body)
            .map_err(|err| common.send_fatal_alert(AlertDescription::DecodeError, err))?;
        // Exact and full length: a shortened or different hash matches
        // nothing.
        let object = self
            .offered(typ)
            .iter()
            .find(|object| object.fingerprint().as_slice() == hash)
            .cloned()
            .ok_or_else(|| {
                common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::UnofferedCachedInfoFingerprint,
                )
            })?;
        debug!("Restored {:?} from the cached_info store", typ);
        common.cached_info.replaced.insert(typ);
        Ok(object)
    }

    /// Keeps `m`, received in full, for the store; refuses it with
    /// `decode_error` when the server acknowledged `typ` and so owes its
    /// hash form. Parsing already reads such a message as a hash form
    /// ([`super::read_handshake`]); this fails closed should a parse path
    /// miss that.
    fn full_message(
        &mut self,
        common: &mut CommonState,
        typ: CachedInformationType,
        m: &Message<'_>,
    ) -> Result<(), Error> {
        if self.acknowledged.contains(typ) {
            return Err(common.send_fatal_alert(
                AlertDescription::DecodeError,
                InvalidMessage::UnexpectedMessage("full message in place of a cached_info hash"),
            ));
        }
        if let MessagePayload::Handshake { encoded, .. } = &m.payload {
            self.received.push((typ, encoded.bytes().to_vec()));
        }
        Ok(())
    }

    /// Stores the messages received in full. Called once the handshake has
    /// completed: the server's Finished verified, after its certificate
    /// chain was (RFC 7924 §7).
    pub(crate) fn handshake_completed(
        self,
        config: &ClientConfig,
        server_name: &ServerName<'static>,
    ) {
        for (typ, message) in self.received {
            match CachedObject::new(config.crypto_provider(), typ, message) {
                Ok(object) => self.store.insert(server_name.clone(), Arc::new(object)),
                Err(_err) => debug!("Not caching {:?}: {:?}", typ, _err),
            }
        }
    }
}

/// Checks the server's `cached_info` answer in a TLS 1.2 ServerHello (RFC
/// 7924 §4): only types we offered objects of, each at most once; anything
/// else is `illegal_parameter`. The answer is acted on by
/// [`expect_hash_forms`] in a full handshake only.
///
/// The unsolicited-extension check has already refused an answer to a
/// ClientHello without the extension.
pub(crate) fn process_server_hello(
    common: &mut CommonState,
    offer: Option<&mut ClientCachedInfo>,
    answer: Option<&ServerHelloCachedInfo>,
) -> Result<(), Error> {
    let Some(answer) = answer else {
        return Ok(());
    };
    let Some(offer) = offer else {
        return Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::UnsolicitedServerHelloExtension,
        ));
    };
    let mut acknowledged = CachedInformationTypes::default();
    for &code in answer.codes() {
        match CachedInformationType::from_code(code) {
            Some(typ) if !offer.offered(typ).is_empty() && !acknowledged.contains(typ) => {
                acknowledged.insert(typ);
            }
            _ => {
                return Err(common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnofferedCachedInfo,
                ));
            }
        }
    }
    offer.acknowledged = acknowledged;
    Ok(())
}

/// In a full handshake, makes the deframing read the acknowledged messages
/// in their hash form (see [`super::read_handshake`]). An abbreviated
/// handshake has neither message, so an acknowledgement there is ignored.
pub(crate) fn expect_hash_forms(common: &mut CommonState, offer: Option<&ClientCachedInfo>) {
    common.cached_info.expect_hash_form = offer.map(|o| o.acknowledged).unwrap_or_default();
}

/// The server's certificate chain from its Certificate message `m`: the
/// chain `m` carries, or, when the server acknowledged `cert`, the chain of
/// the offered object whose fingerprint `m` carries. Either way the caller
/// verifies it as usual.
pub(crate) fn take_certificate(
    common: &mut CommonState,
    offer: Option<&mut ClientCachedInfo>,
    m: &Message<'_>,
) -> Result<CertificateChain<'static>, Error> {
    let typ = CachedInformationType::Cert;
    common.cached_info.expect_hash_form.remove(typ);
    match (offer, &m.payload) {
        (
            Some(offer),
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload(HandshakePayload::Unknown((
                        HandshakeType::Certificate,
                        body,
                    ))),
                ..
            },
        ) if offer.acknowledged.contains(typ) => {
            let object = offer.restore(common, typ, body.bytes())?;
            object.certificate_chain()
        }
        (
            offer,
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::Certificate(chain)),
                ..
            },
        ) => {
            if let Some(offer) = offer {
                offer.full_message(common, typ, m)?;
            }
            Ok(chain.clone().into_owned())
        }
        (_, payload) => Err(crate::check::inappropriate_handshake_message(
            payload,
            &[ContentType::Handshake],
            &[HandshakeType::Certificate],
        )),
    }
}

/// The CertificateRequest the server replaced by its fingerprint, when `m`
/// is one (the server acknowledged `cert_req`); `None` for any other
/// message, which the caller handles as usual. A CertificateRequest
/// received in full is kept for the store.
///
/// A server may acknowledge `cert_req` and then not ask for a certificate
/// at all: there is then no CertificateRequest to replace.
pub(crate) fn restored_certificate_request(
    common: &mut CommonState,
    offer: Option<&mut ClientCachedInfo>,
    m: &Message<'_>,
) -> Result<Option<CertificateRequestPayload>, Error> {
    let typ = CachedInformationType::CertReq;
    common.cached_info.expect_hash_form.remove(typ);
    let Some(offer) = offer else {
        return Ok(None);
    };
    match &m.payload {
        MessagePayload::Handshake {
            parsed:
                HandshakeMessagePayload(HandshakePayload::Unknown((
                    HandshakeType::CertificateRequest,
                    body,
                ))),
            ..
        } if offer.acknowledged.contains(typ) => {
            let object = offer.restore(common, typ, body.bytes())?;
            object.certificate_request().map(Some)
        }
        MessagePayload::Handshake {
            parsed: HandshakeMessagePayload(HandshakePayload::CertificateRequest(_)),
            ..
        } => {
            offer.full_message(common, typ, m)?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

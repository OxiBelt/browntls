//! The client side of the `transparency_info` extension (RFC 9162 §6.5):
//! when it is offered, where an answer is accepted, and what is kept of it.
//! See [`crate::transparency`].

use alloc::vec::Vec;

use super::ClientConfig;
use crate::common_state::CommonState;
use crate::enums::AlertDescription;
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::handshake::{CertificatePayloadTls13, ServerExtensions};
use crate::transparency::TransparencyStatus;

/// The server's Certificate Transparency 2.0 items and their evaluation.
#[derive(Debug, Default)]
pub(crate) struct PeerTransparency {
    /// The `extension_data` received in a full handshake, unverified.
    pub(crate) info: Option<Vec<u8>>,
    /// What the verifier reported.
    pub(crate) status: Option<TransparencyStatus>,
}

impl ClientConfig {
    /// Whether the ClientHello offers `transparency_info`: when the
    /// verifier asks for it or the application wants the raw items, and
    /// never with a raw-public-key verifier, which has no certificate a
    /// log could cover.
    pub(crate) fn offers_transparency_info(&self) -> bool {
        (self.request_transparency_info || self.verifier.requests_transparency_info())
            && !self.verifier.requires_raw_public_keys()
    }
}

/// Checks the `transparency_info` extensions of a server's TLS 1.3
/// Certificate and returns the end entity's. `offered` is whether the
/// ClientHello the server answered carried the extension.
///
/// One we did not offer is `unsupported_extension` (RFC 9846 §4.4.2). RFC
/// 9162 says nothing of one on another entry than the end entity's: it
/// cannot be about the server's certificate, so it is ignored rather than
/// refused and never reaches the verifier.
pub(super) fn tls13_end_entity_list(
    common: &mut CommonState,
    offered: bool,
    cert_chain: &CertificatePayloadTls13<'_>,
) -> Result<Option<Vec<u8>>, Error> {
    if !cert_chain.has_transparency_info() {
        return Ok(None);
    }
    if !offered {
        return Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::UnsolicitedTransparencyInfo,
        ));
    }
    Ok(cert_chain
        .end_entity_transparency_info()
        .map(<[u8]>::to_vec))
}

/// Refuses `transparency_info` in a TLS 1.2 ServerHello that resumes a
/// session: RFC 9162 §6.5 has the server omit it then, and §8.1.1 has the
/// client abort the handshake. Answered with `illegal_parameter`, as for a
/// recognised extension where it may not appear (RFC 9846 §4.3).
pub(super) fn refuse_on_resumption(
    common: &mut CommonState,
    extensions: &ServerExtensions,
) -> Result<(), Error> {
    if extensions.transparency_info.is_some() {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::TransparencyInfoOnResumption,
        ));
    }
    Ok(())
}

#[cfg(all(test, feature = "native"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::common_state::Side;
    use crate::enums::SignatureScheme;
    use crate::msgs::base::Payload;
    use crate::pki_types::{CertificateDer, ServerName, UnixTime};
    use crate::sync::Arc;
    use crate::verify::{
        DigitallySignedStruct, HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };

    /// Never consulted for a certificate: only what it asks for matters
    /// here.
    #[derive(Debug)]
    struct Unused {
        requests: bool,
        raw_keys: bool,
    }

    impl ServerCertVerifier for Unused {
        fn requests_transparency_info(&self) -> bool {
            self.requests
        }

        fn requires_raw_public_keys(&self) -> bool {
            self.raw_keys
        }

        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Err(Error::General("unused".into()))
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("unused".into()))
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("unused".into()))
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    fn config(requests: bool, raw_keys: bool) -> ClientConfig {
        ClientConfig::builder_with_provider(crate::crypto::native::default_provider().into())
            .with_protocol_versions(&[&crate::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Unused { requests, raw_keys }))
            .with_no_client_auth()
    }

    #[test]
    fn offered_on_request_and_never_with_raw_public_keys() {
        let mut plain = config(false, false);
        assert!(!plain.offers_transparency_info());
        plain.request_transparency_info = true;
        assert!(plain.offers_transparency_info());
        assert!(config(true, false).offers_transparency_info());

        // A raw public key has no certificate a log could cover.
        let mut raw = config(true, true);
        assert!(!raw.offers_transparency_info());
        raw.request_transparency_info = true;
        assert!(!raw.offers_transparency_info());
    }

    #[test]
    fn only_the_end_entity_list_is_kept() {
        let certs = [CertificateDer::from(vec![1]), CertificateDer::from(vec![2])];
        let mut chain = CertificatePayloadTls13::new(certs.iter(), None);
        let mut common = CommonState::new(Side::Client);
        assert_eq!(tls13_end_entity_list(&mut common, true, &chain), Ok(None));
        // On an intermediate's entry it is ignored.
        chain.entries[1].transparency_info = Some(Payload::Borrowed(&[0, 0]));
        assert_eq!(tls13_end_entity_list(&mut common, true, &chain), Ok(None));
        chain.entries[0].transparency_info = Some(Payload::Borrowed(&[7]));
        assert_eq!(
            tls13_end_entity_list(&mut common, true, &chain),
            Ok(Some(vec![7]))
        );
        // Not offered in the ClientHello: refused.
        assert_eq!(
            tls13_end_entity_list(&mut common, false, &chain),
            Err(PeerMisbehaved::UnsolicitedTransparencyInfo.into())
        );
    }
}

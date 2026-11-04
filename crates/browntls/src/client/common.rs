//! Types shared by the TLS 1.2 and TLS 1.3 client handshakes.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::ResolvesClientCert;
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::log::{debug, trace};
use crate::msgs::enums::{ClientCertificateType, ExtensionType};
use crate::msgs::handshake::{CertificateChain, DistinguishedName};
use crate::sign::{CertifiedKey, Signer};
use crate::sync::Arc;

/// What the server presented to authenticate itself.
pub(super) struct ServerCertDetails {
    pub(super) cert_chain: CertificateChain<'static>,
    pub(super) ocsp_response: Vec<u8>,
}

impl ServerCertDetails {
    pub(super) fn new(cert_chain: CertificateChain<'static>, ocsp_response: Vec<u8>) -> Self {
        Self {
            cert_chain,
            ocsp_response,
        }
    }
}

/// How the client will answer a CertificateRequest.
pub(super) enum ClientAuthDetails {
    /// Send an empty Certificate.
    Empty { auth_context_tls13: Option<Vec<u8>> },
    /// Send `certkey` and sign with `signer`.
    Verify {
        certkey: Arc<CertifiedKey>,
        signer: Box<dyn Signer>,
        auth_context_tls13: Option<Vec<u8>>,
    },
}

impl ClientAuthDetails {
    /// `certtypes` is the TLS 1.2 CertificateRequest's `certificate_types`
    /// (RFC 5246 §7.4.4); a certificate of another type is not sent.
    pub(super) fn resolve(
        resolver: &dyn ResolvesClientCert,
        canames: Option<&[DistinguishedName]>,
        certtypes: Option<&[ClientCertificateType]>,
        sigschemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
    ) -> Self {
        let acceptable_issuers: Vec<&[u8]> = canames
            .unwrap_or_default()
            .iter()
            .map(AsRef::as_ref)
            .collect();

        if let Some(certkey) = resolver.resolve(&acceptable_issuers, sigschemes) {
            // RFC 5246 §7.4.4, RFC 8422 §5.5: ecdsa_sign covers ECDSA and EdDSA keys.
            let wanted = match certkey.key.algorithm() {
                SignatureAlgorithm::RSA => Some(ClientCertificateType::RSASign),
                SignatureAlgorithm::ECDSA
                | SignatureAlgorithm::ED25519
                | SignatureAlgorithm::ED448 => Some(ClientCertificateType::ECDSASign),
                _ => None,
            };
            let type_acceptable = match (certtypes, wanted) {
                (Some(types), Some(wanted)) => types.contains(&wanted),
                (Some(_), None) => false,
                (None, _) => true,
            };
            if !type_acceptable {
                debug!("Client certificate type not among the server's certificate_types");
                return Self::Empty { auth_context_tls13 };
            }
            if let Some(signer) = certkey.key.choose_scheme(sigschemes) {
                debug!("Attempting client auth");
                return Self::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                };
            }
            debug!("Client certificate key cannot sign with any offered scheme");
        }

        debug!("Client auth requested but no cert/sigscheme available");
        Self::Empty { auth_context_tls13 }
    }
}

/// What the ClientHello offered, kept to validate the server's answers.
#[derive(Debug)]
pub(super) struct ClientHelloDetails {
    pub(super) sent_extensions: Vec<ExtensionType>,
    pub(super) offered_sigschemes: Vec<SignatureScheme>,
}

impl ClientHelloDetails {
    pub(super) fn new() -> Self {
        Self {
            sent_extensions: Vec::new(),
            offered_sigschemes: Vec::new(),
        }
    }

    /// Whether `received` contains an extension we did not send, other than
    /// those in `allowed_unsolicited`.
    pub(super) fn server_sent_unsolicited_extensions(
        &self,
        received: &[ExtensionType],
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        for ext in received {
            if !self.sent_extensions.contains(ext) && !allowed_unsolicited.contains(ext) {
                trace!("Unsolicited extension {:?}", ext);
                return true;
            }
        }
        false
    }
}

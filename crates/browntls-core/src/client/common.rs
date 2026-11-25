//! Types shared by the TLS 1.2 and TLS 1.3 client handshakes.

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::UnixTime;

use super::ResolvesClientCert;
use crate::common_state::Side;
use crate::delegated_credential::DelegatedCredentialKey;
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::log::{debug, trace};
use crate::msgs::enums::{ClientCertificateType, ExtensionType};
use crate::msgs::handshake::{CertificateChain, DistinguishedName};
use crate::revocation::CertificateEvidence;
use crate::sign::{CertifiedKey, Signer};
use crate::sync::Arc;
use crate::verify::ServerCertVerificationContext;

/// What the server presented to authenticate itself.
pub(super) struct ServerCertDetails {
    pub(super) cert_chain: CertificateChain<'static>,
    pub(super) ocsp: Vec<Option<Vec<u8>>>,
    pub(super) scts: Vec<Option<Vec<u8>>>,
    /// The end entity's `transparency_info` (RFC 9162 §6.5).
    pub(super) transparency_info: Option<Vec<u8>>,
}

impl ServerCertDetails {
    pub(super) fn evidence(&self) -> Vec<CertificateEvidence<'_>> {
        let len = self.ocsp.len().max(self.scts.len());
        let len = len.max(usize::from(self.transparency_info.is_some()));
        (0..len)
            .map(|index| CertificateEvidence {
                ocsp: self.ocsp.get(index).and_then(|value| value.as_deref()),
                scts: self.scts.get(index).and_then(|value| value.as_deref()),
                transparency_info: self.transparency_info.as_deref().filter(|_| index == 0),
            })
            .collect()
    }
}

/// Evidence requested by the server alongside a TLS 1.3 client certificate.
#[derive(Default)]
pub(super) struct ClientCertificateExtensions {
    pub(super) ocsp: bool,
    pub(super) sct: bool,
}

impl From<&crate::msgs::handshake::CertificateRequestExtensions> for ClientCertificateExtensions {
    fn from(exts: &crate::msgs::handshake::CertificateRequestExtensions) -> Self {
        Self {
            ocsp: exts.status_request.is_some(),
            sct: exts.sct_request.is_some(),
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
        /// The delegated credential (RFC 9345 §4.1.2) to send on the end
        /// entity's TLS 1.3 CertificateEntry; `signer` then signs with its
        /// key.
        delegated: Option<Arc<DelegatedCredentialKey>>,
    },
}

impl ClientAuthDetails {
    /// `certtypes` is the TLS 1.2 CertificateRequest's `certificate_types`
    /// (RFC 5246 §7.4.4); a certificate of another type is not sent.
    ///
    /// `delegated` is the list of a TLS 1.3 CertificateRequest's
    /// `delegated_credential` extension and the current time, when the
    /// request lets a delegated credential answer it (RFC 9345 §4.1.2).
    /// The first of the certificate's client credentials the request
    /// accepts is then sent and its key signs CertificateVerify: its
    /// `dc_cert_verify_algorithm` must be in that list and in
    /// `sigschemes`, the scheme of its signature in `sigschemes`, and it
    /// must be unexpired with at most seven days left, within the
    /// certificate's validity (§4.1.3). Otherwise the certificate key
    /// signs, if it can.
    pub(super) fn resolve(
        resolver: &dyn ResolvesClientCert,
        canames: Option<&[DistinguishedName]>,
        certtypes: Option<&[ClientCertificateType]>,
        sigschemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
        delegated: Option<(&[SignatureScheme], UnixTime)>,
    ) -> Self {
        let acceptable_issuers: Vec<&[u8]> = canames
            .unwrap_or_default()
            .iter()
            .map(AsRef::as_ref)
            .collect();

        if let Some(certkey) = resolver.resolve(&acceptable_issuers, sigschemes) {
            // A key without a chain can authenticate only through its
            // certificate URLs (RFC 6066 §5), which TLS 1.3 does not have.
            if certkey.cert.is_empty()
                && (auth_context_tls13.is_some() || certkey.certificate_url().is_none())
            {
                debug!("Client certificate key has no chain to send");
                return Self::Empty { auth_context_tls13 };
            }
            // RFC 5246 §7.4.4, RFC 8422 §5.5: ecdsa_sign covers ECDSA and EdDSA
            // keys.
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
            // The credential's scheme was checked to be one its key signs
            // with when it was attached.
            if let Some((dc_schemes, now)) = delegated
                && let Some(dc) = certkey
                    .choose_delegated_credential(Side::Client, dc_schemes, sigschemes, now)
                    .cloned()
                && let Some(signer) = dc
                    .key()
                    .choose_scheme(&[dc.credential().credential.dc_cert_verify_algorithm])
            {
                debug!("Attempting client auth with a delegated credential");
                return Self::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                    delegated: Some(dc),
                };
            }
            // RFC 9963 §3: a legacy RSASSA-PKCS1-v1_5 scheme signs only an
            // answer to a request that listed it. A key naming one anyway
            // ignored the list and is treated as one that cannot sign.
            if let Some(signer) = certkey.key.choose_scheme(sigschemes).filter(|signer| {
                !signer.scheme().is_rsa_pkcs1_legacy() || sigschemes.contains(&signer.scheme())
            }) {
                debug!("Attempting client auth");
                return Self::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                    delegated: None,
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
    /// The `record_size_limit` we announced (RFC 8449), if any.
    pub(super) sent_record_size_limit: Option<u16>,
    /// What the store offered for RFC 7924 `cached_info`, if it is in use.
    #[cfg(feature = "tls12")]
    pub(super) cached_info: Option<crate::cached_info::client::ClientCachedInfo>,
    /// A TLS 1.2 server acknowledged `client_certificate_url` (RFC 6066
    /// §5): a CertificateURL message may replace our Certificate.
    pub(super) certificate_url_accepted: bool,
}

impl ClientHelloDetails {
    pub(super) fn verification_context(&self) -> ServerCertVerificationContext {
        ServerCertVerificationContext::TlsHandshake {
            offered_transparency_info: self
                .sent_extensions
                .contains(&ExtensionType::TransparencyInfo),
            offered_status_request: self.sent_extensions.contains(&ExtensionType::StatusRequest),
        }
    }

    /// The `signature_algorithms` to offer, from the verifier's schemes.
    /// The one list serves every offered version (RFC 9846 §4.3.3). The
    /// ML-DSA schemes are for TLS 1.3 only (`SignatureScheme::is_ml_dsa`),
    /// so a hello that does not offer TLS 1.3 leaves them out. The legacy
    /// schemes of RFC 9963 are never offered, whatever the verifier lists:
    /// they are for a client's own `CertificateVerify`, and a hello that
    /// listed one would invite the server to sign with it (RFC 9963 §3).
    pub(super) fn sigschemes_to_offer(
        mut verifier_schemes: Vec<SignatureScheme>,
        offers_tls13: bool,
    ) -> Vec<SignatureScheme> {
        verifier_schemes.retain(|scheme| {
            !scheme.is_rsa_pkcs1_legacy() && (offers_tls13 || !scheme.is_ml_dsa())
        });
        verifier_schemes
    }

    pub(super) fn new() -> Self {
        Self {
            sent_extensions: Vec::new(),
            offered_sigschemes: Vec::new(),
            sent_record_size_limit: None,
            #[cfg(feature = "tls12")]
            cached_info: None,
            certificate_url_accepted: false,
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

//! Server certificate verification against a root store.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::{
    CertRevocationList, CertificateDer, CertificateRevocationListDer, ExpirationPolicy,
    OwnedCertRevocationList, RevocationCheckDepth, RevocationOptionsBuilder, ServerName, UnixTime,
    UnknownStatusPolicy,
};

use super::anchors::RootCertStore;
use super::verify::{
    ParsedCertificate, WebPkiSupportedAlgorithms, verify_cert_for_usage, verify_server_name,
};
use super::{VerifierBuilderError, crl_error};
use crate::crypto::CryptoProvider;
use crate::enums::SignatureScheme;
use crate::error::Error;
use crate::log::trace;
use crate::revocation::policy::{CrlConfig, PathRequest};
use crate::revocation::{
    CertificateEvidence, PeerEvidence, RevocationCheck, RevocationPolicy, require_local,
};
use crate::sync::Arc;
use crate::verify::{
    DigitallySignedStruct, HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};

/// Builds a [`WebPkiServerVerifier`].
#[derive(Debug, Clone)]
pub struct ServerCertVerifierBuilder {
    roots: Arc<RootCertStore>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    revocation_check_depth: RevocationCheckDepth,
    unknown_revocation_policy: UnknownStatusPolicy,
    revocation_expiration_policy: ExpirationPolicy,
    revocation_policy: Option<RevocationPolicy>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifierBuilder {
    pub(crate) fn new(
        roots: Arc<RootCertStore>,
        supported_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            roots,
            crls: Vec::new(),
            revocation_check_depth: RevocationCheckDepth::Chain,
            unknown_revocation_policy: UnknownStatusPolicy::Deny,
            revocation_expiration_policy: ExpirationPolicy::Ignore,
            revocation_policy: None,
            supported_algs,
        }
    }

    /// Requires the revocation status of the server's certificates under
    /// `policy`, from the CRLs of this builder, stapled OCSP responses,
    /// CRLite and, if the policy allows them, live OCSP queries.
    ///
    /// The CRL options of this builder keep their meaning: unless
    /// [`Self::allow_unknown_revocation_status`] is set, every certificate
    /// they apply to must be covered by a CRL, whatever other evidence
    /// exists.
    pub fn with_revocation_policy(mut self, policy: RevocationPolicy) -> Self {
        self.revocation_policy = Some(policy);
        self
    }

    /// Adds CRLs to check revocation against. With any CRL present, every
    /// certificate in the chain must have a determinable revocation status.
    pub fn with_crls(
        mut self,
        crls: impl IntoIterator<Item = CertificateRevocationListDer<'static>>,
    ) -> Self {
        self.crls.extend(crls);
        self
    }

    /// Checks only the end-entity certificate against the CRLs.
    pub fn only_check_end_entity_revocation(mut self) -> Self {
        self.revocation_check_depth = RevocationCheckDepth::EndEntity;
        self
    }

    /// Accepts certificates whose revocation status no CRL covers.
    pub fn allow_unknown_revocation_status(mut self) -> Self {
        self.unknown_revocation_policy = UnknownStatusPolicy::Allow;
        self
    }

    /// Rejects CRLs past their `nextUpdate`.
    pub fn enforce_revocation_expiration(mut self) -> Self {
        self.revocation_expiration_policy = ExpirationPolicy::Enforce;
        self
    }

    /// Finishes the verifier.
    pub fn build(self) -> Result<Arc<WebPkiServerVerifier>, VerifierBuilderError> {
        if self.roots.is_empty() {
            return Err(VerifierBuilderError::NoRootAnchors);
        }
        let crls = self
            .crls
            .iter()
            .map(|der| {
                OwnedCertRevocationList::from_der(der.as_ref()).map(CertRevocationList::from)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(crl_error)?;
        let mut verifier = WebPkiServerVerifier::new(
            self.roots,
            crls,
            self.revocation_check_depth,
            self.unknown_revocation_policy,
            self.revocation_expiration_policy,
            self.supported_algs,
        );
        verifier.revocation_policy = self.revocation_policy;
        Ok(Arc::new(verifier))
    }
}

/// Verifies server certificates by building a path to a trusted root,
/// checking the server name against the subject alternative names, and
/// optionally checking revocation.
pub struct WebPkiServerVerifier {
    roots: Arc<RootCertStore>,
    crls: Arc<Vec<CertRevocationList<'static>>>,
    revocation_check_depth: RevocationCheckDepth,
    unknown_revocation_policy: UnknownStatusPolicy,
    revocation_expiration_policy: ExpirationPolicy,
    revocation_policy: Option<RevocationPolicy>,
    supported: WebPkiSupportedAlgorithms,
}

impl WebPkiServerVerifier {
    /// Starts a builder using the process-default provider's algorithms.
    #[cfg(feature = "std")]
    pub fn builder(roots: Arc<RootCertStore>) -> ServerCertVerifierBuilder {
        let algs = CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms)
            .or_else(Self::crate_default_algorithms)
            .unwrap_or(EMPTY_ALGORITHMS);
        Self::builder_with_provider_algorithms(roots, algs)
    }

    /// Starts a builder using `provider`'s algorithms.
    pub fn builder_with_provider(
        roots: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
    ) -> ServerCertVerifierBuilder {
        Self::builder_with_provider_algorithms(roots, provider.signature_verification_algorithms)
    }

    fn builder_with_provider_algorithms(
        roots: Arc<RootCertStore>,
        algs: WebPkiSupportedAlgorithms,
    ) -> ServerCertVerifierBuilder {
        ServerCertVerifierBuilder::new(roots, algs)
    }

    #[cfg(feature = "std")]
    fn crate_default_algorithms() -> Option<WebPkiSupportedAlgorithms> {
        #[cfg(all(feature = "rustcrypto", not(feature = "native")))]
        {
            return Some(crate::crypto::rustcrypto::SUPPORTED_SIG_ALGS);
        }
        #[allow(unreachable_code)]
        None
    }

    pub(crate) fn new_without_revocation(
        roots: impl Into<Arc<RootCertStore>>,
        supported: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self::new(
            roots,
            Vec::new(),
            RevocationCheckDepth::Chain,
            UnknownStatusPolicy::Allow,
            ExpirationPolicy::Ignore,
            supported,
        )
    }

    pub(crate) fn new(
        roots: impl Into<Arc<RootCertStore>>,
        crls: Vec<CertRevocationList<'static>>,
        revocation_check_depth: RevocationCheckDepth,
        unknown_revocation_policy: UnknownStatusPolicy,
        revocation_expiration_policy: ExpirationPolicy,
        supported: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            roots: roots.into(),
            crls: Arc::new(crls),
            revocation_check_depth,
            unknown_revocation_policy,
            revocation_expiration_policy,
            revocation_policy: None,
            supported,
        }
    }

    /// Verifies the chain under `policy`. `allow_live` says whether the
    /// caller can transport the OCSP queries of a pending result.
    #[allow(clippy::too_many_arguments)]
    fn verify_with_policy(
        &self,
        policy: &RevocationPolicy,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        evidence: PeerEvidence<'_>,
        now: UnixTime,
        allow_live: bool,
    ) -> Result<RevocationCheck, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        policy.verify_path(&PathRequest {
            end_entity: &cert,
            roots: &self.roots.roots,
            intermediates,
            now,
            algs: self.supported.all,
            usage: browntls_pki::KeyUsage::server_auth(),
            crls: CrlConfig {
                crls: &self.crls,
                depth: self.revocation_check_depth,
                unknown_status: self.unknown_revocation_policy,
                expiration: self.revocation_expiration_policy,
            },
            server_name: Some(server_name),
            evidence,
            allow_live,
        })
    }
}

/// Placeholder algorithm table for a build with no default provider.
static EMPTY_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[],
    mapping: &[],
};

impl ServerCertVerifier for WebPkiServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if let Some(policy) = &self.revocation_policy {
            // This entry point cannot wait for a live query: the policy is
            // decided from local evidence alone.
            let leaf = [CertificateEvidence {
                ocsp: Some(ocsp_response),
                scts: None,
            }];
            require_local(self.verify_with_policy(
                policy,
                end_entity,
                intermediates,
                server_name,
                &leaf,
                now,
                false,
            )?)?;
            return Ok(ServerCertVerified::assertion());
        }

        let cert = ParsedCertificate::try_from(end_entity)?;

        let crl_refs: Vec<&CertRevocationList<'_>> = self.crls.iter().collect();
        let revocation = if self.crls.is_empty() {
            None
        } else {
            RevocationOptionsBuilder::new(&crl_refs).ok().map(|b| {
                b.with_depth(self.revocation_check_depth)
                    .with_status_policy(self.unknown_revocation_policy)
                    .with_expiration_policy(self.revocation_expiration_policy)
                    .build()
            })
        };

        verify_cert_for_usage(
            &cert,
            &self.roots.roots,
            intermediates,
            now,
            self.supported.all,
            browntls_pki::KeyUsage::server_auth(),
            revocation,
        )?;

        if !ocsp_response.is_empty() {
            // Stapled responses are passed through to the application via
            // the verifier API; this verifier does not interpret them.
            trace!("Unvalidated OCSP response: {:?}", ocsp_response.len());
        }

        verify_server_name(&cert, server_name)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_server_cert_with_evidence(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        evidence: PeerEvidence<'_>,
        now: UnixTime,
    ) -> Result<RevocationCheck, Error> {
        let Some(policy) = &self.revocation_policy else {
            let ocsp_response = crate::revocation::leaf_evidence(evidence)
                .ocsp
                .unwrap_or_default();
            self.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
            return Ok(RevocationCheck::Complete(None));
        };
        self.verify_with_policy(
            policy,
            end_entity,
            intermediates,
            server_name,
            evidence,
            now,
            true,
        )
    }

    fn revocation_enabled(&self) -> bool {
        self.revocation_policy.is_some()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        super::verify::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        super::verify::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }

    fn verify_tls13_signature_with_delegated_key(
        &self,
        message: &[u8],
        public_key: &browntls_pki::SubjectPublicKeyInfoDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        super::verify::verify_tls13_signature_with_raw_key(
            message,
            public_key,
            dss,
            &self.supported,
        )
    }
}

impl fmt::Debug for WebPkiServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPkiServerVerifier")
            .field("roots", &self.roots)
            .field("crls", &self.crls.len())
            .field("revocation_check_depth", &self.revocation_check_depth)
            .field("unknown_revocation_policy", &self.unknown_revocation_policy)
            .field(
                "revocation_expiration_policy",
                &self.revocation_expiration_policy,
            )
            .field("revocation_policy", &self.revocation_policy)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Arc<RootCertStore> {
        let anchor = browntls_pki::TrustAnchor {
            subject: browntls_pki::Der::from_slice(&[]),
            subject_public_key_info: browntls_pki::Der::from_slice(&[]),
            name_constraints: None,
        };
        Arc::new([anchor.to_owned()].into_iter().collect())
    }

    #[test]
    fn builder_requires_roots() {
        let b = ServerCertVerifierBuilder::new(Arc::new(RootCertStore::empty()), EMPTY_ALGORITHMS);
        assert!(matches!(
            b.build(),
            Err(VerifierBuilderError::NoRootAnchors)
        ));
        let v = ServerCertVerifierBuilder::new(roots(), EMPTY_ALGORITHMS)
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status()
            .enforce_revocation_expiration()
            .build()
            .unwrap();
        assert!(v.supported_verify_schemes().is_empty());
        assert!(alloc::format!("{v:?}").contains("EndEntity"));
    }

    #[test]
    fn crls_must_parse() {
        let b = ServerCertVerifierBuilder::new(roots(), EMPTY_ALGORITHMS)
            .with_crls([CertificateRevocationListDer::from(alloc::vec![1u8, 2, 3])]);
        assert!(matches!(
            b.build(),
            Err(VerifierBuilderError::InvalidCrl(_))
        ));
    }
}

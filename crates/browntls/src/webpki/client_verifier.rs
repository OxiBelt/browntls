//! Client certificate verification against a root store.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::{
    CertRevocationList, CertificateDer, CertificateRevocationListDer, ExpirationPolicy,
    OwnedCertRevocationList, RevocationCheckDepth, RevocationOptionsBuilder, UnixTime,
    UnknownStatusPolicy,
};

use super::anchors::RootCertStore;
use super::verify::{ParsedCertificate, WebPkiSupportedAlgorithms, verify_cert_for_usage};
use super::{VerifierBuilderError, crl_error};
use crate::crypto::CryptoProvider;
use crate::enums::SignatureScheme;
use crate::error::Error;
use crate::msgs::handshake::DistinguishedName;
use crate::sync::Arc;
use crate::verify::{
    ClientCertVerified, ClientCertVerifier, DigitallySignedStruct, HandshakeSignatureValid,
    NoClientAuth,
};

/// Builds a [`WebPkiClientVerifier`].
#[derive(Debug, Clone)]
pub struct ClientCertVerifierBuilder {
    roots: Arc<RootCertStore>,
    root_hint_subjects: Vec<DistinguishedName>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    revocation_check_depth: RevocationCheckDepth,
    unknown_revocation_policy: UnknownStatusPolicy,
    revocation_expiration_policy: ExpirationPolicy,
    anon_policy: AnonymousClientPolicy,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifierBuilder {
    pub(crate) fn new(
        roots: Arc<RootCertStore>,
        supported_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            root_hint_subjects: roots.subjects(),
            roots,
            crls: Vec::new(),
            revocation_check_depth: RevocationCheckDepth::Chain,
            unknown_revocation_policy: UnknownStatusPolicy::Deny,
            revocation_expiration_policy: ExpirationPolicy::Ignore,
            anon_policy: AnonymousClientPolicy::Deny,
            supported_algs,
        }
    }

    /// Sends no `certificate_authorities` hints in the CertificateRequest.
    pub fn clear_root_hint_subjects(mut self) -> Self {
        self.root_hint_subjects = Vec::new();
        self
    }

    /// Adds subjects to hint at in the CertificateRequest.
    pub fn add_root_hint_subjects(
        mut self,
        subjects: impl IntoIterator<Item = DistinguishedName>,
    ) -> Self {
        self.root_hint_subjects.extend(subjects);
        self
    }

    /// Adds CRLs to check revocation against.
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

    /// Accepts clients that present no certificate at all.
    pub fn allow_unauthenticated(mut self) -> Self {
        self.anon_policy = AnonymousClientPolicy::Allow;
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
    pub fn build(self) -> Result<Arc<dyn ClientCertVerifier>, VerifierBuilderError> {
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
        Ok(Arc::new(WebPkiClientVerifier::new(
            self.roots,
            self.root_hint_subjects,
            crls,
            self.revocation_check_depth,
            self.unknown_revocation_policy,
            self.revocation_expiration_policy,
            self.anon_policy,
            self.supported_algs,
        )))
    }
}

/// Whether a client may skip authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnonymousClientPolicy {
    Allow,
    Deny,
}

/// Verifies client certificates by building a path to a trusted root and
/// optionally checking revocation.
pub struct WebPkiClientVerifier {
    roots: Arc<RootCertStore>,
    root_hint_subjects: Vec<DistinguishedName>,
    crls: Vec<CertRevocationList<'static>>,
    revocation_check_depth: RevocationCheckDepth,
    unknown_revocation_policy: UnknownStatusPolicy,
    revocation_expiration_policy: ExpirationPolicy,
    anonymous_policy: AnonymousClientPolicy,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl WebPkiClientVerifier {
    /// Starts a builder using the process-default provider's algorithms.
    #[cfg(feature = "std")]
    pub fn builder(roots: Arc<RootCertStore>) -> ClientCertVerifierBuilder {
        let algs = CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms)
            .or_else(Self::crate_default_algorithms)
            .unwrap_or(EMPTY_ALGORITHMS);
        ClientCertVerifierBuilder::new(roots, algs)
    }

    /// Starts a builder using `provider`'s algorithms.
    pub fn builder_with_provider(
        roots: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
    ) -> ClientCertVerifierBuilder {
        ClientCertVerifierBuilder::new(roots, provider.signature_verification_algorithms)
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

    /// A verifier that never asks for client authentication.
    pub fn no_client_auth() -> Arc<dyn ClientCertVerifier> {
        Arc::new(NoClientAuth)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        roots: Arc<RootCertStore>,
        root_hint_subjects: Vec<DistinguishedName>,
        crls: Vec<CertRevocationList<'static>>,
        revocation_check_depth: RevocationCheckDepth,
        unknown_revocation_policy: UnknownStatusPolicy,
        revocation_expiration_policy: ExpirationPolicy,
        anonymous_policy: AnonymousClientPolicy,
        supported_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            roots,
            root_hint_subjects,
            crls,
            revocation_check_depth,
            unknown_revocation_policy,
            revocation_expiration_policy,
            anonymous_policy,
            supported_algs,
        }
    }
}

static EMPTY_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[],
    mapping: &[],
};

impl ClientCertVerifier for WebPkiClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.anonymous_policy == AnonymousClientPolicy::Deny
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
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
            self.supported_algs.all,
            browntls_pki::KeyUsage::client_auth(),
            revocation,
        )?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        super::verify::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        super::verify::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

impl fmt::Debug for WebPkiClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPkiClientVerifier")
            .field("roots", &self.roots)
            .field("root_hint_subjects", &self.root_hint_subjects.len())
            .field("crls", &self.crls.len())
            .field("anonymous_policy", &self.anonymous_policy)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Arc<RootCertStore> {
        let anchor = browntls_pki::TrustAnchor {
            subject: browntls_pki::Der::from_slice(&[0x31, 0]),
            subject_public_key_info: browntls_pki::Der::from_slice(&[]),
            name_constraints: None,
        };
        Arc::new([anchor.to_owned()].into_iter().collect())
    }

    #[test]
    fn builder_policies() {
        assert!(matches!(
            ClientCertVerifierBuilder::new(Arc::new(RootCertStore::empty()), EMPTY_ALGORITHMS)
                .build(),
            Err(VerifierBuilderError::NoRootAnchors)
        ));
        let mandatory = ClientCertVerifierBuilder::new(roots(), EMPTY_ALGORITHMS)
            .build()
            .unwrap();
        assert!(mandatory.offer_client_auth());
        assert!(mandatory.client_auth_mandatory());
        assert_eq!(mandatory.root_hint_subjects().len(), 1);

        let optional = ClientCertVerifierBuilder::new(roots(), EMPTY_ALGORITHMS)
            .allow_unauthenticated()
            .clear_root_hint_subjects()
            .add_root_hint_subjects([DistinguishedName::in_sequence(&[1])])
            .build()
            .unwrap();
        assert!(!optional.client_auth_mandatory());
        assert_eq!(optional.root_hint_subjects()[0].as_ref(), [0x30, 1, 1]);

        let none = WebPkiClientVerifier::no_client_auth();
        assert!(!none.offer_client_auth());
    }
}

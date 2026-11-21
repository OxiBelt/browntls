//! End-entity certificate verification (path building, usage, names).

use alloc::vec::Vec;

use crate::cert::{self, Cert};
use crate::crl::RevocationOptions;
use crate::der::{self, tag};
use crate::error::Error;
use crate::name;
use crate::path::ChainOptions;
use crate::signed_data::{self, Spki};
use crate::{
    CertificateDer, Der, ServerName, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer,
    TrustAnchor, UnixTime,
};

/// A caller-supplied check run on each otherwise-valid path.
pub type PathVerifier<'a> = &'a dyn Fn(&VerifiedPath<'_>) -> Result<(), Error>;

/// A parsed end-entity certificate.
///
/// Dereferences to [`Cert`], whose accessors ([`Cert::der`],
/// [`Cert::subject`], [`Cert::subject_alt_names`], [`Cert::extensions`]
/// and so on) inspect the certificate; the methods here verify it.
#[derive(Debug)]
pub struct EndEntityCert<'a> {
    pub(crate) inner: Cert<'a>,
}

impl<'a> core::ops::Deref for EndEntityCert<'a> {
    type Target = Cert<'a>;

    fn deref(&self) -> &Cert<'a> {
        &self.inner
    }
}

impl<'a> TryFrom<&'a CertificateDer<'a>> for EndEntityCert<'a> {
    type Error = Error;

    /// Parses a v3 certificate, rejecting malformed DER, duplicate extensions
    /// and unknown critical extensions.
    fn try_from(cert: &'a CertificateDer<'a>) -> Result<Self, Error> {
        Cert::from_der(cert.as_ref()).map(|inner| Self { inner })
    }
}

impl<'a> EndEntityCert<'a> {
    /// Builds and verifies a path from this certificate to one of
    /// `trust_anchors`, using `intermediate_certs` as candidate issuers.
    ///
    /// Checks signatures with `supported_sig_algs`, validity at `time`, basic
    /// constraints, path length, name constraints, the required `usage`, and
    /// revocation when `revocation` is supplied. `verify_path`, if given, is
    /// called for each otherwise-valid path and may reject it so that path
    /// building continues with alternatives.
    ///
    /// # Errors
    ///
    /// Returns the most specific [`Error`] found when no acceptable path
    /// exists.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_for_usage<'p>(
        &'p self,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        trust_anchors: &'p [TrustAnchor<'_>],
        intermediate_certs: &'p [CertificateDer<'p>],
        time: UnixTime,
        usage: KeyUsage,
        revocation: Option<RevocationOptions<'_>>,
        verify_path: Option<PathVerifier<'_>>,
    ) -> Result<VerifiedPath<'p>, Error> {
        ChainOptions {
            algs: supported_sig_algs,
            trust_anchors,
            intermediates: intermediate_certs,
            time,
            usage,
            revocation,
            verify_path,
        }
        .build(self)
    }

    /// Verifies that the certificate is valid for `name` (DNS SAN matching
    /// with the RFC 9525 wildcard rules and this crate's DNS profile, or IP
    /// SAN matching for addresses). The subject common name is never used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CertNotValidForName`] if no SAN matches.
    pub fn verify_is_valid_for_subject_name(&self, name: &ServerName<'_>) -> Result<(), Error> {
        let san = self.inner.subject_alt_name;
        match name {
            ServerName::DnsName(dns) => name::verify_dns_name(dns, san),
            ServerName::IpAddress(ip) => name::verify_ip_address(ip, san),
        }
    }

    /// Verifies `signature` over `msg` with this certificate's public key
    /// (used for TLS `CertificateVerify` / `ServerKeyExchange`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedSignatureAlgorithmForPublicKey`] if `alg`
    /// does not match the key type, or [`Error::InvalidSignatureForPublicKey`].
    pub fn verify_signature(
        &self,
        alg: &dyn SignatureVerificationAlgorithm,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let spki = Spki::from_contents(self.inner.spki)?;
        signed_data::verify_signature(alg, &spki, msg, signature)
    }

    /// Whether the certificate carries the `DelegationUsage` extension
    /// (OID 1.3.6.1.4.1.44363.44, RFC 9345 §4.2), which allows its key to
    /// sign delegated credentials. A malformed value (anything but `NULL`)
    /// or a second occurrence rejects the certificate when it is parsed.
    #[must_use]
    pub fn has_delegation_usage(&self) -> bool {
        self.inner.delegation_usage.is_some()
    }

    /// Whether the certificate has a `KeyUsage` extension with the
    /// `digitalSignature` bit set. Unlike path validation, which treats an
    /// absent `KeyUsage` as permitting any usage, this requires the
    /// extension: RFC 9345 §4.2 asks for "the digitalSignature KeyUsage".
    #[must_use]
    pub fn has_digital_signature_key_usage(&self) -> bool {
        self.inner
            .key_usage
            .is_some_and(|ku| ku.bit_set(cert::KU_DIGITAL_SIGNATURE))
    }
}

/// Verifies a signature made by a raw public key (RFC 7250).
#[derive(Debug)]
pub struct RawPublicKeyEntity<'a> {
    spki: Spki<'a>,
}

impl<'a> TryFrom<&'a SubjectPublicKeyInfoDer<'a>> for RawPublicKeyEntity<'a> {
    type Error = Error;

    /// Parses a complete `SubjectPublicKeyInfo` `SEQUENCE`.
    fn try_from(spki: &'a SubjectPublicKeyInfoDer<'a>) -> Result<Self, Error> {
        let contents = der::read_all(spki.as_ref(), |r| r.expect(tag::SEQUENCE))?;
        Ok(Self {
            spki: Spki::from_contents(contents)?,
        })
    }
}

impl RawPublicKeyEntity<'_> {
    /// Verifies `signature` over `msg` with the raw public key.
    ///
    /// # Errors
    ///
    /// As for [`EndEntityCert::verify_signature`].
    pub fn verify_signature(
        &self,
        alg: &dyn SignatureVerificationAlgorithm,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        signed_data::verify_signature(alg, &self.spki, msg, signature)
    }
}

/// A verified certificate path.
#[derive(Debug)]
pub struct VerifiedPath<'p> {
    end_entity: &'p EndEntityCert<'p>,
    intermediates: Vec<&'p CertificateDer<'p>>,
    anchor: &'p TrustAnchor<'p>,
}

impl<'p> VerifiedPath<'p> {
    pub(crate) fn new(
        end_entity: &'p EndEntityCert<'p>,
        intermediates: Vec<&'p CertificateDer<'p>>,
        anchor: &'p TrustAnchor<'p>,
    ) -> Self {
        Self {
            end_entity,
            intermediates,
            anchor,
        }
    }

    /// The end-entity certificate.
    #[must_use]
    pub fn end_entity(&self) -> &'p EndEntityCert<'p> {
        self.end_entity
    }

    /// Intermediates from the end entity towards the anchor.
    pub fn intermediate_certificates(&self) -> impl Iterator<Item = &'p CertificateDer<'p>> + '_ {
        self.intermediates.iter().copied()
    }

    /// The trust anchor that terminated the path.
    #[must_use]
    pub fn anchor(&self) -> &'p TrustAnchor<'p> {
        self.anchor
    }
}

/// The extended key usage a path must permit (RFC 5280 §4.2.1.12).
///
/// The purpose is checked on every certificate in the path: a certificate
/// without an EKU extension is acceptable only for "required if present"
/// usages, and `anyExtendedKeyUsage` does not stand in for a purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsage {
    oid: &'static [u8],
    required_if_present: bool,
}

impl KeyUsage {
    /// `id-kp-serverAuth`, required if the EKU extension is present.
    #[must_use]
    pub const fn server_auth() -> Self {
        Self::required_if_present(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])
    }

    /// `id-kp-clientAuth`, required if the EKU extension is present.
    #[must_use]
    pub const fn client_auth() -> Self {
        Self::required_if_present(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])
    }

    /// The encoded OID must be present in an EKU extension.
    #[must_use]
    pub const fn required(oid: &'static [u8]) -> Self {
        Self {
            oid,
            required_if_present: false,
        }
    }

    /// The encoded OID must be present if an EKU extension is present.
    #[must_use]
    pub const fn required_if_present(oid: &'static [u8]) -> Self {
        Self {
            oid,
            required_if_present: true,
        }
    }

    /// The encoded OID.
    #[must_use]
    pub const fn oid(&self) -> &'static [u8] {
        self.oid
    }

    /// Whether a certificate without EKU is acceptable.
    #[must_use]
    pub const fn is_required_if_present(&self) -> bool {
        self.required_if_present
    }
}

/// Interprets a trusted certificate as a [`TrustAnchor`] (subject, SPKI and
/// name constraints are extracted; validity, extensions other than name
/// constraints, and the signature are not checked).
///
/// Unknown critical extensions are ignored, and v1 certificates (which have
/// no extensions) are accepted, since trust-store roots of both kinds exist.
///
/// # Errors
///
/// Returns [`Error::BadDer`] for malformed certificates.
pub fn anchor_from_trusted_cert<'a>(
    cert: &'a CertificateDer<'a>,
) -> Result<TrustAnchor<'a>, Error> {
    match Cert::for_trust_anchor(cert.as_ref()) {
        Ok(parsed) => Ok(TrustAnchor {
            subject: Der::from_slice(parsed.subject),
            subject_public_key_info: Der::from_slice(parsed.spki),
            name_constraints: parsed.name_constraints.map(Der::from_slice),
        }),
        Err(Error::UnsupportedCertVersion) => cert::v1_anchor_fields(cert.as_ref())
            .map(|(subject, spki)| TrustAnchor {
                subject: Der::from_slice(subject),
                subject_public_key_info: Der::from_slice(spki),
                name_constraints: None,
            })
            .map_err(|_| Error::BadDer),
        Err(e) => Err(e),
    }
}

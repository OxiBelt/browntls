//! X.509 v3 certificate parsing (RFC 5280 §4).
//!
//! Parsing is eager and strict: every field this crate interprets is decoded
//! and validated when the certificate is parsed, so later validation steps
//! work on well-formed data. Fields this crate does not interpret (issuer and
//! subject `Name` contents, unrecognised non-critical extensions) are kept
//! as opaque bytes and can be parsed on demand ([`Name`], [`Extension`]).

use core::fmt;

use crate::asn1_time::read_time;
use crate::der::{self, BitFlags, CERT_LEN_LIMIT, HexDebug, Reader, tag};
use crate::error::Error;
use crate::extensions::{
    self, AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, Extension, Extensions,
    KeyPurposeIdIter, KeyUsageFlags, NameConstraints, UnknownExtensionPolicy, set_once,
};
use crate::name::{self, GeneralName, GeneralNames, Name};
use crate::signed_data::{SignedData, Spki};
use crate::{CertificateDer, SubjectPublicKeyInfoDer, UnixTime};

/// `KeyUsage` bit positions (RFC 5280 §4.2.1.3).
pub(crate) const KU_DIGITAL_SIGNATURE: usize = 0;
pub(crate) const KU_KEY_CERT_SIGN: usize = 5;
pub(crate) const KU_CRL_SIGN: usize = 6;

/// A parsed X.509 v3 certificate (RFC 5280 §4.1), CA or end entity.
///
/// [`Cert::try_from`] applies the same strict parsing as
/// [`EndEntityCert`](crate::EndEntityCert), which dereferences to a `Cert`,
/// and as path validation applies to intermediates: strict DER, version 3
/// only, `tbsCertificate.signature` equal to `signatureAlgorithm`, a
/// well-formed `SubjectPublicKeyInfo`, no duplicate extension the crate
/// decodes, no unknown critical extension, and every decoded extension
/// valid (see [`extensions`](crate::extensions)). Parsing a certificate
/// checks nothing about its signature, validity period or trust: verify
/// paths with [`EndEntityCert::verify_for_usage`] and signatures with
/// [`SignedData`].
///
/// Everything returned borrows from the certificate's DER encoding.
/// Certificate elements are limited to 65535 octets, so parsing and every
/// accessor are linear in at most that many octets.
///
/// [`EndEntityCert::verify_for_usage`]: crate::EndEntityCert::verify_for_usage
#[derive(Clone, Copy)]
pub struct Cert<'a> {
    /// The complete DER encoding.
    pub(crate) der: &'a [u8],
    /// `tbsCertificate`, `signatureAlgorithm` and `signatureValue`.
    pub(crate) signed: SignedData<'a>,
    /// `serialNumber` contents (two's complement, as encoded).
    pub(crate) serial: &'a [u8],
    /// `issuer` `Name` contents (without the outer `SEQUENCE`).
    pub(crate) issuer: &'a [u8],
    /// `validity.notBefore`.
    pub(crate) not_before: UnixTime,
    /// `validity.notAfter`.
    pub(crate) not_after: UnixTime,
    /// `subject` `Name` contents (without the outer `SEQUENCE`).
    pub(crate) subject: &'a [u8],
    /// `subjectPublicKeyInfo` contents (without the outer `SEQUENCE`).
    pub(crate) spki: &'a [u8],
    /// `subjectPublicKeyInfo` complete encoding.
    pub(crate) spki_der: &'a [u8],
    /// Contents of the `SEQUENCE OF Extension` (empty when absent).
    pub(crate) extensions: &'a [u8],
    pub(crate) basic_constraints: Option<BasicConstraints>,
    pub(crate) key_usage: Option<BitFlags<'a>>,
    /// `ExtKeyUsageSyntax` contents: a `SEQUENCE OF KeyPurposeId`.
    pub(crate) eku: Option<&'a [u8]>,
    /// `GeneralNames` contents of `subjectAltName`.
    pub(crate) subject_alt_name: Option<&'a [u8]>,
    /// `NameConstraints` contents.
    pub(crate) name_constraints: Option<&'a [u8]>,
    /// `CRLDistributionPoints` contents: a `SEQUENCE OF DistributionPoint`.
    pub(crate) crl_distribution_points: Option<&'a [u8]>,
    /// `SubjectKeyIdentifier` contents.
    pub(crate) subject_key_id: Option<&'a [u8]>,
    pub(crate) authority_key_id: Option<AuthorityKeyIdentifier<'a>>,
    /// Whether the `DelegationUsage` extension (RFC 9345 §4.2) is present.
    pub(crate) delegation_usage: Option<()>,
}

impl<'a> TryFrom<&'a CertificateDer<'a>> for Cert<'a> {
    type Error = Error;

    /// Parses a v3 certificate as described on [`Cert`].
    ///
    /// # Errors
    ///
    /// [`Error::BadDer`] or [`Error::TrailingData`] for malformed DER,
    /// [`Error::UnsupportedCertVersion`],
    /// [`Error::SignatureAlgorithmMismatch`], [`Error::BadDerTime`],
    /// [`Error::UnsupportedCriticalExtension`], [`Error::MalformedExtensions`]
    /// (including a duplicate decoded extension),
    /// [`Error::ExtensionValueInvalid`] or [`Error::MalformedNameConstraint`].
    fn try_from(cert: &'a CertificateDer<'a>) -> Result<Self, Error> {
        Self::from_der(cert.as_ref())
    }
}

impl<'a> Cert<'a> {
    /// Parses a certificate presented by a peer: unknown critical extensions
    /// are rejected.
    pub(crate) fn from_der(der: &'a [u8]) -> Result<Self, Error> {
        Self::parse(der, UnknownExtensionPolicy::Strict)
    }

    /// Parses a certificate the caller already trusts: unknown critical
    /// extensions are ignored.
    pub(crate) fn for_trust_anchor(der: &'a [u8]) -> Result<Self, Error> {
        Self::parse(der, UnknownExtensionPolicy::IgnoreCritical)
    }

    fn parse(der: &'a [u8], policy: UnknownExtensionPolicy) -> Result<Self, Error> {
        let (tbs, signed) = der::read_all(der, |r| {
            r.nested(tag::SEQUENCE, |cert| SignedData::read(cert, CERT_LEN_LIMIT))
        })?;

        der::read_all(tbs, |tbs| {
            version3(tbs)?;
            // RFC 5280 §4.1.2.2 requires positive serials of at most 20
            // octets, but deployed CAs violate both rules and the RFC asks
            // relying parties to cope; only the DER encoding is checked.
            let serial = tbs.integer()?;
            let signature = tbs.expect(tag::SEQUENCE)?;
            if signature != signed.algorithm {
                return Err(Error::SignatureAlgorithmMismatch);
            }
            let issuer = tbs.expect(tag::SEQUENCE)?;
            let (not_before, not_after) =
                tbs.nested(tag::SEQUENCE, |v| Ok((read_time(v)?, read_time(v)?)))?;
            let subject = tbs.expect(tag::SEQUENCE)?;
            let spki = tbs.expect_tlv(tag::SEQUENCE)?;
            Spki::from_contents(spki.value)?;
            // issuerUniqueID and subjectUniqueID (deprecated, never
            // generated by conforming CAs) are skipped if present.
            tbs.optional(tag::context(1))?;
            tbs.optional(tag::context(2))?;

            let mut cert = Cert {
                der,
                signed,
                serial,
                issuer,
                not_before,
                not_after,
                subject,
                spki: spki.value,
                spki_der: spki.raw,
                extensions: &[],
                basic_constraints: None,
                key_usage: None,
                eku: None,
                subject_alt_name: None,
                name_constraints: None,
                crl_distribution_points: None,
                subject_key_id: None,
                authority_key_id: None,
                delegation_usage: None,
            };

            if let Some(wrapped) = tbs.optional(tag::context_constructed(3))? {
                let exts = der::read_all(wrapped, |r| r.expect(tag::SEQUENCE))?;
                // RFC 5280 requires at least one extension when the field is
                // present, but empty extension lists occur in practice.
                extensions::for_each(exts, true, |ext| cert.remember_extension(&ext, policy))?;
                cert.extensions = exts;
            }
            Ok(cert)
        })
    }

    fn remember_extension(
        &mut self,
        ext: &Extension<'a>,
        policy: UnknownExtensionPolicy,
    ) -> Result<(), Error> {
        // RFC 9345 §4.2: `DelegationUsage ::= NULL`, outside `id-ce`.
        if ext.id == extensions::oid::DELEGATION_USAGE {
            return set_once(&mut self.delegation_usage, || {
                value(ext, |r| {
                    if r.expect(tag::NULL)?.is_empty() {
                        Ok(())
                    } else {
                        Err(Error::BadDer)
                    }
                })
            });
        }
        match ext.id_ce_arc() {
            // id-ce-subjectKeyIdentifier
            Some(14) => set_once(&mut self.subject_key_id, || {
                value(ext, |r| r.expect(tag::OCTET_STRING))
            }),
            // id-ce-keyUsage
            Some(15) => set_once(&mut self.key_usage, || {
                value(ext, |r| der::bit_string_flags(r.expect(tag::BIT_STRING)?))
            }),
            // id-ce-subjectAltName
            Some(17) => set_once(&mut self.subject_alt_name, || {
                let names = sequence(ext)?;
                name::validate_general_names(names).map_err(|_| Error::ExtensionValueInvalid)?;
                Ok(names)
            }),
            // id-ce-basicConstraints
            Some(19) => set_once(&mut self.basic_constraints, || {
                value(ext, |r| {
                    r.nested(tag::SEQUENCE, |bc| {
                        let ca = bc.default_false_boolean()?;
                        // pathLenConstraint is only meaningful for CAs, but
                        // some end-entity certificates carry one.
                        let path_len_constraint = if bc.at_end() {
                            None
                        } else {
                            Some(bc.small_nonnegative_integer()?)
                        };
                        Ok(BasicConstraints {
                            ca,
                            path_len_constraint,
                        })
                    })
                })
            }),
            // id-ce-nameConstraints
            Some(30) => set_once(&mut self.name_constraints, || {
                let nc = sequence(ext).map_err(|_| Error::MalformedNameConstraint)?;
                name::constraints::validate(nc)?;
                Ok(nc)
            }),
            // id-ce-cRLDistributionPoints
            Some(31) => set_once(&mut self.crl_distribution_points, || {
                let dps = sequence(ext)?;
                // SEQUENCE SIZE (1..MAX) OF DistributionPoint; the contents
                // of each point are interpreted leniently when consulted.
                if dps.is_empty() {
                    return Err(Error::ExtensionValueInvalid);
                }
                der::read_all(dps, |r| {
                    while !r.at_end() {
                        r.expect(tag::SEQUENCE)?;
                    }
                    Ok(())
                })
                .map_err(|_| Error::ExtensionValueInvalid)?;
                Ok(dps)
            }),
            // id-ce-authorityKeyIdentifier
            Some(35) => set_once(&mut self.authority_key_id, || {
                value(ext, |r| {
                    r.nested(tag::SEQUENCE, |aki| {
                        let key_identifier = aki.optional(tag::context(0))?;
                        let authority_cert_issuer = aki.optional(tag::context_constructed(1))?;
                        let authority_cert_serial_number = aki.optional(tag::context(2))?;
                        Ok(AuthorityKeyIdentifier {
                            key_identifier,
                            authority_cert_issuer,
                            authority_cert_serial_number,
                        })
                    })
                })
            }),
            // id-ce-extKeyUsage
            Some(37) => set_once(&mut self.eku, || {
                let purposes = sequence(ext)?;
                der::read_all(purposes, |r| {
                    while !r.at_end() {
                        r.oid()?;
                    }
                    Ok(())
                })
                .map_err(|_| Error::ExtensionValueInvalid)?;
                Ok(purposes)
            }),
            _ => ext.unsupported(policy),
        }
    }

    /// Whether `bit` of `KeyUsage` is set, or the extension is absent.
    ///
    /// RFC 5280 requires `KeyUsage` on CA certificates, but historically its
    /// absence has been treated as permitting any usage.
    pub(crate) fn key_usage_permits(&self, bit: usize) -> bool {
        self.key_usage.is_none_or(|ku| ku.bit_set(bit))
    }

    /// The certificate's DER encoding.
    #[must_use]
    pub fn der(&self) -> CertificateDer<'a> {
        CertificateDer::from_slice(self.der)
    }

    /// The `serialNumber` contents: big-endian two's complement, as encoded
    /// (minimal, but not checked to be positive or at most 20 octets, which
    /// deployed CAs do not always respect).
    #[must_use]
    pub fn serial(&self) -> &'a [u8] {
        self.serial
    }

    /// The `issuer` `Name` contents (without the outer SEQUENCE), compared
    /// as bytes with issuer subjects during path building. Not validated:
    /// [`Name::from_contents`] parses it.
    #[must_use]
    pub fn issuer(&self) -> &'a [u8] {
        self.issuer
    }

    /// The `subject` `Name` contents (without the outer SEQUENCE). Not
    /// validated: [`Name::from_contents`] parses it.
    #[must_use]
    pub fn subject(&self) -> &'a [u8] {
        self.subject
    }

    /// The certificate's `SubjectPublicKeyInfo` (DER, with outer SEQUENCE),
    /// checked to be a `SEQUENCE` (the algorithm identifier, whose contents
    /// are not interpreted) followed by a `BIT STRING` without unused bits.
    #[must_use]
    pub fn subject_public_key_info(&self) -> SubjectPublicKeyInfoDer<'a> {
        SubjectPublicKeyInfoDer::from_slice(self.spki_der)
    }

    /// `validity.notBefore`.
    #[must_use]
    pub fn not_before(&self) -> UnixTime {
        self.not_before
    }

    /// `validity.notAfter`.
    #[must_use]
    pub fn not_after(&self) -> UnixTime {
        self.not_after
    }

    /// The signed parts of the certificate (`tbsCertificate`,
    /// `signatureAlgorithm`, `signatureValue`), to verify the signature with
    /// an issuer's key ([`SignedData::verify_signature`]).
    #[must_use]
    pub fn signed_data(&self) -> SignedData<'a> {
        self.signed
    }

    /// Every extension, decoded or not, in encoding order. Iteration cannot
    /// fail.
    #[must_use]
    pub fn extensions(&self) -> Extensions<'a> {
        Extensions::new(self.extensions)
    }

    /// The first extension whose `extnID` contents equal `extn_id` (see
    /// [`extensions::oid`]). Only the extensions this crate decodes are
    /// guaranteed not to repeat.
    #[must_use]
    pub fn extension(&self, extn_id: &[u8]) -> Option<Extension<'a>> {
        self.extensions().find(|ext| ext.extn_id() == extn_id)
    }

    /// The `subjectAltName` entries (RFC 5280 §4.2.1.6), or `None` without
    /// the extension. The entries were validated when the certificate was
    /// parsed, so iteration yields no error; values are returned as
    /// encoded ([`GeneralName`]).
    ///
    /// To check that the certificate is valid for a server name use
    /// [`EndEntityCert::verify_is_valid_for_subject_name`], never this list.
    ///
    /// [`EndEntityCert::verify_is_valid_for_subject_name`]: crate::EndEntityCert::verify_is_valid_for_subject_name
    #[must_use]
    pub fn subject_alt_names(&self) -> Option<GeneralNames<'a>> {
        self.subject_alt_name
            .map(|names| GeneralNames::new(Some(names)))
    }

    /// The `dNSName` entries of `subjectAltName` that are valid presented
    /// identifiers: relative names in the preferred name syntax
    /// (underscores tolerated), optionally starting with a `*.` wildcard
    /// label followed by at least two labels. These are the names
    /// [`EndEntityCert::verify_is_valid_for_subject_name`] can match (ASCII
    /// case-insensitively); other `dNSName`s are skipped.
    ///
    /// Do not use this to implement name verification: use
    /// [`EndEntityCert::verify_is_valid_for_subject_name`].
    ///
    /// [`EndEntityCert::verify_is_valid_for_subject_name`]: crate::EndEntityCert::verify_is_valid_for_subject_name
    pub fn valid_dns_names(&self) -> impl Iterator<Item = &'a str> + use<'a> {
        GeneralNames::new(self.subject_alt_name).filter_map(|name| match name {
            Ok(GeneralName::DnsName(dns)) if name::is_valid_presented_dns_id(dns) => {
                core::str::from_utf8(dns).ok()
            }
            _ => None,
        })
    }

    /// The `uniformResourceIdentifier` entries of `subjectAltName` that are
    /// valid UTF-8, with no further validation (as rustls-webpki).
    pub fn valid_uri_names(&self) -> impl Iterator<Item = &'a str> + use<'a> {
        GeneralNames::new(self.subject_alt_name).filter_map(|name| match name {
            Ok(GeneralName::UniformResourceIdentifier(uri)) => core::str::from_utf8(uri).ok(),
            _ => None,
        })
    }

    /// The `basicConstraints` extension.
    #[must_use]
    pub fn basic_constraints(&self) -> Option<BasicConstraints> {
        self.basic_constraints
    }

    /// The `keyUsage` extension.
    #[must_use]
    pub fn key_usage(&self) -> Option<KeyUsageFlags<'a>> {
        self.key_usage.map(KeyUsageFlags)
    }

    /// The `extKeyUsage` extension's purposes.
    #[must_use]
    pub fn extended_key_usage(&self) -> Option<KeyPurposeIdIter<'a>> {
        self.eku.map(KeyPurposeIdIter::new)
    }

    /// The `subjectKeyIdentifier` extension: the `KeyIdentifier` octets.
    #[must_use]
    pub fn subject_key_identifier(&self) -> Option<&'a [u8]> {
        self.subject_key_id
    }

    /// The `authorityKeyIdentifier` extension.
    #[must_use]
    pub fn authority_key_identifier(&self) -> Option<AuthorityKeyIdentifier<'a>> {
        self.authority_key_id
    }

    /// The `cRLDistributionPoints` extension's points, parsed strictly one
    /// at a time ([`CrlDistributionPoints`]).
    #[must_use]
    pub fn crl_distribution_points(&self) -> Option<CrlDistributionPoints<'a>> {
        self.crl_distribution_points.map(CrlDistributionPoints::new)
    }

    /// The `nameConstraints` extension.
    #[must_use]
    pub fn name_constraints(&self) -> Option<NameConstraints<'a>> {
        self.name_constraints.map(NameConstraints::from_validated)
    }
}

/// A `Name` for `Debug`: parsed when valid, hexadecimal otherwise.
struct NameDebug<'a>(&'a [u8]);

impl fmt::Debug for NameDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Name::from_contents(self.0) {
            Ok(name) => name.fmt(f),
            Err(_) => HexDebug(self.0).fmt(f),
        }
    }
}

impl fmt::Debug for Cert<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cert")
            .field("serial", &HexDebug(self.serial))
            .field("issuer", &NameDebug(self.issuer))
            .field("subject", &NameDebug(self.subject))
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("subject_public_key_info", &HexDebug(self.spki_der))
            .field("extensions", &self.extensions())
            .finish_non_exhaustive()
    }
}

/// Decodes the whole `extnValue` with `f`.
fn value<'a, T>(
    ext: &Extension<'a>,
    f: impl FnOnce(&mut Reader<'a>) -> Result<T, Error>,
) -> Result<T, Error> {
    der::read_all(ext.value, f).map_err(|_| Error::ExtensionValueInvalid)
}

/// Decodes an `extnValue` that is a single `SEQUENCE`, returning its contents.
fn sequence<'a>(ext: &Extension<'a>) -> Result<&'a [u8], Error> {
    value(ext, |r| r.expect(tag::SEQUENCE))
}

// mozilla::pkix accepts v1 through v4; like webpki, only v3 is accepted here,
// since every extension this crate relies on requires v3.
fn version3(tbs: &mut Reader<'_>) -> Result<(), Error> {
    let version = tbs
        .expect(tag::context_constructed(0))
        .map_err(|_| Error::UnsupportedCertVersion)?;
    match der::read_all(version, Reader::small_nonnegative_integer) {
        Ok(2) => Ok(()),
        _ => Err(Error::UnsupportedCertVersion),
    }
}

/// Extracts the subject and `SubjectPublicKeyInfo` of a v1 certificate, for
/// use as a trust anchor. v1 certificates have no extensions, so there are
/// no name constraints to extract.
pub(crate) fn v1_anchor_fields(der: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    der::read_all(der, |r| {
        r.nested(tag::SEQUENCE, |cert| {
            let (tbs, _) = SignedData::read(cert, CERT_LEN_LIMIT)?;
            der::read_all(tbs, |tbs| {
                tbs.integer()?; // serialNumber (no version field in v1)
                tbs.expect(tag::SEQUENCE)?; // signature
                tbs.expect(tag::SEQUENCE)?; // issuer
                tbs.expect(tag::SEQUENCE)?; // validity
                let subject = tbs.expect(tag::SEQUENCE)?;
                let spki = tbs.expect(tag::SEQUENCE)?;
                Spki::from_contents(spki)?;
                Ok((subject, spki))
            })
        })
    })
}

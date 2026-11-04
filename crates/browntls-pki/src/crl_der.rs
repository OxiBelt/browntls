//! CRL (RFC 5280 §5) and distribution point (§4.2.1.13, §5.2.5) decoding.

use crate::UnixTime;
use crate::asn1_time::read_time;
use crate::cert::Cert;
use crate::crl::{BorrowedRevokedCert, RevocationReason};
use crate::der::{self, CRL_LEN_LIMIT, Reader, tag};
use crate::error::Error;
use crate::extensions::{self, Extension, UnknownExtensionPolicy, set_once};
use crate::name::{GeneralName, GeneralNames};
use crate::path::Role;
use crate::signed_data::SignedData;

/// The fields of a `CertificateList` this crate uses.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CertList<'a> {
    pub(crate) signed: SignedData<'a>,
    /// `issuer` `Name` contents.
    pub(crate) issuer: &'a [u8],
    pub(crate) this_update: UnixTime,
    pub(crate) next_update: UnixTime,
    /// `revokedCertificates` contents (empty when absent).
    pub(crate) revoked: &'a [u8],
    /// `issuingDistributionPoint` extension value (the `SEQUENCE` encoding).
    pub(crate) issuing_distribution_point: Option<&'a [u8]>,
}

impl<'a> CertList<'a> {
    /// Parses a v2 CRL. Supported extensions: CRL number, authority key
    /// identifier, issuing distribution point (full-name scope only). Delta
    /// and indirect CRLs, reason partitioning and unknown critical extensions
    /// are rejected; `nextUpdate` and the extension list are required.
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, Error> {
        let (tbs, signed) = der::read_all(der, |r| {
            let outer = r.expect_limited(tag::SEQUENCE, CRL_LEN_LIMIT)?;
            der::read_all(outer, |list| SignedData::read(list, CRL_LEN_LIMIT))
        })?;

        let crl = der::read_all(tbs, |tbs| {
            // version is OPTIONAL in the module but required (v2, encoded as
            // 1) whenever extensions are present, which this profile needs.
            match tbs.small_nonnegative_integer() {
                Ok(1) => {}
                _ => return Err(Error::UnsupportedCrlVersion),
            }
            let signature = tbs.expect(tag::SEQUENCE)?;
            if signature != signed.algorithm {
                return Err(Error::SignatureAlgorithmMismatch);
            }
            let issuer = tbs.expect(tag::SEQUENCE)?;
            let this_update = read_time(tbs)?;
            // RFC 5280 §5.1.2.5: conforming issuers MUST include nextUpdate.
            let next_update = read_time(tbs)?;
            let revoked = if tbs.peek(tag::SEQUENCE) {
                tbs.expect_limited(tag::SEQUENCE, CRL_LEN_LIMIT)?
            } else {
                &[]
            };

            let mut crl = CertList {
                signed,
                issuer,
                this_update,
                next_update,
                revoked,
                issuing_distribution_point: None,
            };
            // RFC 5280 §5.2 requires the CRL number and authority key
            // identifier extensions, so the list must be present.
            let wrapped = tbs
                .expect(tag::context_constructed(0))
                .map_err(|_| Error::MalformedExtensions)?;
            let exts = der::read_all(wrapped, |r| r.expect(tag::SEQUENCE))
                .map_err(|_| Error::MalformedExtensions)?;
            let mut crl_number_seen = None;
            extensions::for_each(exts, false, |ext| {
                crl.remember_extension(&ext, &mut crl_number_seen)
            })?;
            Ok(crl)
        })?;

        if let Some(idp) = crl.issuing_distribution_point {
            IssuingDistributionPoint::parse(idp)?;
        }
        Ok(crl)
    }

    fn remember_extension(
        &mut self,
        ext: &Extension<'a>,
        crl_number_seen: &mut Option<()>,
    ) -> Result<(), Error> {
        match ext.id_ce_arc() {
            // id-ce-cRLNumber: a non-negative INTEGER of at most 20 octets.
            Some(20) => set_once(crl_number_seen, || {
                let number = der::read_all(ext.value, Reader::nonnegative_integer)
                    .map_err(|_| Error::InvalidCrlNumber)?;
                if number.len() > 20 {
                    return Err(Error::InvalidCrlNumber);
                }
                Ok(())
            }),
            // id-ce-deltaCRLIndicator
            Some(27) => Err(Error::UnsupportedDeltaCrl),
            // id-ce-issuingDistributionPoint
            Some(28) => set_once(&mut self.issuing_distribution_point, || Ok(ext.value)),
            // id-ce-authorityKeyIdentifier: recognised, not used.
            Some(35) => der::read_all(ext.value, |r| {
                r.nested(tag::SEQUENCE, |aki| {
                    aki.optional(tag::context(0))?;
                    aki.optional(tag::context_constructed(1))?;
                    aki.optional(tag::context(2))?;
                    Ok(())
                })
            })
            .map_err(|_| Error::ExtensionValueInvalid),
            _ => ext.unsupported(UnknownExtensionPolicy::Strict),
        }
    }
}

/// Reads one `revokedCertificates` entry.
pub(crate) fn read_revoked_cert<'a>(
    reader: &mut Reader<'a>,
) -> Result<BorrowedRevokedCert<'a>, Error> {
    reader.nested(tag::SEQUENCE, |entry| {
        // Serial numbers are accepted with any sign or length, as for
        // certificates; only the encoding is checked.
        let serial_number = entry.integer().map_err(|_| Error::InvalidSerialNumber)?;
        let revocation_date = read_time(entry)?;
        let mut revoked = BorrowedRevokedCert {
            serial_number,
            revocation_date,
            reason_code: None,
            invalidity_date: None,
        };
        if entry.at_end() {
            return Ok(revoked);
        }
        // Some issuers encode "no extensions" as an empty SEQUENCE.
        let exts = entry.expect(tag::SEQUENCE)?;
        extensions::for_each(exts, true, |ext| revoked.remember_extension(&ext))?;
        Ok(revoked)
    })
}

impl<'a> BorrowedRevokedCert<'a> {
    fn remember_extension(&mut self, ext: &Extension<'a>) -> Result<(), Error> {
        match ext.id_ce_arc() {
            // id-ce-cRLReasons
            Some(21) => set_once(&mut self.reason_code, || {
                let code = der::read_all(ext.value, |r| r.expect(tag::ENUMERATED))?;
                match code {
                    [value] => RevocationReason::try_from(*value),
                    _ => Err(Error::BadDer),
                }
            }),
            // id-ce-invalidityDate
            Some(24) => set_once(&mut self.invalidity_date, || {
                der::read_all(ext.value, read_time)
            }),
            // id-ce-certificateIssuer: only appears in indirect CRLs.
            Some(29) => Err(Error::UnsupportedIndirectCrl),
            _ => ext.unsupported(UnknownExtensionPolicy::Strict),
        }
    }
}

/// The scope of a CRL as declared by its `issuingDistributionPoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IssuingDistributionPoint<'a> {
    /// `fullName` `GeneralNames` contents.
    full_names: &'a [u8],
    only_user_certs: bool,
    only_ca_certs: bool,
}

impl<'a> IssuingDistributionPoint<'a> {
    /// Parses the extension value, rejecting the forms this crate does not
    /// support: indirect CRLs, reason partitioning, attribute certificates,
    /// and distribution points without a full name.
    pub(crate) fn parse(value: &'a [u8]) -> Result<Self, Error> {
        let mut distribution_point = None;
        let mut only_user_certs = false;
        let mut only_ca_certs = false;
        let mut only_some_reasons = false;
        let mut indirect = false;
        let mut only_attribute_certs = false;
        der::read_all(value, |r| {
            r.nested(tag::SEQUENCE, |idp| {
                while !idp.at_end() {
                    let tlv = idp.tlv()?;
                    match tlv.tag {
                        t if t == tag::context_constructed(0) => {
                            set_once(&mut distribution_point, || Ok(tlv.value))?;
                        }
                        t if t == tag::context(1) => {
                            only_user_certs = der::boolean_value(tlv.value)?;
                        }
                        t if t == tag::context(2) => {
                            only_ca_certs = der::boolean_value(tlv.value)?;
                        }
                        t if t == tag::context(3) => {
                            der::bit_string_flags(tlv.value)?;
                            only_some_reasons = true;
                        }
                        t if t == tag::context(4) => {
                            indirect = der::boolean_value(tlv.value)?;
                        }
                        t if t == tag::context(5) => {
                            only_attribute_certs = der::boolean_value(tlv.value)?;
                        }
                        _ => return Err(Error::BadDer),
                    }
                }
                Ok(())
            })
        })?;
        if only_attribute_certs {
            // Conforming issuers MUST set this to FALSE (RFC 5280 §5.2.5).
            return Err(Error::MalformedExtensions);
        }
        if indirect {
            return Err(Error::UnsupportedIndirectCrl);
        }
        if only_some_reasons {
            return Err(Error::UnsupportedRevocationReasonsPartitioning);
        }
        let Some(distribution_point) = distribution_point else {
            return Err(Error::UnsupportedCrlIssuingDistributionPoint);
        };
        match DistributionPointName::parse(distribution_point) {
            Ok(DistributionPointName::FullName(full_names)) => Ok(Self {
                full_names,
                only_user_certs,
                only_ca_certs,
            }),
            Ok(DistributionPointName::RelativeToIssuer) => {
                Err(Error::UnsupportedCrlIssuingDistributionPoint)
            }
            Err(_) => Err(Error::MalformedExtensions),
        }
    }

    /// Whether this scope covers `cert`, given the certificate's own CRL
    /// distribution points: the scope's certificate kind must admit the
    /// certificate's role, and when the certificate names distribution
    /// points, one of their URIs must appear in this scope's full name.
    /// Distribution points this crate cannot interpret are skipped.
    pub(crate) fn covers(&self, cert: &Cert<'_>, role: Role) -> bool {
        if (self.only_ca_certs && role != Role::Issuer)
            || (self.only_user_certs && role != Role::EndEntity)
        {
            return false;
        }
        let Some(points) = cert.crl_distribution_points else {
            return true;
        };
        let mut reader = Reader::new(points);
        while !reader.at_end() {
            // Each point is a SEQUENCE (checked when the certificate was
            // parsed), so a malformed one is skipped as a whole.
            let Ok(point) = DistributionPoint::read(&mut reader) else {
                continue;
            };
            if point.crl_issuer || point.reasons {
                continue;
            }
            let Some(DistributionPointName::FullName(names)) = point.name else {
                continue;
            };
            let has_common_uri = GeneralNames::new(Some(names)).any(|name| {
                let Ok(GeneralName::Uri(uri)) = name else {
                    return false;
                };
                GeneralNames::new(Some(self.full_names))
                    .any(|idp| matches!(idp, Ok(GeneralName::Uri(u)) if u == uri))
            });
            if has_common_uri {
                return true;
            }
        }
        false
    }
}

/// `DistributionPointName` (RFC 5280 §4.2.1.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DistributionPointName<'a> {
    /// `GeneralNames` contents.
    FullName(&'a [u8]),
    RelativeToIssuer,
}

impl<'a> DistributionPointName<'a> {
    fn parse(value: &'a [u8]) -> Result<Self, Error> {
        der::read_all(value, |r| {
            let tlv = r.tlv()?;
            match tlv.tag {
                t if t == tag::context_constructed(0) => Ok(Self::FullName(tlv.value)),
                t if t == tag::context_constructed(1) => Ok(Self::RelativeToIssuer),
                _ => Err(Error::BadDer),
            }
        })
    }
}

/// One `DistributionPoint` of a certificate's `cRLDistributionPoints`.
#[derive(Clone, Copy, Debug)]
struct DistributionPoint<'a> {
    name: Option<DistributionPointName<'a>>,
    reasons: bool,
    crl_issuer: bool,
}

impl<'a> DistributionPoint<'a> {
    fn read(reader: &mut Reader<'a>) -> Result<Self, Error> {
        reader.nested(tag::SEQUENCE, |dp| {
            let mut name = None;
            let mut reasons = None;
            let mut crl_issuer = None;
            while !dp.at_end() {
                let tlv = dp.tlv()?;
                match tlv.tag {
                    t if t == tag::context_constructed(0) => {
                        set_once(&mut name, || DistributionPointName::parse(tlv.value))?;
                    }
                    t if t == tag::context(1) => {
                        set_once(&mut reasons, || {
                            der::bit_string_flags(tlv.value).map(|_| ())
                        })?;
                    }
                    t if t == tag::context_constructed(2) => {
                        set_once(&mut crl_issuer, || Ok(()))?;
                    }
                    _ => return Err(Error::BadDer),
                }
            }
            // Either distributionPoint or cRLIssuer MUST be present.
            if name.is_none() && crl_issuer.is_none() {
                return Err(Error::MalformedExtensions);
            }
            Ok(Self {
                name,
                reasons: reasons.is_some(),
                crl_issuer: crl_issuer.is_some(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idp(inner: &[u8]) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![tag::SEQUENCE, inner.len() as u8];
        v.extend_from_slice(inner);
        v
    }

    // distributionPoint [0] { fullName [0] { URI "http://x" } }
    const FULL_NAME_DP: &[u8] = b"\xa0\x0c\xa0\x0a\x86\x08http://x";

    #[test]
    fn issuing_distribution_point() {
        assert!(IssuingDistributionPoint::parse(&idp(FULL_NAME_DP)).is_ok());
        // onlyContainsUserCerts TRUE
        let mut user = FULL_NAME_DP.to_vec();
        user.extend_from_slice(b"\x81\x01\xff");
        let user_idp = idp(&user);
        let parsed = IssuingDistributionPoint::parse(&user_idp).unwrap();
        assert!(parsed.only_user_certs && !parsed.only_ca_certs);
        // Relative name, missing name, indirect, reasons, attribute certs.
        assert_eq!(
            IssuingDistributionPoint::parse(&idp(b"\xa0\x02\xa1\x00")),
            Err(Error::UnsupportedCrlIssuingDistributionPoint)
        );
        assert_eq!(
            IssuingDistributionPoint::parse(&idp(b"\x81\x01\xff")),
            Err(Error::UnsupportedCrlIssuingDistributionPoint)
        );
        let mut indirect = FULL_NAME_DP.to_vec();
        indirect.extend_from_slice(b"\x84\x01\xff");
        assert_eq!(
            IssuingDistributionPoint::parse(&idp(&indirect)),
            Err(Error::UnsupportedIndirectCrl)
        );
        let mut reasons = FULL_NAME_DP.to_vec();
        reasons.extend_from_slice(b"\x83\x02\x06\x40");
        assert_eq!(
            IssuingDistributionPoint::parse(&idp(&reasons)),
            Err(Error::UnsupportedRevocationReasonsPartitioning)
        );
        let mut attr = FULL_NAME_DP.to_vec();
        attr.extend_from_slice(b"\x85\x01\xff");
        assert_eq!(
            IssuingDistributionPoint::parse(&idp(&attr)),
            Err(Error::MalformedExtensions)
        );
        // Unknown tag and bad boolean.
        assert_eq!(
            IssuingDistributionPoint::parse(&idp(b"\x86\x01\xff")),
            Err(Error::BadDer)
        );
        let mut bad_bool = FULL_NAME_DP.to_vec();
        bad_bool.extend_from_slice(b"\x81\x01\x01");
        assert_eq!(
            IssuingDistributionPoint::parse(&idp(&bad_bool)),
            Err(Error::BadDer)
        );
    }

    #[test]
    fn distribution_points() {
        let mut r = Reader::new(b"\x30\x0e\xa0\x0c\xa0\x0a\x86\x08http://x");
        let dp = DistributionPoint::read(&mut r).unwrap();
        assert!(matches!(dp.name, Some(DistributionPointName::FullName(_))));
        assert!(!dp.reasons && !dp.crl_issuer);
        // Reasons only is malformed.
        let mut r = Reader::new(b"\x30\x04\x81\x02\x06\x40");
        assert_eq!(
            DistributionPoint::read(&mut r).err(),
            Some(Error::MalformedExtensions)
        );
        // cRLIssuer only is fine.
        let mut r = Reader::new(b"\x30\x02\xa2\x00");
        assert!(DistributionPoint::read(&mut r).unwrap().crl_issuer);
    }
}

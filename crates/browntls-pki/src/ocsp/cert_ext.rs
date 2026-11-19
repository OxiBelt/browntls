//! Certificate extensions related to OCSP: TLS feature (RFC 7633),
//! authority information access (RFC 5280 section 4.2.2.1) and
//! `id-pkix-ocsp-nocheck` (RFC 6960 section 4.2.2.2.1).
//!
//! [`Cert`] parsing does not decode these extensions, so each function
//! validates the one it reads and rejects a certificate that repeats it.

use super::oid;
use crate::cert::Cert;
use crate::der::{self, Reader, tag};
use crate::error::Error;
use crate::extensions::Extension;

/// `uniformResourceIdentifier [6] IMPLICIT IA5String` of `GeneralName`.
const GENERAL_NAME_URI: u8 = tag::context(6);

/// The TLS feature number of `status_request` (RFC 6066).
const STATUS_REQUEST: &[u8] = &[5];

/// The only extension of `cert` with identifier `extn_id`.
fn unique_extension<'a>(cert: &Cert<'a>, extn_id: &[u8]) -> Result<Option<Extension<'a>>, Error> {
    let mut found = None;
    for ext in cert.extensions().filter(|ext| ext.id == extn_id) {
        if found.is_some() {
            return Err(Error::MalformedExtensions);
        }
        found = Some(ext);
    }
    Ok(found)
}

/// Whether the certificate requires a stapled OCSP response ("OCSP
/// Must-Staple"): its TLS feature extension (RFC 7633) lists
/// `status_request`.
///
/// # Errors
///
/// [`Error::MalformedExtensions`] if the extension is repeated,
/// [`Error::ExtensionValueInvalid`] if its value is not a `SEQUENCE` of
/// non-negative `INTEGER`s.
pub fn must_staple(cert: &Cert<'_>) -> Result<bool, Error> {
    let Some(ext) = unique_extension(cert, oid::TLS_FEATURE)? else {
        return Ok(false);
    };
    der::read_all(ext.value, |r| {
        r.nested(tag::SEQUENCE, |features| {
            let mut found = false;
            while !features.at_end() {
                found |= features.nonnegative_integer()? == STATUS_REQUEST;
            }
            Ok(found)
        })
    })
    .map_err(|_| Error::ExtensionValueInvalid)
}

/// Whether the certificate carries `id-pkix-ocsp-nocheck`, by which a CA
/// tells clients to trust an OCSP responder certificate for its lifetime
/// without checking its revocation.
///
/// # Errors
///
/// [`Error::MalformedExtensions`] if the extension is repeated,
/// [`Error::ExtensionValueInvalid`] if its value is not `NULL`.
pub fn has_ocsp_nocheck(cert: &Cert<'_>) -> Result<bool, Error> {
    let Some(ext) = unique_extension(cert, oid::NOCHECK)? else {
        return Ok(false);
    };
    match der::read_all(ext.value, |r| r.expect(tag::NULL)) {
        Ok([]) => Ok(true),
        _ => Err(Error::ExtensionValueInvalid),
    }
}

/// The OCSP responder URIs of the certificate's authority information
/// access extension (`id-ad-ocsp`), in encoding order.
///
/// The URIs are returned as encoded, checked only to be ASCII; a caller
/// that fetches them decides which schemes and hosts it accepts.
///
/// # Errors
///
/// [`Error::MalformedExtensions`] if the extension is repeated,
/// [`Error::ExtensionValueInvalid`] if its value is not a non-empty
/// `SEQUENCE` of `AccessDescription`.
pub fn ocsp_responder_uris<'a>(cert: &Cert<'a>) -> Result<AccessUris<'a>, Error> {
    access_uris(cert, oid::AD_OCSP)
}

/// The URIs of the certificate's authority information access extension
/// from which the issuer's certificate may be retrieved
/// (`id-ad-caIssuers`), as [`ocsp_responder_uris`] returns the responder's.
///
/// # Errors
///
/// As [`ocsp_responder_uris`].
pub fn ca_issuer_uris<'a>(cert: &Cert<'a>) -> Result<AccessUris<'a>, Error> {
    access_uris(cert, oid::AD_CA_ISSUERS)
}

fn access_uris<'a>(cert: &Cert<'a>, method: &'static [u8]) -> Result<AccessUris<'a>, Error> {
    let Some(ext) = unique_extension(cert, oid::AUTHORITY_INFO_ACCESS)? else {
        return Ok(AccessUris {
            reader: Reader::new(&[]),
            method,
        });
    };
    let descriptions = der::read_all(ext.value, |r| {
        let descriptions = r.expect(tag::SEQUENCE)?;
        if descriptions.is_empty() {
            return Err(Error::BadDer);
        }
        der::read_all(descriptions, |list| {
            while !list.at_end() {
                read_access_description(list)?;
            }
            Ok(())
        })?;
        Ok(descriptions)
    })
    .map_err(|_| Error::ExtensionValueInvalid)?;
    Ok(AccessUris {
        reader: Reader::new(descriptions),
        method,
    })
}

/// Reads `AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER,
/// accessLocation GeneralName }`, returning the method and, when the
/// location is a URI, its octets.
fn read_access_description<'a>(
    reader: &mut Reader<'a>,
) -> Result<(&'a [u8], Option<&'a [u8]>), Error> {
    reader.nested(tag::SEQUENCE, |description| {
        let method = description.oid()?;
        let location = description.tlv()?;
        let uri = (location.tag == GENERAL_NAME_URI).then_some(location.value);
        Ok((method, uri))
    })
}

/// An iterator over the URIs of one access method in an authority
/// information access extension. Locations of other name types, and URIs
/// that are not ASCII, are skipped. The extension was validated by the
/// function that returned the iterator, so iteration cannot fail.
#[derive(Clone, Debug)]
pub struct AccessUris<'a> {
    reader: Reader<'a>,
    method: &'static [u8],
}

impl<'a> Iterator for AccessUris<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.reader.at_end() {
            let Ok((method, uri)) = read_access_description(&mut self.reader) else {
                // Validated before; a failure (impossible) ends iteration.
                self.reader = Reader::new(&[]);
                return None;
            };
            if method != self.method {
                continue;
            }
            let uri = uri
                .filter(|uri| uri.is_ascii())
                .and_then(|uri| core::str::from_utf8(uri).ok());
            if uri.is_some() {
                return uri;
            }
        }
        None
    }
}

impl core::iter::FusedIterator for AccessUris<'_> {}

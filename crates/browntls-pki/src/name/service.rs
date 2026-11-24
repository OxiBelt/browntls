//! Shared extraction of DNS hosts and SRVName values for service identities
//! and name constraints.

use alloc::borrow::Cow;

use fluent_uri::Uri;

use crate::der::{self, Reader, tag};
use crate::error::Error;

const SRV_NAME_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, 0x07];
const MAX_URI_IDENTIFIER_LEN: usize = u16::MAX as usize;

/// Returns the SRVName IA5String contents from an `otherName` value.
///
/// `Ok(None)` means the otherName uses a different type OID. A malformed
/// value with the SRVName OID is an error.
pub(crate) fn srv_name_value(value: &[u8]) -> Result<Option<&[u8]>, Error> {
    der::read_all(value, |reader| {
        let oid = reader.expect(tag::OID)?;
        let value = reader.tlv()?;
        if oid != SRV_NAME_OID {
            return Ok(None);
        }
        if value.tag != tag::context_constructed(0) {
            return Err(Error::BadDer);
        }
        let mut inner = Reader::new(value.value);
        let name = inner.expect(0x16)?;
        if !inner.at_end() || name.is_empty() || !name.is_ascii() {
            return Err(Error::BadDer);
        }
        Ok(Some(name))
    })
}

/// Extracts the scheme and ASCII DNS reg-name host from a URI identifier.
///
/// Generic URI authority syntax is validated before extracting the host.
/// SIP carries its host in a scheme-specific part rather than a generic
/// authority. Only the scheme and DNS host contribute to the URI-ID.
pub(crate) fn uri_dns_components(uri: &[u8], allow_bare_sip: bool) -> Option<(&str, Cow<'_, str>)> {
    if uri.len() > MAX_URI_IDENTIFIER_LEN || !uri.is_ascii() {
        return None;
    }
    let text = core::str::from_utf8(uri).ok()?;
    let parsed = Uri::parse(text).ok()?;
    let scheme = parsed.scheme().as_str();
    let is_sip = scheme.eq_ignore_ascii_case("sip") || scheme.eq_ignore_ascii_case("sips");
    if let Some(authority) = parsed.authority() {
        if is_sip {
            return None;
        }
        return Some((scheme, reg_name(authority.host())?));
    }
    if !allow_bare_sip || !is_sip || parsed.fragment().is_some() {
        return None;
    }
    let (_, sip) = text.split_once(':')?;
    let address = match sip.split_once('@') {
        Some((userinfo, address)) => {
            if !valid_sip_userinfo(userinfo) || address.contains('@') {
                return None;
            }
            address
        }
        None => sip,
    };
    let host_port = address.split([';', '?']).next()?;
    let host = if let Some((host, port)) = host_port.split_once(':') {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        host
    } else {
        host_port
    };
    Some((scheme, reg_name(host)?))
}

/// RFC 3261 §25.1 userinfo. The URI parser has already checked escapes.
/// SIP allows '?' and ';' in the user, before the literal '@' delimiter.
fn valid_sip_userinfo(userinfo: &str) -> bool {
    fn common(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || b"-_.!~*'()%&=+$,".contains(&byte)
    }
    let (user, password) = match userinfo.split_once(':') {
        Some((user, password)) => (user, Some(password)),
        None => (userinfo, None),
    };
    !user.is_empty()
        && user
            .bytes()
            .all(|byte| common(byte) || b";?/".contains(&byte))
        && password.is_none_or(|password| password.bytes().all(common))
}

fn reg_name(host: &str) -> Option<Cow<'_, str>> {
    if host.is_empty() {
        return None;
    }
    let mut decoded = None;
    let mut cursor = 0;
    while let Some(offset) = host[cursor..].find('%') {
        let index = cursor + offset;
        let encoded = host.get(index + 1..index + 3)?;
        let byte = u8::from_str_radix(encoded, 16).ok()?;
        let character = byte as char;
        if !character.is_ascii_alphanumeric() && !matches!(character, '-' | '.' | '_' | '~') {
            return None;
        }
        let output =
            decoded.get_or_insert_with(|| alloc::string::String::with_capacity(host.len()));
        output.push_str(&host[cursor..index]);
        output.push(character);
        cursor = index + 3;
    }
    let normalized = match decoded {
        Some(mut value) => {
            value.push_str(&host[cursor..]);
            Cow::Owned(value)
        }
        None => Cow::Borrowed(host),
    };
    if normalized.len() > 253 || !normalized.is_ascii() {
        return None;
    }
    crate::DnsName::try_from_ascii(&normalized).ok()?;
    Some(normalized)
}

/// Whether an underscore-prefixed DNS SRV service label is syntactically valid.
pub(crate) fn valid_srv_service(service: &str) -> bool {
    let Some(label) = service.strip_prefix('_') else {
        return false;
    };
    !label.is_empty()
        && service.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

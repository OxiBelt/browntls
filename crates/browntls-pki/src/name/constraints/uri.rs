//! RFC 5280 URI name constraints.

use crate::error::Error;
use crate::name::service::uri_dns_components;
use crate::server_name::DnsName;

/// Whether a URI's DNS authority host is inside a URI constraint base.
pub(super) fn presented_matches_constraint(uri: &[u8], base: &[u8]) -> Result<bool, Error> {
    let (_, host) = uri_dns_components(uri, false).ok_or(Error::NameConstraintViolation)?;
    if !valid_domain(&host) {
        return Err(Error::NameConstraintViolation);
    }
    let base = core::str::from_utf8(base).map_err(|_| Error::MalformedNameConstraint)?;
    let domain = base.strip_prefix('.').unwrap_or(base);
    if !valid_domain(domain) {
        return Err(Error::MalformedNameConstraint);
    }
    if base.starts_with('.') {
        Ok(within_domain(&host, domain))
    } else {
        Ok(host.eq_ignore_ascii_case(domain))
    }
}

pub(super) fn valid_domain(name: &str) -> bool {
    !name.ends_with('.') && DnsName::try_from_ascii(name).is_ok()
}

/// Whether `name` is a proper subdomain of `domain`.
pub(super) fn within_domain(name: &str, domain: &str) -> bool {
    let Some(offset) = name.len().checked_sub(domain.len()) else {
        return false;
    };
    let name = name.as_bytes();
    offset > 0 && name[offset - 1] == b'.' && name[offset..].eq_ignore_ascii_case(domain.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_host_and_subdomain_constraints() {
        let host = b"example.com";
        let domain = b".example.com";
        let apex = b"https://EXAMPLE.com/path";
        let child = b"https://api.example.com/";
        assert_eq!(presented_matches_constraint(apex, host), Ok(true));
        assert_eq!(presented_matches_constraint(child, host), Ok(false));
        assert_eq!(presented_matches_constraint(apex, domain), Ok(false));
        assert_eq!(presented_matches_constraint(child, domain), Ok(true));
        assert_eq!(
            presented_matches_constraint(b"https://badexample.com/", domain),
            Ok(false)
        );
    }

    #[test]
    fn uri_constraint_requires_a_dns_authority_host_and_dns_base() {
        for uri in [
            b"sip:example.com".as_slice(),
            b"mailto:user@example.com",
            b"https:///missing-host",
            b"https://127.0.0.1/",
            b"https://[::1]/",
        ] {
            assert_eq!(
                presented_matches_constraint(uri, b"example.com"),
                Err(Error::NameConstraintViolation)
            );
        }
        assert_eq!(
            presented_matches_constraint(b"https://example.com/", b"bad..example.com"),
            Err(Error::MalformedNameConstraint)
        );
    }
}

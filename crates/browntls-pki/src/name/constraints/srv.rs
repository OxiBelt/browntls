//! RFC 4985 SRVName name constraints.

use crate::error::Error;
use crate::service_identity::valid_srv_service;

use super::uri::{valid_domain, within_domain};

/// Whether a presented SRVName matches the service and/or domain in a base.
pub(super) fn presented_matches_constraint(presented: &[u8], base: &[u8]) -> Result<bool, Error> {
    let (Some(service), Some(domain)) = parts(presented).ok_or(Error::NameConstraintViolation)?
    else {
        return Err(Error::NameConstraintViolation);
    };
    let (base_service, base_domain) = parts(base).ok_or(Error::MalformedNameConstraint)?;
    Ok(
        base_service.is_none_or(|base| service.eq_ignore_ascii_case(base))
            && base_domain.is_none_or(|base| {
                domain.eq_ignore_ascii_case(base) || within_domain(domain, base)
            }),
    )
}

fn parts(value: &[u8]) -> Option<(Option<&str>, Option<&str>)> {
    let value = core::str::from_utf8(value).ok()?;
    if !value.starts_with('_') {
        return valid_domain(value).then_some((None, Some(value)));
    }
    if let Some((service, domain)) = value.split_once('.') {
        return (valid_srv_service(service) && valid_domain(domain))
            .then_some((Some(service), Some(domain)));
    }
    valid_srv_service(value).then_some((Some(value), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_domain_and_combined_constraints() {
        for base in [b"_imap.example.com".as_slice(), b"_IMAP", b"example.com"] {
            assert_eq!(
                presented_matches_constraint(b"_imap.example.com", base),
                Ok(true)
            );
            assert_eq!(
                presented_matches_constraint(b"_imap.sub.example.com", base),
                Ok(true)
            );
        }
        assert_eq!(
            presented_matches_constraint(b"_imap.badexample.com", b"example.com"),
            Ok(false)
        );
        assert_eq!(
            presented_matches_constraint(b"_smtp.example.com", b"_imap"),
            Ok(false)
        );
        assert_eq!(
            presented_matches_constraint(b"_smtp.example.com", b"example.com"),
            Ok(true)
        );
    }

    #[test]
    fn malformed_relevant_srv_name_fails_closed() {
        for name in [
            b"imap.example.com".as_slice(),
            b"_imap",
            b"_imap._tcp.example.com",
            b"_imap.example.com.",
        ] {
            assert_eq!(
                presented_matches_constraint(name, b"_imap"),
                Err(Error::NameConstraintViolation)
            );
        }
        assert_eq!(
            presented_matches_constraint(b"_imap.example.com", b".example.com"),
            Err(Error::MalformedNameConstraint)
        );
    }
}

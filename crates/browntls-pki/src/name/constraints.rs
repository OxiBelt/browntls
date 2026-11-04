//! Name constraints (RFC 5280 §4.2.1.10).
//!
//! The constraints of a CA apply to every certificate below it in the path.
//! Each presented name is compared with every constraint base of the same
//! form: a presented name must match at least one permitted subtree of its
//! form (when any exist) and no excluded subtree. Forms this crate does not
//! implement fail closed: `directoryName` and `uniformResourceIdentifier`
//! bases match nothing permitted and everything excluded, and any other
//! form rejects the path when both the name and a base use it.

use super::dns::{self, IdRole};
use super::{GeneralName, GeneralNames, ip};
use crate::cert::Cert;
use crate::der::{self, Reader, tag};
use crate::error::Error;
use crate::path::Budget;

/// Which subtree list a base belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Subtrees {
    Permitted,
    Excluded,
}

/// Checks the structure of `NameConstraints` contents: at least one of the
/// subtree lists, each non-empty and made of `GeneralSubtree`s without the
/// `minimum`/`maximum` fields this profile forbids.
pub(crate) fn validate(contents: &[u8]) -> Result<(), Error> {
    der::read_all(contents, |r| {
        let (permitted, excluded) = split(r)?;
        if permitted.is_none() && excluded.is_none() {
            return Err(Error::MalformedNameConstraint);
        }
        for subtrees in [permitted, excluded].into_iter().flatten() {
            if subtrees.is_empty() {
                return Err(Error::MalformedNameConstraint);
            }
            der::read_all(subtrees, |r| {
                while !r.at_end() {
                    read_subtree(r)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    })
    .map_err(|_| Error::MalformedNameConstraint)
}

/// Applies the constraints in `contents` to every certificate in `certs`.
pub(crate) fn check<'a>(
    contents: &[u8],
    certs: impl Iterator<Item = &'a Cert<'a>>,
    budget: &mut Budget,
) -> Result<(), Error> {
    let (permitted, excluded) =
        der::read_all(contents, split).map_err(|_| Error::MalformedNameConstraint)?;
    for cert in certs {
        for name in GeneralNames::new(cert.subject_alt_name) {
            check_name(name?, permitted, excluded, budget)?;
        }
        // The subject is a directory name and is always present.
        check_name(GeneralName::DirectoryName, permitted, excluded, budget)?;
    }
    Ok(())
}

type SubtreeLists<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);

fn split<'a>(r: &mut Reader<'a>) -> Result<SubtreeLists<'a>, Error> {
    let permitted = r.optional(tag::context_constructed(0))?;
    let excluded = r.optional(tag::context_constructed(1))?;
    Ok((permitted, excluded))
}

fn read_subtree<'a>(r: &mut Reader<'a>) -> Result<GeneralName<'a>, Error> {
    // GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] DEFAULT 0,
    // maximum [1] OPTIONAL }; this profile requires both to be absent.
    r.nested(tag::SEQUENCE, GeneralName::read)
}

fn check_name(
    name: GeneralName<'_>,
    permitted: Option<&[u8]>,
    excluded: Option<&[u8]>,
    budget: &mut Budget,
) -> Result<(), Error> {
    for (kind, subtrees) in [
        (Subtrees::Permitted, permitted),
        (Subtrees::Excluded, excluded),
    ] {
        let Some(subtrees) = subtrees else {
            continue;
        };
        let mut reader = Reader::new(subtrees);
        let mut any_of_this_form = false;
        let mut matched = false;
        while !reader.at_end() {
            budget.consume_name_constraint_comparison()?;
            let base = read_subtree(&mut reader).map_err(|_| Error::MalformedNameConstraint)?;
            let matches = match (name, base) {
                (GeneralName::DnsName(n), GeneralName::DnsName(b)) => {
                    dns::presented_matches(n, IdRole::Constraint(kind), b)?
                }
                (GeneralName::IpAddress(n), GeneralName::IpAddress(b)) => {
                    ip::presented_matches_constraint(n, b)?
                }
                // Not implemented: fail closed by matching nothing permitted
                // and everything excluded.
                (GeneralName::DirectoryName, GeneralName::DirectoryName)
                | (GeneralName::Uri(_), GeneralName::Uri(_)) => kind == Subtrees::Excluded,
                // A constraint on a form this crate cannot process must
                // reject a certificate presenting that form (RFC 5280 §4.2).
                (GeneralName::Unsupported(n), GeneralName::Unsupported(b)) if n == b => {
                    return Err(Error::NameConstraintViolation);
                }
                _ => continue,
            };
            match kind {
                Subtrees::Permitted => {
                    any_of_this_form = true;
                    matched |= matches;
                }
                Subtrees::Excluded if matches => return Err(Error::NameConstraintViolation),
                Subtrees::Excluded => {}
            }
        }
        if any_of_this_form && !matched {
            return Err(Error::NameConstraintViolation);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subtree(name: &[u8]) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![tag::SEQUENCE, (name.len()) as u8];
        v.extend_from_slice(name);
        v
    }

    fn list(tag_byte: u8, subtrees: &[&[u8]]) -> alloc::vec::Vec<u8> {
        let body: alloc::vec::Vec<u8> = subtrees.iter().flat_map(|s| subtree(s)).collect();
        let mut v = alloc::vec![tag_byte, body.len() as u8];
        v.extend(body);
        v
    }

    const DNS_EXAMPLE: &[u8] = b"\x82\x0bexample.com";

    #[test]
    fn validation() {
        let permitted = list(0xa0, &[DNS_EXAMPLE]);
        assert_eq!(validate(&permitted), Ok(()));
        assert_eq!(validate(&[]), Err(Error::MalformedNameConstraint));
        assert_eq!(validate(&[0xa0, 0x00]), Err(Error::MalformedNameConstraint));
        // Excluded before permitted is out of order.
        let mut swapped = list(0xa1, &[DNS_EXAMPLE]);
        swapped.extend(permitted.clone());
        assert_eq!(validate(&swapped), Err(Error::MalformedNameConstraint));
        // A minimum field is forbidden.
        let mut with_min = DNS_EXAMPLE.to_vec();
        with_min.extend_from_slice(&[0x80, 0x01, 0x00]);
        assert_eq!(
            validate(&list(0xa0, &[&with_min])),
            Err(Error::MalformedNameConstraint)
        );
        // Unknown GeneralName choice.
        assert_eq!(
            validate(&list(0xa0, &[b"\x89\x01a"])),
            Err(Error::MalformedNameConstraint)
        );
    }

    fn check_single(nc: &[u8], name: GeneralName<'_>) -> Result<(), Error> {
        let (p, e) = der::read_all(nc, split).unwrap();
        check_name(name, p, e, &mut Budget::default())
    }

    #[test]
    fn semantics() {
        let permitted = list(0xa0, &[DNS_EXAMPLE]);
        assert_eq!(
            check_single(&permitted, GeneralName::DnsName(b"www.example.com")),
            Ok(())
        );
        assert_eq!(
            check_single(&permitted, GeneralName::DnsName(b"example.org")),
            Err(Error::NameConstraintViolation)
        );
        // Other forms are unaffected by DNS constraints.
        assert_eq!(
            check_single(&permitted, GeneralName::IpAddress(&[1, 2, 3, 4])),
            Ok(())
        );
        assert_eq!(check_single(&permitted, GeneralName::DirectoryName), Ok(()));
        let excluded = list(0xa1, &[DNS_EXAMPLE]);
        assert_eq!(
            check_single(&excluded, GeneralName::DnsName(b"www.example.com")),
            Err(Error::NameConstraintViolation)
        );
        assert_eq!(
            check_single(&excluded, GeneralName::DnsName(b"example.org")),
            Ok(())
        );
        // Directory name constraints fail closed.
        let dir = list(0xa0, &[b"\xa4\x00"]);
        assert_eq!(
            check_single(&dir, GeneralName::DirectoryName),
            Err(Error::NameConstraintViolation)
        );
        // rfc822Name constraints only matter for rfc822Name SANs.
        let mail = list(0xa0, &[b"\x81\x0bexample.com"]);
        assert_eq!(
            check_single(&mail, GeneralName::DnsName(b"example.com")),
            Ok(())
        );
        assert_eq!(
            check_single(&mail, GeneralName::Unsupported(1)),
            Err(Error::NameConstraintViolation)
        );
        // Malformed presented DNS names are an error here.
        assert_eq!(
            check_single(&permitted, GeneralName::DnsName(b"bad..example.com")),
            Err(Error::MalformedDnsIdentifier)
        );
    }

    #[test]
    fn budget_is_consumed() {
        let permitted = list(0xa0, &[DNS_EXAMPLE, DNS_EXAMPLE]);
        let (p, e) = der::read_all(&permitted, split).unwrap();
        let mut budget = Budget::with_name_constraint_comparisons(1);
        assert_eq!(
            check_name(GeneralName::DnsName(b"example.com"), p, e, &mut budget),
            Err(Error::MaximumNameConstraintComparisonsExceeded)
        );
    }
}

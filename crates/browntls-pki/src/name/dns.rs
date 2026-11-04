//! DNS identifier matching for `dNSName` presented identifiers, reference
//! identifiers (RFC 6125 §6.4) and `dNSName` name constraints (RFC 5280
//! §4.2.1.10).
//!
//! Rules, which follow the consensus of NSS, Chromium and webpki rather than
//! the most permissive reading of the RFCs:
//!
//! * Comparison is ASCII case-insensitive; names are A-labels (RFC 5890).
//! * A wildcard is only accepted as the complete left-most label (`*.`) and
//!   must be followed by at least two labels, so `*.example.com` is valid but
//!   `*.com`, `w*.example.com` and `*.*.example.com` are not.
//! * A wildcard matches exactly one non-empty label, never the empty string.
//! * Presented identifiers and constraints must be relative; a reference
//!   identifier may carry a trailing dot and then matches the relative form.
//! * A constraint `example.com` matches that name and every subdomain; a
//!   constraint `.example.com` matches only subdomains; a constraint `""`
//!   matches every name. Comparison is on label boundaries, so
//!   `badexample.com` does not match `example.com`.
//! * Against permitted subtrees a wildcard label is compared literally, so
//!   `*.example.com` is inside `example.com` but outside `foo.example.com`.
//!   Against excluded subtrees the wildcard is expanded, so `*.example.com`
//!   is excluded by `foo.example.com` because it could match that name.

use super::constraints::Subtrees;
use super::{GeneralName, GeneralNames};
use crate::error::Error;
use crate::server_name::DnsName;

/// The role of the identifier a presented `dNSName` is compared with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdRole {
    /// The reference identifier the client wants to reach.
    Reference,
    /// An identifier presented in a certificate.
    Presented,
    /// A name constraint base.
    Constraint(Subtrees),
}

/// Checks that some `dNSName` in `san` matches `reference`.
pub(crate) fn verify_dns_name(reference: &DnsName<'_>, san: Option<&[u8]>) -> Result<(), Error> {
    let reference = reference.as_ref().as_bytes();
    for name in GeneralNames::new(san) {
        let GeneralName::DnsName(presented) = name? else {
            continue;
        };
        match presented_matches(presented, IdRole::Reference, reference) {
            Ok(true) => return Ok(()),
            // A malformed presented identifier can match nothing; keep
            // looking at the remaining names.
            Ok(false) | Err(Error::MalformedDnsIdentifier) => {}
            Err(e) => return Err(e),
        }
    }
    Err(Error::CertNotValidForName)
}

/// Whether `presented` matches `reference`, interpreted according to `role`.
pub(crate) fn presented_matches(
    presented: &[u8],
    role: IdRole,
    reference: &[u8],
) -> Result<bool, Error> {
    if !is_valid_dns_id(presented, IdRole::Presented, true) {
        return Err(Error::MalformedDnsIdentifier);
    }
    if !is_valid_dns_id(reference, role, false) {
        return Err(match role {
            IdRole::Constraint(_) => Error::MalformedNameConstraint,
            _ => Error::MalformedDnsIdentifier,
        });
    }

    let mut p = presented;
    let mut r = reference;

    // A longer presented identifier may match a constraint when the extra
    // left-hand labels are dropped. The drop must end on a label boundary
    // unless the constraint itself starts with the boundary dot.
    if let IdRole::Constraint(_) = role
        && p.len() > r.len()
    {
        if r.is_empty() {
            return Ok(true);
        }
        let skip = p.len() - r.len();
        if !r.starts_with(b".") && p.get(skip - 1) != Some(&b'.') {
            return Ok(false);
        }
        p = &p[skip..];
    }

    // Expand a wildcard label, except against permitted subtrees where it
    // is compared literally (a wildcard can reach outside the subtree).
    if p.first() == Some(&b'*') && role != IdRole::Constraint(Subtrees::Permitted) {
        p = &p[1..];
        // The label must absorb at least one byte, up to the next dot.
        match r.iter().skip(1).position(|&b| b == b'.') {
            Some(i) => r = &r[i + 1..],
            None => return Ok(false),
        }
    }

    if p.len() > r.len() {
        return Ok(false);
    }
    let (head, tail) = r.split_at(p.len());
    if !p.eq_ignore_ascii_case(head) {
        return Ok(false);
    }
    Ok(match (tail, role) {
        ([], _) => true,
        // A relative presented identifier matches an absolute reference.
        ([b'.'], IdRole::Reference) => true,
        _ => false,
    })
}

const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 253;

/// RFC 1034 §3.5 preferred name syntax as modified by RFC 1123 §2.1, with
/// underscores tolerated for compatibility, wildcard labels when
/// `allow_wildcard`, and the role-specific rules described in the module
/// documentation.
fn is_valid_dns_id(name: &[u8], role: IdRole, allow_wildcard: bool) -> bool {
    if name.len() > MAX_NAME_LEN {
        return false;
    }
    let constraint = matches!(role, IdRole::Constraint(_));
    if name.is_empty() {
        return constraint;
    }

    let mut rest = name;
    let mut completed_labels = 0usize;
    let is_wildcard = allow_wildcard && rest.first() == Some(&b'*');
    if is_wildcard {
        match rest {
            [b'*', b'.', tail @ ..] => {
                rest = tail;
                completed_labels = 1;
            }
            _ => return false,
        }
    }

    // Only a constraint may start with a dot, and only as its first byte.
    let mut first_byte = !is_wildcard;
    let mut label_len = 0usize;
    let mut all_numeric = false;
    let mut ends_with_hyphen = false;
    for &b in rest {
        match b {
            b'-' => {
                if label_len == 0 {
                    return false;
                }
                all_numeric = false;
                ends_with_hyphen = true;
                label_len += 1;
            }
            b'0'..=b'9' => {
                if label_len == 0 {
                    all_numeric = true;
                }
                ends_with_hyphen = false;
                label_len += 1;
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                all_numeric = false;
                ends_with_hyphen = false;
                label_len += 1;
            }
            b'.' => {
                if (label_len == 0 && !(constraint && first_byte)) || ends_with_hyphen {
                    return false;
                }
                label_len = 0;
                completed_labels += 1;
            }
            _ => return false,
        }
        if label_len > MAX_LABEL_LEN {
            return false;
        }
        first_byte = false;
    }

    // Only reference identifiers may be absolute.
    if label_len == 0 && role != IdRole::Reference {
        return false;
    }
    if ends_with_hyphen || all_numeric {
        return false;
    }
    if is_wildcard {
        let labels = completed_labels + usize::from(label_len > 0);
        if labels < 3 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(p: &[u8], r: &[u8]) -> Result<bool, Error> {
        presented_matches(p, IdRole::Reference, r)
    }

    fn permitted(p: &[u8], r: &[u8]) -> Result<bool, Error> {
        presented_matches(p, IdRole::Constraint(Subtrees::Permitted), r)
    }

    fn excluded(p: &[u8], r: &[u8]) -> Result<bool, Error> {
        presented_matches(p, IdRole::Constraint(Subtrees::Excluded), r)
    }

    #[test]
    fn reference_matching() {
        assert_eq!(reference(b"example.com", b"example.com"), Ok(true));
        assert_eq!(reference(b"EXAMPLE.com", b"example.COM"), Ok(true));
        assert_eq!(reference(b"example.com", b"example.com."), Ok(true));
        assert_eq!(reference(b"example.com", b"www.example.com"), Ok(false));
        assert_eq!(reference(b"www.example.com", b"example.com"), Ok(false));
        assert_eq!(reference(b"example.com", b"example.co"), Ok(false));
        assert_eq!(
            reference(b"example.com", b"example.com.."),
            Err(Error::MalformedDnsIdentifier)
        );
        // Absolute presented identifiers are malformed.
        assert_eq!(
            reference(b"example.com.", b"example.com"),
            Err(Error::MalformedDnsIdentifier)
        );
        assert_eq!(reference(b"", b"a"), Err(Error::MalformedDnsIdentifier));
        assert_eq!(reference(b"a", b""), Err(Error::MalformedDnsIdentifier));
        // Underscores and digits.
        assert_eq!(
            reference(b"_sip.example.com", b"_sip.example.com"),
            Ok(true)
        );
        assert_eq!(
            reference(b"1.2.3.4", b"1.2.3.4"),
            Err(Error::MalformedDnsIdentifier)
        );
    }

    #[test]
    fn wildcards() {
        assert_eq!(reference(b"*.example.com", b"www.example.com"), Ok(true));
        assert_eq!(reference(b"*.example.com", b"WWW.EXAMPLE.COM"), Ok(true));
        assert_eq!(reference(b"*.example.com", b"www.example.com."), Ok(true));
        assert_eq!(reference(b"*.example.com", b"example.com"), Ok(false));
        assert_eq!(reference(b"*.example.com", b"a.b.example.com"), Ok(false));
        assert_eq!(reference(b"*.example.com", b"www.example.org"), Ok(false));
        assert_eq!(
            reference(b"*.example.com", b".example.com"),
            Err(Error::MalformedDnsIdentifier)
        );
        // Partial wildcards, non-leading wildcards and public-suffix-like
        // wildcards are malformed.
        for bad in [
            &b"w*.example.com"[..],
            b"*w.example.com",
            b"www.*.com",
            b"*.*.example.com",
            b"*.com",
            b"*",
            b"*.",
            b"*.example.com.",
        ] {
            assert_eq!(
                reference(bad, b"www.example.com"),
                Err(Error::MalformedDnsIdentifier),
                "{}",
                core::str::from_utf8(bad).unwrap()
            );
        }
    }

    #[test]
    fn syntax() {
        assert_eq!(
            reference(b"-a.example.com", b"x"),
            Err(Error::MalformedDnsIdentifier)
        );
        assert_eq!(
            reference(b"a-.example.com", b"x"),
            Err(Error::MalformedDnsIdentifier)
        );
        assert_eq!(
            reference(b"a..example.com", b"x"),
            Err(Error::MalformedDnsIdentifier)
        );
        assert_eq!(
            reference(b".example.com", b"x"),
            Err(Error::MalformedDnsIdentifier)
        );
        assert_eq!(
            reference(b"ex ample.com", b"x"),
            Err(Error::MalformedDnsIdentifier)
        );
        assert_eq!(
            reference(b"ex\xc3\xa4mple.com", b"x"),
            Err(Error::MalformedDnsIdentifier)
        );
        let long_label = [b'a'; 64];
        assert_eq!(
            reference(&long_label, b"x"),
            Err(Error::MalformedDnsIdentifier)
        );
        let ok_label = [b'a'; 63];
        assert_eq!(reference(&ok_label, &ok_label), Ok(true));
        let mut long_name = alloc::vec::Vec::new();
        for _ in 0..4 {
            long_name.extend_from_slice(&[b'a'; 63]);
            long_name.push(b'.');
        }
        long_name.pop();
        assert_eq!(long_name.len(), 255);
        assert_eq!(
            reference(&long_name, b"x"),
            Err(Error::MalformedDnsIdentifier)
        );
    }

    #[test]
    fn constraints() {
        // Exact and subdomain matches on label boundaries.
        assert_eq!(permitted(b"example.com", b"example.com"), Ok(true));
        assert_eq!(permitted(b"www.example.com", b"example.com"), Ok(true));
        assert_eq!(permitted(b"a.b.example.com", b"example.com"), Ok(true));
        assert_eq!(permitted(b"badexample.com", b"example.com"), Ok(false));
        assert_eq!(permitted(b"example.com", b"www.example.com"), Ok(false));
        assert_eq!(permitted(b"example.org", b"example.com"), Ok(false));
        // Leading dot: subdomains only.
        assert_eq!(permitted(b"www.example.com", b".example.com"), Ok(true));
        assert_eq!(permitted(b"example.com", b".example.com"), Ok(false));
        assert_eq!(permitted(b"badexample.com", b".example.com"), Ok(false));
        // Empty constraint matches everything.
        assert_eq!(permitted(b"example.com", b""), Ok(true));
        assert_eq!(excluded(b"example.com", b""), Ok(true));
        // Absolute constraints and double dots are malformed.
        assert_eq!(
            permitted(b"example.com", b"example.com."),
            Err(Error::MalformedNameConstraint)
        );
        assert_eq!(
            permitted(b"example.com", b"."),
            Err(Error::MalformedNameConstraint)
        );
        assert_eq!(
            permitted(b"example.com", b"..example.com"),
            Err(Error::MalformedNameConstraint)
        );
        // Wildcards: literal against permitted, expanded against excluded.
        assert_eq!(permitted(b"*.example.com", b"example.com"), Ok(true));
        assert_eq!(permitted(b"*.example.com", b"foo.example.com"), Ok(false));
        assert_eq!(excluded(b"*.example.com", b"example.com"), Ok(true));
        assert_eq!(excluded(b"*.example.com", b"foo.example.com"), Ok(true));
        assert_eq!(excluded(b"*.example.com", b"foo.example.org"), Ok(false));
        assert_eq!(excluded(b"*.example.com", b"a.foo.example.com"), Ok(false));
        // Reference-style absolute match is not allowed for constraints.
        assert_eq!(permitted(b"example.com", b"example.com"), Ok(true));
    }

    #[test]
    fn verify_against_san() {
        let san = b"\x82\x0bexample.com\x82\x0d*.example.org";
        let name = |s: &'static str| DnsName::try_from(s).unwrap();
        assert_eq!(verify_dns_name(&name("example.com"), Some(san)), Ok(()));
        assert_eq!(verify_dns_name(&name("www.example.org"), Some(san)), Ok(()));
        assert_eq!(verify_dns_name(&name("EXAMPLE.COM."), Some(san)), Ok(()));
        assert_eq!(
            verify_dns_name(&name("www.example.com"), Some(san)),
            Err(Error::CertNotValidForName)
        );
        assert_eq!(
            verify_dns_name(&name("example.com"), None),
            Err(Error::CertNotValidForName)
        );
        // A malformed presented name is skipped, not fatal.
        let san = b"\x82\x03a..\x82\x0bexample.com";
        assert_eq!(verify_dns_name(&name("example.com"), Some(san)), Ok(()));
        // A malformed SAN sequence is fatal.
        assert_eq!(
            verify_dns_name(&name("example.com"), Some(b"\x82")),
            Err(Error::BadDer)
        );
    }
}

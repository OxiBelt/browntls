//! `iPAddress` matching (RFC 5280 §4.2.1.6) and CIDR-style `iPAddress` name
//! constraints (RFC 5280 §4.2.1.10).

use super::{GeneralName, GeneralNames};
use crate::error::Error;
use crate::server_name::IpAddr;

/// Checks that some `iPAddress` in `san` equals `reference`. Addresses are
/// compared as octets in network byte order; the subject is never consulted.
pub(crate) fn verify_ip_address(reference: &IpAddr, san: Option<&[u8]>) -> Result<(), Error> {
    let reference = reference.as_bytes();
    for name in GeneralNames::new(san) {
        if let GeneralName::IpAddress(presented) = name?
            && presented == reference
        {
            return Ok(());
        }
    }
    Err(Error::CertNotValidForName)
}

/// Whether the presented address `name` lies in the subnet `constraint`,
/// which is an address followed by a mask of the same length. The mask must
/// be a run of one bits followed by a run of zero bits.
pub(crate) fn presented_matches_constraint(name: &[u8], constraint: &[u8]) -> Result<bool, Error> {
    let half = match (name.len(), constraint.len()) {
        (4, 8) => 4,
        (16, 32) => 16,
        // Different address families never match.
        (4, 32) | (16, 8) => return Ok(false),
        (4 | 16, _) => return Err(Error::InvalidNetworkMaskConstraint),
        _ => return Err(Error::BadDer),
    };
    let (address, mask) = constraint.split_at(half);
    // Validate the whole mask before comparing, so a malformed constraint is
    // rejected whether or not the address differs in an earlier byte (an
    // excluded subtree must not quietly fail to match).
    let mut seen_zero = false;
    for &m in mask {
        if m.leading_ones() + m.trailing_zeros() != 8 || (seen_zero && m != 0) {
            return Err(Error::InvalidNetworkMaskConstraint);
        }
        if m != 0xff {
            seen_zero = true;
        }
    }
    Ok(name
        .iter()
        .zip(address)
        .zip(mask)
        .all(|((&n, &a), &m)| (n ^ a) & m == 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let san = b"\x87\x04\xc0\x00\x02\x01\x87\x10\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x01";
        assert_eq!(
            verify_ip_address(&IpAddr::V4([192, 0, 2, 1]), Some(san)),
            Ok(())
        );
        assert_eq!(
            verify_ip_address(&IpAddr::try_from("2001:db8::1").unwrap(), Some(san)),
            Ok(())
        );
        assert_eq!(
            verify_ip_address(&IpAddr::V4([192, 0, 2, 2]), Some(san)),
            Err(Error::CertNotValidForName)
        );
        assert_eq!(
            verify_ip_address(&IpAddr::V4([192, 0, 2, 1]), None),
            Err(Error::CertNotValidForName)
        );
        // A truncated iPAddress never matches.
        assert_eq!(
            verify_ip_address(&IpAddr::V4([192, 0, 2, 1]), Some(b"\x87\x03\xc0\x00\x02")),
            Err(Error::CertNotValidForName)
        );
    }

    #[test]
    fn constraints() {
        let net = [192, 0, 2, 0, 255, 255, 255, 0];
        assert_eq!(
            presented_matches_constraint(&[192, 0, 2, 7], &net),
            Ok(true)
        );
        assert_eq!(
            presented_matches_constraint(&[192, 0, 3, 7], &net),
            Ok(false)
        );
        assert_eq!(
            presented_matches_constraint(&[192, 0, 2, 7], &[192, 0, 2, 0, 255, 255, 0, 255]),
            Err(Error::InvalidNetworkMaskConstraint)
        );
        assert_eq!(
            presented_matches_constraint(&[192, 0, 2, 7], &[192, 0, 2, 0, 255, 255, 0x7f, 0]),
            Err(Error::InvalidNetworkMaskConstraint)
        );
        // Rejected even when the address already differs before the bad
        // mask byte.
        assert_eq!(
            presented_matches_constraint(&[10, 0, 2, 7], &[192, 0, 2, 0, 255, 0, 255, 0]),
            Err(Error::InvalidNetworkMaskConstraint)
        );
        assert_eq!(
            presented_matches_constraint(&[192, 0, 2, 7], &[192, 0, 2, 0, 255, 255]),
            Err(Error::InvalidNetworkMaskConstraint)
        );
        assert_eq!(
            presented_matches_constraint(&[192, 0, 2, 7], &[0; 32]),
            Ok(false)
        );
        assert_eq!(
            presented_matches_constraint(&[1, 2, 3], &net),
            Err(Error::BadDer)
        );
        // /0 permits everything, /32 is exact.
        assert_eq!(
            presented_matches_constraint(&[10, 0, 0, 1], &[0, 0, 0, 0, 0, 0, 0, 0]),
            Ok(true)
        );
        assert_eq!(
            presented_matches_constraint(&[10, 0, 0, 1], &[10, 0, 0, 2, 255, 255, 255, 255]),
            Ok(false)
        );
    }
}

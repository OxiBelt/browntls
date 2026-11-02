//! The trust anchor store.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::{CertificateDer, TrustAnchor};

use super::pki_error;
use crate::error::Error;
use crate::log::{debug, trace};
use crate::msgs::handshake::DistinguishedName;

/// A set of trusted root certificates.
#[derive(Clone, Default)]
pub struct RootCertStore {
    /// The anchors.
    pub roots: Vec<TrustAnchor<'static>>,
}

impl RootCertStore {
    /// An empty store.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Adds every certificate in `der_certs` that parses, returning
    /// `(added, ignored)` counts.
    pub fn add_parsable_certificates<'a>(
        &mut self,
        der_certs: impl IntoIterator<Item = CertificateDer<'a>>,
    ) -> (usize, usize) {
        let mut valid = 0;
        let mut invalid = 0;
        for der in der_certs {
            match browntls_pki::anchor_from_trusted_cert(&der) {
                Ok(anchor) => {
                    self.roots.push(anchor.to_owned());
                    valid += 1;
                }
                Err(err) => {
                    trace!("invalid cert der {:?}", err);
                    debug!("certificate parsing failed: {:?}", err);
                    invalid += 1;
                }
            }
        }
        (valid, invalid)
    }

    /// Adds one certificate, failing if it does not parse.
    pub fn add(&mut self, der: CertificateDer<'_>) -> Result<(), Error> {
        let anchor = browntls_pki::anchor_from_trusted_cert(&der).map_err(pki_error)?;
        self.roots.push(anchor.to_owned());
        Ok(())
    }

    /// The subject names of every anchor, for `certificate_authorities`.
    pub fn subjects(&self) -> Vec<DistinguishedName> {
        self.roots
            .iter()
            .map(|r| DistinguishedName::in_sequence(r.subject.as_ref()))
            .collect()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The number of anchors.
    pub fn len(&self) -> usize {
        self.roots.len()
    }
}

impl FromIterator<TrustAnchor<'static>> for RootCertStore {
    fn from_iter<T: IntoIterator<Item = TrustAnchor<'static>>>(iter: T) -> Self {
        Self {
            roots: iter.into_iter().collect(),
        }
    }
}

impl Extend<TrustAnchor<'static>> for RootCertStore {
    fn extend<T: IntoIterator<Item = TrustAnchor<'static>>>(&mut self, iter: T) {
        self.roots.extend(iter);
    }
}

impl fmt::Debug for RootCertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootCertStore")
            .field("roots", &format_args!("({} anchors)", self.roots.len()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browntls_pki::Der;

    #[test]
    fn subjects_and_counts() {
        let anchor = TrustAnchor {
            subject: Der::from_slice(&[0x31, 0x00]),
            subject_public_key_info: Der::from_slice(&[]),
            name_constraints: None,
        };
        let store: RootCertStore = [anchor.to_owned()].into_iter().collect();
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        assert_eq!(store.subjects()[0].as_ref(), [0x30, 2, 0x31, 0]);
        assert_eq!(alloc::format!("{store:?}"), "RootCertStore { roots: (1 anchors) }");
    }
}

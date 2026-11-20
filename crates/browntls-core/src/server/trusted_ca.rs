//! A certificate resolver that follows the client's `trusted_ca_keys`
//! (RFC 6066 §6).

use alloc::vec;
use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use super::server_conn::{ClientHello, ResolvesServerCert};
use crate::error::Error;
use crate::msgs::handshake::TrustedAuthority;
use crate::sign::CertifiedKey;
use crate::sync::Arc;

/// Chooses the certificate chain with the CA root keys a client lists in
/// its `trusted_ca_keys` extension (RFC 6066 §6), and falls back to another
/// resolver otherwise.
///
/// Each chain is registered under the identifiers of the root it ends in.
/// When the client sent the extension, a chain with an identifier equal to
/// one in the client's list, and whose key signs with one of the client's
/// signature schemes, is chosen and the choice acknowledged
/// ([`ClientHello::acknowledge_trusted_ca_keys`]), so that a full TLS 1.2
/// handshake answers with the empty extension. Identifiers compare as
/// values: a chain registered under [`TrustedAuthority::PreAgreed`] is
/// chosen for a client that lists `pre_agreed`, and names compare as DER
/// bytes. Otherwise (no extension, an empty list, no match) the fallback
/// resolver's answer is returned, unacknowledged.
///
/// A name need not identify one root (RFC 6066 §6): after a CA key
/// rollover, the old and the new root usually share it. So a match on
/// `cert_sha1_hash` wins over one on `key_sha1_hash`, which wins over one
/// on `x509_name` or `pre_agreed`, whatever their order; among matches of
/// the same kind the first chain registered wins.
///
/// In TLS 1.3 the client's list is used the same way, but nothing is
/// acknowledged on the wire: the extension does not exist there.
#[derive(Debug)]
pub struct ResolvesServerCertUsingTrustedCaKeys {
    entries: Vec<(Vec<TrustedAuthority>, Arc<CertifiedKey>)>,
    fallback: Arc<dyn ResolvesServerCert>,
}

impl ResolvesServerCertUsingTrustedCaKeys {
    /// A resolver with no chains yet, answering with `fallback` until a
    /// registered chain matches.
    pub fn new(fallback: Arc<dyn ResolvesServerCert>) -> Self {
        Self {
            entries: Vec::new(),
            fallback,
        }
    }

    /// Registers `certified_key` under `authorities`, after the chains
    /// already registered.
    pub fn add(&mut self, authorities: Vec<TrustedAuthority>, certified_key: Arc<CertifiedKey>) {
        self.entries.push((authorities, certified_key));
    }

    /// Registers `certified_key` under the `cert_sha1_hash`,
    /// `key_sha1_hash` and `x509_name` identifiers of `root`, the CA
    /// certificate its chain ends in (see [`TrustedAuthority`] for how
    /// each is derived; `sha1` is a one-shot SHA-1 function such as
    /// `crypto::native::sha1`).
    ///
    /// A malformed `root` is [`CertificateError::BadEncoding`] and
    /// registers nothing.
    ///
    /// [`CertificateError::BadEncoding`]: crate::CertificateError::BadEncoding
    pub fn add_for_root(
        &mut self,
        root: &CertificateDer<'_>,
        sha1: fn(&[u8]) -> [u8; 20],
        certified_key: Arc<CertifiedKey>,
    ) -> Result<(), Error> {
        let authorities = vec![
            TrustedAuthority::cert_sha1_hash(root, sha1),
            TrustedAuthority::key_sha1_hash(root, sha1)?,
            TrustedAuthority::x509_name(root)?,
        ];
        self.add(authorities, certified_key);
        Ok(())
    }
}

impl ResolvesServerCert for ResolvesServerCertUsingTrustedCaKeys {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(listed) = client_hello.trusted_ca_keys() {
            let schemes = client_hello.signature_schemes();
            let chosen = (0..=WEAKEST).find_map(|rank| {
                self.entries.iter().find(|(authorities, certified_key)| {
                    authorities
                        .iter()
                        .any(|ours| strength(ours) == rank && listed.contains(ours))
                        && certified_key.key.choose_scheme(schemes).is_some()
                })
            });
            if let Some((_, certified_key)) = chosen {
                client_hello.acknowledge_trusted_ca_keys();
                return Some(certified_key.clone());
            }
        }
        self.fallback.resolve(client_hello)
    }

    fn only_raw_public_keys(&self) -> bool {
        self.fallback.only_raw_public_keys()
    }
}

/// How precisely an identifier names one root, `0` being the most precise:
/// a certificate hash names one certificate, a key hash one key (which a
/// re-issued root keeps), and a name or `pre_agreed` possibly several.
fn strength(authority: &TrustedAuthority) -> u8 {
    match authority {
        TrustedAuthority::CertSha1Hash(_) => 0,
        TrustedAuthority::KeySha1Hash(_) => 1,
        TrustedAuthority::X509Name(_) | TrustedAuthority::PreAgreed => WEAKEST,
    }
}

/// The rank [`strength`] gives the least precise identifiers.
const WEAKEST: u8 = 2;

//! Signing keys and certified key material.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use browntls_pki::{AlgorithmIdentifier, CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer};

use super::CryptoProvider;
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::{Error, InconsistentKeys};
use crate::sync::Arc;
use crate::x509;

/// A private key that can produce handshake signatures.
pub trait SigningKey: Debug + Send + Sync {
    /// Picks a scheme from `offered` this key can sign with, if any.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;

    /// The key's `SubjectPublicKeyInfo`, if it can be computed.
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        None
    }

    /// The key's algorithm family.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A signer committed to one scheme.
pub trait Signer: Debug + Send + Sync {
    /// Signs `message`.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// The scheme this signer uses.
    fn scheme(&self) -> SignatureScheme;
}

/// A certificate chain and the signing key for its end entity.
#[derive(Clone, Debug)]
pub struct CertifiedKey {
    /// The chain, end entity first.
    pub cert: Vec<CertificateDer<'static>>,

    /// The end entity's signing key.
    pub key: Arc<dyn SigningKey>,

    /// A stapled OCSP response for the end entity, if any.
    pub ocsp: Option<Vec<u8>>,
}

impl CertifiedKey {
    /// Loads `key` with `provider` and checks it matches the end entity.
    pub fn from_der(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        provider: &CryptoProvider,
    ) -> Result<Self, Error> {
        let private_key = provider.key_provider.load_private_key(key)?;
        let certified_key = Self::new(cert_chain, private_key);
        match certified_key.keys_match() {
            Ok(()) | Err(Error::InconsistentKeys(InconsistentKeys::Unknown)) => Ok(certified_key),
            Err(err) => Err(err),
        }
    }

    /// Pairs `cert` and `key` without checking them.
    pub fn new(cert: Vec<CertificateDer<'static>>, key: Arc<dyn SigningKey>) -> Self {
        Self {
            cert,
            key,
            ocsp: None,
        }
    }

    /// Checks that the key's public half matches the end-entity certificate.
    pub fn keys_match(&self) -> Result<(), Error> {
        let Some(key_spki) = self.key.public_key() else {
            return Err(InconsistentKeys::Unknown.into());
        };
        let cert_spki = x509::subject_public_key_info(self.end_entity_cert()?.as_ref())?;
        if key_spki.as_ref() == cert_spki {
            Ok(())
        } else {
            Err(InconsistentKeys::KeyMismatch.into())
        }
    }

    /// The end-entity certificate.
    pub fn end_entity_cert(&self) -> Result<&CertificateDer<'_>, Error> {
        self.cert.first().ok_or(Error::NoCertificatesPresented)
    }
}

/// Resolves to one fixed [`CertifiedKey`] for every connection.
///
/// Implements both the client and the server certificate resolver traits.
#[derive(Debug)]
pub struct SingleCertAndKey(pub(crate) Arc<CertifiedKey>);

impl From<CertifiedKey> for SingleCertAndKey {
    fn from(certified_key: CertifiedKey) -> Self {
        Self(Arc::new(certified_key))
    }
}

impl From<Arc<CertifiedKey>> for SingleCertAndKey {
    fn from(certified_key: Arc<CertifiedKey>) -> Self {
        Self(certified_key)
    }
}

/// Encodes a `SubjectPublicKeyInfo` from an algorithm identifier and raw key.
pub fn public_key_to_spki(
    alg_id: &AlgorithmIdentifier,
    public_key: impl AsRef<[u8]>,
) -> SubjectPublicKeyInfoDer<'static> {
    spki_from_parts(alg_id.as_ref(), public_key.as_ref())
}

/// Encodes a `SubjectPublicKeyInfo` from the contents of its
/// `AlgorithmIdentifier` and the raw key.
pub(crate) fn spki_from_parts(
    algorithm: &[u8],
    public_key: &[u8],
) -> SubjectPublicKeyInfoDer<'static> {
    let mut inner = x509::wrap_in_sequence(algorithm);
    inner.extend(x509::wrap_in_bit_string(public_key));
    SubjectPublicKeyInfoDer::from(x509::wrap_in_sequence(&inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_encoding() {
        let spki = public_key_to_spki(&browntls_pki::alg_id::ED25519, [0xaa; 32]);
        let (alg, key) = x509::split_spki(spki.as_ref()).unwrap();
        assert_eq!(alg, browntls_pki::alg_id::ED25519.as_bytes());
        assert_eq!(key, [0xaa; 32]);
    }
}

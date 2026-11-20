//! Signing keys and certified key material.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use browntls_pki::{AlgorithmIdentifier, CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer};

use super::CryptoProvider;
use crate::delegated_credential::{DelegatedCredential, DelegatedCredentialKey};
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::{Error, InconsistentKeys};
use crate::msgs::handshake::CertificatePayloadTls13;
use crate::sync::Arc;
use crate::x509;

/// The longest OCSP response a `CertificateStatus` can carry
/// (`OCSPResponse<1..2^24-1>`, RFC 6066 §8).
const MAX_OCSP_RESPONSE_LEN: usize = 0xff_ffff;

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

    /// A stapled OCSP response for the end entity, if any. Responses for
    /// the rest of the chain are set with [`Self::set_ocsp_for`].
    pub ocsp: Option<Vec<u8>>,

    /// OCSP responses for the certificates after the end entity: element
    /// `i` belongs to `cert[i + 1]`.
    intermediate_ocsp: Vec<Option<Vec<u8>>>,

    /// The end entity's encoded `SignedCertificateTimestampList`.
    sct_list: Option<Vec<u8>>,

    /// The end entity's encoded `TransItemList` (RFC 9162 §6.3).
    transparency_info: Option<Vec<u8>>,

    /// Delegated credentials for the end entity (RFC 9345); see
    /// [`Self::delegated_credentials`].
    delegated_credentials: Vec<Arc<DelegatedCredentialKey>>,

    /// URLs naming the chain, for a TLS 1.2 client (RFC 6066 §5); see
    /// [`Self::set_certificate_url`].
    certificate_url: Option<crate::certificate_url::CertificateUrl>,
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
            intermediate_ocsp: Vec::new(),
            sct_list: None,
            transparency_info: None,
            delegated_credentials: Vec::new(),
            certificate_url: None,
        }
    }

    /// The OCSP response to staple for `cert[chain_index]`, if one is
    /// configured: [`Self::ocsp`] for the end entity (index 0). An empty
    /// response counts as none.
    pub fn ocsp_for(&self, chain_index: usize) -> Option<&[u8]> {
        let response = match chain_index.checked_sub(1) {
            None => self.ocsp.as_deref(),
            // `cert` is public and may have been shortened since.
            Some(_) if chain_index >= self.cert.len() => None,
            Some(intermediate) => self.intermediate_ocsp.get(intermediate)?.as_deref(),
        };
        response.filter(|response| !response.is_empty())
    }

    /// Sets, or with `None` or an empty response removes, the DER-encoded
    /// OCSP response to staple for `cert[chain_index]`. Index 0 is the end
    /// entity and sets [`Self::ocsp`]. The response is not interpreted.
    ///
    /// It is sent to a peer that asks for certificate status; TLS 1.3 can
    /// carry one for every certificate in the chain (RFC 8446 §4.4.2.1).
    ///
    /// Fails if the chain has no such certificate, or if the response is
    /// longer than its 24-bit length field allows.
    pub fn set_ocsp_for(
        &mut self,
        chain_index: usize,
        response: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        if chain_index >= self.cert.len() {
            return Err(Error::general(
                "no certificate at this chain index for the OCSP response",
            ));
        }
        let response = response.filter(|response| !response.is_empty());
        if response
            .as_ref()
            .is_some_and(|r| r.len() > MAX_OCSP_RESPONSE_LEN)
        {
            return Err(Error::general("OCSP response is too large"));
        }
        let Some(intermediate) = chain_index.checked_sub(1) else {
            self.ocsp = response;
            return Ok(());
        };
        if self.intermediate_ocsp.len() <= intermediate {
            self.intermediate_ocsp.resize(intermediate + 1, None);
        }
        self.intermediate_ocsp[intermediate] = response;
        Ok(())
    }

    /// The end entity's signed certificate timestamps, as an encoded
    /// `SignedCertificateTimestampList` (RFC 6962 §3.3), if configured.
    pub fn sct_list(&self) -> Option<&[u8]> {
        self.sct_list.as_deref()
    }

    /// Sets, or with `None` removes, the end entity's signed certificate
    /// timestamps: an encoded `SignedCertificateTimestampList` (RFC 6962
    /// §3.3), sent to a peer that asks for them.
    ///
    /// Fails unless it is a well-formed, non-empty list of non-empty SCTs;
    /// the SCTs themselves are not interpreted.
    pub fn set_sct_list(&mut self, sct_list: Option<Vec<u8>>) -> Result<(), Error> {
        if let Some(sct_list) = &sct_list
            && CertificatePayloadTls13::validate_sct_list(sct_list).is_err()
        {
            return Err(Error::general("malformed SignedCertificateTimestampList"));
        }
        self.sct_list = sct_list;
        Ok(())
    }

    /// The end entity's Certificate Transparency 2.0 items, as an encoded
    /// `TransItemList` (RFC 9162 §6.3), if configured.
    pub fn transparency_info(&self) -> Option<&[u8]> {
        self.transparency_info.as_deref()
    }

    /// Sets, or with `None` removes, the end entity's Certificate
    /// Transparency 2.0 items: an encoded `TransItemList` (RFC 9162 §6.3)
    /// sent in the `transparency_info` extension (§6.5) to a client that
    /// offers it, during a full handshake only (in the TLS 1.2 ServerHello,
    /// or on the end entity's TLS 1.3 CertificateEntry).
    ///
    /// The list is sent as given. RFC 9162 §6.5 says a server SHOULD
    /// leave out items the certificate or its stapled OCSP response
    /// already carries; the application builds the list accordingly (see
    /// [`TransItemList`](browntls_pki::transparency::TransItemList)).
    ///
    /// Fails unless the list parses and holds at least one SCT
    /// (`x509_sct_v2` or `precert_sct_v2`, §6.4), or if it is longer than
    /// an extension body (65535 octets). Items are not verified.
    pub fn set_transparency_info(&mut self, list: Option<Vec<u8>>) -> Result<(), Error> {
        if let Some(list) = &list {
            let parsed = browntls_pki::transparency::TransItemList::parse(list)
                .map_err(|_| Error::general("malformed TransItemList"))?;
            if !parsed.has_sct() {
                return Err(Error::general("TransItemList without an SCT"));
            }
            if list.len() > usize::from(u16::MAX) {
                return Err(Error::general("TransItemList is too large"));
            }
        }
        self.transparency_info = list;
        Ok(())
    }

    /// Adds a delegated credential for the end entity, with its private
    /// `key` (RFC 9345). See [`DelegatedCredentialKey::new`] for the checks.
    pub fn with_delegated_credential(
        mut self,
        credential: DelegatedCredential,
        key: Arc<dyn SigningKey>,
    ) -> Result<Self, Error> {
        let dc = DelegatedCredentialKey::new(self.end_entity_cert()?, credential, key)?;
        self.delegated_credentials.push(Arc::new(dc));
        Ok(self)
    }

    /// The delegated credentials added with
    /// [`Self::with_delegated_credential`], most preferred first. A TLS 1.3
    /// server sends the first one the client accepts and signs
    /// CertificateVerify with its key; otherwise `key` signs.
    pub fn delegated_credentials(&self) -> &[Arc<DelegatedCredentialKey>] {
        &self.delegated_credentials
    }

    /// Sets, or with `None` removes, the URLs a TLS 1.2 client sends in
    /// place of its chain (a CertificateURL message, RFC 6066 §5) when
    /// [`ClientConfig::enable_client_certificate_url`] is set and the server
    /// accepted them. [`Self::cert`] may then be empty: a key without a
    /// chain authenticates only through its URLs, and sends an empty
    /// Certificate (and no CertificateVerify) to any other server.
    ///
    /// The server fetches the URLs; they must name the DER objects whose
    /// hashes they carry. Servers ignore this.
    ///
    /// [`ClientConfig::enable_client_certificate_url`]: crate::ClientConfig::enable_client_certificate_url
    pub fn set_certificate_url(&mut self, urls: Option<crate::certificate_url::CertificateUrl>) {
        self.certificate_url = urls;
    }

    /// The URLs set with [`Self::set_certificate_url`].
    pub fn certificate_url(&self) -> Option<&crate::certificate_url::CertificateUrl> {
        self.certificate_url.as_ref()
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
mod tests;

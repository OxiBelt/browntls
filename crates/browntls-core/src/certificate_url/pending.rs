//! A server's outstanding client certificate URL query and the checks its
//! answer goes through.

use alloc::string::String;
use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use super::{
    CertChainType, CertificateUrlError, ClientCertificateUrlPolicy, ClientCertificateUrlQuery,
    ClientCertificateUrlResponse, SHA1_LEN, UrlAndHash, decode_pki_path, refused_url,
};
use crate::msgs::handshake::{CertificateChain, CertificateUrlPayload};

/// The query a server connection waits on, with what its answer is checked
/// against.
pub(crate) struct PendingCertificateUrl {
    query: ClientCertificateUrlQuery,
    sha1: fn(&[u8]) -> [u8; SHA1_LEN],
    max_fetched_len: usize,
}

impl PendingCertificateUrl {
    /// Applies `policy` to the URLs of `message`. Nothing the policy refuses
    /// becomes a query.
    pub(crate) fn new(
        policy: &ClientCertificateUrlPolicy,
        message: &CertificateUrlPayload,
    ) -> Result<Self, CertificateUrlError> {
        if message.entries.len() > policy.max_urls {
            return Err(CertificateUrlError::RefusedByPolicy);
        }
        let mut entries = Vec::with_capacity(message.entries.len());
        for entry in &message.entries {
            if refused_url(policy, &entry.url) {
                return Err(CertificateUrlError::RefusedByPolicy);
            }
            // Printable ASCII, as `refused_url` checked.
            let url = String::from_utf8(entry.url.clone())
                .map_err(|_| CertificateUrlError::RefusedByPolicy)?;
            entries.push(UrlAndHash {
                url,
                sha1_hash: entry.sha1_hash,
            });
        }
        Ok(Self {
            query: ClientCertificateUrlQuery::new(message.chain_type, entries),
            sha1: policy.sha1,
            max_fetched_len: policy.max_fetched_len,
        })
    }

    pub(crate) fn query(&self) -> &ClientCertificateUrlQuery {
        &self.query
    }

    /// Checks the application's answer and returns the client's chain in
    /// TLS order: the objects exist, are as many as the URLs, fit the size
    /// limit together, have the hashes the client sent, and (for a
    /// `pkipath`) form a well-formed PkiPath.
    pub(crate) fn into_chain(
        self,
        response: ClientCertificateUrlResponse,
    ) -> Result<CertificateChain<'static>, CertificateUrlError> {
        let objects = match response {
            ClientCertificateUrlResponse::Fetched(objects) => objects,
            ClientCertificateUrlResponse::Unobtainable => {
                return Err(CertificateUrlError::Unobtainable);
            }
        };
        let entries = self.query.entries();
        if objects.len() != entries.len() {
            return Err(CertificateUrlError::WrongObjectCount);
        }
        let total = objects
            .iter()
            .map(Vec::len)
            .fold(0usize, usize::saturating_add);
        if total > self.max_fetched_len {
            return Err(CertificateUrlError::FetchedTooLarge);
        }
        // RFC 6066 §5: every object must have the hash the client sent.
        if objects
            .iter()
            .zip(entries)
            .any(|(object, entry)| (self.sha1)(object) != *entry.sha1_hash())
        {
            return Err(CertificateUrlError::HashMismatch);
        }
        let certs = match self.query.chain_type() {
            CertChainType::IndividualCerts => {
                objects.into_iter().map(CertificateDer::from).collect()
            }
            CertChainType::PkiPath => {
                let [object] = objects.as_slice() else {
                    return Err(CertificateUrlError::WrongObjectCount);
                };
                decode_pki_path(object).map_err(|_| CertificateUrlError::MalformedPkiPath)?
            }
        };
        Ok(CertificateChain(certs))
    }
}

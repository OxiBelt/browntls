//! Types shared by the TLS 1.2 and TLS 1.3 server handshakes.

use browntls_pki::CertificateDer;

use crate::delegated_credential::DelegatedCredentialKey;
use crate::sign::{CertifiedKey, SigningKey};
use crate::sync::Arc;

/// The certificate and key chosen for this connection.
pub(super) struct ActiveCertifiedKey<'a> {
    cert: &'a [CertificateDer<'static>],
    key: &'a dyn SigningKey,
    ocsp: Option<&'a [u8]>,
    delegated_credentials: &'a [Arc<DelegatedCredentialKey>],
}

impl<'a> ActiveCertifiedKey<'a> {
    pub(super) fn from_certified_key(certkey: &'a CertifiedKey) -> Self {
        Self {
            cert: &certkey.cert,
            key: &*certkey.key,
            ocsp: certkey.ocsp.as_deref(),
            delegated_credentials: &certkey.delegated_credentials,
        }
    }

    pub(super) fn get_cert(&self) -> &'a [CertificateDer<'static>] {
        self.cert
    }

    pub(super) fn get_key(&self) -> &'a dyn SigningKey {
        self.key
    }

    pub(super) fn get_ocsp(&self) -> Option<&'a [u8]> {
        self.ocsp
    }

    pub(super) fn get_delegated_credentials(&self) -> &'a [Arc<DelegatedCredentialKey>] {
        self.delegated_credentials
    }
}

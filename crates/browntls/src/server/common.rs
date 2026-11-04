//! Types shared by the TLS 1.2 and TLS 1.3 server handshakes.

use browntls_pki::CertificateDer;

use crate::sign::{CertifiedKey, SigningKey};

/// The certificate and key chosen for this connection.
pub(super) struct ActiveCertifiedKey<'a> {
    cert: &'a [CertificateDer<'static>],
    key: &'a dyn SigningKey,
    ocsp: Option<&'a [u8]>,
}

impl<'a> ActiveCertifiedKey<'a> {
    pub(super) fn from_certified_key(certkey: &'a CertifiedKey) -> Self {
        Self {
            cert: &certkey.cert,
            key: &*certkey.key,
            ocsp: certkey.ocsp.as_deref(),
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
}

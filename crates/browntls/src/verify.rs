//! Certificate and handshake-signature verification interfaces.

use alloc::vec::Vec;
use core::fmt::Debug;

use browntls_pki::{CertificateDer, ServerName, UnixTime};

use crate::enums::SignatureScheme;
use crate::error::{Error, InvalidMessage};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::DistinguishedName;

/// A handshake signature was verified. Only verifiers can construct this.
#[derive(Debug)]
pub struct HandshakeSignatureValid(());

impl HandshakeSignatureValid {
    /// Asserts that a signature was verified.
    pub fn assertion() -> Self {
        Self(())
    }
}

/// A Finished message was verified.
#[derive(Debug)]
pub(crate) struct FinishedMessageVerified(());

impl FinishedMessageVerified {
    pub(crate) fn assertion() -> Self {
        Self(())
    }
}

/// A server certificate chain was verified.
#[derive(Debug)]
pub struct ServerCertVerified(());

impl ServerCertVerified {
    /// Asserts that a server certificate was verified.
    pub fn assertion() -> Self {
        Self(())
    }
}

/// A client certificate chain was verified.
#[derive(Debug)]
pub struct ClientCertVerified(());

impl ClientCertVerified {
    /// Asserts that a client certificate was verified.
    pub fn assertion() -> Self {
        Self(())
    }
}

/// Decides whether a server's certificate and handshake signatures are acceptable.
pub trait ServerCertVerifier: Debug + Send + Sync {
    /// Verifies the server's certificate chain against `server_name` at `now`.
    ///
    /// `ocsp_response` is the stapled OCSP response, or empty.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error>;

    /// Verifies a TLS 1.2 ServerKeyExchange signature.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Verifies a TLS 1.3 CertificateVerify signature.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// The schemes this verifier can check; offered in `signature_algorithms`.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;

    /// Whether the server must present a raw public key instead of a certificate (RFC 7250).
    fn requires_raw_public_keys(&self) -> bool {
        false
    }

    /// Subjects to send in `certificate_authorities`, if any.
    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        None
    }
}

/// Decides whether a client's certificate and handshake signatures are acceptable.
pub trait ClientCertVerifier: Debug + Send + Sync {
    /// Whether to send a CertificateRequest at all.
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Whether a client that sends no certificate is rejected.
    fn client_auth_mandatory(&self) -> bool {
        self.offer_client_auth()
    }

    /// Subjects to send in the CertificateRequest.
    fn root_hint_subjects(&self) -> &[DistinguishedName];

    /// Verifies the client's certificate chain at `now`.
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error>;

    /// Verifies a TLS 1.2 CertificateVerify signature.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Verifies a TLS 1.3 CertificateVerify signature.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// The schemes this verifier can check; sent in the CertificateRequest.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;

    /// Whether the client must present a raw public key instead of a certificate (RFC 7250).
    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}

/// A [`ClientCertVerifier`] that never requests client authentication.
#[derive(Debug)]
pub struct NoClientAuth;

impl ClientCertVerifier for NoClientAuth {
    fn offer_client_auth(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Err(Error::general("client authentication is not enabled"))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::general("client authentication is not enabled"))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::general("client authentication is not enabled"))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Vec::new()
    }
}

/// A signature and the scheme that produced it (RFC 8446 §4.4.3, RFC 5246 §4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigitallySignedStruct {
    /// The scheme.
    pub scheme: SignatureScheme,
    sig: PayloadU16,
}

impl DigitallySignedStruct {
    pub(crate) fn new(scheme: SignatureScheme, sig: Vec<u8>) -> Self {
        Self {
            scheme,
            sig: PayloadU16::new(sig),
        }
    }

    /// The signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.sig.0
    }
}

impl Codec<'_> for DigitallySignedStruct {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.scheme.encode(bytes);
        self.sig.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let scheme = SignatureScheme::read(r)?;
        let sig = PayloadU16::read(r)?;
        if sig.0.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self { scheme, sig })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dss_roundtrip() {
        let dss = DigitallySignedStruct::new(SignatureScheme::ED25519, alloc::vec![1, 2, 3]);
        assert_eq!(dss.get_encoding(), [0x08, 0x07, 0, 3, 1, 2, 3]);
        assert_eq!(
            DigitallySignedStruct::read_bytes(&dss.get_encoding()).unwrap(),
            dss
        );
        assert_eq!(
            DigitallySignedStruct::read_bytes(&[0x08, 0x07, 0, 0]),
            Err(InvalidMessage::IllegalEmptyValue)
        );
        assert_eq!(dss.signature(), [1, 2, 3]);
    }

    #[test]
    fn assertions_are_debug() {
        assert_eq!(
            alloc::format!("{:?}", ClientCertVerified::assertion()),
            "ClientCertVerified(())"
        );
        assert_eq!(
            alloc::format!("{:?}", ServerCertVerified::assertion()),
            "ServerCertVerified(())"
        );
        assert_eq!(
            alloc::format!("{:?}", HandshakeSignatureValid::assertion()),
            "HandshakeSignatureValid(())"
        );
        assert_eq!(
            alloc::format!("{:?}", FinishedMessageVerified::assertion()),
            "FinishedMessageVerified(())"
        );
        assert!(!NoClientAuth.offer_client_auth());
        assert!(!NoClientAuth.client_auth_mandatory());
    }
}

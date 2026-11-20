//! The view of a ClientHello given to the application.

use browntls_pki::DnsName;

use crate::enums::{CertificateType, CipherSuite, SignatureScheme};
use crate::msgs::enums::NamedGroup;
use crate::msgs::handshake::{ClientHelloPayload, DistinguishedName, ProtocolName};

/// What a [`ResolvesServerCert`](super::ResolvesServerCert) sees of the
/// ClientHello.
#[derive(Debug)]
pub struct ClientHello<'a> {
    pub(in crate::server) server_name: Option<&'a DnsName<'static>>,
    pub(in crate::server) signature_schemes: &'a [SignatureScheme],
    pub(in crate::server) alpn: Option<&'a [ProtocolName]>,
    pub(in crate::server) cipher_suites: &'a [CipherSuite],
    pub(in crate::server) certificate_authorities: Option<&'a [DistinguishedName]>,
    pub(in crate::server) named_groups: Option<&'a [NamedGroup]>,
    pub(in crate::server) client_cert_types: Option<&'a [CertificateType]>,
    pub(in crate::server) server_cert_types: Option<&'a [CertificateType]>,
    pub(crate) external_id_hash: Option<&'a crate::external_binding::ExternalIdHash>,
    pub(crate) external_session_id: Option<&'a crate::external_binding::ExternalSessionId>,
}

impl<'a> ClientHello<'a> {
    pub(in crate::server) fn new(
        server_name: Option<&'a DnsName<'static>>,
        signature_schemes: &'a [SignatureScheme],
        payload: &'a ClientHelloPayload,
    ) -> Self {
        Self {
            server_name,
            signature_schemes,
            alpn: payload.alpn_protocols(),
            cipher_suites: &payload.cipher_suites,
            certificate_authorities: payload.extensions.certificate_authorities.as_deref(),
            named_groups: payload.named_groups(),
            client_cert_types: payload.extensions.client_certificate_types.as_deref(),
            server_cert_types: payload.extensions.server_certificate_types.as_deref(),
            external_id_hash: payload.extensions.external_id_hash.as_ref(),
            external_session_id: payload.extensions.external_session_id.as_ref(),
        }
    }

    /// The certificate types the client can present (RFC 7250), if it said.
    pub fn client_cert_types(&self) -> Option<&'a [CertificateType]> {
        self.client_cert_types
    }

    /// The certificate types the client accepts from us (RFC 7250), if it said.
    pub fn server_cert_types(&self) -> Option<&'a [CertificateType]> {
        self.server_cert_types
    }

    /// The server name indicated by the client, if any.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.map(|n| n.as_ref())
    }

    /// The signature schemes the client accepts.
    pub fn signature_schemes(&self) -> &[SignatureScheme] {
        self.signature_schemes
    }

    /// The ALPN protocols the client offered, if any.
    pub fn alpn(&self) -> Option<impl Iterator<Item = &'a [u8]>> {
        self.alpn
            .map(|protocols| protocols.iter().map(ProtocolName::as_ref))
    }

    /// The cipher suites the client offered.
    pub fn cipher_suites(&self) -> &[CipherSuite] {
        self.cipher_suites
    }

    /// The certificate authorities the client trusts, if it said.
    pub fn certificate_authorities(&self) -> Option<&'a [DistinguishedName]> {
        self.certificate_authorities
    }

    /// The key exchange groups the client offered, if any.
    pub fn named_groups(&self) -> Option<&'a [NamedGroup]> {
        self.named_groups
    }
}

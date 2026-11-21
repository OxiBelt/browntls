//! The view of a ClientHello given to the application.

use core::sync::atomic::{AtomicBool, Ordering};

use browntls_pki::DnsName;

use crate::enums::{CertificateType, CipherSuite, SignatureScheme};
use crate::msgs::enums::NamedGroup;
use crate::msgs::handshake::{
    ClientHelloPayload, DistinguishedName, ProtocolName, TrustedAuthority,
};

/// What a [`ResolvesServerCert`](super::ResolvesServerCert) sees of the
/// ClientHello.
#[derive(Debug)]
pub struct ClientHello<'a> {
    pub(in crate::server) server_name: Option<&'a DnsName<'static>>,
    pub(in crate::server) signature_schemes: &'a [SignatureScheme],
    pub(in crate::server) alpn: Option<&'a [ProtocolName]>,
    pub(in crate::server) cipher_suites: &'a [CipherSuite],
    cert_with_extern_psk: bool,
    pub(in crate::server) certificate_authorities: Option<&'a [DistinguishedName]>,
    pub(in crate::server) named_groups: Option<&'a [NamedGroup]>,
    pub(in crate::server) client_cert_types: Option<&'a [CertificateType]>,
    pub(in crate::server) server_cert_types: Option<&'a [CertificateType]>,
    pub(crate) external_id_hash: Option<&'a crate::external_binding::ExternalIdHash>,
    pub(crate) external_session_id: Option<&'a crate::external_binding::ExternalSessionId>,
    pub(in crate::server) trusted_ca_keys: Option<&'a [TrustedAuthority]>,
    /// Set by [`Self::acknowledge_trusted_ca_keys`]; owned by the handshake
    /// that asked for a certificate, `None` where none listens.
    pub(in crate::server) trusted_ca_keys_ack: Option<&'a AtomicBool>,
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
            cert_with_extern_psk: payload.extensions.cert_with_extern_psk.is_some(),
            certificate_authorities: payload.extensions.certificate_authorities.as_deref(),
            named_groups: payload.named_groups(),
            client_cert_types: payload.extensions.client_certificate_types.as_deref(),
            server_cert_types: payload.extensions.server_certificate_types.as_deref(),
            external_id_hash: payload.extensions.external_id_hash.as_ref(),
            external_session_id: payload.extensions.external_session_id.as_ref(),
            trusted_ca_keys: payload.extensions.trusted_ca_keys.as_deref(),
            trusted_ca_keys_ack: None,
        }
    }

    /// Lets [`Self::acknowledge_trusted_ca_keys`] set `ack`.
    pub(in crate::server) fn with_trusted_ca_keys_ack(mut self, ack: &'a AtomicBool) -> Self {
        self.trusted_ca_keys_ack = Some(ack);
        self
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

    /// Whether this view of the ClientHello offers RFC 9973.
    ///
    /// This is a peer-controlled routing signal. Before ECH is processed a
    /// view of the outer ClientHello does not reveal the inner offer.
    pub fn offers_cert_with_extern_psk(&self) -> bool {
        self.cert_with_extern_psk
    }

    /// The certificate authorities the client trusts, if it said.
    pub fn certificate_authorities(&self) -> Option<&'a [DistinguishedName]> {
        self.certificate_authorities
    }

    /// The key exchange groups the client offered, if any.
    pub fn named_groups(&self) -> Option<&'a [NamedGroup]> {
        self.named_groups
    }

    /// The CA root keys the client says it possesses (the
    /// `trusted_ca_keys` extension, RFC 6066 §6), if it sent the extension.
    /// An empty list claims a set of root keys agreed by other means.
    ///
    /// The extension exists in TLS 1.2 only, but the list is given whichever
    /// version the handshake goes on to negotiate. The list is sent in the
    /// clear (RFC 6066 §11.4).
    pub fn trusted_ca_keys(&self) -> Option<&'a [TrustedAuthority]> {
        self.trusted_ca_keys
    }

    /// Says that the certificate chain chosen for this ClientHello was
    /// selected with the help of [`Self::trusted_ca_keys`]. A certificate
    /// resolver calls it from
    /// [`ResolvesServerCert::resolve`](super::ResolvesServerCert::resolve)
    /// before returning that chain.
    ///
    /// The server then includes an empty `trusted_ca_keys` extension in its
    /// ServerHello (RFC 6066 §6) when, and only when, the handshake is a
    /// full TLS 1.2 one and the client sent the extension. In TLS 1.3, and
    /// when a TLS 1.2 session is resumed, nothing is sent.
    ///
    /// Where no handshake is waiting for the answer (the `ClientHello` of
    /// `Accepted` read by an `Acceptor`, or of an
    /// [`UnbufferedAccepted`](super::UnbufferedAccepted)) the call does
    /// nothing: the resolver of the configuration the connection goes on
    /// with is asked again.
    pub fn acknowledge_trusted_ca_keys(&self) {
        if let Some(ack) = self.trusted_ca_keys_ack {
            ack.store(true, Ordering::Relaxed);
        }
    }
}

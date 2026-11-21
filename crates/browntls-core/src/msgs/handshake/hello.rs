//! ClientHello, ServerHello and HelloRetryRequest.

use alloc::vec::Vec;

use super::extensions::{encode_extension, read_extensions};
use super::{
    CertificateStatusRequest, ClientSessionTicket, ClientTicketRequest, DistinguishedName,
    HandshakePayload, KeyShareEntry, MAX_HANDSHAKE_SIZE, PresharedKeyOffer, ProtocolName, Random,
    ServerExtensions, ServerNamePayload, SessionId, TrustedAuthority, encode_trusted_authorities,
    read_payload, read_trusted_authorities,
};
use crate::ech::codec::EchClientHello;
use crate::enums::{
    CertificateCompressionAlgorithm, CertificateType, CipherSuite, HandshakeType, ProtocolVersion,
    SignatureScheme,
};
use crate::error::InvalidMessage;
use crate::external_binding::{ExternalIdHash, ExternalSessionId};
use crate::msgs::base::{Payload, PayloadU8, PayloadU16};
use crate::msgs::codec::{
    Codec, LengthPrefixedBuffer, ListLength, Reader, encode_vec_u8, encode_vec_u16,
    read_nonempty_vec_u8, read_nonempty_vec_u16, u24,
};
use crate::msgs::enums::{
    Compression, ECPointFormat, ExtensionType, NamedGroup, PskKeyExchangeMode,
};

/// The special `Random` value that marks a HelloRetryRequest (RFC 8446 §4.1.3).
pub(crate) static HELLO_RETRY_REQUEST_RANDOM: Random = Random([
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
]);

/// The extensions a client may send.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ClientExtensions {
    pub(crate) server_name: Option<ServerNamePayload<'static>>,
    pub(crate) named_groups: Option<Vec<NamedGroup>>,
    pub(crate) ec_point_formats: Option<Vec<ECPointFormat>>,
    pub(crate) signature_schemes: Option<Vec<SignatureScheme>>,
    pub(crate) signature_schemes_cert: Option<Vec<SignatureScheme>>,
    pub(crate) protocols: Option<Vec<ProtocolName>>,
    pub(crate) certificate_status_request: Option<CertificateStatusRequest>,
    pub(crate) sct_request: Option<()>,
    /// RFC 9162 §6.5: an empty `transparency_info` extension.
    pub(crate) transparency_info: Option<()>,
    pub(crate) extended_master_secret: Option<()>,
    /// RFC 7366: an empty `encrypt_then_mac` extension.
    pub(crate) encrypt_then_mac: Option<()>,
    /// RFC 6066 §5: an empty `client_certificate_url` extension (TLS 1.2).
    pub(crate) client_certificate_url: Option<()>,
    /// RFC 6066 §6: the root keys the client says it possesses (TLS 1.2).
    /// The list may be empty.
    pub(crate) trusted_ca_keys: Option<Vec<TrustedAuthority>>,
    /// RFC 6066 §7: an empty `truncated_hmac` extension. Parsed so that a
    /// malformed one is refused; never sent and never acknowledged
    /// (RFC 9325 §4.6).
    pub(crate) truncated_hmac: Option<()>,
    pub(crate) session_ticket: Option<ClientSessionTicket>,
    pub(crate) supported_versions: Option<Vec<ProtocolVersion>>,
    pub(crate) key_shares: Option<Vec<KeyShareEntry>>,
    pub(crate) psk_modes: Option<Vec<PskKeyExchangeMode>>,
    pub(crate) early_data: Option<()>,
    /// RFC 9846 §4.3.6: an empty `post_handshake_auth` extension.
    pub(crate) post_handshake_auth: Option<()>,
    pub(crate) cookie: Option<PayloadU16>,
    pub(crate) renegotiation_info: Option<PayloadU8>,
    pub(crate) certificate_authorities: Option<Vec<DistinguishedName>>,
    pub(crate) certificate_compression: Option<Vec<CertificateCompressionAlgorithm>>,
    pub(crate) client_certificate_types: Option<Vec<CertificateType>>,
    pub(crate) server_certificate_types: Option<Vec<CertificateType>>,
    pub(crate) transport_parameters: Option<Payload<'static>>,
    /// Only ever valid inside an EncodedClientHelloInner (RFC 9849 §5.1);
    /// parsed so a server can reject it anywhere else.
    pub(crate) ech_outer_extensions: Option<Vec<ExtensionType>>,
    /// RFC 9849 §5: encoded after every other extension but the GREASE
    /// extension, `padding` and `pre_shared_key`.
    pub(crate) encrypted_client_hello: Option<EchClientHello>,
    /// RFC 9345 §4.1.1: the schemes accepted for a delegated credential.
    pub(crate) delegated_credential: Option<Vec<SignatureScheme>>,
    /// RFC 8449: the largest record we are willing to receive.
    pub(crate) record_size_limit: Option<u16>,
    /// RFC 9149: how many TLS 1.3 tickets we would like.
    pub(crate) ticket_request: Option<ClientTicketRequest>,
    /// RFC 8844 §3.2: the hash of our identity assertion, or empty.
    pub(crate) external_id_hash: Option<ExternalIdHash>,
    /// RFC 8844 §4.3: our external session identifier (SDP `tls-id`).
    pub(crate) external_session_id: Option<ExternalSessionId>,
    /// RFC 7924: the fingerprints of cached messages (TLS 1.2).
    pub(crate) cached_info: Option<crate::cached_info::ClientHelloCachedInfo>,
    /// RFC 8701: an empty GREASE extension of this type, encoded first.
    /// Never part of `present_types`.
    pub(crate) grease_first: Option<u16>,
    /// RFC 8701: a one-byte GREASE extension of this type, encoded after
    /// every other extension but `padding` and `pre_shared_key`. Never part
    /// of `present_types`.
    pub(crate) grease_last: Option<u16>,
    /// RFC 7685: the length of the all-zero `padding` body, encoded just
    /// before `pre_shared_key`. Never part of `present_types`: a server
    /// must not echo it.
    pub(crate) padding: Option<usize>,
    /// Extension types present but not understood, in order.
    pub(crate) unknown: Vec<ExtensionType>,
    /// Always encoded last (RFC 8446 §4.2.11).
    pub(crate) preshared_key: Option<PresharedKeyOffer>,
    /// RFC 8773 `tls_cert_with_extern_psk`: an empty extension.
    pub(crate) cert_with_extern_psk: Option<()>,
}

impl ClientExtensions {
    /// The types of every extension present, for unsolicited-extension checks.
    pub(crate) fn present_types(&self) -> Vec<ExtensionType> {
        let mut out = Vec::new();
        let mut add = |p: bool, t: ExtensionType| {
            if p {
                out.push(t);
            }
        };
        add(self.server_name.is_some(), ExtensionType::ServerName);
        add(self.named_groups.is_some(), ExtensionType::EllipticCurves);
        add(
            self.ec_point_formats.is_some(),
            ExtensionType::ECPointFormats,
        );
        add(
            self.signature_schemes.is_some(),
            ExtensionType::SignatureAlgorithms,
        );
        add(
            self.signature_schemes_cert.is_some(),
            ExtensionType::SignatureAlgorithmsCert,
        );
        add(
            self.protocols.is_some(),
            ExtensionType::ALProtocolNegotiation,
        );
        add(
            self.certificate_status_request.is_some(),
            ExtensionType::StatusRequest,
        );
        add(self.sct_request.is_some(), ExtensionType::SCT);
        add(
            self.transparency_info.is_some(),
            ExtensionType::TransparencyInfo,
        );
        add(
            self.extended_master_secret.is_some(),
            ExtensionType::ExtendedMasterSecret,
        );
        add(
            self.encrypt_then_mac.is_some(),
            ExtensionType::EncryptThenMac,
        );
        add(
            self.client_certificate_url.is_some(),
            ExtensionType::ClientCertificateUrl,
        );
        add(self.trusted_ca_keys.is_some(), ExtensionType::TrustedCAKeys);
        add(self.truncated_hmac.is_some(), ExtensionType::TruncatedHMAC);
        add(self.session_ticket.is_some(), ExtensionType::SessionTicket);
        add(
            self.supported_versions.is_some(),
            ExtensionType::SupportedVersions,
        );
        add(self.key_shares.is_some(), ExtensionType::KeyShare);
        add(self.psk_modes.is_some(), ExtensionType::PSKKeyExchangeModes);
        add(self.early_data.is_some(), ExtensionType::EarlyData);
        add(
            self.post_handshake_auth.is_some(),
            ExtensionType::PostHandshakeAuth,
        );
        add(self.cookie.is_some(), ExtensionType::Cookie);
        add(
            self.renegotiation_info.is_some(),
            ExtensionType::RenegotiationInfo,
        );
        add(
            self.certificate_authorities.is_some(),
            ExtensionType::CertificateAuthorities,
        );
        add(
            self.certificate_compression.is_some(),
            ExtensionType::CompressCertificate,
        );
        add(
            self.client_certificate_types.is_some(),
            ExtensionType::ClientCertificateType,
        );
        add(
            self.server_certificate_types.is_some(),
            ExtensionType::ServerCertificateType,
        );
        add(
            self.transport_parameters.is_some(),
            ExtensionType::TransportParameters,
        );
        add(
            self.delegated_credential.is_some(),
            ExtensionType::DelegatedCredential,
        );
        add(
            self.record_size_limit.is_some(),
            ExtensionType::RecordSizeLimit,
        );
        add(self.ticket_request.is_some(), ExtensionType::TicketRequest);
        add(self.cached_info.is_some(), ExtensionType::CachedInfo);
        add(
            self.external_id_hash.is_some(),
            ExtensionType::ExternalIdHash,
        );
        add(
            self.external_session_id.is_some(),
            ExtensionType::ExternalSessionId,
        );
        add(
            self.cert_with_extern_psk.is_some(),
            ExtensionType::TlsCertWithExternPsk,
        );
        add(
            self.ech_outer_extensions.is_some(),
            ExtensionType::EncryptedClientHelloOuterExtensions,
        );
        add(
            self.encrypted_client_hello.is_some(),
            ExtensionType::EncryptedClientHello,
        );
        for unknown in &self.unknown {
            add(true, *unknown);
        }
        add(self.preshared_key.is_some(), ExtensionType::PreSharedKey);
        out
    }
}

impl ClientExtensions {
    /// Encodes the extension block, the DTLS 1.3 way when `dtls`: the
    /// `cookie` extension first, so that a stateless server finds it in
    /// the first fragment (RFC 9147 §5.1), and DTLS versions in
    /// `supported_versions` (RFC 9147 §5.3).
    fn encode_with(&self, bytes: &mut Vec<u8>, dtls: bool) {
        let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        let out = &mut *list.buf;
        let cookie_first = dtls && self.cookie.is_some();
        if cookie_first && let Some(cookie) = &self.cookie {
            encode_extension(ExtensionType::Cookie, out, |b| cookie.encode(b));
        }
        if let Some(grease) = self.grease_first {
            encode_extension(ExtensionType::Unknown(grease), out, |_| {});
        }
        if let Some(sn) = &self.server_name {
            encode_extension(ExtensionType::ServerName, out, |b| sn.encode(b));
        }
        if let Some(groups) = &self.named_groups {
            encode_extension(ExtensionType::EllipticCurves, out, |b| {
                encode_vec_u16(b, groups)
            });
        }
        if let Some(formats) = &self.ec_point_formats {
            encode_extension(ExtensionType::ECPointFormats, out, |b| {
                encode_vec_u8(b, formats)
            });
        }
        if let Some(schemes) = &self.signature_schemes {
            encode_extension(ExtensionType::SignatureAlgorithms, out, |b| {
                encode_vec_u16(b, schemes);
            });
        }
        if let Some(schemes) = &self.signature_schemes_cert {
            encode_extension(ExtensionType::SignatureAlgorithmsCert, out, |b| {
                encode_vec_u16(b, schemes);
            });
        }
        if let Some(protocols) = &self.protocols {
            encode_extension(ExtensionType::ALProtocolNegotiation, out, |b| {
                encode_vec_u16(b, protocols);
            });
        }
        if let Some(csr) = &self.certificate_status_request {
            encode_extension(ExtensionType::StatusRequest, out, |b| csr.encode(b));
        }
        if self.sct_request.is_some() {
            encode_extension(ExtensionType::SCT, out, |_| {});
        }
        if self.transparency_info.is_some() {
            encode_extension(ExtensionType::TransparencyInfo, out, |_| {});
        }
        if self.extended_master_secret.is_some() {
            encode_extension(ExtensionType::ExtendedMasterSecret, out, |_| {});
        }
        if self.encrypt_then_mac.is_some() {
            encode_extension(ExtensionType::EncryptThenMac, out, |_| {});
        }
        if self.client_certificate_url.is_some() {
            encode_extension(ExtensionType::ClientCertificateUrl, out, |_| {});
        }
        if let Some(authorities) = &self.trusted_ca_keys {
            encode_extension(ExtensionType::TrustedCAKeys, out, |b| {
                encode_trusted_authorities(authorities, b);
            });
        }
        if self.truncated_hmac.is_some() {
            encode_extension(ExtensionType::TruncatedHMAC, out, |_| {});
        }
        if let Some(ticket) = &self.session_ticket {
            encode_extension(ExtensionType::SessionTicket, out, |b| match ticket {
                ClientSessionTicket::Request => {}
                ClientSessionTicket::Offer(t) => t.encode(b),
            });
        }
        if let Some(versions) = &self.supported_versions {
            encode_extension(ExtensionType::SupportedVersions, out, |b| {
                if dtls {
                    let wire: Vec<ProtocolVersion> =
                        versions.iter().copied().map(dtls::swap_version).collect();
                    encode_vec_u8(b, &wire);
                } else {
                    encode_vec_u8(b, versions);
                }
            });
        }
        if let Some(shares) = &self.key_shares {
            encode_extension(ExtensionType::KeyShare, out, |b| encode_vec_u16(b, shares));
        }
        if let Some(modes) = &self.psk_modes {
            encode_extension(ExtensionType::PSKKeyExchangeModes, out, |b| {
                encode_vec_u8(b, modes)
            });
        }
        if self.early_data.is_some() {
            encode_extension(ExtensionType::EarlyData, out, |_| {});
        }
        if self.post_handshake_auth.is_some() {
            encode_extension(ExtensionType::PostHandshakeAuth, out, |_| {});
        }
        if let Some(cookie) = &self.cookie
            && !cookie_first
        {
            encode_extension(ExtensionType::Cookie, out, |b| cookie.encode(b));
        }
        if let Some(ri) = &self.renegotiation_info {
            encode_extension(ExtensionType::RenegotiationInfo, out, |b| ri.encode(b));
        }
        if let Some(cas) = &self.certificate_authorities {
            encode_extension(ExtensionType::CertificateAuthorities, out, |b| {
                encode_vec_u16(b, cas);
            });
        }
        if let Some(algs) = &self.certificate_compression {
            encode_extension(ExtensionType::CompressCertificate, out, |b| {
                encode_vec_u8(b, algs)
            });
        }
        if let Some(types) = &self.client_certificate_types {
            encode_extension(ExtensionType::ClientCertificateType, out, |b| {
                encode_vec_u8(b, types);
            });
        }
        if let Some(types) = &self.server_certificate_types {
            encode_extension(ExtensionType::ServerCertificateType, out, |b| {
                encode_vec_u8(b, types);
            });
        }
        if let Some(tp) = &self.transport_parameters {
            encode_extension(ExtensionType::TransportParameters, out, |b| tp.encode(b));
        }
        if let Some(schemes) = &self.delegated_credential {
            encode_extension(ExtensionType::DelegatedCredential, out, |b| {
                encode_vec_u16(b, schemes);
            });
        }
        if let Some(limit) = self.record_size_limit {
            encode_extension(ExtensionType::RecordSizeLimit, out, |b| limit.encode(b));
        }
        if let Some(request) = &self.ticket_request {
            encode_extension(ExtensionType::TicketRequest, out, |b| request.encode(b));
        }
        if let Some(hash) = &self.external_id_hash {
            encode_extension(ExtensionType::ExternalIdHash, out, |b| hash.encode(b));
        }
        if let Some(id) = &self.external_session_id {
            encode_extension(ExtensionType::ExternalSessionId, out, |b| id.encode(b));
        }
        if let Some(cached) = &self.cached_info {
            encode_extension(ExtensionType::CachedInfo, out, |b| cached.encode(b));
        }
        if self.cert_with_extern_psk.is_some() {
            encode_extension(ExtensionType::TlsCertWithExternPsk, out, |_| {});
        }
        if let Some(types) = &self.ech_outer_extensions {
            encode_extension(
                ExtensionType::EncryptedClientHelloOuterExtensions,
                out,
                |b| {
                    encode_vec_u8(b, types);
                },
            );
        }
        if let Some(ech) = &self.encrypted_client_hello {
            encode_extension(ExtensionType::EncryptedClientHello, out, |b| ech.encode(b));
        }
        if let Some(grease) = self.grease_last {
            // RFC 8701 §3: the second GREASE extension is not empty.
            encode_extension(ExtensionType::Unknown(grease), out, |b| b.push(0));
        }
        if let Some(len) = self.padding {
            // RFC 7685 §3: the body is all zeros.
            encode_extension(ExtensionType::Padding, out, |b| {
                b.resize(b.len() + len, 0);
            });
        }
        if let Some(psk) = &self.preshared_key {
            encode_extension(ExtensionType::PreSharedKey, out, |b| psk.encode(b));
        }
    }
}

impl Codec<'_> for ClientExtensions {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.encode_with(bytes, false);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();
        let seen = read_extensions(r, |typ, body| {
            match typ {
                ExtensionType::ServerName => {
                    out.server_name = Some(ServerNamePayload::read_client(body)?.into_owned());
                }
                ExtensionType::EllipticCurves => {
                    out.named_groups = Some(read_nonempty_vec_u16(body, "NamedGroups")?);
                }
                ExtensionType::ECPointFormats => {
                    out.ec_point_formats = Some(read_nonempty_vec_u8(body, "ECPointFormats")?);
                }
                ExtensionType::SignatureAlgorithms => {
                    out.signature_schemes = Some(read_nonempty_vec_u16(body, "SignatureSchemes")?);
                }
                ExtensionType::SignatureAlgorithmsCert => {
                    out.signature_schemes_cert =
                        Some(read_nonempty_vec_u16(body, "SignatureSchemesCert")?);
                }
                ExtensionType::ALProtocolNegotiation => {
                    out.protocols = Some(read_nonempty_vec_u16(body, "ProtocolNameList")?);
                }
                ExtensionType::StatusRequest => {
                    out.certificate_status_request = Some(CertificateStatusRequest::read(body)?);
                }
                ExtensionType::SCT => out.sct_request = Some(()),
                // RFC 9162 §6.5: the body must be empty, which
                // `read_extensions` enforces (decode_error otherwise).
                ExtensionType::TransparencyInfo => out.transparency_info = Some(()),
                ExtensionType::ExtendedMasterSecret => out.extended_master_secret = Some(()),
                ExtensionType::EncryptThenMac => out.encrypt_then_mac = Some(()),
                ExtensionType::ClientCertificateUrl => out.client_certificate_url = Some(()),
                ExtensionType::TrustedCAKeys => {
                    out.trusted_ca_keys = Some(read_trusted_authorities(body)?);
                }
                ExtensionType::TruncatedHMAC => out.truncated_hmac = Some(()),
                ExtensionType::SessionTicket => {
                    out.session_ticket = Some(if body.any_left() {
                        ClientSessionTicket::Offer(Payload::read(body).into_owned())
                    } else {
                        ClientSessionTicket::Request
                    });
                }
                ExtensionType::SupportedVersions => {
                    out.supported_versions = Some(read_nonempty_vec_u8(body, "SupportedVersions")?);
                }
                ExtensionType::KeyShare => {
                    out.key_shares = Some(crate::msgs::codec::read_vec_u16(body)?);
                }
                ExtensionType::PSKKeyExchangeModes => {
                    out.psk_modes = Some(read_nonempty_vec_u8(body, "PskKeyExchangeModes")?);
                }
                ExtensionType::EarlyData => out.early_data = Some(()),
                ExtensionType::PostHandshakeAuth => out.post_handshake_auth = Some(()),
                ExtensionType::Cookie => {
                    let cookie = PayloadU16::read(body)?;
                    if cookie.0.is_empty() {
                        return Err(InvalidMessage::IllegalEmptyValue);
                    }
                    out.cookie = Some(cookie);
                }
                ExtensionType::RenegotiationInfo => {
                    out.renegotiation_info = Some(PayloadU8::read(body)?);
                }
                ExtensionType::CertificateAuthorities => {
                    out.certificate_authorities =
                        Some(read_nonempty_vec_u16(body, "CertificateAuthorities")?);
                }
                ExtensionType::CompressCertificate => {
                    out.certificate_compression = Some(read_nonempty_vec_u8(
                        body,
                        "CertificateCompressionAlgorithms",
                    )?);
                }
                ExtensionType::ClientCertificateType => {
                    out.client_certificate_types =
                        Some(read_nonempty_vec_u8(body, "ClientCertificateTypes")?);
                }
                ExtensionType::ServerCertificateType => {
                    out.server_certificate_types =
                        Some(read_nonempty_vec_u8(body, "ServerCertificateTypes")?);
                }
                // RFC 9001 §8.2 only; the pre-RFC draft code point 0xffa5 is
                // left unrecognised.
                ExtensionType::TransportParameters => {
                    out.transport_parameters = Some(Payload::read(body).into_owned());
                }
                ExtensionType::RecordSizeLimit => {
                    out.record_size_limit = Some(u16::read(body)?);
                }
                ExtensionType::TicketRequest => {
                    out.ticket_request = Some(ClientTicketRequest::read(body)?);
                }
                ExtensionType::ExternalIdHash => {
                    out.external_id_hash = Some(ExternalIdHash::read(body)?);
                }
                ExtensionType::ExternalSessionId => {
                    out.external_session_id = Some(ExternalSessionId::read(body)?);
                }
                ExtensionType::CachedInfo => {
                    out.cached_info = Some(crate::cached_info::ClientHelloCachedInfo::read(body)?);
                }
                ExtensionType::Padding => {
                    // RFC 7685 §3: the server ignores the content.
                    out.padding = Some(body.rest().len());
                }
                ExtensionType::PreSharedKey => {
                    out.preshared_key = Some(PresharedKeyOffer::read(body)?);
                }
                ExtensionType::EncryptedClientHelloOuterExtensions => {
                    out.ech_outer_extensions = Some(read_nonempty_vec_u8(body, "OuterExtensions")?);
                }
                ExtensionType::EncryptedClientHello => {
                    out.encrypted_client_hello = Some(EchClientHello::read(body)?);
                }
                ExtensionType::DelegatedCredential => {
                    // SignatureSchemeList:
                    // supported_signature_algorithm<2..2^16-2>.
                    out.delegated_credential =
                        Some(read_nonempty_vec_u16(body, "DelegatedCredentialSchemes")?);
                }
                ExtensionType::TlsCertWithExternPsk => out.cert_with_extern_psk = Some(()),
                other => {
                    out.unknown.push(other);
                    body.rest();
                }
            }
            Ok(())
        })?;
        if out.preshared_key.is_some() && seen.last() != Some(&ExtensionType::PreSharedKey) {
            return Err(InvalidMessage::PreSharedKeyIsNotFinalExtension);
        }
        Ok(out)
    }
}

/// A ClientHello message (RFC 8446 §4.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHelloPayload {
    pub(crate) client_version: ProtocolVersion,
    pub(crate) random: Random,
    pub(crate) session_id: SessionId,
    /// DTLS 1.3 only (RFC 9147 §5.3): `legacy_cookie`, which follows
    /// `legacy_session_id`. `Some` selects the DTLS encoding, whose
    /// versions (held here in their TLS form) are DTLS ones on the wire.
    pub(crate) legacy_cookie: Option<PayloadU8>,
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) compression_methods: Vec<Compression>,
    pub(crate) extensions: ClientExtensions,
}

impl Codec<'_> for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let dtls = self.legacy_cookie.is_some();
        dtls::on_wire(self.client_version, dtls).encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        if let Some(cookie) = &self.legacy_cookie {
            cookie.encode(bytes);
        }
        encode_vec_u16(bytes, &self.cipher_suites);
        encode_vec_u8(bytes, &self.compression_methods);
        self.extensions.encode_with(bytes, dtls);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Self::read_with(r, false)
    }
}

impl ClientHelloPayload {
    /// Reads a ClientHello, in the DTLS 1.3 encoding when `dtls` (see
    /// `legacy_cookie`).
    fn read_with(r: &mut Reader<'_>, dtls: bool) -> Result<Self, InvalidMessage> {
        let client_version = dtls::on_wire(ProtocolVersion::read(r)?, dtls);
        let random = Random::read(r)?;
        let session_id = SessionId::read(r)?;
        let legacy_cookie = match dtls {
            true => Some(PayloadU8::read(r)?),
            false => None,
        };
        let cipher_suites = read_nonempty_vec_u16(r, "CipherSuites")?;
        let compression_methods = read_nonempty_vec_u8(r, "CompressionMethods")?;
        // RFC 5246 §7.4.1.2: the extensions block is optional for TLS 1.2
        // clients. Accept its absence; every TLS 1.3 client sends it.
        let mut extensions = if r.any_left() {
            ClientExtensions::read(r)?
        } else {
            ClientExtensions::default()
        };
        if dtls && let Some(versions) = &mut extensions.supported_versions {
            for version in versions.iter_mut() {
                *version = dtls::swap_version(*version);
            }
        }
        Ok(Self {
            client_version,
            random,
            session_id,
            legacy_cookie,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// The ALPN protocols offered, if any.
    pub(crate) fn alpn_protocols(&self) -> Option<&[ProtocolName]> {
        self.extensions.protocols.as_deref()
    }

    /// The signature schemes offered, if any.
    pub(crate) fn signature_schemes(&self) -> Option<&[SignatureScheme]> {
        self.extensions.signature_schemes.as_deref()
    }

    /// The key shares offered, if any.
    pub(crate) fn key_shares(&self) -> Option<&[KeyShareEntry]> {
        self.extensions.key_shares.as_deref()
    }

    /// The named groups offered, if any.
    pub(crate) fn named_groups(&self) -> Option<&[NamedGroup]> {
        self.extensions.named_groups.as_deref()
    }

    /// The SNI host name, if a valid one was sent.
    pub(crate) fn sni(&self) -> Option<&browntls_pki::DnsName<'static>> {
        match &self.extensions.server_name {
            Some(ServerNamePayload::SingleDnsName(d)) => Some(d),
            _ => None,
        }
    }

    pub(crate) fn ems_support_offered(&self) -> bool {
        self.extensions.extended_master_secret.is_some()
    }

    pub(crate) fn early_data_offered(&self) -> bool {
        self.extensions.early_data.is_some()
    }

    /// Whether any two key shares name the same group (RFC 8446 §4.2.8).
    pub(crate) fn has_duplicate_key_share(&self) -> bool {
        let Some(shares) = self.key_shares() else {
            return false;
        };
        for (i, a) in shares.iter().enumerate() {
            if shares[i + 1..].iter().any(|b| b.group == a.group) {
                return true;
            }
        }
        false
    }

    /// Whether any two certificate compression algorithms repeat.
    pub(crate) fn has_duplicate_certificate_compression(&self) -> bool {
        let Some(algs) = &self.extensions.certificate_compression else {
            return false;
        };
        for (i, a) in algs.iter().enumerate() {
            if algs[i + 1..].contains(a) {
                return true;
            }
        }
        false
    }
}

/// A ServerHello message (RFC 8446 §4.1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerHelloPayload {
    pub(crate) legacy_version: ProtocolVersion,
    pub(crate) random: Random,
    pub(crate) session_id: SessionId,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) compression_method: Compression,
    pub(crate) extensions: ServerExtensions,
    /// DTLS 1.3 (RFC 9147 §5.4): the versions, held here in their TLS
    /// form, are DTLS ones on the wire.
    pub(crate) dtls: bool,
}

/// The result of parsing a ServerHello-shaped message.
// Short-lived: `HandshakePayload::read` converts it at once, so boxing the
// larger variant would only add an allocation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ServerHelloOrRetry {
    Hello(ServerHelloPayload),
    Retry(HelloRetryRequest),
}

impl ServerHelloPayload {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        dtls::on_wire(self.legacy_version, self.dtls).encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);
        if self.dtls {
            let mut extensions = self.extensions.clone();
            extensions.supported_versions = extensions.supported_versions.map(dtls::swap_version);
            extensions.encode(bytes);
        } else {
            self.extensions.encode(bytes);
        }
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<ServerHelloOrRetry, InvalidMessage> {
        let legacy_version = ProtocolVersion::read(r)?;
        let random = Random::read(r)?;
        let session_id = SessionId::read(r)?;
        let cipher_suite = CipherSuite::read(r)?;
        let compression_method = Compression::read(r)?;
        if random == HELLO_RETRY_REQUEST_RANDOM {
            let extensions = HelloRetryRequestExtensions::read(r)?;
            return Ok(ServerHelloOrRetry::Retry(HelloRetryRequest {
                legacy_version,
                session_id,
                cipher_suite,
                compression_method,
                extensions,
                dtls: false,
            }));
        }
        // RFC 5246 §7.4.1.3: the extensions block may be absent.
        let extensions = if r.any_left() {
            ServerExtensions::read(r)?
        } else {
            ServerExtensions::default()
        };
        Ok(ServerHelloOrRetry::Hello(Self {
            legacy_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
            dtls: false,
        }))
    }

    /// Whether the random ends with one of the downgrade sentinels.
    pub(crate) fn has_downgrade_sentinel(&self) -> bool {
        let tail = &self.random.0[24..];
        tail == super::DOWNGRADE_SENTINEL_TLS12 || tail == super::DOWNGRADE_SENTINEL_TLS11
    }
}

/// The extensions permitted in a HelloRetryRequest (RFC 8446 §4.1.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct HelloRetryRequestExtensions {
    pub(crate) key_share: Option<NamedGroup>,
    pub(crate) cookie: Option<PayloadU16>,
    pub(crate) supported_versions: Option<ProtocolVersion>,
    /// RFC 9849 §5: the server's `hrr_accept_confirmation`.
    pub(crate) encrypted_client_hello: Option<[u8; 8]>,
    /// Present only when an unknown extension was seen; the handshake will
    /// reject the message, but the codec records it for diagnostics.
    pub(crate) unknown: Vec<ExtensionType>,
}

impl Codec<'_> for HelloRetryRequestExtensions {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        let out = &mut *list.buf;
        if let Some(group) = &self.key_share {
            encode_extension(ExtensionType::KeyShare, out, |b| group.encode(b));
        }
        if let Some(cookie) = &self.cookie {
            encode_extension(ExtensionType::Cookie, out, |b| cookie.encode(b));
        }
        if let Some(v) = &self.supported_versions {
            encode_extension(ExtensionType::SupportedVersions, out, |b| v.encode(b));
        }
        if let Some(conf) = &self.encrypted_client_hello {
            encode_extension(ExtensionType::EncryptedClientHello, out, |b| {
                b.extend_from_slice(conf);
            });
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();
        read_extensions(r, |typ, body| {
            match typ {
                ExtensionType::EncryptedClientHello => {
                    // RFC 9849 §6.1.4: any length but 8 is decode_error.
                    let conf = body
                        .take(8)
                        .ok_or(InvalidMessage::MissingData("ECHHelloRetryRequest"))?;
                    let mut out_conf = [0u8; 8];
                    out_conf.copy_from_slice(conf);
                    out.encrypted_client_hello = Some(out_conf);
                }
                ExtensionType::KeyShare => out.key_share = Some(NamedGroup::read(body)?),
                ExtensionType::Cookie => {
                    let cookie = PayloadU16::read(body)?;
                    if cookie.0.is_empty() {
                        return Err(InvalidMessage::IllegalEmptyValue);
                    }
                    out.cookie = Some(cookie);
                }
                ExtensionType::SupportedVersions => {
                    out.supported_versions = Some(ProtocolVersion::read(body)?);
                }
                other => {
                    out.unknown.push(other);
                    body.rest();
                }
            }
            Ok(())
        })?;
        Ok(out)
    }
}

/// A HelloRetryRequest message (RFC 8446 §4.1.4), encoded as a ServerHello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HelloRetryRequest {
    pub(crate) legacy_version: ProtocolVersion,
    pub(crate) session_id: SessionId,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) compression_method: Compression,
    pub(crate) extensions: HelloRetryRequestExtensions,
    /// DTLS 1.3, as for [`ServerHelloPayload::dtls`].
    pub(crate) dtls: bool,
}

impl HelloRetryRequest {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        dtls::on_wire(self.legacy_version, self.dtls).encode(bytes);
        HELLO_RETRY_REQUEST_RANDOM.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);
        if self.dtls {
            let mut extensions = self.extensions.clone();
            extensions.supported_versions = extensions.supported_versions.map(dtls::swap_version);
            extensions.encode(bytes);
        } else {
            self.extensions.encode(bytes);
        }
    }
}

/// A complete handshake message: type, length and body.
#[derive(Debug)]
pub struct HandshakeMessagePayload<'a>(pub(crate) HandshakePayload<'a>);

impl<'a> HandshakeMessagePayload<'a> {
    /// The message type.
    pub(crate) fn typ(&self) -> HandshakeType {
        self.0.handshake_type()
    }

    /// Encodes the message: type, 24-bit length, body. A HelloRetryRequest is
    /// written as a ServerHello.
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        let typ = match self.0 {
            HandshakePayload::HelloRetryRequest(_) => HandshakeType::ServerHello,
            _ => self.typ(),
        };
        typ.encode(bytes);
        let nested = LengthPrefixedBuffer::new(
            ListLength::U24 {
                max: usize::MAX,
                error: InvalidMessage::MessageTooLarge,
            },
            bytes,
        );
        self.0.encode(nested.buf);
    }

    /// Parses a message whose version-dependent fields follow `vers`.
    pub fn read_version(r: &mut Reader<'a>, vers: ProtocolVersion) -> Result<Self, InvalidMessage> {
        let typ = HandshakeType::read(r)?;
        let len = u24::read(r)?.0;
        if len > MAX_HANDSHAKE_SIZE {
            return Err(InvalidMessage::HandshakePayloadTooLarge);
        }
        let mut sub = r.sub(len as usize)?;
        let payload = read_payload(typ, vers, &mut sub)?;
        Ok(Self(payload))
    }

    /// Builds the synthetic `message_hash` message used to replace the first
    /// ClientHello in the transcript after a HelloRetryRequest
    /// (RFC 8446 §4.4.1).
    pub(crate) fn build_handshake_hash(hash: &[u8]) -> HandshakeMessagePayload<'static> {
        HandshakeMessagePayload(HandshakePayload::MessageHash(Payload::new(hash.to_vec())))
    }

    /// The encoding of this ClientHello with the PSK binders removed, for the
    /// binder HMAC (RFC 8446 §4.2.11.2).
    pub(crate) fn encoding_for_binder_signing(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        self.encode(&mut encoded);
        encoded.truncate(encoded.len().saturating_sub(self.total_binder_length()));
        encoded
    }

    /// The encoded length of a ClientHello's PSK binders: zero for any other
    /// message, or for a ClientHello without a PSK offer.
    pub(crate) fn total_binder_length(&self) -> usize {
        match &self.0 {
            HandshakePayload::ClientHello(ch) => ch
                .extensions
                .preshared_key
                .as_ref()
                .map_or(0, |psk| psk.binders_encoded_len()),
            _ => 0,
        }
    }

    /// Converts into an owned message.
    pub(crate) fn into_owned(self) -> HandshakeMessagePayload<'static> {
        HandshakeMessagePayload(self.0.into_owned())
    }
}

impl<'a> Codec<'a> for HandshakeMessagePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode(self, bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Self::read_version(r, ProtocolVersion::TLSv1_2)
    }
}

mod dtls;

#[cfg(test)]
mod tests;

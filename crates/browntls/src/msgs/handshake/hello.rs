//! ClientHello, ServerHello and HelloRetryRequest.

use alloc::vec::Vec;

use super::extensions::{encode_extension, read_extensions};
use super::{
    CertificateStatusRequest, ClientSessionTicket, DistinguishedName, HandshakePayload,
    KeyShareEntry, MAX_HANDSHAKE_SIZE, PresharedKeyOffer, ProtocolName, Random, ServerExtensions,
    ServerNamePayload, SessionId, read_payload,
};
use crate::enums::{
    CertificateCompressionAlgorithm, CertificateType, CipherSuite, HandshakeType, ProtocolVersion,
    SignatureScheme,
};
use crate::error::InvalidMessage;
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
    pub(crate) extended_master_secret: Option<()>,
    pub(crate) session_ticket: Option<ClientSessionTicket>,
    pub(crate) supported_versions: Option<Vec<ProtocolVersion>>,
    pub(crate) key_shares: Option<Vec<KeyShareEntry>>,
    pub(crate) psk_modes: Option<Vec<PskKeyExchangeMode>>,
    pub(crate) early_data: Option<()>,
    pub(crate) cookie: Option<PayloadU16>,
    pub(crate) renegotiation_info: Option<PayloadU8>,
    pub(crate) certificate_authorities: Option<Vec<DistinguishedName>>,
    pub(crate) certificate_compression: Option<Vec<CertificateCompressionAlgorithm>>,
    pub(crate) client_certificate_types: Option<Vec<CertificateType>>,
    pub(crate) server_certificate_types: Option<Vec<CertificateType>>,
    pub(crate) transport_parameters: Option<Payload<'static>>,
    /// Extension types present but not understood, in order.
    pub(crate) unknown: Vec<ExtensionType>,
    /// Always encoded last (RFC 8446 §4.2.11).
    pub(crate) preshared_key: Option<PresharedKeyOffer>,
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
            self.extended_master_secret.is_some(),
            ExtensionType::ExtendedMasterSecret,
        );
        add(self.session_ticket.is_some(), ExtensionType::SessionTicket);
        add(
            self.supported_versions.is_some(),
            ExtensionType::SupportedVersions,
        );
        add(self.key_shares.is_some(), ExtensionType::KeyShare);
        add(self.psk_modes.is_some(), ExtensionType::PSKKeyExchangeModes);
        add(self.early_data.is_some(), ExtensionType::EarlyData);
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
        for unknown in &self.unknown {
            add(true, *unknown);
        }
        add(self.preshared_key.is_some(), ExtensionType::PreSharedKey);
        out
    }
}

impl Codec<'_> for ClientExtensions {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        let out = &mut *list.buf;
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
        if self.extended_master_secret.is_some() {
            encode_extension(ExtensionType::ExtendedMasterSecret, out, |_| {});
        }
        if let Some(ticket) = &self.session_ticket {
            encode_extension(ExtensionType::SessionTicket, out, |b| match ticket {
                ClientSessionTicket::Request => {}
                ClientSessionTicket::Offer(t) => t.encode(b),
            });
        }
        if let Some(versions) = &self.supported_versions {
            encode_extension(ExtensionType::SupportedVersions, out, |b| {
                encode_vec_u8(b, versions);
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
        if let Some(cookie) = &self.cookie {
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
        if let Some(psk) = &self.preshared_key {
            encode_extension(ExtensionType::PreSharedKey, out, |b| psk.encode(b));
        }
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
                ExtensionType::ExtendedMasterSecret => out.extended_master_secret = Some(()),
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
                ExtensionType::TransportParameters | ExtensionType::TransportParametersDraft => {
                    out.transport_parameters = Some(Payload::read(body).into_owned());
                }
                ExtensionType::PreSharedKey => {
                    out.preshared_key = Some(PresharedKeyOffer::read(body)?);
                }
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
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) compression_methods: Vec<Compression>,
    pub(crate) extensions: ClientExtensions,
}

impl Codec<'_> for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        encode_vec_u16(bytes, &self.cipher_suites);
        encode_vec_u8(bytes, &self.compression_methods);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let client_version = ProtocolVersion::read(r)?;
        let random = Random::read(r)?;
        let session_id = SessionId::read(r)?;
        let cipher_suites = read_nonempty_vec_u16(r, "CipherSuites")?;
        let compression_methods = read_nonempty_vec_u8(r, "CompressionMethods")?;
        // RFC 5246 §7.4.1.2: the extensions block is optional for TLS 1.2
        // clients. Accept its absence; every TLS 1.3 client sends it.
        let extensions = if r.any_left() {
            ClientExtensions::read(r)?
        } else {
            ClientExtensions::default()
        };
        Ok(Self {
            client_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }
}

impl ClientHelloPayload {
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
}

/// The result of parsing a ServerHello-shaped message.
pub(crate) enum ServerHelloOrRetry {
    Hello(ServerHelloPayload),
    Retry(HelloRetryRequest),
}

impl ServerHelloPayload {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        self.legacy_version.encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);
        self.extensions.encode(bytes);
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
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();
        read_extensions(r, |typ, body| {
            match typ {
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
}

impl HelloRetryRequest {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        self.legacy_version.encode(bytes);
        HELLO_RETRY_REQUEST_RANDOM.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);
        self.extensions.encode(bytes);
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
    /// ClientHello in the transcript after a HelloRetryRequest (RFC 8446 §4.4.1).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_client_hello() -> ClientHelloPayload {
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from([1u8; 32]),
            session_id: SessionId::from_slice(&[2u8; 32]).unwrap(),
            cipher_suites: alloc::vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            ],
            compression_methods: alloc::vec![Compression::Null],
            extensions: ClientExtensions {
                server_name: Some(ServerNamePayload::SingleDnsName(
                    browntls_pki::DnsName::try_from("example.com")
                        .unwrap()
                        .to_owned(),
                )),
                named_groups: Some(alloc::vec![NamedGroup::X25519]),
                signature_schemes: Some(alloc::vec![SignatureScheme::ED25519]),
                protocols: Some(alloc::vec![ProtocolName::from(b"h2".to_vec())]),
                supported_versions: Some(alloc::vec![ProtocolVersion::TLSv1_3]),
                key_shares: Some(alloc::vec![KeyShareEntry::new(
                    NamedGroup::X25519,
                    &[9; 32]
                )]),
                psk_modes: Some(alloc::vec![PskKeyExchangeMode::PSK_DHE_KE]),
                preshared_key: Some(PresharedKeyOffer::new(
                    super::super::PresharedKeyIdentity::new(alloc::vec![1, 2, 3], 7),
                    alloc::vec![0xab; 32],
                )),
                ..Default::default()
            },
        }
    }

    #[test]
    fn client_hello_roundtrip() {
        let ch = sample_client_hello();
        let msg = HandshakeMessagePayload(HandshakePayload::ClientHello(ch.clone()));
        let enc = msg.get_encoding();
        assert_eq!(enc[0], 1);
        let back = HandshakeMessagePayload::read_version(
            &mut Reader::init(&enc),
            ProtocolVersion::TLSv1_3,
        )
        .unwrap();
        match back.0 {
            HandshakePayload::ClientHello(parsed) => assert_eq!(parsed, ch),
            other => panic!("wrong payload {other:?}"),
        }
        // binder truncation removes exactly the binders list
        let truncated = msg.encoding_for_binder_signing();
        assert_eq!(truncated.len(), enc.len() - (2 + 33));
        assert_eq!(&enc[..truncated.len()], &truncated[..]);
    }

    #[test]
    fn psk_must_be_last() {
        let mut ch = sample_client_hello();
        // Encode manually with PSK first by swapping extension order:
        let mut bytes = Vec::new();
        ch.client_version.encode(&mut bytes);
        ch.random.encode(&mut bytes);
        ch.session_id.encode(&mut bytes);
        encode_vec_u16(&mut bytes, &ch.cipher_suites);
        encode_vec_u8(&mut bytes, &ch.compression_methods);
        let psk = ch.extensions.preshared_key.take().unwrap();
        let mut exts = Vec::new();
        {
            let list = LengthPrefixedBuffer::new(ListLength::U16, &mut exts);
            encode_extension(ExtensionType::PreSharedKey, list.buf, |b| psk.encode(b));
            encode_extension(ExtensionType::SupportedVersions, list.buf, |b| {
                encode_vec_u8(b, &[ProtocolVersion::TLSv1_3]);
            });
        }
        bytes.extend(exts);
        assert_eq!(
            ClientHelloPayload::read_bytes(&bytes),
            Err(InvalidMessage::PreSharedKeyIsNotFinalExtension)
        );
    }

    #[test]
    fn client_hello_rejects_empty_lists_and_duplicates() {
        let mut ch = sample_client_hello();
        ch.cipher_suites.clear();
        assert_eq!(
            ClientHelloPayload::read_bytes(&ch.get_encoding()),
            Err(InvalidMessage::IllegalEmptyList("CipherSuites"))
        );
        let ch = sample_client_hello();
        let mut enc = ch.get_encoding();
        // Build an extension block containing the same extension twice.
        let mut bytes = Vec::new();
        ch.client_version.encode(&mut bytes);
        ch.random.encode(&mut bytes);
        ch.session_id.encode(&mut bytes);
        encode_vec_u16(&mut bytes, &ch.cipher_suites);
        encode_vec_u8(&mut bytes, &ch.compression_methods);
        {
            let list = LengthPrefixedBuffer::new(ListLength::U16, &mut bytes);
            encode_extension(ExtensionType::EarlyData, list.buf, |_| {});
            encode_extension(ExtensionType::EarlyData, list.buf, |_| {});
        }
        assert_eq!(
            ClientHelloPayload::read_bytes(&bytes),
            Err(InvalidMessage::DuplicateExtension(0x2a))
        );
        enc.truncate(10);
        assert!(ClientHelloPayload::read_bytes(&enc).is_err());
    }

    #[test]
    fn client_hello_without_extensions_block() {
        let ch = ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from([0u8; 32]),
            session_id: SessionId::empty(),
            cipher_suites: alloc::vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            compression_methods: alloc::vec![Compression::Null],
            extensions: ClientExtensions::default(),
        };
        let mut enc = ch.get_encoding();
        // strip the (empty) extension block
        enc.truncate(enc.len() - 2);
        let back = ClientHelloPayload::read_bytes(&enc).unwrap();
        assert_eq!(back, ch);
        assert!(back.sni().is_none());
        assert!(!back.has_duplicate_key_share());
    }

    #[test]
    fn server_hello_and_hrr() {
        let sh = ServerHelloPayload {
            legacy_version: ProtocolVersion::TLSv1_2,
            random: Random::from([5u8; 32]),
            session_id: SessionId::empty(),
            cipher_suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            compression_method: Compression::Null,
            extensions: ServerExtensions {
                supported_versions: Some(ProtocolVersion::TLSv1_3),
                key_share: Some(KeyShareEntry::new(NamedGroup::X25519, &[1; 32])),
                ..Default::default()
            },
        };
        let msg = HandshakeMessagePayload(HandshakePayload::ServerHello(sh.clone()));
        let enc = msg.get_encoding();
        match HandshakeMessagePayload::read_bytes(&enc).unwrap().0 {
            HandshakePayload::ServerHello(back) => assert_eq!(back, sh),
            other => panic!("{other:?}"),
        }
        assert!(!sh.has_downgrade_sentinel());

        let hrr = HelloRetryRequest {
            legacy_version: ProtocolVersion::TLSv1_2,
            session_id: SessionId::empty(),
            cipher_suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            compression_method: Compression::Null,
            extensions: HelloRetryRequestExtensions {
                key_share: Some(NamedGroup::secp256r1),
                supported_versions: Some(ProtocolVersion::TLSv1_3),
                cookie: Some(PayloadU16::new(alloc::vec![1, 2])),
                unknown: Vec::new(),
            },
        };
        let msg = HandshakeMessagePayload(HandshakePayload::HelloRetryRequest(hrr.clone()));
        let enc = msg.get_encoding();
        assert_eq!(enc[0], u8::from(HandshakeType::ServerHello));
        match HandshakeMessagePayload::read_bytes(&enc).unwrap().0 {
            HandshakePayload::HelloRetryRequest(back) => assert_eq!(back, hrr),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn oversize_handshake_rejected() {
        let bytes = [1, 0x01, 0, 0];
        assert_eq!(
            HandshakeMessagePayload::read_bytes(&bytes).unwrap_err(),
            InvalidMessage::HandshakePayloadTooLarge
        );
        let bytes = [1, 0, 0, 5, 0];
        assert_eq!(
            HandshakeMessagePayload::read_bytes(&bytes).unwrap_err(),
            InvalidMessage::MessageTooShort
        );
    }

    #[test]
    fn message_hash_cannot_come_from_wire() {
        let bytes = [0xfe, 0, 0, 1, 0];
        assert_eq!(
            HandshakeMessagePayload::read_bytes(&bytes).unwrap_err(),
            InvalidMessage::UnexpectedMessage("MessageHash")
        );
    }

    #[test]
    fn unknown_handshake_type_is_opaque() {
        let bytes = [0x7f, 0, 0, 2, 1, 2];
        let msg = HandshakeMessagePayload::read_bytes(&bytes).unwrap();
        assert_eq!(msg.typ(), HandshakeType::Unknown(0x7f));
        assert_eq!(msg.get_encoding(), bytes);
    }
}

//! Protocol enums that are not part of the public API.
#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]

use crate::crypto::KeyExchangeAlgorithm;
use crate::msgs::codec::{Codec, Reader};

enum_builder! {
    /// The `HashAlgorithm` TLS protocol enum (RFC 5246 §7.4.1.4.1).
    #[repr(u8)]
    #[allow(missing_docs)]
    pub enum HashAlgorithm {
        NONE => 0x00,
        MD5 => 0x01,
        SHA1 => 0x02,
        SHA224 => 0x03,
        SHA256 => 0x04,
        SHA384 => 0x05,
        SHA512 => 0x06,
    }
}

enum_builder! {
    /// The `ClientCertificateType` TLS protocol enum (RFC 5246 §7.4.4).
    #[repr(u8)]
    pub(crate) enum ClientCertificateType {
        RSASign => 0x01,
        DSSSign => 0x02,
        RSAFixedDH => 0x03,
        DSSFixedDH => 0x04,
        RSAEphemeralDH => 0x05,
        DSSEphemeralDH => 0x06,
        FortezzaDMS => 0x14,
        ECDSASign => 0x40,
        RSAFixedECDH => 0x41,
        ECDSAFixedECDH => 0x42,
    }
}

enum_builder! {
    /// The `Compression` TLS protocol enum (RFC 5246 §7.4.1.2).
    #[repr(u8)]
    pub(crate) enum Compression {
        Null => 0x00,
        Deflate => 0x01,
        LSZ => 0x40,
    }
}

enum_builder! {
    /// The `AlertLevel` TLS protocol enum (RFC 8446 §6).
    #[repr(u8)]
    pub(crate) enum AlertLevel {
        Warning => 0x01,
        Fatal => 0x02,
    }
}

enum_builder! {
    /// The `ExtensionType` TLS protocol enum (RFC 8446 §4.2).
    #[repr(u16)]
    pub(crate) enum ExtensionType {
        ServerName => 0x0000,
        MaxFragmentLength => 0x0001,
        ClientCertificateUrl => 0x0002,
        TrustedCAKeys => 0x0003,
        TruncatedHMAC => 0x0004,
        StatusRequest => 0x0005,
        UserMapping => 0x0006,
        ClientAuthz => 0x0007,
        ServerAuthz => 0x0008,
        CertificateType => 0x0009,
        EllipticCurves => 0x000a,
        ECPointFormats => 0x000b,
        SRP => 0x000c,
        SignatureAlgorithms => 0x000d,
        UseSRTP => 0x000e,
        Heartbeat => 0x000f,
        ALProtocolNegotiation => 0x0010,
        SCT => 0x0012,
        ClientCertificateType => 0x0013,
        ServerCertificateType => 0x0014,
        Padding => 0x0015,
        EncryptThenMac => 0x0016,
        ExtendedMasterSecret => 0x0017,
        CompressCertificate => 0x001b,
        SessionTicket => 0x0023,
        PreSharedKey => 0x0029,
        EarlyData => 0x002a,
        SupportedVersions => 0x002b,
        Cookie => 0x002c,
        PSKKeyExchangeModes => 0x002d,
        TicketEarlyDataInfo => 0x002e,
        CertificateAuthorities => 0x002f,
        OIDFilters => 0x0030,
        PostHandshakeAuth => 0x0031,
        SignatureAlgorithmsCert => 0x0032,
        KeyShare => 0x0033,
        TransportParameters => 0x0039,
        NextProtocolNegotiation => 0x3374,
        ChannelId => 0x754f,
        RenegotiationInfo => 0xff01,
        TransportParametersDraft => 0xffa5,
        EncryptedClientHello => 0xfe0d,
        EncryptedClientHelloOuterExtensions => 0xfd00,
    }
}

enum_builder! {
    /// The `ServerNameType` TLS protocol enum (RFC 6066 §3).
    #[repr(u8)]
    pub(crate) enum ServerNameType {
        HostName => 0x00,
    }
}

enum_builder! {
    /// The `NamedGroup` TLS protocol enum (RFC 8446 §4.2.7, RFC 7919).
    #[repr(u16)]
    pub enum NamedGroup {
        /// NIST P-256 (secp256r1).
        secp256r1 => 0x0017,
        /// NIST P-384 (secp384r1).
        secp384r1 => 0x0018,
        /// NIST P-521 (secp521r1).
        secp521r1 => 0x0019,
        /// Curve25519 (RFC 7748).
        X25519 => 0x001d,
        /// Curve448 (RFC 7748).
        X448 => 0x001e,
        /// 2048-bit finite field group (RFC 7919).
        FFDHE2048 => 0x0100,
        /// 3072-bit finite field group (RFC 7919).
        FFDHE3072 => 0x0101,
        /// 4096-bit finite field group (RFC 7919).
        FFDHE4096 => 0x0102,
        /// 6144-bit finite field group (RFC 7919).
        FFDHE6144 => 0x0103,
        /// 8192-bit finite field group (RFC 7919).
        FFDHE8192 => 0x0104,
        /// ML-KEM-512 (FIPS 203).
        MLKEM512 => 0x0200,
        /// ML-KEM-768 (FIPS 203).
        MLKEM768 => 0x0201,
        /// ML-KEM-1024 (FIPS 203).
        MLKEM1024 => 0x0202,
        /// Hybrid secp256r1 + ML-KEM-768 (draft-ietf-tls-ecdhe-mlkem).
        secp256r1MLKEM768 => 0x11eb,
        /// Hybrid X25519 + ML-KEM-768 (draft-ietf-tls-ecdhe-mlkem).
        X25519MLKEM768 => 0x11ec,
        /// Hybrid secp384r1 + ML-KEM-1024 (draft-ietf-tls-ecdhe-mlkem).
        secp384r1MLKEM1024 => 0x11ed,
    }
}

impl NamedGroup {
    /// Whether the group belongs to the non-preferred tier: the groups
    /// RFC 9846 defines beyond those §9.1 makes mandatory or recommended,
    /// i.e. X448 and the RFC 7919 finite-field groups. A server ranks them
    /// after every other mutually supported group, whatever the client's
    /// key shares or order.
    pub fn is_non_preferred(self) -> bool {
        matches!(
            self,
            Self::X448
                | Self::FFDHE2048
                | Self::FFDHE3072
                | Self::FFDHE4096
                | Self::FFDHE6144
                | Self::FFDHE8192
        )
    }

    /// The TLS 1.2 key exchange algorithm family of this group.
    pub fn key_exchange_algorithm(self) -> KeyExchangeAlgorithm {
        match u16::from(self) {
            x if (0x100..0x200).contains(&x) => KeyExchangeAlgorithm::DHE,
            _ => KeyExchangeAlgorithm::ECDHE,
        }
    }
}

enum_builder! {
    /// The `ECPointFormat` TLS protocol enum (RFC 8422 §5.1.2).
    #[repr(u8)]
    pub(crate) enum ECPointFormat {
        Uncompressed => 0x00,
        ANSIX962CompressedPrime => 0x01,
        ANSIX962CompressedChar2 => 0x02,
    }
}

enum_builder! {
    /// The `ECCurveType` TLS protocol enum (RFC 8422 §5.4).
    #[repr(u8)]
    pub(crate) enum ECCurveType {
        ExplicitPrime => 0x01,
        ExplicitChar2 => 0x02,
        NamedCurve => 0x03,
    }
}

enum_builder! {
    /// The `PskKeyExchangeMode` TLS protocol enum (RFC 8446 §4.2.9).
    #[repr(u8)]
    pub(crate) enum PskKeyExchangeMode {
        PSK_KE => 0x00,
        PSK_DHE_KE => 0x01,
    }
}

enum_builder! {
    /// The `KeyUpdateRequest` TLS protocol enum (RFC 8446 §4.6.3).
    #[repr(u8)]
    pub(crate) enum KeyUpdateRequest {
        UpdateNotRequested => 0x00,
        UpdateRequested => 0x01,
    }
}

enum_builder! {
    /// The `CertificateStatusType` TLS protocol enum (RFC 6066 §8).
    #[repr(u8)]
    pub(crate) enum CertificateStatusType {
        OCSP => 0x01,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn roundtrips() {
        test_enum8::<HashAlgorithm>(HashAlgorithm::NONE, HashAlgorithm::SHA512);
        test_enum8::<ClientCertificateType>(
            ClientCertificateType::RSASign,
            ClientCertificateType::ECDSAFixedECDH,
        );
        test_enum8::<Compression>(Compression::Null, Compression::LSZ);
        test_enum8::<AlertLevel>(AlertLevel::Warning, AlertLevel::Fatal);
        test_enum16::<ExtensionType>(ExtensionType::ServerName, ExtensionType::RenegotiationInfo);
        test_enum16::<NamedGroup>(NamedGroup::secp256r1, NamedGroup::X25519MLKEM768);
        test_enum8::<ECPointFormat>(
            ECPointFormat::Uncompressed,
            ECPointFormat::ANSIX962CompressedChar2,
        );
        test_enum8::<ECCurveType>(ECCurveType::ExplicitPrime, ECCurveType::NamedCurve);
        test_enum8::<PskKeyExchangeMode>(
            PskKeyExchangeMode::PSK_KE,
            PskKeyExchangeMode::PSK_DHE_KE,
        );
        test_enum8::<KeyUpdateRequest>(
            KeyUpdateRequest::UpdateNotRequested,
            KeyUpdateRequest::UpdateRequested,
        );
        test_enum8::<CertificateStatusType>(
            CertificateStatusType::OCSP,
            CertificateStatusType::OCSP,
        );
        assert_eq!(
            NamedGroup::FFDHE2048.key_exchange_algorithm(),
            KeyExchangeAlgorithm::DHE
        );
        assert_eq!(
            NamedGroup::X25519.key_exchange_algorithm(),
            KeyExchangeAlgorithm::ECDHE
        );
    }

    pub(crate) fn test_enum8<T: for<'a> Codec<'a>>(first: T, last: T) {
        let first_v = get8(&first);
        let last_v = get8(&last);
        for val in first_v..=last_v {
            let mut buf = Vec::new();
            val.encode(&mut buf);
            assert_eq!(buf.len(), 1);
            let t = T::read_bytes(&buf).unwrap();
            assert_eq!(val, get8(&t));
        }
    }

    pub(crate) fn test_enum16<T: for<'a> Codec<'a>>(first: T, last: T) {
        let first_v = get16(&first);
        let last_v = get16(&last);
        for val in first_v..=last_v {
            let mut buf = Vec::new();
            val.encode(&mut buf);
            assert_eq!(buf.len(), 2);
            let t = T::read_bytes(&buf).unwrap();
            assert_eq!(val, get16(&t));
        }
    }

    fn get8<T: for<'a> Codec<'a>>(enum_value: &T) -> u8 {
        let enc = enum_value.get_encoding();
        assert_eq!(enc.len(), 1);
        enc[0]
    }

    fn get16<T: for<'a> Codec<'a>>(enum_value: &T) -> u16 {
        let enc = enum_value.get_encoding();
        assert_eq!(enc.len(), 2);
        u16::from_be_bytes([enc[0], enc[1]])
    }
}

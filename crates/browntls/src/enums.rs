//! Public protocol code points (IANA TLS registries).
#![allow(non_camel_case_types)]
#![allow(missing_docs)]

use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::HashAlgorithm;

enum_builder! {
    /// The `AlertDescription` TLS protocol enum (RFC 9846 §6).
    #[repr(u8)]
    pub enum AlertDescription {
        CloseNotify => 0x00,
        UnexpectedMessage => 0x0a,
        BadRecordMac => 0x14,
        DecryptionFailed => 0x15,
        RecordOverflow => 0x16,
        DecompressionFailure => 0x1e,
        HandshakeFailure => 0x28,
        NoCertificate => 0x29,
        BadCertificate => 0x2a,
        UnsupportedCertificate => 0x2b,
        CertificateRevoked => 0x2c,
        CertificateExpired => 0x2d,
        CertificateUnknown => 0x2e,
        IllegalParameter => 0x2f,
        UnknownCA => 0x30,
        AccessDenied => 0x31,
        DecodeError => 0x32,
        DecryptError => 0x33,
        ExportRestriction => 0x3c,
        ProtocolVersion => 0x46,
        InsufficientSecurity => 0x47,
        InternalError => 0x50,
        InappropriateFallback => 0x56,
        UserCanceled => 0x5a,
        NoRenegotiation => 0x64,
        MissingExtension => 0x6d,
        UnsupportedExtension => 0x6e,
        CertificateUnobtainable => 0x6f,
        UnrecognisedName => 0x70,
        BadCertificateStatusResponse => 0x71,
        BadCertificateHashValue => 0x72,
        UnknownPSKIdentity => 0x73,
        CertificateRequired => 0x74,
        /// RFC 9846 §6.2: an error not covered by a more specific alert.
        GeneralError => 0x75,
        NoApplicationProtocol => 0x78,
        EncryptedClientHelloRequired => 0x79,
    }
}

enum_builder! {
    /// The `HandshakeType` TLS protocol enum (RFC 8446 §4).
    #[repr(u8)]
    pub enum HandshakeType {
        HelloRequest => 0x00,
        ClientHello => 0x01,
        ServerHello => 0x02,
        HelloVerifyRequest => 0x03,
        NewSessionTicket => 0x04,
        EndOfEarlyData => 0x05,
        HelloRetryRequest => 0x06,
        EncryptedExtensions => 0x08,
        Certificate => 0x0b,
        ServerKeyExchange => 0x0c,
        CertificateRequest => 0x0d,
        ServerHelloDone => 0x0e,
        CertificateVerify => 0x0f,
        ClientKeyExchange => 0x10,
        Finished => 0x14,
        CertificateURL => 0x15,
        CertificateStatus => 0x16,
        KeyUpdate => 0x18,
        CompressedCertificate => 0x19,
        MessageHash => 0xfe,
    }
}

enum_builder! {
    /// The `ContentType` TLS protocol enum (RFC 8446 §5.1).
    #[repr(u8)]
    pub enum ContentType {
        ChangeCipherSpec => 0x14,
        Alert => 0x15,
        Handshake => 0x16,
        ApplicationData => 0x17,
        Heartbeat => 0x18,
    }
}

enum_builder! {
    /// The `ProtocolVersion` TLS protocol enum.
    #[repr(u16)]
    pub enum ProtocolVersion {
        SSLv2 => 0x0002,
        SSLv3 => 0x0300,
        TLSv1_0 => 0x0301,
        TLSv1_1 => 0x0302,
        TLSv1_2 => 0x0303,
        TLSv1_3 => 0x0304,
        DTLSv1_0 => 0xfeff,
        DTLSv1_2 => 0xfefd,
        DTLSv1_3 => 0xfefc,
    }
}

enum_builder! {
    /// The `CipherSuite` TLS protocol enum (the subset this library knows by name).
    #[repr(u16)]
    pub enum CipherSuite {
        TLS_NULL_WITH_NULL_NULL => 0x0000,
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV => 0x00ff,
        TLS_FALLBACK_SCSV => 0x5600,
        TLS13_AES_128_GCM_SHA256 => 0x1301,
        TLS13_AES_256_GCM_SHA384 => 0x1302,
        TLS13_CHACHA20_POLY1305_SHA256 => 0x1303,
        TLS13_AES_128_CCM_SHA256 => 0x1304,
        TLS13_AES_128_CCM_8_SHA256 => 0x1305,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => 0xc009,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 0xc00a,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => 0xc013,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => 0xc014,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc023,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc024,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => 0xc027,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => 0xc028,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02b,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02c,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xc02f,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xc030,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca8,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca9,
    }
}

impl CipherSuite {
    /// Whether the suite belongs to the non-preferred tier: the TLS 1.3
    /// suites RFC 9846 defines beyond those §9.1 makes mandatory or
    /// recommended, i.e. AES-128-CCM and AES-128-CCM-8. A server ranks them
    /// after every other mutually supported suite, whatever the client's
    /// order.
    pub fn is_non_preferred(self) -> bool {
        matches!(
            self,
            Self::TLS13_AES_128_CCM_SHA256
                | Self::TLS13_AES_128_CCM_8_SHA256
                | Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                | Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                | Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                | Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                | Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
                | Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
                | Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
                | Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        )
    }
}

enum_builder! {
    /// The `SignatureScheme` TLS protocol enum (RFC 8446 §4.2.3).
    #[repr(u16)]
    pub enum SignatureScheme {
        RSA_PKCS1_SHA1 => 0x0201,
        ECDSA_SHA1_Legacy => 0x0203,
        RSA_PKCS1_SHA256 => 0x0401,
        ECDSA_NISTP256_SHA256 => 0x0403,
        RSA_PKCS1_SHA384 => 0x0501,
        ECDSA_NISTP384_SHA384 => 0x0503,
        RSA_PKCS1_SHA512 => 0x0601,
        ECDSA_NISTP521_SHA512 => 0x0603,
        RSA_PSS_SHA256 => 0x0804,
        RSA_PSS_SHA384 => 0x0805,
        RSA_PSS_SHA512 => 0x0806,
        ED25519 => 0x0807,
        ED448 => 0x0808,
        RSA_PSS_PSS_SHA256 => 0x0809,
        RSA_PSS_PSS_SHA384 => 0x080a,
        RSA_PSS_PSS_SHA512 => 0x080b,
        ML_DSA_44 => 0x0904,
        ML_DSA_65 => 0x0905,
        ML_DSA_87 => 0x0906,
    }
}

impl SignatureScheme {
    /// The signature algorithm family of this scheme, if known.
    pub(crate) fn algorithm(&self) -> Option<SignatureAlgorithm> {
        match *self {
            Self::RSA_PKCS1_SHA1
            | Self::RSA_PKCS1_SHA256
            | Self::RSA_PKCS1_SHA384
            | Self::RSA_PKCS1_SHA512
            | Self::RSA_PSS_SHA256
            | Self::RSA_PSS_SHA384
            | Self::RSA_PSS_SHA512
            | Self::RSA_PSS_PSS_SHA256
            | Self::RSA_PSS_PSS_SHA384
            | Self::RSA_PSS_PSS_SHA512 => Some(SignatureAlgorithm::RSA),
            Self::ECDSA_SHA1_Legacy
            | Self::ECDSA_NISTP256_SHA256
            | Self::ECDSA_NISTP384_SHA384
            | Self::ECDSA_NISTP521_SHA512 => Some(SignatureAlgorithm::ECDSA),
            Self::ED25519 => Some(SignatureAlgorithm::ED25519),
            Self::ED448 => Some(SignatureAlgorithm::ED448),
            _ => None,
        }
    }

    /// Whether this scheme may be used for TLS 1.3 handshake signatures
    /// (RFC 8446 §4.2.3: no SHA-1, no RSASSA-PKCS1-v1_5, no DSA).
    pub(crate) fn supported_in_tls13(&self) -> bool {
        let [hash, sign] = self.to_array();
        match HashAlgorithm::from(hash) {
            HashAlgorithm::NONE
            | HashAlgorithm::MD5
            | HashAlgorithm::SHA1
            | HashAlgorithm::SHA224 => {
                return false;
            }
            _ => {}
        }
        !matches!(
            SignatureAlgorithm::from(sign),
            SignatureAlgorithm::Anonymous | SignatureAlgorithm::RSA | SignatureAlgorithm::DSA
        )
    }
}

enum_builder! {
    /// The `SignatureAlgorithm` TLS protocol enum (RFC 5246 §7.4.1.4.1).
    #[repr(u8)]
    pub enum SignatureAlgorithm {
        Anonymous => 0x00,
        RSA => 0x01,
        DSA => 0x02,
        ECDSA => 0x03,
        ED25519 => 0x07,
        ED448 => 0x08,
    }
}

enum_builder! {
    /// Certificate compression algorithms (RFC 8879 §3).
    #[repr(u16)]
    pub enum CertificateCompressionAlgorithm {
        Zlib => 1,
        Brotli => 2,
        Zstd => 3,
    }
}

enum_builder! {
    /// The `CertificateType` TLS protocol enum (RFC 7250 §4).
    #[repr(u8)]
    #[derive(Default)]
    pub enum CertificateType {
        #[default]
        X509 => 0x00,
        RawPublicKey => 0x02,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::enums::tests::{test_enum8, test_enum16};

    #[test]
    fn roundtrips() {
        test_enum8::<AlertDescription>(
            AlertDescription::CloseNotify,
            AlertDescription::EncryptedClientHelloRequired,
        );
        test_enum8::<HandshakeType>(HandshakeType::HelloRequest, HandshakeType::MessageHash);
        test_enum8::<ContentType>(ContentType::ChangeCipherSpec, ContentType::Heartbeat);
        test_enum16::<ProtocolVersion>(ProtocolVersion::SSLv2, ProtocolVersion::TLSv1_3);
        test_enum16::<SignatureScheme>(SignatureScheme::RSA_PKCS1_SHA1, SignatureScheme::ML_DSA_87);
        test_enum8::<SignatureAlgorithm>(SignatureAlgorithm::Anonymous, SignatureAlgorithm::ED448);
        test_enum16::<CertificateCompressionAlgorithm>(
            CertificateCompressionAlgorithm::Zlib,
            CertificateCompressionAlgorithm::Zstd,
        );
        test_enum8::<CertificateType>(CertificateType::X509, CertificateType::RawPublicKey);
    }

    #[test]
    fn tls13_signature_restrictions() {
        assert!(!SignatureScheme::RSA_PKCS1_SHA1.supported_in_tls13());
        assert!(!SignatureScheme::RSA_PKCS1_SHA256.supported_in_tls13());
        assert!(!SignatureScheme::ECDSA_SHA1_Legacy.supported_in_tls13());
        assert!(SignatureScheme::ECDSA_NISTP256_SHA256.supported_in_tls13());
        assert!(SignatureScheme::ED25519.supported_in_tls13());
        assert!(SignatureScheme::RSA_PSS_SHA256.supported_in_tls13());
        // RFC 9846 §4.3.3: RSASSA-PSS with an RSASSA-PSS public key.
        for scheme in [
            SignatureScheme::RSA_PSS_PSS_SHA256,
            SignatureScheme::RSA_PSS_PSS_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA512,
        ] {
            assert!(scheme.supported_in_tls13());
            assert_eq!(scheme.algorithm(), Some(SignatureAlgorithm::RSA));
        }
        assert_eq!(u16::from(SignatureScheme::RSA_PSS_PSS_SHA256), 0x0809);
        assert_eq!(u16::from(SignatureScheme::RSA_PSS_PSS_SHA384), 0x080a);
        assert_eq!(u16::from(SignatureScheme::RSA_PSS_PSS_SHA512), 0x080b);
        assert!(SignatureScheme::from(0x081a).supported_in_tls13());
    }

    #[test]
    fn debug_of_unknown_values() {
        assert_eq!(
            alloc::format!("{:?}", CipherSuite::from(0x1234)),
            "CipherSuite(0x1234)"
        );
        assert_eq!(
            alloc::format!("{:?}", CipherSuite::TLS13_AES_128_GCM_SHA256),
            "TLS13_AES_128_GCM_SHA256"
        );
    }
}

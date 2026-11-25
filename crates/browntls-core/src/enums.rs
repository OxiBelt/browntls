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
        /// RFC 9147 §9: too many connection IDs were requested (DTLS).
        TooManyCidsRequested => 0x34,
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
        /// RFC 9147 §9 (DTLS 1.3).
        RequestConnectionId => 0x09,
        /// RFC 9147 §9 (DTLS 1.3).
        NewConnectionId => 0x0a,
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
        /// RFC 9146: a DTLS 1.2 record that carries a connection ID.
        Tls12Cid => 0x19,
        /// RFC 9147 §7: the DTLS 1.3 ACK message.
        Ack => 0x1a,
        /// RFC 9853: the DTLS return routability check.
        ReturnRoutabilityCheck => 0x1b,
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
    /// The `CipherSuite` TLS protocol enum (the subset this library knows by
    /// name).
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
    /// recommended, i.e. AES-128-CCM and AES-128-CCM-8, and the TLS 1.2
    /// ECDHE AES-CBC suites. A server ranks them after every other mutually
    /// supported suite, whatever the client's order.
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
        RSA_PKCS1_SHA256_LEGACY => 0x0420,
        RSA_PKCS1_SHA384 => 0x0501,
        ECDSA_NISTP384_SHA384 => 0x0503,
        RSA_PKCS1_SHA384_LEGACY => 0x0520,
        RSA_PKCS1_SHA512 => 0x0601,
        ECDSA_NISTP521_SHA512 => 0x0603,
        RSA_PKCS1_SHA512_LEGACY => 0x0620,
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
    ///
    /// The RFC 9963 legacy schemes are not among them: they are RSASSA-
    /// PKCS1-v1_5, which TLS 1.3 allows in one message alone. See
    /// [`Self::is_rsa_pkcs1_legacy`] and
    /// [`Self::supported_in_tls13_client_auth`].
    pub(crate) fn supported_in_tls13(&self) -> bool {
        if self.is_rsa_pkcs1_legacy() {
            return false;
        }
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

    /// Whether this is an ML-DSA scheme (`draft-ietf-tls-mldsa-06`), which
    /// that draft specifies for TLS 1.3 `CertificateVerify` and for
    /// certificate signatures only. So:
    ///
    /// - A TLS 1.2 handshake never offers one in a CertificateRequest, signs
    ///   with one or accepts one, whatever the provider's algorithms and the
    ///   keys can do. A ClientHello that offers TLS 1.3 keeps them in the
    ///   single `signature_algorithms` list, which serves both versions
    ///   (RFC 9846 §4.3.3).
    /// - Delegated credentials (RFC 9345) and exported authenticators
    ///   (RFC 9261) do not use them: no specification says how, and such a
    ///   combination is not enabled by assumption.
    ///
    /// The code point decides, so that `Unknown(0x0904)`, which an
    /// application can construct, is treated like `ML_DSA_44`.
    pub(crate) fn is_ml_dsa(&self) -> bool {
        matches!(u16::from(*self), 0x0904..=0x0906)
    }

    /// Whether this is one of the legacy RSASSA-PKCS1-v1_5 schemes of
    /// RFC 9963 (`rsa_pkcs1_sha256_legacy`, `rsa_pkcs1_sha384_legacy`,
    /// `rsa_pkcs1_sha512_legacy`; 0x0420, 0x0520, 0x0620), which exist for
    /// clients whose RSA key cannot make RSASSA-PSS signatures (some
    /// hardware tokens). RFC 9963 §3 defines them for the signature in the
    /// client's TLS 1.3 `CertificateVerify` and for nothing else. So:
    ///
    /// - A ClientHello never lists one in `signature_algorithms`, a server
    ///   never signs with one and a client never accepts one in the
    ///   server's `CertificateVerify`, whatever the provider's algorithms,
    ///   the verifier and the keys can do.
    /// - A server accepts one in the client's `CertificateVerify` only
    ///   when its CertificateRequest listed it, and a client signs with
    ///   one only then.
    /// - TLS 1.2 handshakes, delegated credentials (RFC 9345) and exported
    ///   authenticators (RFC 9261) never use them.
    ///
    /// The code point decides, so that `Unknown(0x0420)`, which an
    /// application can construct, is refused wherever
    /// `RSA_PKCS1_SHA256_LEGACY` is. It is not accepted where the named
    /// scheme is: offers and signers are compared by value, so a verifier
    /// or a key has to name the schemes by their constants.
    pub(crate) fn is_rsa_pkcs1_legacy(&self) -> bool {
        matches!(u16::from(*self), 0x0420 | 0x0520 | 0x0620)
    }

    /// Whether this scheme may sign a client's TLS 1.3 `CertificateVerify`
    /// in the handshake or in post-handshake authentication: the TLS 1.3
    /// schemes and the RFC 9963 legacy ones.
    pub(crate) fn supported_in_tls13_client_auth(&self) -> bool {
        self.supported_in_tls13() || self.is_rsa_pkcs1_legacy()
    }

    /// Whether this scheme is specified for TLS 1.3 only, so that no
    /// TLS 1.2 message may carry it: the ML-DSA schemes and the RFC 9963
    /// legacy ones.
    pub(crate) fn is_tls13_only(&self) -> bool {
        self.is_ml_dsa() || self.is_rsa_pkcs1_legacy()
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
        test_enum8::<ContentType>(
            ContentType::ChangeCipherSpec,
            ContentType::ReturnRoutabilityCheck,
        );
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

    /// RFC 9963: the legacy schemes are TLS 1.3 schemes for the client's
    /// `CertificateVerify` only, by code point.
    #[test]
    fn rsa_pkcs1_legacy_schemes() {
        for (scheme, code) in [
            (SignatureScheme::RSA_PKCS1_SHA256_LEGACY, 0x0420),
            (SignatureScheme::RSA_PKCS1_SHA384_LEGACY, 0x0520),
            (SignatureScheme::RSA_PKCS1_SHA512_LEGACY, 0x0620),
        ] {
            assert_eq!(u16::from(scheme), code);
            assert_eq!(SignatureScheme::from(code), scheme);
            for scheme in [scheme, SignatureScheme::Unknown(code)] {
                assert!(scheme.is_rsa_pkcs1_legacy());
                assert!(!scheme.supported_in_tls13());
                assert!(scheme.supported_in_tls13_client_auth());
                assert!(scheme.is_tls13_only() && !scheme.is_ml_dsa());
                // Not an RSA scheme of TLS 1.2 suite selection.
                assert_eq!(scheme.algorithm(), None);
            }
        }
        for code in [0x0401, 0x041f, 0x0421, 0x0320, 0x0720, 0x0804, 0x0904] {
            let scheme = SignatureScheme::from(code);
            assert!(!scheme.is_rsa_pkcs1_legacy(), "{code:#06x}");
            assert_eq!(
                scheme.supported_in_tls13_client_auth(),
                scheme.supported_in_tls13(),
                "{code:#06x}"
            );
        }
        assert!(!SignatureScheme::RSA_PKCS1_SHA256.is_tls13_only());
        assert!(SignatureScheme::ML_DSA_65.is_tls13_only());
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

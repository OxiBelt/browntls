//! Tests for the session values in the parent module.

use browntls_pki::CertificateDer;

use super::*;

fn sample() -> ServerSessionValue {
    let mut v = ServerSessionValue::new(
        Some(&DnsName::try_from("example.com").unwrap()),
        ProtocolVersion::TLSv1_3,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        &[1, 2, 3],
        Some(CertificateChain(alloc::vec![
            CertificateDer::from_slice(&[9]).into_owned()
        ])),
        Some(alloc::vec![b'h', b'2']),
        alloc::vec![7, 7],
        UnixTime::since_unix_epoch(core::time::Duration::from_secs(1000)),
        0x1234,
    );
    v.set_extended_ms_used();
    v
}

#[test]
fn server_value_roundtrip() {
    let v = sample();
    let enc = v.get_encoding();
    let back = ServerSessionValue::read_bytes(&enc).unwrap();
    assert_eq!(back.sni, v.sni);
    assert_eq!(back.version, v.version);
    assert_eq!(back.cipher_suite, v.cipher_suite);
    assert_eq!(back.master_secret, v.master_secret);
    assert!(back.extended_ms);
    assert_eq!(back.client_cert_chain, v.client_cert_chain);
    assert_eq!(back.alpn, v.alpn);
    assert_eq!(back.application_data, v.application_data);
    assert_eq!(back.creation_time_sec, 1000);
    assert_eq!(back.age_obfuscation_offset, 0x1234);
    assert!(!back.is_fresh());
    assert!(ServerSessionValue::read_bytes(&enc[..enc.len() - 1]).is_err());
    assert!(alloc::format!("{back:?}").contains("example.com"));
    assert_eq!(back.external_psk, None);
    assert_eq!(back.delegated_credential_expiry, None);
}

#[test]
fn server_value_delegated_credential_expiry_roundtrip() {
    let mut v = sample();
    let expiry = UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_234));
    v.set_delegated_credential_expiry(Some(expiry));
    let enc = v.get_encoding();
    let back = ServerSessionValue::read_bytes(&enc).unwrap();
    assert_eq!(back.delegated_credential_expiry, Some(expiry));

    let mut invalid_tag = sample().get_encoding();
    *invalid_tag.last_mut().unwrap() = 4;
    assert!(ServerSessionValue::read_bytes(&invalid_tag).is_err());

    let mut legacy = sample().get_encoding();
    assert_eq!(legacy.pop(), Some(0));
    assert!(ServerSessionValue::read_bytes(&legacy).is_err());

    let mut tls12 = sample();
    tls12.version = ProtocolVersion::TLSv1_2;
    tls12.set_delegated_credential_expiry(Some(expiry));
    assert!(ServerSessionValue::read_bytes(&tls12.get_encoding()).is_err());
}

#[test]
fn server_value_client_delegated_credential_expiry_roundtrip() {
    let server = UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_234));
    let client = UnixTime::since_unix_epoch(core::time::Duration::from_secs(5_678));
    for (server, client) in [(None, Some(client)), (Some(server), Some(client))] {
        let mut v = sample();
        v.set_delegated_credential_expiry(server);
        v.client_delegated_credential_expiry = client;
        let enc = v.get_encoding();
        let back = ServerSessionValue::read_bytes(&enc).unwrap();
        assert_eq!(back.delegated_credential_expiry, server);
        assert_eq!(back.client_delegated_credential_expiry, client);
        assert!(alloc::format!("{back:?}").contains("client_delegated_credential_expiry"));
        // Every deadline the tag announces must follow.
        assert!(ServerSessionValue::read_bytes(&enc[..enc.len() - 1]).is_err());
    }

    // A client credential authenticates a certificate chain, in TLS 1.3.
    let mut no_chain = sample();
    no_chain.client_cert_chain = None;
    no_chain.client_delegated_credential_expiry = Some(client);
    assert!(ServerSessionValue::read_bytes(&no_chain.get_encoding()).is_err());
    let mut tls12 = sample();
    tls12.version = ProtocolVersion::TLSv1_2;
    tls12.client_delegated_credential_expiry = Some(client);
    assert!(ServerSessionValue::read_bytes(&tls12.get_encoding()).is_err());
}

#[test]
fn server_value_external_psk_roundtrip() {
    for import_context in [None, Some(Vec::new()), Some(alloc::vec![5, 6])] {
        let mut v = sample();
        let binding = ExternalPskBinding {
            identity: b"psk".to_vec(),
            import_context,
            key_tag: alloc::vec![0x55; 32],
        };
        v.set_external_psk(Some(binding.clone()));
        let enc = v.get_encoding();
        let back = ServerSessionValue::read_bytes(&enc).unwrap();
        assert_eq!(back.external_psk, Some(binding));
        assert!(ServerSessionValue::read_bytes(&enc[..enc.len() - 1]).is_err());
    }
    let mut enc = sample().get_encoding();
    *enc.last_mut().unwrap() = 3;
    assert!(ServerSessionValue::read_bytes(&enc).is_err());

    // Identity-only records from before key binding are unsafe to resume.
    for (import_context, current_tag, legacy_tag) in [(None, 3, 1), (Some(b"ctx".to_vec()), 4, 2)] {
        let mut v = sample();
        v.set_external_psk(Some(ExternalPskBinding {
            identity: b"legacy".to_vec(),
            import_context,
            key_tag: alloc::vec![0x55; 32],
        }));
        let mut enc = v.get_encoding();
        let marker = [current_tag, 0, 6, b'l', b'e', b'g', b'a', b'c', b'y'];
        let at = enc
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap();
        enc[at] = legacy_tag;
        assert!(ServerSessionValue::read_bytes(&enc).is_err());
    }

    for len in [31, 49] {
        let mut v = sample();
        v.set_external_psk(Some(ExternalPskBinding {
            identity: b"psk".to_vec(),
            import_context: None,
            key_tag: alloc::vec![0x55; len],
        }));
        assert!(ServerSessionValue::read_bytes(&v.get_encoding()).is_err());
    }
}

/// A DTLS ticket is told apart from a TLS one by its version, and is read
/// back with the TLS 1.3 checks.
#[test]
fn server_value_dtls_version_roundtrip() {
    let expiry = UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_234));
    let mut v = sample();
    v.version = ProtocolVersion::DTLSv1_3;
    v.set_delegated_credential_expiry(Some(expiry));
    let back = ServerSessionValue::read_bytes(&v.get_encoding()).unwrap();
    assert_eq!(back.version, ProtocolVersion::DTLSv1_3);
    assert_eq!(back.delegated_credential_expiry, Some(expiry));

    let tls = ServerSessionValue::read_bytes(&sample().get_encoding()).unwrap();
    assert_eq!(tls.version, ProtocolVersion::TLSv1_3);
    assert_ne!(tls.version, back.version);
}

#[test]
fn client_value_protocol() {
    let v = tls13_client_value(1);
    assert_eq!(v.protocol(), Protocol::Tls13);
    let v = v.with_protocol(Protocol::Dtls13);
    assert_eq!(v.protocol(), Protocol::Dtls13);
    assert!(alloc::format!("{v:?}").contains("Dtls13"));
}

#[test]
fn freshness() {
    let v = sample();
    let now = UnixTime::since_unix_epoch(core::time::Duration::from_secs(1010));
    // client says 10 000 ms old, obfuscated by the offset
    let fresh = v.set_freshness(10_000u32.wrapping_add(0x1234), now);
    assert!(fresh.is_fresh());
    let v = sample();
    let stale = v.set_freshness(500_000u32.wrapping_add(0x1234), now);
    assert!(!stale.is_fresh());
}

#[derive(Debug)]
struct DummyVerifier;
impl ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<crate::verify::ServerCertVerified, crate::Error> {
        Err(crate::Error::General("dummy".into()))
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &crate::verify::DigitallySignedStruct,
    ) -> Result<crate::verify::HandshakeSignatureValid, crate::Error> {
        Err(crate::Error::General("dummy".into()))
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &crate::verify::DigitallySignedStruct,
    ) -> Result<crate::verify::HandshakeSignatureValid, crate::Error> {
        Err(crate::Error::General("dummy".into()))
    }
    fn supported_verify_schemes(&self) -> Vec<crate::enums::SignatureScheme> {
        Vec::new()
    }
}

#[derive(Debug)]
struct DummyResolver;
impl ResolvesClientCert for DummyResolver {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[crate::enums::SignatureScheme],
    ) -> Option<Arc<crate::crypto::signer::CertifiedKey>> {
        None
    }
    fn has_certs(&self) -> bool {
        false
    }
}

fn binding_objects() -> (Arc<dyn ServerCertVerifier>, Arc<dyn ResolvesClientCert>) {
    (Arc::new(DummyVerifier), Arc::new(DummyResolver))
}

#[test]
fn client_value_config_binding() {
    let (verifier, creds) = binding_objects();
    let (other_verifier, other_creds) = binding_objects();
    let binding = ClientConfigBinding {
        server_cert_verifier: &verifier,
        client_creds: &creds,
    };
    let now = UnixTime::since_unix_epoch(core::time::Duration::from_secs(100));
    let common = ClientSessionCommon::new(
        alloc::vec![1],
        &[2],
        now,
        60,
        Arc::new(CertificateChain::default()),
        &binding,
    );
    // The same objects, also through cloned `Arc`s, are compatible.
    let (verifier2, creds2) = (verifier.clone(), creds.clone());
    assert!(common.compatible_config(&ClientConfigBinding {
        server_cert_verifier: &verifier2,
        client_creds: &creds2,
    }));
    assert!(common.clone().compatible_config(&binding));
    // Another verifier or another resolver, even of the same type, is not.
    assert!(!common.compatible_config(&ClientConfigBinding {
        server_cert_verifier: &other_verifier,
        client_creds: &creds,
    }));
    assert!(!common.compatible_config(&ClientConfigBinding {
        server_cert_verifier: &verifier,
        client_creds: &other_creds,
    }));
    // The session does not keep the verifier alive, and a verifier
    // allocated after it was dropped never matches.
    drop((verifier, verifier2));
    let (fresh_verifier, _) = binding_objects();
    assert!(!common.compatible_config(&ClientConfigBinding {
        server_cert_verifier: &fresh_verifier,
        client_creds: &creds,
    }));
}

#[test]
fn client_value_age() {
    let chain = Arc::new(CertificateChain::default());
    let suite = Tls13CipherSuite {
        common: crate::suites::CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &DummyHash,
            confidentiality_limit: 1,
        },
        hkdf_provider: &DummyHkdf,
        aead_alg: &DummyAead,
        quic: None,
    };
    let suite: &'static Tls13CipherSuite = alloc::boxed::Box::leak(alloc::boxed::Box::new(suite));
    let created = UnixTime::since_unix_epoch(core::time::Duration::from_secs(100));
    let expiry = UnixTime::since_unix_epoch(core::time::Duration::from_secs(200));
    let (verifier, creds) = binding_objects();
    let binding = ClientConfigBinding {
        server_cert_verifier: &verifier,
        client_creds: &creds,
    };
    let mut v = Tls13ClientSessionValue::new(
        suite,
        alloc::vec![1],
        &[2],
        chain,
        &binding,
        created,
        60,
        5,
        0,
    )
    .with_delegated_credential_expiry(Some(expiry));
    assert_eq!(v.max_early_data_size(), 0);
    assert!(!v.delegated_credential_expired_at(created));
    let later = UnixTime::since_unix_epoch(core::time::Duration::from_secs(130));
    let r = Retrieved::new(&v, later);
    assert_eq!(r.obfuscated_ticket_age(), 30_000 + 5);
    v.rewind_epoch(10);
    assert_eq!(v.delegated_credential_expiry(), Some(expiry));
    assert!(v.delegated_credential_expired_at(expiry));
    let r2 = Retrieved::new(v, later);
    assert!(!r2.has_expired());
    let much_later = UnixTime::since_unix_epoch(core::time::Duration::from_secs(1000));
    let r3 = Retrieved::new(r2.value, much_later);
    assert!(r3.has_expired());
}

/// A TLS 1.3 client ticket whose ticket bytes are `[ticket]`, for tests
/// that only look at its identity.
pub(crate) fn tls13_client_value(ticket: u8) -> Tls13ClientSessionValue {
    let suite = Tls13CipherSuite {
        common: crate::suites::CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &DummyHash,
            confidentiality_limit: 1,
        },
        hkdf_provider: &DummyHkdf,
        aead_alg: &DummyAead,
        quic: None,
    };
    let suite: &'static Tls13CipherSuite = alloc::boxed::Box::leak(alloc::boxed::Box::new(suite));
    let (verifier, creds) = binding_objects();
    let binding = ClientConfigBinding {
        server_cert_verifier: &verifier,
        client_creds: &creds,
    };
    Tls13ClientSessionValue::new(
        suite,
        alloc::vec![ticket],
        &[2],
        Arc::new(CertificateChain::default()),
        &binding,
        UnixTime::since_unix_epoch(core::time::Duration::from_secs(100)),
        60,
        0,
        0,
    )
}

struct DummyHash;
impl crate::crypto::hash::Hash for DummyHash {
    fn start(&self) -> alloc::boxed::Box<dyn crate::crypto::hash::Context> {
        unimplemented!()
    }
    fn hash(&self, _: &[u8]) -> crate::crypto::hash::Output {
        unimplemented!()
    }
    fn output_len(&self) -> usize {
        32
    }
    fn algorithm(&self) -> crate::crypto::hash::HashAlgorithm {
        crate::crypto::hash::HashAlgorithm::SHA256
    }
}
struct DummyHkdf;
impl crate::crypto::tls13::Hkdf for DummyHkdf {
    fn extract_from_zero_ikm(
        &self,
        _: Option<&[u8]>,
    ) -> alloc::boxed::Box<dyn crate::crypto::tls13::HkdfExpander> {
        unimplemented!()
    }
    fn extract_from_secret(
        &self,
        _: Option<&[u8]>,
        _: &[u8],
    ) -> alloc::boxed::Box<dyn crate::crypto::tls13::HkdfExpander> {
        unimplemented!()
    }
    fn expander_for_okm(
        &self,
        _: &crate::crypto::tls13::OkmBlock,
    ) -> alloc::boxed::Box<dyn crate::crypto::tls13::HkdfExpander> {
        unimplemented!()
    }
    fn hmac_sign(&self, _: &crate::crypto::tls13::OkmBlock, _: &[u8]) -> crate::crypto::hmac::Tag {
        unimplemented!()
    }
}
struct DummyAead;
impl crate::crypto::cipher::Tls13AeadAlgorithm for DummyAead {
    fn encrypter(
        &self,
        _: crate::crypto::cipher::AeadKey,
        _: crate::crypto::cipher::Iv,
    ) -> alloc::boxed::Box<dyn crate::crypto::cipher::MessageEncrypter> {
        unimplemented!()
    }
    fn decrypter(
        &self,
        _: crate::crypto::cipher::AeadKey,
        _: crate::crypto::cipher::Iv,
    ) -> alloc::boxed::Box<dyn crate::crypto::cipher::MessageDecrypter> {
        unimplemented!()
    }
    fn key_len(&self) -> usize {
        16
    }
    fn extract_keys(
        &self,
        _: crate::crypto::cipher::AeadKey,
        _: crate::crypto::cipher::Iv,
    ) -> Result<
        crate::suites::ConnectionTrafficSecrets,
        crate::crypto::cipher::UnsupportedOperationError,
    > {
        Err(crate::crypto::cipher::UnsupportedOperationError)
    }
}

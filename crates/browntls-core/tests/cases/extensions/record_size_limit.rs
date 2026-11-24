use std::sync::OnceLock;

use browntls_core::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use browntls_core::{
    AlertDescription, CipherSuiteCommon, ConnectionTrafficSecrets, ContentType,
    SupportedCipherSuite, Tls13CipherSuite,
};

use super::*;

struct ReportFirstRecordLength(&'static dyn Tls13AeadAlgorithm);

impl Tls13AeadAlgorithm for ReportFirstRecordLength {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(FirstRecordLength {
            inner: self.0.decrypter(key, iv),
            first: true,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        self.0.extract_keys(key, iv)
    }
}

struct FirstRecordLength {
    inner: Box<dyn MessageDecrypter>,
    first: bool,
}

impl MessageDecrypter for FirstRecordLength {
    fn decrypt<'a>(
        &mut self,
        msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let plain = self.inner.decrypt(msg, seq)?;
        if std::mem::take(&mut self.first)
            && plain.typ == ContentType::Handshake
            && plain.payload.first() == Some(&8)
        {
            // Exercise the handshake's accounting with the length a
            // provider would report for this record with additional
            // authenticated padding. Keep the wire exchange unchanged.
            assert!(plain.record_plaintext_len() <= 64);
            Ok(InboundPlainMessage::with_record_plaintext_len(
                plain.typ,
                plain.version,
                plain.payload,
                65,
            ))
        } else {
            Ok(plain)
        }
    }
}

fn suite() -> &'static Tls13CipherSuite {
    static AEAD: OnceLock<ReportFirstRecordLength> = OnceLock::new();
    static SUITE: OnceLock<Tls13CipherSuite> = OnceLock::new();
    SUITE.get_or_init(|| {
        let orig = prov::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap();
        Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: orig.common.suite,
                hash_provider: orig.common.hash_provider,
                confidentiality_limit: orig.common.confidentiality_limit,
            },
            hkdf_provider: orig.hkdf_provider,
            aead_alg: AEAD.get_or_init(|| ReportFirstRecordLength(orig.aead_alg)),
            quic: None,
        }
    })
}

#[test]
fn record_size_limit_checks_the_record_carrying_encrypted_extensions() {
    let chain = server_chain(KeyType::EcdsaP256);
    for limit in [Some(64), None] {
        let mut provider = prov::default_provider();
        provider.cipher_suites = vec![SupportedCipherSuite::Tls13(suite())];
        let mut client = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        client.record_size_limit = Some(64);
        let mut server = server_with(&chain, &[&version::TLS13]);
        server.record_size_limit = limit;
        let (mut client, mut server) = connect(client, server);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        transfer(&mut server, &mut client);
        if limit.is_some() {
            assert_eq!(
                client.process_new_packets().err(),
                Some(Error::PeerSentOversizedRecord)
            );
            transfer(&mut client, &mut server);
            assert_eq!(
                server.process_new_packets().err(),
                Some(Error::AlertReceived(AlertDescription::RecordOverflow)),
            );
        } else {
            client.process_new_packets().unwrap();
            do_handshake(&mut client, &mut server).unwrap();
        }
    }
}

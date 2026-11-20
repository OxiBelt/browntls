// TLS 1.3 Certificate messages edited in flight: `transparency_info` on a
// server's entry the ClientHello did not ask for, and on a client's entry
// (RFC 9162 defines none for client certificates). The handshake runs with
// the identity in place of TLS 1.3 record protection, so the encrypted
// flight can be edited; CertificateVerify still covers the real transcript,
// which an edit breaks, so only checks made on the Certificate itself can
// produce the errors expected here. Included by `cases/transparency.rs`.

mod plain {
    use browntls_core::crypto::cipher::{
        AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
        OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
        UnsupportedOperationError,
    };
    use browntls_core::crypto::{CipherSuiteCommon, CryptoProvider};
    use browntls_core::{
        ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion, SupportedCipherSuite,
        Tls13CipherSuite,
    };

    /// "Ciphertext" that is the inner plaintext: content, then type.
    struct PlainAead;

    struct Plain;

    impl Tls13AeadAlgorithm for PlainAead {
        fn encrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageEncrypter> {
            Box::new(Plain)
        }

        fn decrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageDecrypter> {
            Box::new(Plain)
        }

        fn key_len(&self) -> usize {
            16
        }

        fn extract_keys(
            &self,
            _key: AeadKey,
            _iv: Iv,
        ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
            Err(UnsupportedOperationError)
        }
    }

    impl MessageEncrypter for Plain {
        fn encrypt(
            &mut self,
            msg: OutboundPlainMessage<'_>,
            _seq: u64,
        ) -> Result<OutboundOpaqueMessage, Error> {
            let mut payload = PrefixedPayload::with_capacity(msg.payload.len() + 1);
            payload.extend_from_chunks(&msg.payload);
            payload.extend_from_slice(&[u8::from(msg.typ)]);
            Ok(OutboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload,
            ))
        }

        fn encrypted_payload_len(&self, payload_len: usize) -> usize {
            payload_len + 1
        }
    }

    impl MessageDecrypter for Plain {
        fn decrypt<'a>(
            &mut self,
            msg: InboundOpaqueMessage<'a>,
            _seq: u64,
        ) -> Result<InboundPlainMessage<'a>, Error> {
            msg.into_tls13_unpadded_message()
        }
    }

    /// `provider` with every TLS 1.3 suite's record protection replaced.
    pub(super) fn plain(mut provider: CryptoProvider) -> CryptoProvider {
        for suite in &mut provider.cipher_suites {
            if let SupportedCipherSuite::Tls13(real) = *suite {
                let fake: &'static Tls13CipherSuite = Box::leak(Box::new(Tls13CipherSuite {
                    common: CipherSuiteCommon {
                        suite: real.common.suite,
                        hash_provider: real.common.hash_provider,
                        confidentiality_limit: real.common.confidentiality_limit,
                    },
                    hkdf_provider: real.hkdf_provider,
                    aead_alg: &PlainAead,
                    quic: None,
                }));
                *suite = SupportedCipherSuite::Tls13(fake);
            }
        }
        provider
    }
}

fn plain_provider() -> Arc<browntls_core::crypto::CryptoProvider> {
    Arc::new(plain::plain(prov::default_provider()))
}

/// `flight` with `ext` added to the extensions of the first entry of the
/// TLS 1.3 Certificate message in its (identity-protected) records.
fn add_to_certificate(flight: &[u8], ext: &[u8]) -> Vec<u8> {
    let be16 = |b: &[u8]| usize::from(u16::from_be_bytes([b[0], b[1]]));
    let be24 = |b: &[u8]| usize::from(b[0]) << 16 | be16(&b[1..]);
    let put24 = |n: usize| u32::try_from(n).unwrap().to_be_bytes()[1..].to_vec();
    let mut out = Vec::new();
    let mut found = false;
    let mut at = 0;
    while at < flight.len() {
        let len = be16(&flight[at + 3..]);
        let record = &flight[at + 5..at + 5 + len];
        let mut inner = record.to_vec();
        if flight[at] == 23 && !found && record.last() == Some(&22) {
            let mut msgs = Vec::new();
            let body = &record[..record.len() - 1];
            let mut m = 0;
            while m < body.len() {
                let msg_len = be24(&body[m + 1..]);
                let msg = &body[m + 4..m + 4 + msg_len];
                if body[m] == 11 && !found {
                    found = true;
                    // context, certificate_list, then the first entry's
                    // cert_data and extensions.
                    let list_at = 1 + usize::from(msg[0]);
                    let exts_at = list_at + 3 + 3 + be24(&msg[list_at + 3..]);
                    let mut new = msg[..list_at].to_vec();
                    new.extend(put24(be24(&msg[list_at..]) + ext.len()));
                    new.extend_from_slice(&msg[list_at + 3..exts_at]);
                    let exts_len = u16::try_from(be16(&msg[exts_at..]) + ext.len()).unwrap();
                    new.extend(exts_len.to_be_bytes());
                    new.extend_from_slice(ext);
                    new.extend_from_slice(&msg[exts_at + 2..]);
                    msgs.push(11);
                    msgs.extend(put24(new.len()));
                    msgs.extend(new);
                } else {
                    msgs.extend_from_slice(&body[m..m + 4 + msg_len]);
                }
                m += 4 + msg_len;
            }
            msgs.push(22);
            inner = msgs;
        }
        out.extend_from_slice(&flight[at..at + 3]);
        out.extend(u16::try_from(inner.len()).unwrap().to_be_bytes());
        out.extend(inner);
        at += 5 + len;
    }
    assert!(found, "no Certificate message in the flight");
    out
}

/// A TLS 1.3 server for `chain` over the identity record protection,
/// configured with `list` but without certificate compression.
fn plain_server(chain: &Chain, list: Vec<u8>, client: Option<&Chain>) -> ServerConfig {
    let provider = plain_provider();
    let mut key =
        CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider).unwrap();
    key.set_transparency_info(Some(list)).unwrap();
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .unwrap();
    let builder = match client {
        Some(client) => builder.with_client_cert_verifier(PinnedClientVerifier::new(client, true)),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
    config.cert_compressors = Vec::new();
    config.cert_decompressors = Vec::new();
    config
}

/// A TLS 1.3 client over the identity record protection, offering
/// `transparency_info` or not, without certificate compression.
fn plain_client(pki: &CtPki, offer: bool, client: Option<&Chain>) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(plain_provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_webpki_verifier(verifier(pki, None));
    let mut config = match client {
        Some(chain) => builder
            .with_client_auth_cert(chain.cert_chain(), chain.private_key())
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.request_transparency_info = offer;
    config.cert_compressors = Vec::new();
    config.cert_decompressors = Vec::new();
    config
}

#[test]
fn tls13_unsolicited_certificate_entry_extension_is_refused() {
    let fx = Fixture::new();
    let items = list(&[fx.sct(&fx.log_a)]);
    let server = Arc::new(plain_server(&fx.chain, items.clone(), None));
    for offer in [false, true] {
        let client = Arc::new(plain_client(&fx.pki, offer, None));
        let mut c = ClientConnection::new(client, server_name()).unwrap();
        let mut s = ServerConnection::new(server.clone()).unwrap();
        deliver(&mut s, &take_tls(&mut c)).unwrap();
        let flight = take_tls(&mut s);
        if offer {
            // The server answered the offer itself; the edit adds a second
            // extension, which the codec refuses.
            assert!(matches!(
                deliver(&mut c, &add_to_certificate(&flight, &EMPTY_EXTENSION)),
                Err(Error::InvalidMessage(_))
            ));
            continue;
        }
        let forged = add_to_certificate(&flight, &EMPTY_EXTENSION);
        assert_eq!(
            deliver(&mut c, &forged),
            Err(Error::PeerMisbehaved(
                browntls_core::PeerMisbehaved::UnsolicitedTransparencyInfo
            ))
        );
        assert_eq!(
            deliver(&mut s, &take_tls(&mut c)),
            Err(Error::AlertReceived(AlertDescription::UnsupportedExtension))
        );
    }
}

#[test]
fn client_certificate_entry_extension_is_refused() {
    let fx = Fixture::new();
    let client_chain = client_chain(KeyType::EcdsaP256);
    let items = list(&[fx.sct(&fx.log_a)]);
    let server = Arc::new(plain_server(&fx.chain, items, Some(&client_chain)));
    let client = || Arc::new(plain_client(&fx.pki, true, Some(&client_chain)));

    // Unedited, the client authenticates.
    let (_c, s, cr, sr) = connect(&client(), &server);
    cr.unwrap();
    sr.unwrap();
    assert!(s.peer_certificates().is_some());

    // A new configuration, so that no ticket makes it a resumption.
    let mut c = ClientConnection::new(client(), server_name()).unwrap();
    let mut s = ServerConnection::new(server).unwrap();
    deliver(&mut s, &take_tls(&mut c)).unwrap();
    deliver(&mut c, &take_tls(&mut s)).unwrap();
    let forged = add_to_certificate(&take_tls(&mut c), &EMPTY_EXTENSION);
    assert_eq!(
        deliver(&mut s, &forged),
        Err(Error::PeerMisbehaved(
            browntls_core::PeerMisbehaved::UnsolicitedCertExtension
        ))
    );
    assert_eq!(
        deliver(&mut c, &take_tls(&mut s)),
        Err(Error::AlertReceived(AlertDescription::UnsupportedExtension))
    );
}

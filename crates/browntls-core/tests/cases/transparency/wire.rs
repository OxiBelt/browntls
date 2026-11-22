// The extension where it must not appear, malformed ClientHello bodies,
// and certificate compression. Included by `cases/transparency.rs`.

/// Every TLS byte `conn` has queued.
fn take_tls<D: browntls_core::SideData>(conn: &mut browntls_core::ConnectionCommon<D>) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).unwrap();
    }
    out
}

/// `flight` with `ext` added to the extensions of the hello message that
/// opens its first record: a ClientHello when `client_hello`, else a
/// ServerHello. Lengths are fixed up; the transcript is not.
fn add_hello_extension(flight: &[u8], client_hello: bool, ext: &[u8]) -> Vec<u8> {
    let be16 = |b: &[u8]| usize::from(u16::from_be_bytes([b[0], b[1]]));
    assert_eq!(flight[0], 22, "not a handshake record");
    let record_len = be16(&flight[3..5]);
    let record = &flight[5..5 + record_len];
    assert_eq!(record[0], if client_hello { 1 } else { 2 });
    let msg_len = usize::from(record[1]) << 16 | be16(&record[2..4]);
    let body = &record[4..4 + msg_len];
    // legacy_version, random, session ID.
    let mut at = 34 + 1 + usize::from(body[34]);
    if client_hello {
        at += 2 + be16(&body[at..]); // cipher suites
        at += 1 + usize::from(body[at]); // compression methods
    } else {
        at += 2 + 1; // cipher suite, compression method
    }
    let exts_len = be16(&body[at..]);
    let mut new_body = body[..at].to_vec();
    new_body.extend(u16::try_from(exts_len + ext.len()).unwrap().to_be_bytes());
    new_body.extend_from_slice(ext);
    new_body.extend_from_slice(&body[at + 2..]);
    let mut new_record = vec![record[0]];
    new_record.extend(&u32::try_from(new_body.len()).unwrap().to_be_bytes()[1..]);
    new_record.extend(new_body);
    new_record.extend_from_slice(&record[4 + msg_len..]);
    let mut out = flight[..3].to_vec();
    out.extend(u16::try_from(new_record.len()).unwrap().to_be_bytes());
    out.extend(new_record);
    out.extend_from_slice(&flight[5 + record_len..]);
    out
}

/// Feeds `bytes` to `conn` and processes them.
fn deliver<D: browntls_core::SideData>(
    conn: &mut browntls_core::ConnectionCommon<D>,
    bytes: &[u8],
) -> Result<(), Error> {
    let mut rd = bytes;
    while !rd.is_empty() {
        conn.read_tls(&mut rd).unwrap();
    }
    conn.process_new_packets().map(|_| ())
}

/// An empty `transparency_info` extension.
const EMPTY_EXTENSION: [u8; 4] = [0, 52, 0, 0];

#[test]
fn tls12_resumed_server_hello_with_the_extension_is_refused() {
    let fx = Fixture::new();
    let v = &version::TLS12;
    let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
    let server = server(&fx.chain, Some(list(&[fx.sct(&fx.log_a)])), None, v);
    let (_c, _s, cr, sr) = connect(&client, &server);
    cr.unwrap();
    sr.unwrap();

    let mut c = ClientConnection::new(client, server_name()).unwrap();
    let mut s = ServerConnection::new(server).unwrap();
    deliver(&mut s, &take_tls(&mut c)).unwrap();
    assert_eq!(s.handshake_kind(), Some(HandshakeKind::Resumed));
    let flight = add_hello_extension(&take_tls(&mut s), false, &EMPTY_EXTENSION);
    assert_eq!(
        deliver(&mut c, &flight),
        Err(Error::PeerMisbehaved(
            browntls_core::PeerMisbehaved::TransparencyInfoOnResumption
        ))
    );
    assert_eq!(
        deliver(&mut s, &take_tls(&mut c)),
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn tls12_unsolicited_server_hello_extension_is_refused() {
    let fx = Fixture::new();
    let v = &version::TLS12;
    let mut c = ClientConnection::new(fx.client(None, v), server_name()).unwrap();
    let mut s = ServerConnection::new(server(&fx.chain, None, None, v)).unwrap();
    deliver(&mut s, &take_tls(&mut c)).unwrap();
    let flight = add_hello_extension(&take_tls(&mut s), false, &EMPTY_EXTENSION);
    assert_eq!(
        deliver(&mut c, &flight),
        Err(Error::PeerMisbehaved(
            browntls_core::PeerMisbehaved::UnsolicitedServerHelloExtension
        ))
    );
    assert_eq!(
        deliver(&mut s, &take_tls(&mut c)),
        Err(Error::AlertReceived(AlertDescription::UnsupportedExtension))
    );
}

#[test]
fn client_hello_extension_must_be_empty() {
    let fx = Fixture::new();
    for v in VERSIONS {
        let mut c = ClientConnection::new(fx.client(None, v), server_name()).unwrap();
        let mut s = ServerConnection::new(server(&fx.chain, None, None, v)).unwrap();
        // RFC 9162 §6.5: non-empty `extension_data` is decode_error.
        let hello = add_hello_extension(&take_tls(&mut c), true, &[0, 52, 0, 1, 0]);
        assert!(matches!(
            deliver(&mut s, &hello),
            Err(Error::InvalidMessage(_))
        ));
        assert_eq!(
            deliver(&mut c, &take_tls(&mut s)),
            Err(Error::AlertReceived(AlertDescription::DecodeError))
        );
    }
}

/// A verifier whose answer to `requests_transparency_info` can change
/// between the ClientHello and the server's Certificate.
#[derive(Debug)]
struct Flipping {
    inner: Arc<WebPkiServerVerifier>,
    offer: std::sync::atomic::AtomicBool,
    forward_context: bool,
}

impl browntls_core::client::danger::ServerCertVerifier for Flipping {
    fn verify_server_cert(
        &self,
        end_entity: &browntls_core::pki_types::CertificateDer<'_>,
        intermediates: &[browntls_core::pki_types::CertificateDer<'_>],
        server_name: &browntls_core::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: browntls_core::pki_types::UnixTime,
    ) -> Result<browntls_core::client::danger::ServerCertVerified, Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &browntls_core::pki_types::CertificateDer<'_>,
        dss: &browntls_core::DigitallySignedStruct,
    ) -> Result<browntls_core::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_server_cert_with_context(
        &self,
        end_entity: &browntls_core::pki_types::CertificateDer<'_>,
        intermediates: &[browntls_core::pki_types::CertificateDer<'_>],
        identity: CertificateIdentity<'_>,
        evidence: browntls_core::revocation::PeerEvidence<'_>,
        now: browntls_core::pki_types::UnixTime,
        context: ServerCertVerificationContext,
    ) -> Result<ServerCertificateVerification, Error> {
        if self.forward_context {
            return self.inner.verify_server_cert_with_context(
                end_entity,
                intermediates,
                identity,
                evidence,
                now,
                context,
            );
        }
        self.inner.verify_server_cert_with_identity(
            end_entity,
            intermediates,
            identity,
            evidence,
            now,
            true,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &browntls_core::pki_types::CertificateDer<'_>,
        dss: &browntls_core::DigitallySignedStruct,
    ) -> Result<browntls_core::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<browntls_core::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requests_transparency_info(&self) -> bool {
        self.offer.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// What the ClientHello carried decides whether a server's TLS 1.3 entry
/// extension was solicited, not what the verifier says later.
#[test]
fn tls13_answer_to_the_sent_offer_is_accepted() {
    check_sent_ct_offer(false);
    check_sent_ct_offer(true);
}

fn check_sent_ct_offer(retry: bool) {
    use browntls_core::client::danger::ServerCertVerifier as _;

    let fx = Fixture::new();
    let v = &version::TLS13;
    let flipping = Arc::new(Flipping {
        inner: verifier(&fx.pki, Some(fx.requirements(&[&fx.log_a]))),
        offer: true.into(),
        forward_context: true,
    });
    assert!(flipping.requests_transparency_info());
    let mut client_provider = prov::default_provider();
    client_provider.kx_groups = vec![prov::kx_group::X25519, prov::kx_group::SECP256R1];
    let client = ClientConfig::builder_with_provider(Arc::new(client_provider))
        .with_protocol_versions(&[v])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(flipping.clone())
        .with_no_client_auth();
    let items = list(&[fx.sct(&fx.log_a)]);
    let mut server_provider = prov::default_provider();
    let group = if retry {
        prov::kx_group::SECP256R1
    } else {
        prov::kx_group::X25519
    };
    server_provider.kx_groups = vec![group];
    let mut key = CertifiedKey::from_der(
        fx.chain.cert_chain(),
        fx.chain.private_key(),
        &server_provider,
    )
    .unwrap();
    key.set_transparency_info(Some(items.clone())).unwrap();
    let server = ServerConfig::builder_with_provider(Arc::new(server_provider))
        .with_protocol_versions(&[v])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
    // The ClientHello offers the extension; the Certificate then finds a
    // verifier that no longer asks for it.
    let mut c = ClientConnection::new(Arc::new(client), server_name()).unwrap();
    flipping
        .offer
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let mut s = ServerConnection::new(Arc::new(server)).unwrap();
    let (cr, sr) = do_handshake_until_error(&mut c, &mut s);
    cr.unwrap();
    sr.unwrap();
    assert_eq!(
        c.handshake_kind(),
        Some(if retry {
            HandshakeKind::FullWithHelloRetryRequest
        } else {
            HandshakeKind::Full
        })
    );
    assert_eq!(c.peer_transparency_info(), Some(&items[..]));
    assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 0)));
}

#[test]
fn ct_wrappers_preserve_the_offer_and_verification_context() {
    let fx = Fixture::new();
    let ocsp = fx
        .pki
        .ocsp(&fx.chain.end_entity, Some(&list(&[fx.sct(&fx.log_a)])));
    for v in VERSIONS {
        let server = server(&fx.chain, None, Some(ocsp.clone()), v);
        for (offers, forwards) in [(true, true), (false, true), (true, false)] {
            let wrapper = Arc::new(Flipping {
                inner: verifier(&fx.pki, Some(fx.requirements(&[&fx.log_a]))),
                offer: offers.into(),
                forward_context: forwards,
            });
            let client = Arc::new(
                ClientConfig::builder_with_provider(provider())
                    .with_protocol_versions(&[v])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(wrapper)
                    .with_no_client_auth(),
            );
            let (c, _, cr, sr) = connect(&client, &server);
            if offers && forwards {
                cr.unwrap();
                sr.unwrap();
                assert_eq!(c.peer_transparency_info(), None);
                assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 0)));
            } else {
                assert_refused(cr, sr, CertificateError::TransparencyOfferRequired);
                assert_eq!(c.peer_transparency_status(), None);
            }
        }
    }
}

/// Records what it "compresses" and sends it as it is.
#[derive(Debug)]
struct IdentityCompression;

static COMPRESSED: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());
static IDENTITY: IdentityCompression = IdentityCompression;

impl browntls_core::compress::CertCompressor for IdentityCompression {
    fn compress(
        &self,
        input: Vec<u8>,
        _level: browntls_core::compress::CompressionLevel,
    ) -> Result<Vec<u8>, browntls_core::compress::CompressionFailed> {
        COMPRESSED.lock().unwrap().push(input.clone());
        Ok(input)
    }

    fn algorithm(&self) -> browntls_core::CertificateCompressionAlgorithm {
        browntls_core::CertificateCompressionAlgorithm::Zstd
    }
}

impl browntls_core::compress::CertDecompressor for IdentityCompression {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), browntls_core::compress::DecompressionFailed> {
        if input.len() != output.len() {
            return Err(browntls_core::compress::DecompressionFailed);
        }
        output.copy_from_slice(input);
        Ok(())
    }

    fn algorithm(&self) -> browntls_core::CertificateCompressionAlgorithm {
        browntls_core::CertificateCompressionAlgorithm::Zstd
    }
}

#[test]
fn compressed_certificate_carries_the_extension() {
    let fx = Fixture::new();
    let v = &version::TLS13;
    let items = list(&[fx.sct(&fx.log_a)]);
    let mut client = client_with(&fx.pki, Some(fx.requirements(&[&fx.log_a])), v);
    client.cert_decompressors = vec![&IDENTITY];
    let mut server = (*server(&fx.chain, Some(items.clone()), None, v)).clone();
    server.cert_compressors = vec![&IDENTITY];
    let (c, _s, cr, sr) = connect(&Arc::new(client), &Arc::new(server));
    cr.unwrap();
    sr.unwrap();
    assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 0)));
    // The list travelled inside the CompressedCertificate message.
    assert!(
        COMPRESSED
            .lock()
            .unwrap()
            .iter()
            .any(|input| input.windows(items.len()).any(|w| w == items))
    );
}

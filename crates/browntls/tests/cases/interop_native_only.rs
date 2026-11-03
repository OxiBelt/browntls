// Native-only interoperability cases, included by `tests/interop_native.rs`
// after `cases/interop.rs` (whose plumbing they use).
//
// What the RustCrypto provider cannot do: sign with RSA keys (so every RSA
// scheme is checked in both directions), make certificate signatures with
// keys it generated, and offer the ML-KEM-1024 groups (which rustls with ring
// lacks, so only the negotiation around them is checked here).

const RSA_PSS: [browntls::SignatureScheme; 3] = [
    browntls::SignatureScheme::RSA_PSS_SHA256,
    browntls::SignatureScheme::RSA_PSS_SHA384,
    browntls::SignatureScheme::RSA_PSS_SHA512,
];

const RSA_PKCS1: [browntls::SignatureScheme; 3] = [
    browntls::SignatureScheme::RSA_PKCS1_SHA256,
    browntls::SignatureScheme::RSA_PKCS1_SHA384,
    browntls::SignatureScheme::RSA_PKCS1_SHA512,
];

/// The RSA schemes a handshake signature may use in `version`.
fn rsa_schemes(version: u16) -> Vec<browntls::SignatureScheme> {
    if version == 0x0304 {
        RSA_PSS.to_vec()
    } else {
        RSA_PSS.iter().chain(RSA_PKCS1.iter()).copied().collect()
    }
}

/// `(version, suite, scheme)` for every RSA handshake signature: RSA-PSS
/// with each TLS 1.3 suite, RSA-PSS and PKCS #1 v1.5 with each `ECDHE_RSA`
/// suite.
fn rsa_matrix() -> Vec<(u16, u16, browntls::SignatureScheme)> {
    let mut out = Vec::new();
    for (version, suite, keys) in suite_matrix() {
        if keys.contains(&KeyType::Rsa2048) {
            for scheme in rsa_schemes(version) {
                out.push((version, suite, scheme));
            }
        }
    }
    // 3 TLS 1.3 suites x 3 + 3 ECDHE_RSA suites x 6
    assert_eq!(out.len(), 27);
    out
}

fn r_scheme(scheme: browntls::SignatureScheme) -> rustls::SignatureScheme {
    rustls::SignatureScheme::from(u16::from(scheme))
}

/// A rustls web-PKI server verifier that offers only `offer` and records
/// the scheme of every handshake signature it checks.
#[derive(Debug)]
struct RustlsServerSchemes {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    offer: Vec<rustls::SignatureScheme>,
    seen: std::sync::Mutex<Vec<rustls::SignatureScheme>>,
}

impl RustlsServerSchemes {
    fn new(roots: Arc<rustls::RootCertStore>, offer: rustls::SignatureScheme) -> Arc<Self> {
        Arc::new(Self {
            inner: rustls::client::WebPkiServerVerifier::builder_with_provider(
                roots,
                r_provider(None, None),
            )
            .build()
            .unwrap(),
            offer: vec![offer],
            seen: std::sync::Mutex::new(Vec::new()),
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for RustlsServerSchemes {
    fn verify_server_cert(
        &self,
        end_entity: &rpki::CertificateDer<'_>,
        intermediates: &[rpki::CertificateDer<'_>],
        server_name: &rpki::ServerName<'_>,
        ocsp_response: &[u8],
        now: rpki::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rpki::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.seen.lock().unwrap().push(dss.scheme);
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rpki::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.seen.lock().unwrap().push(dss.scheme);
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.offer.clone()
    }
}

/// A rustls web-PKI client verifier that offers only `offer` in its
/// CertificateRequest and records the scheme of every client signature.
#[derive(Debug)]
struct RustlsClientSchemes {
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    offer: Vec<rustls::SignatureScheme>,
    seen: std::sync::Mutex<Vec<rustls::SignatureScheme>>,
}

impl RustlsClientSchemes {
    fn new(roots: Arc<rustls::RootCertStore>, offer: rustls::SignatureScheme) -> Arc<Self> {
        Arc::new(Self {
            inner: rustls::server::WebPkiClientVerifier::builder_with_provider(
                roots,
                r_provider(None, None),
            )
            .build()
            .unwrap(),
            offer: vec![offer],
            seen: std::sync::Mutex::new(Vec::new()),
        })
    }
}

impl rustls::server::danger::ClientCertVerifier for RustlsClientSchemes {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rpki::CertificateDer<'_>,
        intermediates: &[rpki::CertificateDer<'_>],
        now: rpki::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rpki::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.seen.lock().unwrap().push(dss.scheme);
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rpki::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.seen.lock().unwrap().push(dss.scheme);
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.offer.clone()
    }
}

fn cert_bytes(chain: &Chain) -> Vec<Vec<u8>> {
    chain
        .cert_chain()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect()
}

// ----------------------------------------------------------- RSA signatures

#[test]
fn native_rsa_server_to_rustls_client_every_scheme_and_suite() {
    init_logging();
    let chain = server_chain(KeyType::Rsa2048);
    for (version, suite, scheme) in rsa_matrix() {
        let verifier = RustlsServerSchemes::new(r_roots(&chain), r_scheme(scheme));
        let client_config =
            rustls::ClientConfig::builder_with_provider(r_provider(Some(suite), None))
                .with_protocol_versions(r_versions(version))
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth();
        let mut client = r_connect_client(client_config);
        let mut server =
            browntls::ServerConnection::new(Arc::new(b_server(&chain, version, None, None)))
                .unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        assert_eq!(c, Ok(()), "{version:#06x} {suite:#06x} {scheme:?}");
        assert_eq!(s, Ok(()), "{version:#06x} {suite:#06x} {scheme:?}");
        assert_eq!(server.version(), Some(version));
        assert_eq!(server.suite(), Some(suite));
        assert_eq!(*verifier.seen.lock().unwrap(), [r_scheme(scheme)]);
        round_trip(&mut client, &mut server);
    }
}

#[test]
fn rustls_rsa_server_to_native_client_every_scheme_and_suite() {
    init_logging();
    let chain = server_chain(KeyType::Rsa2048);
    for (version, suite, scheme) in rsa_matrix() {
        let verifier =
            SchemeRecordingServerVerifier::new(PinnedServerVerifier::new(&chain), &[scheme]);
        let client_config =
            browntls::ClientConfig::builder_with_provider(b_provider(Some(suite), None))
                .with_protocol_versions(b_versions(version))
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth();
        let mut client = b_connect_client(client_config);
        let mut server =
            rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None))).unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        assert_eq!(c, Ok(()), "{version:#06x} {suite:#06x} {scheme:?}");
        assert_eq!(s, Ok(()), "{version:#06x} {suite:#06x} {scheme:?}");
        assert_eq!(client.version(), Some(version));
        assert_eq!(client.suite(), Some(suite));
        assert_eq!(verifier.seen(), [scheme]);
        round_trip(&mut client, &mut server);
    }
}

#[test]
fn native_rsa_client_auth_to_rustls_server_every_scheme() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Rsa2048);
    for version in [0x0304u16, 0x0303] {
        for scheme in rsa_schemes(version) {
            let verifier = RustlsClientSchemes::new(r_roots(&client_chain), r_scheme(scheme));
            let server_config = rustls::ServerConfig::builder_with_provider(r_provider(None, None))
                .with_protocol_versions(r_versions(version))
                .unwrap()
                .with_client_cert_verifier(verifier.clone())
                .with_single_cert(r_certs(&chain), r_key(&chain))
                .unwrap();
            let mut client = b_connect_client(b_client_with_auth(&chain, &client_chain, version));
            let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
            let (c, s) = handshake(&mut client, &mut server);
            assert_eq!(c, Ok(()), "{version:#06x} {scheme:?}");
            assert_eq!(s, Ok(()), "{version:#06x} {scheme:?}");
            assert_eq!(server.version(), Some(version));
            assert_eq!(*verifier.seen.lock().unwrap(), [r_scheme(scheme)]);
            assert_eq!(server.peer_certs().unwrap(), cert_bytes(&client_chain));
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn rustls_rsa_client_auth_to_native_server_every_scheme() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Rsa2048);
    for version in [0x0304u16, 0x0303] {
        for scheme in rsa_schemes(version) {
            let verifier = SchemeRecordingClientVerifier::new(
                PinnedClientVerifier::new(&client_chain, true),
                &[scheme],
            );
            let server_config =
                browntls::ServerConfig::builder_with_provider(b_provider(None, None))
                    .with_protocol_versions(b_versions(version))
                    .unwrap()
                    .with_client_cert_verifier(verifier.clone())
                    .with_single_cert(chain.cert_chain(), chain.private_key())
                    .unwrap();
            let mut client = r_connect_client(r_client_with_auth(&chain, &client_chain, version));
            let mut server = browntls::ServerConnection::new(Arc::new(server_config)).unwrap();
            let (c, s) = handshake(&mut client, &mut server);
            assert_eq!(c, Ok(()), "{version:#06x} {scheme:?}");
            assert_eq!(s, Ok(()), "{version:#06x} {scheme:?}");
            assert_eq!(server.version(), Some(version));
            assert_eq!(verifier.seen(), [scheme]);
            assert_eq!(server.peer_certs().unwrap(), cert_bytes(&client_chain));
            round_trip(&mut client, &mut server);
        }
    }
}

/// Chains whose keys `browntls-crypto` generated and whose certificate
/// signatures the native provider made are accepted by rustls's webpki, and
/// ring signs with the native PKCS #8 export.
#[test]
fn natively_signed_chains_interoperate_with_rustls() {
    init_logging();
    let ecdsa_chain = server_chain(KeyType::EcdsaP256);
    for alg in native_keys::CERT_ALGS {
        let native_chain = native_keys::server_chain(alg);
        let native_client_chain = native_keys::client_chain(alg);
        for version in [0x0304u16, 0x0303] {
            // rustls (webpki) validates the native server's chain.
            let mut client = r_connect_client(r_client(&native_chain, version, None, None));
            let mut server = browntls::ServerConnection::new(Arc::new(b_server(
                &native_chain,
                version,
                None,
                None,
            )))
            .unwrap();
            handshake_ok(&mut client, &mut server);
            assert_eq!(client.version(), Some(version));
            round_trip(&mut client, &mut server);

            // rustls (webpki) validates the native client's chain.
            let mut client = b_connect_client(b_client_with_auth(
                &ecdsa_chain,
                &native_client_chain,
                version,
            ));
            let mut server = rustls::ServerConnection::new(Arc::new(r_server_with_client_auth(
                &ecdsa_chain,
                &native_client_chain,
                version,
            )))
            .unwrap();
            handshake_ok(&mut client, &mut server);
            assert_eq!(
                server.peer_certs().unwrap(),
                cert_bytes(&native_client_chain)
            );
            round_trip(&mut client, &mut server);

            // A rustls server signs with the natively generated key; the
            // native client validates the chain with its web-PKI verifier.
            let mut roots = browntls::RootCertStore::empty();
            roots.add(native_chain.ca.clone()).unwrap();
            let client_config =
                browntls::ClientConfig::builder_with_provider(b_provider(None, None))
                    .with_protocol_versions(b_versions(version))
                    .unwrap()
                    .with_root_certificates(Arc::new(roots))
                    .with_no_client_auth();
            let mut client = b_connect_client(client_config);
            let mut server = rustls::ServerConnection::new(Arc::new(r_server(
                &native_chain,
                version,
                None,
                None,
            )))
            .unwrap();
            handshake_ok(&mut client, &mut server);
            assert_eq!(client.peer_certs().unwrap(), cert_bytes(&native_chain));
            round_trip(&mut client, &mut server);
        }
    }
}

// ------------------------------------------------- ML-KEM-1024 negotiation

#[test]
fn native_client_preferring_mlkem1024_retries_with_rustls() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::MLKEM1024, prov::kx_group::X25519];
    let client_config = browntls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(b_versions(0x0304))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let mut client = b_connect_client(client_config);
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    // ring has no ML-KEM: the only share is unusable, so rustls retries.
    assert_eq!(
        client.handshake_kind(),
        Some(browntls::HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        browntls::NamedGroup::X25519
    );
    round_trip(&mut client, &mut server);
}

#[test]
fn native_client_secp384r1mlkem1024_falls_back_to_its_classical_share_with_rustls() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP384);
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![
        prov::kx_group::SECP384R1MLKEM1024,
        prov::kx_group::SECP384R1,
    ];
    let client_config = browntls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(b_versions(0x0304))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let mut client = b_connect_client(client_config);
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(client.handshake_kind(), Some(browntls::HandshakeKind::Full));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        browntls::NamedGroup::secp384r1
    );
    round_trip(&mut client, &mut server);
}

#[test]
fn rustls_client_to_native_server_preferring_mlkem1024() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![
        prov::kx_group::MLKEM1024,
        prov::kx_group::SECP384R1MLKEM1024,
        prov::kx_group::X25519,
    ];
    let server_config = browntls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(b_versions(0x0304))
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let mut client = r_connect_client(r_client(&chain, 0x0304, None, None));
    let mut server = browntls::ServerConnection::new(Arc::new(server_config)).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(server.handshake_kind(), Some(browntls::HandshakeKind::Full));
    assert_eq!(
        server.negotiated_key_exchange_group().unwrap().name(),
        browntls::NamedGroup::X25519
    );
    round_trip(&mut client, &mut server);
}

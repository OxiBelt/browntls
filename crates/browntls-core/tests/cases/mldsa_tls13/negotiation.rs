// Cases included by `cases/mldsa_tls13.rs`, which holds the imports and the
// shared helpers: what a peer without the opt-in (or with part of it) gets,
// the key loaders, and choosing between a classical and an ML-DSA key.

/// An ML-DSA-only server against clients that do not offer its scheme: a
/// client without the opt-in, one with the X.509-only table, and one that
/// offers only the other two ML-DSA schemes. The server finds no scheme its
/// key can sign with, and says `handshake_failure`.
#[test]
fn ml_dsa_only_server_against_clients_without_its_scheme() {
    let server = server_id(Alg::Ml(Set::MlDsa44));
    let mut other_two = prov::provider()
        .signature_verification_algorithms
        .supported_schemes();
    other_two.extend([SignatureScheme::ML_DSA_65, SignatureScheme::ML_DSA_87]);
    let verifiers = [
        ("default", server_verifier(prov::provider(), &server)),
        (
            "X.509-only",
            server_verifier(prov::provider_with_ml_dsa_certificates(), &server),
        ),
        (
            "other sets",
            server_verifier_offering(prov::provider_with_ml_dsa(), &server, &other_two),
        ),
    ];
    for (what, verifier) in verifiers {
        let offered = verifier.supported_verify_schemes();
        assert!(!offered.contains(&SignatureScheme::ML_DSA_44), "{what}");
        let (mut c, mut s) = connect(
            client_config(prov::provider_with_ml_dsa(), verifier.clone(), None),
            server_config(prov::provider_with_ml_dsa(), &server, None),
        );
        let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
        assert_eq!(
            server_res,
            Err(Error::PeerIncompatible(
                PeerIncompatible::NoSignatureSchemesInCommon
            )),
            "{what}"
        );
        assert_eq!(
            client_res,
            Err(Error::AlertReceived(AlertDescription::HandshakeFailure)),
            "{what}"
        );
        assert!(verifier.seen().is_empty());
    }
}

/// The default key loader refuses ML-DSA keys and the opt-in one loads
/// them as well as every classical key the default one loads; so does a
/// server configuration built with each.
#[test]
fn key_loaders() {
    let default = prov::provider();
    let opt_in = prov::provider_with_ml_dsa();
    for set in ml_dsa::SETS {
        let id = server_id(Alg::Ml(set));
        assert!(
            default
                .key_provider
                .load_private_key(id.private_key.clone_key())
                .is_err()
        );
        assert!(
            CertifiedKey::from_der(id.chain.clone(), id.private_key.clone_key(), &default).is_err()
        );
        assert!(
            ServerConfig::builder_with_provider(arc(prov::provider()))
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(id.chain.clone(), id.private_key.clone_key())
                .is_err()
        );
        let key = id.signing_key(&opt_in);
        // No TLS 1.2 family (an unassigned value), and its own scheme only.
        assert_eq!(key.algorithm(), SignatureAlgorithm::Unknown(0xff));
        assert!(key.choose_scheme(&ML_DSA_SCHEMES).unwrap().scheme() == scheme_of(set));
        CertifiedKey::from_der(id.chain.clone(), id.private_key.clone_key(), &opt_in).unwrap();
    }
    for &key_type in common::KeyType::SIGNING {
        let chain = common::server_chain(key_type);
        let from_default = default
            .key_provider
            .load_private_key(chain.private_key())
            .unwrap();
        let from_opt_in = opt_in
            .key_provider
            .load_private_key(chain.private_key())
            .unwrap();
        assert_eq!(
            from_default.algorithm(),
            from_opt_in.algorithm(),
            "{key_type:?}"
        );
        assert_eq!(
            from_default.public_key().map(|k| k.as_ref().to_vec()),
            from_opt_in.public_key().map(|k| k.as_ref().to_vec()),
            "{key_type:?}"
        );
    }
    // A P-256 key from the certificate builder too.
    let p256 = server_id(Alg::P256);
    assert_eq!(
        p256.signing_key(&opt_in).algorithm(),
        SignatureAlgorithm::ECDSA
    );
}

/// A client with an ML-DSA certificate against a server whose client
/// verifier lacks the opt-in: the CertificateRequest lists no ML-DSA
/// scheme, so the client has nothing to sign with and sends an empty
/// Certificate. Mandatory client authentication then fails with
/// `certificate_required` (RFC 9846 §4.5.1); optional client
/// authentication completes unauthenticated.
#[test]
fn ml_dsa_client_against_a_verifier_without_the_opt_in() {
    let server = server_id(Alg::P256);
    let client = client_id(Alg::Ml(Set::MlDsa65));
    for mandatory in [true, false] {
        let client_verifier = client_verifier(prov::provider(), &client, mandatory);
        let (mut c, mut s) = connect(
            client_config(
                prov::provider_with_ml_dsa(),
                server_verifier(prov::provider_with_ml_dsa(), &server),
                Some(&client),
            ),
            server_config(
                prov::provider(),
                &server,
                Some(client_verifier.clone() as Arc<dyn ClientCertVerifier>),
            ),
        );
        if mandatory {
            let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
            assert_eq!(server_res, Err(Error::NoCertificatesPresented));
            assert_eq!(
                client_res,
                Err(Error::AlertReceived(AlertDescription::CertificateRequired))
            );
        } else {
            handshake(&mut c, &mut s).unwrap();
            assert!(s.peer_certificates().is_none());
            exchange(&mut c, &mut s);
        }
        assert!(client_verifier.seen().is_empty());
    }
}

/// Picks the first of its keys that can sign with a scheme the client
/// offered (as the resolver sees them).
#[derive(Debug)]
struct FirstUsable(Vec<Arc<CertifiedKey>>);

impl browntls_core::server::ResolvesServerCert for FirstUsable {
    fn resolve(
        &self,
        client_hello: browntls_core::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        let offered = client_hello.signature_schemes();
        self.0
            .iter()
            .find(|key| key.key.choose_scheme(offered).is_some())
            .cloned()
    }
}

/// A server holding an ML-DSA and an ECDSA certified key, preferring
/// ML-DSA: an opt-in client gets ML-DSA, a default client ECDSA, and a
/// TLS 1.2-only client (even with the opt-in table) ECDSA over TLS 1.2.
#[test]
fn server_with_ml_dsa_and_classical_keys() {
    let ml = server_id(Alg::Ml(Set::MlDsa65));
    let classical = server_id(Alg::P256);
    let opt_in = prov::provider_with_ml_dsa();
    let resolver = Arc::new(FirstUsable(vec![
        Arc::new(ml.certified_key(&opt_in)),
        Arc::new(classical.certified_key(&opt_in)),
    ]));
    let server_config = || {
        ServerConfig::builder_with_provider(arc(prov::provider_with_ml_dsa()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone())
    };
    let both = roots(&[&ml, &classical]);
    let verifier = |provider: CryptoProvider| {
        let inner = WebPkiServerVerifier::builder_with_provider(both.clone(), arc(provider))
            .build()
            .unwrap();
        let offer = inner.supported_verify_schemes();
        SchemeRecordingServerVerifier::new(inner, &offer)
    };

    #[cfg_attr(not(feature = "tls12"), allow(unused_mut))]
    let mut cases = vec![
        (prov::provider_with_ml_dsa(), &version::TLS13, &ml),
        (prov::provider(), &version::TLS13, &classical),
    ];
    #[cfg(feature = "tls12")]
    cases.push((prov::provider_with_ml_dsa(), &version::TLS12, &classical));
    for (provider, version, expected) in cases {
        let recorder = verifier(provider.clone());
        let client_config = ClientConfig::builder_with_provider(arc(provider))
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(recorder.clone())
            .with_no_client_auth();
        let (mut c, mut s) = connect(client_config, server_config());
        handshake(&mut c, &mut s).unwrap();
        assert_eq!(c.protocol_version(), Some(version.version));
        assert_eq!(c.peer_certificates().unwrap(), expected.chain);
        assert_eq!(
            recorder.seen(),
            [expected.scheme()],
            "{:?}",
            version.version
        );
        exchange(&mut c, &mut s);
    }
}

/// An ML-DSA-only server that also offers TLS 1.2, against a TLS 1.2-only
/// client with the opt-in table: the key has no TLS 1.2 signature
/// algorithm, so no TLS 1.2 cipher suite is usable with it.
#[cfg(feature = "tls12")]
#[test]
fn ml_dsa_only_server_against_a_tls12_client() {
    let server = server_id(Alg::Ml(Set::MlDsa65));
    let server_config = ServerConfig::builder_with_provider(arc(prov::provider_with_ml_dsa()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(server.chain.clone(), server.private_key.clone_key())
        .unwrap();
    let verifier = server_verifier(prov::provider_with_ml_dsa(), &server);
    let client_config = ClientConfig::builder_with_provider(arc(prov::provider_with_ml_dsa()))
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let (mut c, mut s) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
    assert_eq!(
        server_res,
        Err(Error::PeerIncompatible(
            PeerIncompatible::NoCipherSuitesInCommon
        ))
    );
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );
    assert!(verifier.seen().is_empty());
}

/// `CertifiedKey::from_der` and `keys_match` with an ML-DSA key: its own
/// certificate matches; a certificate of another parameter set, of another
/// key of the same set, or of a P-256 key does not
/// (`InconsistentKeys::KeyMismatch`).
#[test]
fn certified_key_consistency() {
    let opt_in = prov::provider_with_ml_dsa();
    let own = server_id(Alg::Ml(Set::MlDsa65));
    let mismatch = Error::InconsistentKeys(browntls_core::InconsistentKeys::KeyMismatch);
    let others = [
        ("own", own.chain.clone(), Ok(())),
        (
            "other set",
            server_id(Alg::Ml(Set::MlDsa44)).chain,
            Err(mismatch.clone()),
        ),
        (
            "other key, same set",
            identity(
                Alg::Ml(Set::MlDsa65),
                &[Alg::P256],
                Purpose::Server,
                "other",
            )
            .chain,
            Err(mismatch.clone()),
        ),
        ("P-256", server_id(Alg::P256).chain, Err(mismatch)),
    ];
    for (what, chain, expected) in others {
        let from_der = CertifiedKey::from_der(chain.clone(), own.private_key.clone_key(), &opt_in);
        assert_eq!(from_der.map(|_| ()), expected, "{what}");
        let certified = CertifiedKey::new(chain, own.signing_key(&opt_in));
        assert_eq!(certified.keys_match(), expected, "{what}");
    }
}

/// The opt-in key loader: an ML-DSA PKCS #8 key in the `both` form whose
/// seed and expanded key disagree (RFC 9881 §8.2) fails with an error that
/// names ML-DSA, while bytes that name no ML-DSA algorithm fail as with the
/// default loader.
#[test]
fn opt_in_loader_errors() {
    use browntls_crypto::mldsa::{self, MlDsa65, PrivateKeyFormat};

    let key = mldsa::SigningKey::<MlDsa65>::from_seed(&[0x65; 32]);
    let mut der = vec![0; mldsa::SigningKey::<MlDsa65>::PKCS8_MAX_LEN];
    let len = key.to_pkcs8_der(PrivateKeyFormat::Both, &mut der).unwrap();
    der.truncate(len);
    let load = |provider: &CryptoProvider, der: &[u8]| {
        provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())))
    };
    let opt_in = prov::provider_with_ml_dsa();
    let default = prov::provider();
    assert!(load(&opt_in, &der).is_ok());

    // The last byte is in the expanded key.
    *der.last_mut().unwrap() ^= 1;
    let err = load(&opt_in, &der).unwrap_err();
    assert!(err.to_string().contains("ML-DSA"), "{err}");
    assert_ne!(Some(&err), load(&default, &der).err().as_ref());

    for garbage in [
        &[][..],
        &[1, 2, 3],
        &[0x30, 0x00],
        &[0x30, 0x03, 0x02, 0x01, 0x00],
    ] {
        assert_eq!(
            load(&opt_in, garbage).unwrap_err(),
            load(&default, garbage).unwrap_err(),
            "{garbage:?}"
        );
    }
}

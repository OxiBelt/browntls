// Cases included by `cases/rsa_pkcs1_legacy.rs`, which holds the imports
// and the shared helpers: rustls 0.23 (ring provider) peers whose keys
// sign a TLS 1.3 CertificateVerify with RSASSA-PKCS1-v1_5 whatever they
// are offered. rustls sends the scheme its signer names without checking
// it against the peer's list (as found by these cases), so it delivers
// messages a browntls peer never sends: a client CertificateVerify under
// a legacy scheme the request did not list, or under `rsa_pkcs1_sha256`,
// and a server CertificateVerify under a legacy scheme.

/// One side of a connection, for driving browntls and rustls peers
/// against each other in memory.
trait Peer {
    type Err: std::fmt::Debug;
    /// Everything the peer has queued to send.
    fn take(&mut self) -> Vec<u8>;
    /// Gives the peer `bytes` and processes them.
    fn give(&mut self, bytes: &[u8]) -> Result<(), Self::Err>;
    fn busy(&self) -> bool;
    fn send(&mut self, data: &[u8]);
    fn received(&mut self) -> Vec<u8>;
}

macro_rules! impl_peer {
    ($ty:ty, $err:ty) => {
        impl Peer for $ty {
            type Err = $err;

            fn take(&mut self) -> Vec<u8> {
                let mut buf = Vec::new();
                while self.wants_write() {
                    self.write_tls(&mut buf).unwrap();
                }
                buf
            }

            fn give(&mut self, mut bytes: &[u8]) -> Result<(), $err> {
                while !bytes.is_empty() {
                    match self.read_tls(&mut bytes) {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::Other => {
                            self.process_new_packets()?;
                        }
                        Err(e) => panic!("read_tls failed: {e}"),
                    }
                }
                self.process_new_packets()?;
                Ok(())
            }

            fn busy(&self) -> bool {
                self.is_handshaking()
            }

            fn send(&mut self, data: &[u8]) {
                self.writer().write_all(data).unwrap();
            }

            fn received(&mut self) -> Vec<u8> {
                let mut out = Vec::new();
                match self.reader().read_to_end(&mut out) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("read failed: {e}"),
                }
                out
            }
        }
    };
}

impl_peer!(ClientConnection, Error);
impl_peer!(ServerConnection, Error);
impl_peer!(rustls::ClientConnection, rustls::Error);
impl_peer!(rustls::ServerConnection, rustls::Error);

/// Runs a handshake between `client` and `server` until both are done or
/// one fails; after a failure the other side reads what the failing side
/// sent (its alert). Returns both results.
fn mixed_handshake<C: Peer, P: Peer>(
    client: &mut C,
    server: &mut P,
) -> (Result<(), C::Err>, Result<(), P::Err>) {
    for _ in 0..16 {
        if !client.busy() && !server.busy() {
            break;
        }
        if let Err(e) = server.give(&client.take()) {
            return (client.give(&server.take()), Err(e));
        }
        if let Err(e) = client.give(&server.take()) {
            return (Err(e), server.give(&client.take()));
        }
    }
    (Ok(()), Ok(()))
}

/// Sends `data` from `from` to `to` and returns what `to` received.
fn carry<A: Peer, B: Peer>(from: &mut A, to: &mut B, data: &[u8]) -> Vec<u8> {
    from.send(data);
    to.give(&from.take()).unwrap();
    to.received()
}

fn r_cert(cert: &CertificateDer<'_>) -> rustls_pki_types::CertificateDer<'static> {
    rustls_pki_types::CertificateDer::from(cert.as_ref().to_vec())
}

fn r_chain(chain: &Chain) -> Vec<rustls_pki_types::CertificateDer<'static>> {
    chain.cert_chain().iter().map(r_cert).collect()
}

fn r_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

static R_TLS13: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

/// A rustls signing key that names `names` whatever it is offered, and
/// signs with RSASSA-PKCS1-v1_5 and SHA-256 (the `rsa` crate); it records
/// every list it is offered.
#[derive(Debug)]
struct RustlsPkcs1Key {
    names: rustls::SignatureScheme,
    key: Arc<rsa::PrivateKey>,
    offered: Mutex<Vec<Vec<u16>>>,
}

impl rustls::sign::SigningKey for RustlsPkcs1Key {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        let offered = offered.iter().map(|s| u16::from(*s)).collect();
        self.offered.lock().unwrap().push(offered);
        Some(Box::new(RustlsPkcs1Signer {
            names: self.names,
            key: self.key.clone(),
        }))
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
struct RustlsPkcs1Signer {
    names: rustls::SignatureScheme,
    key: Arc<rsa::PrivateKey>,
}

impl rustls::sign::Signer for RustlsPkcs1Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(Hash::Sha256.pkcs1(&self.key, message))
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.names
    }
}

/// A rustls client certificate resolver answering with `key` and
/// recording the schemes of every request (as rustls passes them on).
#[derive(Debug)]
struct RustlsClientCert {
    key: Arc<rustls::sign::CertifiedKey>,
    seen: Mutex<Vec<Vec<u16>>>,
}

impl RustlsClientCert {
    fn seen(&self) -> Vec<Vec<u16>> {
        self.seen.lock().unwrap().clone()
    }
}

impl rustls::client::ResolvesClientCert for RustlsClientCert {
    fn resolve(
        &self,
        _hints: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let seen = sigschemes.iter().map(|s| u16::from(*s)).collect();
        self.seen.lock().unwrap().push(seen);
        Some(self.key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A rustls server certificate resolver answering with `key` and recording
/// the `signature_algorithms` of every ClientHello.
#[derive(Debug)]
struct RustlsServerCert {
    key: Arc<rustls::sign::CertifiedKey>,
    seen: Mutex<Vec<Vec<u16>>>,
}

impl rustls::server::ResolvesServerCert for RustlsServerCert {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let seen = client_hello
            .signature_schemes()
            .iter()
            .map(|s| u16::from(*s))
            .collect();
        self.seen.lock().unwrap().push(seen);
        Some(self.key.clone())
    }
}

/// A TLS 1.3 rustls client trusting [`server`], presenting
/// [`rsa_client`]'s chain with a key that names `names` and signs with
/// RSASSA-PKCS1-v1_5 and SHA-256.
fn rustls_client(
    names: rustls::SignatureScheme,
) -> (rustls::ClientConnection, Arc<RustlsClientCert>) {
    let key = Arc::new(RustlsPkcs1Key {
        names,
        key: rsa_key(rsa_client()),
        offered: Mutex::new(Vec::new()),
    });
    let resolver = Arc::new(RustlsClientCert {
        key: Arc::new(rustls::sign::CertifiedKey::new(r_chain(rsa_client()), key)),
        seen: Mutex::new(Vec::new()),
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(r_cert(&server().ca)).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(r_provider())
        .with_protocol_versions(&R_TLS13)
        .unwrap()
        .with_root_certificates(roots)
        .with_client_cert_resolver(resolver.clone());
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let client = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    (client, resolver)
}

/// A browntls TLS 1.3 server presenting [`server`] whose client verifier
/// (mandatory, for [`rsa_client`]'s CA) is built with `provider`.
fn browntls_server(
    provider: CryptoProvider,
) -> (ServerConnection, Arc<SchemeRecordingClientVerifier>) {
    let verifier = client_verifier(provider.clone(), rsa_client(), true);
    let config = server_config_for(provider, &TLS13, verifier.clone());
    (ServerConnection::new(Arc::new(config)).unwrap(), verifier)
}

/// A rustls client that signs its CertificateVerify with
/// `rsa_pkcs1_sha256_legacy` (sent as `Unknown(0x0420)`, rustls has no
/// name for it) against a browntls server without the opt-in, whose
/// CertificateRequest did not list it: the server refuses the scheme
/// before verifying the signature, with `illegal_parameter` (RFC 9963 §3,
/// RFC 9846 §4.4.3).
#[test]
fn rustls_client_with_an_unadvertised_legacy_scheme() {
    let (mut client, resolver) = rustls_client(rustls::SignatureScheme::Unknown(0x0420));
    let (mut server, verifier) = browntls_server(prov::provider());
    let (client_res, server_res) = mixed_handshake(&mut client, &mut server);
    assert_eq!(server_res, Err(UNADVERTISED));
    assert_eq!(
        client_res,
        Err(rustls::Error::AlertReceived(
            rustls::AlertDescription::IllegalParameter
        ))
    );
    assert!(verifier.seen().is_empty());
    assert_eq!(resolver.seen().len(), 1, "rustls answered the request");
}

/// The same rustls client against an opted-in browntls server, whose
/// request lists the scheme: rustls builds the CertificateVerify content
/// and RSASSA-PKCS1-v1_5 encoding independently, browntls verifies it,
/// and the connection works. rustls's resolver is given the legacy
/// schemes at the end of the request's list: rustls drops only the
/// schemes it knows TLS 1.3 forbids, and passes unknown code points on.
#[test]
fn rustls_client_with_a_legacy_scheme_against_an_opted_in_server() {
    let (mut client, resolver) = rustls_client(rustls::SignatureScheme::Unknown(0x0420));
    let (mut server, verifier) = browntls_server(prov::provider_with_rsa_pkcs1_legacy());
    let (client_res, server_res) = mixed_handshake(&mut client, &mut server);
    assert_eq!(server_res, Ok(()));
    assert_eq!(client_res, Ok(()));
    assert_eq!(verifier.seen(), [S::RSA_PKCS1_SHA256_LEGACY]);
    assert_eq!(
        server.peer_certificates().unwrap(),
        rsa_client().cert_chain()
    );
    let seen = resolver.seen();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].ends_with(&[0x0620, 0x0520, 0x0420]),
        "{:x?}",
        seen[0]
    );
    assert_eq!(carry(&mut client, &mut server, b"ping"), b"ping");
    assert_eq!(carry(&mut server, &mut client, b"pong"), b"pong");
}

/// `rsa_pkcs1_sha256` (0x0401) in a TLS 1.3 client CertificateVerify, from
/// a rustls client, to an opted-in server: TLS 1.3 never allows it (RFC
/// 9846 §4.2.3), the request did not list it, and the server refuses it
/// with `illegal_parameter`, although the same signature bytes would be
/// valid under 0x0420.
#[test]
fn rustls_client_with_rsa_pkcs1_sha256_in_tls13() {
    let (mut client, _) = rustls_client(rustls::SignatureScheme::RSA_PKCS1_SHA256);
    let (mut server, verifier) = browntls_server(prov::provider_with_rsa_pkcs1_legacy());
    let (client_res, server_res) = mixed_handshake(&mut client, &mut server);
    assert_eq!(server_res, Err(UNADVERTISED));
    assert_eq!(
        client_res,
        Err(rustls::Error::AlertReceived(
            rustls::AlertDescription::IllegalParameter
        ))
    );
    assert!(verifier.seen().is_empty());
}

/// A double of a client's server certificate verifier that advertises the
/// legacy schemes too and would verify a server signature under them
/// (with the client-signature function and the opt-in table).
#[derive(Debug)]
struct LegacyAcceptingServerVerifier {
    inner: Arc<WebPkiServerVerifier>,
    seen: Mutex<Vec<S>>,
}

impl ServerCertVerifier for LegacyAcceptingServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.seen.lock().unwrap().push(dss.scheme);
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.seen.lock().unwrap().push(dss.scheme);
        browntls_core::crypto::verify_tls13_client_signature(
            message,
            cert,
            dss,
            &prov::provider_with_rsa_pkcs1_legacy().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<S> {
        let mut schemes = self.inner.supported_verify_schemes();
        schemes.extend(OPT_IN_ORDER);
        schemes
    }
}

/// A rustls TLS 1.3 server presenting [`rsa_server`] that signs its
/// CertificateVerify with `rsa_pkcs1_sha256_legacy` (RSASSA-PKCS1-v1_5,
/// SHA-256) whatever the client offered, against a browntls client with
/// the default provider, with the opt-in provider everywhere, and with a
/// verifier double that advertises and would verify the legacy schemes.
/// RFC 9963 §3 defines them for the client's CertificateVerify only: each
/// client refuses the scheme before verifying anything, with
/// `illegal_parameter`. No ClientHello lists a legacy scheme.
#[test]
fn server_certificate_verify_with_a_legacy_scheme() {
    let rsa_server = rsa_server();
    let webpki = |provider: CryptoProvider| {
        WebPkiServerVerifier::builder_with_provider(roots(rsa_server), Arc::new(provider))
            .build()
            .unwrap()
    };
    let double = Arc::new(LegacyAcceptingServerVerifier {
        inner: webpki(prov::provider_with_rsa_pkcs1_legacy()),
        seen: Mutex::new(Vec::new()),
    });
    // The double would accept such a signature by the server's key.
    let message = b"a message";
    let signature = Hash::Sha256.pkcs1(&rsa_key(rsa_server), message);
    let dss = DigitallySignedStruct::new(S::RSA_PKCS1_SHA256_LEGACY, signature);
    double
        .verify_tls13_signature(message, &rsa_server.end_entity, &dss)
        .unwrap();
    double.seen.lock().unwrap().clear();

    let default = server_verifier(prov::provider(), rsa_server);
    let opt_in = server_verifier(prov::provider_with_rsa_pkcs1_legacy(), rsa_server);
    let clients: [(&str, CryptoProvider, Arc<dyn ServerCertVerifier>); 3] = [
        ("default", prov::provider(), default.clone()),
        (
            "opt-in",
            prov::provider_with_rsa_pkcs1_legacy(),
            opt_in.clone(),
        ),
        (
            "double",
            prov::provider_with_rsa_pkcs1_legacy(),
            double.clone(),
        ),
    ];
    for (what, provider, verifier) in clients {
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&TLS13)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let mut client = ClientConnection::new(Arc::new(config), common::server_name()).unwrap();

        let key = Arc::new(RustlsPkcs1Key {
            names: rustls::SignatureScheme::Unknown(0x0420),
            key: rsa_key(rsa_server),
            offered: Mutex::new(Vec::new()),
        });
        let resolver = Arc::new(RustlsServerCert {
            key: Arc::new(rustls::sign::CertifiedKey::new(
                r_chain(rsa_server),
                key.clone(),
            )),
            seen: Mutex::new(Vec::new()),
        });
        let config = rustls::ServerConfig::builder_with_provider(r_provider())
            .with_protocol_versions(&R_TLS13)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();

        let (client_res, server_res) = mixed_handshake(&mut client, &mut server);
        assert_eq!(client_res, Err(UNADVERTISED), "{what}");
        assert_eq!(
            server_res,
            Err(rustls::Error::AlertReceived(
                rustls::AlertDescription::IllegalParameter
            )),
            "{what}"
        );
        let hellos = resolver.seen.lock().unwrap().clone();
        assert_eq!(hellos.len(), 1, "{what}");
        assert!(
            hellos[0]
                .iter()
                .all(|s| !matches!(s, 0x0420 | 0x0520 | 0x0620)),
            "{what}: {:x?}",
            hellos[0]
        );
        assert_eq!(key.offered.lock().unwrap().len(), 1, "{what}: it signed");
    }
    assert!(default.seen().is_empty());
    assert!(opt_in.seen().is_empty());
    assert!(double.seen.lock().unwrap().is_empty());
}

/// Server authentication with an RSA certificate when the client has
/// opted in everywhere: a rustls server with its own RSA key (ring) signs
/// its CertificateVerify with RSASSA-PSS, which the client verifies; the
/// opt-in adds no way for a server to authenticate.
#[test]
fn rsa_server_still_authenticates_with_pss() {
    let rsa_server = rsa_server();
    let verifier = server_verifier(prov::provider_with_rsa_pkcs1_legacy(), rsa_server);
    let config =
        ClientConfig::builder_with_provider(Arc::new(prov::provider_with_rsa_pkcs1_legacy()))
            .with_protocol_versions(&TLS13)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
    let mut client = ClientConnection::new(Arc::new(config), common::server_name()).unwrap();
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
        rsa_server.end_entity_key.clone(),
    ));
    let config = rustls::ServerConfig::builder_with_provider(r_provider())
        .with_protocol_versions(&R_TLS13)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(r_chain(rsa_server), key)
        .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    let (client_res, server_res) = mixed_handshake(&mut client, &mut server);
    assert_eq!(client_res, Ok(()));
    assert_eq!(server_res, Ok(()));
    assert_eq!(verifier.seen(), [S::RSA_PSS_SHA512]);
    assert_eq!(carry(&mut client, &mut server, b"ping"), b"ping");
}

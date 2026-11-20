//! Unit tests: the per-connection context lists, and exported
//! authenticators between unbuffered connections in whatever configuration
//! the library is built, `std` or not.

use alloc::vec;

use super::*;

#[test]
fn context_lists_are_capped_separately() {
    let mut state = AuthenticatorState::default();
    state.add_request(b"ours", vec![1]);
    // A peer fills the list of spontaneous authenticators...
    for i in 0..MAX_CONTEXTS {
        let context = (i as u32).to_be_bytes().to_vec();
        state.check_spontaneous(&context).unwrap();
        state.record(Answered::Spontaneous(context));
    }
    assert!(matches!(
        state.check_spontaneous(b"one more"),
        Err(Error::General(_))
    ));
    // ...and of authenticators we made (one per request it sends).
    for i in 0..MAX_CONTEXTS {
        let context = (i as u32).to_be_bytes().to_vec();
        state.check_make(&context).unwrap();
        state.made.push(context);
    }
    assert!(state.check_make(b"one more").is_err());
    // Answers to our own request still validate, once.
    let index = state.find_request(&[1]).unwrap();
    state.record(Answered::Request(index));
    assert_eq!(
        state.find_request(&[1]),
        Err(PeerMisbehaved::ReusedAuthenticatorContext.into())
    );
    // A request we did not make is refused.
    assert!(matches!(state.find_request(&[2]), Err(Error::General(_))));
    // A spontaneous authenticator may not take a requested context.
    let mut state = AuthenticatorState::default();
    state.add_request(b"ours", vec![1]);
    assert_eq!(
        state.check_spontaneous(b"ours"),
        Err(PeerMisbehaved::ReusedAuthenticatorContext.into())
    );
}

/// Exported authenticators between unbuffered connections, the only kind
/// there is without `std`. This module is built with every configuration
/// the unit tests are, so `cargo test -p browntls-core --lib
/// --no-default-features --features alloc,rustcrypto,tls12` shows that the API
/// compiles and works with the library built without `std`. It uses `alloc`
/// and `core` only (the certificates come from `rcgen`).
#[cfg(any(feature = "rustcrypto", feature = "native"))]
mod unbuffered {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::fmt;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::time::Duration;

    use super::AuthenticatorRequestExtensions;
    use crate::client::UnbufferedClientConnection;
    use crate::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use crate::conn::SideData;
    use crate::crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
    };
    use crate::enums::SignatureScheme;
    use crate::error::{CertificateError, Error, PeerMisbehaved};
    use crate::msgs::handshake::DistinguishedName;
    use crate::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use crate::server::UnbufferedServerConnection;
    use crate::server::danger::{ClientCertVerified, ClientCertVerifier};
    use crate::sign::CertifiedKey;
    use crate::sync::Arc;
    use crate::time_provider::TimeProvider;
    use crate::unbuffered::{
        ConnectionState, EncodeError, InsufficientSizeError, UnbufferedConnectionCommon,
    };
    use crate::verify::DigitallySignedStruct;
    use crate::{ClientConfig, ServerConfig, SupportedProtocolVersion, version};

    #[cfg(feature = "rustcrypto")]
    fn provider() -> CryptoProvider {
        crate::crypto::rustcrypto::default_provider()
    }

    #[cfg(not(feature = "rustcrypto"))]
    fn provider() -> CryptoProvider {
        crate::crypto::native::default_provider()
    }

    /// A fixed time that can be stopped, as if no clock were configured
    /// (the default without `std`).
    #[derive(Debug, Default)]
    struct Clock {
        stopped: AtomicBool,
    }

    impl Clock {
        fn set_stopped(&self, stopped: bool) {
            self.stopped.store(stopped, Ordering::Relaxed);
        }
    }

    impl TimeProvider for Clock {
        fn current_time(&self) -> Option<UnixTime> {
            (!self.stopped.load(Ordering::Relaxed))
                .then(|| UnixTime::since_unix_epoch(Duration::from_secs(1_767_225_600)))
        }
    }

    /// Accepts one end-entity certificate, and verifies signatures with
    /// the provider's algorithms.
    struct Pinned {
        expected: CertificateDer<'static>,
        algs: WebPkiSupportedAlgorithms,
    }

    impl Pinned {
        fn check(&self, end_entity: &CertificateDer<'_>) -> Result<(), Error> {
            if end_entity.as_ref() == self.expected.as_ref() {
                Ok(())
            } else {
                Err(CertificateError::UnknownIssuer.into())
            }
        }
    }

    impl fmt::Debug for Pinned {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Pinned").finish_non_exhaustive()
        }
    }

    impl ServerCertVerifier for Pinned {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            self.check(end_entity)
                .map(|()| ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(message, cert, dss, &self.algs)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(message, cert, dss, &self.algs)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.algs.supported_schemes()
        }
    }

    impl ClientCertVerifier for Pinned {
        fn offer_client_auth(&self) -> bool {
            false
        }

        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, Error> {
            self.check(end_entity)
                .map(|()| ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(message, cert, dss, &self.algs)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(message, cert, dss, &self.algs)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.algs.supported_schemes()
        }
    }

    /// A self-signed certificate for `name` and its PKCS#8 key.
    fn identity(
        name: &str,
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (
            CertificateDer::from(cert.der().to_vec()),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    struct Pair {
        client: UnbufferedClientConnection,
        server: UnbufferedServerConnection,
        clock: Arc<Clock>,
        server_cert: CertificateDer<'static>,
        client_cert: CertificateDer<'static>,
        server_key: CertifiedKey,
        client_key: CertifiedKey,
    }

    /// An unbuffered pair over `versions`, not connected yet.
    fn pair(versions: &[&'static SupportedProtocolVersion]) -> Pair {
        let provider = Arc::new(provider());
        let clock = Arc::new(Clock::default());
        let (server_cert, server_der) = identity("localhost", &rcgen::PKCS_ECDSA_P256_SHA256);
        let (client_cert, client_der) = identity("client.example", &rcgen::PKCS_ED25519);
        let pinned = |expected: &CertificateDer<'static>| {
            Arc::new(Pinned {
                expected: expected.clone(),
                algs: provider.signature_verification_algorithms,
            })
        };
        let client_config = ClientConfig::builder_with_details(provider.clone(), clock.clone())
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(pinned(&server_cert))
            .with_no_client_auth();
        let server_config = ServerConfig::builder_with_details(provider.clone(), clock.clone())
            .with_protocol_versions(versions)
            .unwrap()
            .with_client_cert_verifier(pinned(&client_cert))
            .with_single_cert(vec![server_cert.clone()], server_der.clone_key())
            .unwrap();
        Pair {
            client: UnbufferedClientConnection::new(
                Arc::new(client_config),
                ServerName::try_from("localhost").unwrap(),
            )
            .unwrap(),
            server: UnbufferedServerConnection::new(Arc::new(server_config)).unwrap(),
            clock,
            server_key: CertifiedKey::from_der(vec![server_cert.clone()], server_der, &provider)
                .unwrap(),
            client_key: CertifiedKey::from_der(vec![client_cert.clone()], client_der, &provider)
                .unwrap(),
            server_cert,
            client_cert,
        }
    }

    /// Runs `conn` until it needs input, appending what it sends to `out`.
    fn drive<D: SideData>(
        conn: &mut UnbufferedConnectionCommon<D>,
        incoming: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) {
        let mut size = 512;
        for _ in 0..1_000 {
            let status = conn.process_tls_records(&mut incoming[..]);
            let discard = status.discard;
            let settled = match status.state.unwrap() {
                ConnectionState::EncodeTlsData(mut encode) => {
                    let mut buf = vec![0u8; size];
                    match encode.encode(&mut buf) {
                        Ok(n) => out.extend_from_slice(&buf[..n]),
                        Err(EncodeError::InsufficientSize(InsufficientSizeError {
                            required_size,
                        })) => size = required_size,
                    }
                    false
                }
                ConnectionState::TransmitTlsData(transmit) => {
                    transmit.done();
                    false
                }
                ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => true,
                other => panic!("unexpected state {other:?}"),
            };
            incoming.drain(..discard);
            if settled {
                return;
            }
        }
        panic!("the connection did not settle");
    }

    fn connect(p: &mut Pair) {
        let (mut client_in, mut server_in) = (Vec::new(), Vec::new());
        for _ in 0..8 {
            drive(&mut p.client, &mut client_in, &mut server_in);
            drive(&mut p.server, &mut server_in, &mut client_in);
        }
        assert!(!p.client.is_handshaking() && !p.server.is_handshaking());
    }

    fn versions() -> Vec<&'static [&'static SupportedProtocolVersion]> {
        static TLS13: &[&SupportedProtocolVersion] = &[&version::TLS13];
        #[cfg(feature = "tls12")]
        static TLS12: &[&SupportedProtocolVersion] = &[&version::TLS12];
        vec![
            TLS13,
            #[cfg(feature = "tls12")]
            TLS12,
        ]
    }

    #[test]
    fn round_trips() {
        let none = AuthenticatorRequestExtensions::default();
        for versions in versions() {
            let mut p = pair(versions);
            connect(&mut p);

            // The client asks, the server answers. Without a clock, as by
            // default without `std`, validation fails and records nothing.
            let request = p.client.request_authenticator(b"client", &none).unwrap();
            let auth = p
                .server
                .authenticator(Some(&request), Some(&p.server_key))
                .unwrap();
            p.clock.set_stopped(true);
            assert_eq!(
                p.client.validate_authenticator(Some(&request), &auth),
                Err(Error::FailedToGetCurrentTime)
            );
            p.clock.set_stopped(false);
            assert_eq!(
                p.client.validate_authenticator(Some(&request), &auth),
                Ok(Some(vec![p.server_cert.clone()]))
            );
            assert_eq!(
                p.client.validate_authenticator(Some(&request), &auth),
                Err(PeerMisbehaved::ReusedAuthenticatorContext.into())
            );

            // The server asks, the client answers, then declines.
            let request = p.server.request_authenticator(b"server", &none).unwrap();
            let auth = p
                .client
                .authenticator(&request, Some(&p.client_key))
                .unwrap();
            p.clock.set_stopped(true);
            assert_eq!(
                p.server.validate_authenticator(&request, &auth),
                Err(Error::FailedToGetCurrentTime)
            );
            p.clock.set_stopped(false);
            assert_eq!(
                p.server.validate_authenticator(&request, &auth),
                Ok(Some(vec![p.client_cert.clone()]))
            );
            let request = p.server.request_authenticator(b"declined", &none).unwrap();
            let auth = p.client.authenticator(&request, None).unwrap();
            assert_eq!(p.server.validate_authenticator(&request, &auth), Ok(None));

            // A spontaneous server authenticator.
            let auth = p.server.authenticator(None, Some(&p.server_key)).unwrap();
            assert_eq!(
                p.client.validate_authenticator(None, &auth),
                Ok(Some(vec![p.server_cert.clone()]))
            );
        }
    }

    #[test]
    fn need_a_completed_handshake() {
        let none = AuthenticatorRequestExtensions::default();
        let mut p = pair(&[&version::TLS13]);
        let request = p.client.request_authenticator(b"early", &none).unwrap();
        let not_complete = Err(Error::HandshakeNotComplete);
        assert_eq!(p.client.authenticator(&request, None), not_complete);
        assert_eq!(
            p.client.validate_authenticator(None, &request),
            Err(Error::HandshakeNotComplete)
        );
        assert_eq!(p.server.request_authenticator(b"x", &none), not_complete);
        assert_eq!(
            p.server.authenticator(None, Some(&p.server_key)),
            not_complete
        );
        assert_eq!(
            p.server.validate_authenticator(&request, &request),
            Err(Error::HandshakeNotComplete)
        );
        connect(&mut p);
        let auth = p
            .server
            .authenticator(Some(&request), Some(&p.server_key))
            .unwrap();
        assert!(
            p.client
                .validate_authenticator(Some(&request), &auth)
                .unwrap()
                .is_some()
        );
    }
}

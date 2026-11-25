//! DTLS 1.3 (RFC 9147) with ML-DSA authentication over a simulated
//! datagram network with a virtual clock: the Certificate and
//! CertificateVerify messages are fragmented over many datagrams (§4.4),
//! reassembled, and retransmitted when a fragment is lost (§5.8). DTLS 1.2
//! never uses ML-DSA (`draft-ietf-tls-mldsa-06` defines the schemes for
//! TLS 1.3 only).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use browntls_core::version::TLS13;
use browntls_core::{
    ClientConfig, Error, HandshakeKind, PeerIncompatible, ProtocolVersion, ServerConfig,
    SignatureScheme, dtls,
};

use crate::common::{KeyType, PinnedServerVerifier};
use crate::identity::{Setup, opt_in, server_name};
use crate::ml_dsa::{SETS, Set};

const PEER: &[u8] = b"192.0.2.1:4433";

/// Decides whether the n-th datagram of a direction is delivered.
type Policy = Box<dyn FnMut(usize, &[u8]) -> bool>;

/// One direction of the network.
struct Link {
    policy: Policy,
    sent: usize,
    largest: usize,
    bytes: usize,
    inbox: VecDeque<Vec<u8>>,
}

impl Link {
    fn new(policy: impl FnMut(usize, &[u8]) -> bool + 'static) -> Self {
        Self {
            policy: Box::new(policy),
            sent: 0,
            largest: 0,
            bytes: 0,
            inbox: VecDeque::new(),
        }
    }

    fn perfect() -> Self {
        Self::new(|_, _| true)
    }

    fn send(&mut self, datagram: Vec<u8>) {
        self.largest = self.largest.max(datagram.len());
        self.bytes += datagram.len();
        if (self.policy)(self.sent, &datagram) {
            self.inbox.push_back(datagram);
        }
        self.sent += 1;
    }
}

/// Which endpoint failed (the errors are for failure messages).
#[derive(Debug)]
#[allow(dead_code)]
enum Failure {
    Client(Error),
    Server(Error),
    Stalled,
}

struct Pair {
    client: dtls::ClientConnection,
    server: dtls::ServerConnection,
}

impl Pair {
    fn new(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Self {
        Self::with_versions(client, server, dtls::Versions::V1_3, dtls::Versions::V1_3)
    }

    /// A pair whose server has a fresh cookie sealer and ticketer: a ticket
    /// from an earlier pair is not accepted, so every handshake is full.
    fn with_versions(
        client: &Arc<ClientConfig>,
        server: &Arc<ServerConfig>,
        client_versions: dtls::Versions,
        server_versions: dtls::Versions,
    ) -> Self {
        let mut server = (**server).clone();
        server.hello_retry_cookies = Some(crate::prov::Ticketer::new().unwrap());
        server.ticketer = crate::prov::Ticketer::new().unwrap();
        Self {
            client: dtls::ClientConnection::new_with_versions(
                client.clone(),
                server_name(),
                client_versions,
            )
            .unwrap(),
            server: dtls::ServerConnection::new_with_versions(
                Arc::new(server),
                PEER,
                server_versions,
            )
            .unwrap(),
        }
    }

    fn set_mtu(&mut self, mtu: usize) {
        self.client.set_mtu(mtu).unwrap();
        self.server.set_mtu(mtu).unwrap();
    }

    fn settled(&self) -> bool {
        !self.client.is_handshaking()
            && !self.server.is_handshaking()
            && self.client.next_timeout().is_none()
            && self.server.next_timeout().is_none()
    }

    /// Runs until both handshakes are complete and every flight is
    /// acknowledged, advancing the clock to the next timer when the
    /// network is quiet.
    fn run(&mut self, net: &mut Net) -> Result<(), Failure> {
        for _ in 0..10_000 {
            let mut moved = false;
            let mut out = Vec::new();
            while self.client.write_datagram(&mut out, net.now).unwrap() {
                net.to_server.send(std::mem::take(&mut out));
                moved = true;
            }
            while self.server.write_datagram(&mut out, net.now).unwrap() {
                net.to_client.send(std::mem::take(&mut out));
                moved = true;
            }
            while let Some(mut datagram) = net.to_server.inbox.pop_front() {
                moved = true;
                let got = self
                    .server
                    .read_datagram(&mut datagram, net.now)
                    .map_err(Failure::Server)?;
                for range in got.app_data() {
                    net.server_received.push(datagram[range.clone()].to_vec());
                }
            }
            while let Some(mut datagram) = net.to_client.inbox.pop_front() {
                moved = true;
                let got = self
                    .client
                    .read_datagram(&mut datagram, net.now)
                    .map_err(Failure::Client)?;
                for range in got.app_data() {
                    net.client_received.push(datagram[range.clone()].to_vec());
                }
            }
            if moved {
                continue;
            }
            if self.settled() {
                return Ok(());
            }
            let next = [self.client.next_timeout(), self.server.next_timeout()]
                .into_iter()
                .flatten()
                .min()
                .ok_or(Failure::Stalled)?;
            net.now = net.now.max(next);
            net.timeouts += 1;
            self.client
                .handle_timeout(net.now)
                .map_err(Failure::Client)?;
            self.server
                .handle_timeout(net.now)
                .map_err(Failure::Server)?;
        }
        panic!("the simulation did not settle");
    }

    /// One datagram of application data each way, delivered.
    fn exchange(&mut self, net: &mut Net) {
        let mut out = Vec::new();
        self.client.send(b"client data", &mut out).unwrap();
        net.to_server.inbox.push_back(std::mem::take(&mut out));
        self.server.send(b"server data", &mut out).unwrap();
        net.to_client.inbox.push_back(out);
        self.run(net).unwrap();
        assert!(net.server_received.contains(&b"client data".to_vec()));
        assert!(net.client_received.contains(&b"server data".to_vec()));
    }

    fn assert_version(&self, version: ProtocolVersion) {
        assert_eq!(self.client.protocol_version(), Some(version));
        assert_eq!(self.server.protocol_version(), Some(version));
    }
}

struct Net {
    now: Duration,
    to_server: Link,
    to_client: Link,
    client_received: Vec<Vec<u8>>,
    server_received: Vec<Vec<u8>>,
    timeouts: usize,
}

impl Net {
    fn new(to_server: Link, to_client: Link) -> Self {
        Self {
            now: Duration::from_secs(1000),
            to_server,
            to_client,
            client_received: Vec::new(),
            server_received: Vec::new(),
            timeouts: 0,
        }
    }

    fn perfect() -> Self {
        Self::new(Link::perfect(), Link::perfect())
    }
}

/// A protected DTLS 1.3 record of epoch 2 (handshake traffic keys) starts
/// the datagram: unified header `001CSLEE` with `EE` = 2 (RFC 9147 §4).
/// Such datagrams carry EncryptedExtensions to Finished.
fn handshake_epoch(datagram: &[u8]) -> bool {
    datagram[0] & 0xe0 == 0x20 && datagram[0] & 0x03 == 2
}

#[test]
fn dtls13_server_and_mutual_authentication_with_every_parameter_set() {
    for set in SETS {
        for mutual in [false, true] {
            let setup = Setup::new(set, mutual);
            let mut pair = Pair::new(&setup.client, &setup.server);
            let mut net = Net::perfect();
            pair.run(&mut net).unwrap();
            pair.assert_version(ProtocolVersion::DTLSv1_3);
            // The cookie exchange (RFC 9147 §5.1) is a HelloRetryRequest.
            assert_eq!(
                pair.client.handshake_kind(),
                Some(HandshakeKind::FullWithHelloRetryRequest)
            );
            setup.assert_schemes(set);
            assert_eq!(pair.client.peer_certificates().unwrap().len(), 2);
            // The default MTU (1200) holds every datagram.
            assert!(net.to_client.largest <= 1200);
            assert!(net.to_server.largest <= 1200);
            println!(
                "{set:?} mutual={mutual}: to client {} datagrams {} bytes, \
                 to server {} datagrams {} bytes",
                net.to_client.sent, net.to_client.bytes, net.to_server.sent, net.to_server.bytes
            );
            pair.exchange(&mut net);
        }
    }
}

/// ML-DSA-87 mutual authentication with the smallest MTU: each side's
/// Certificate (about 15 kB) and CertificateVerify (4627-byte signature)
/// are cut into fragments of at most 256-byte datagrams and reassembled.
#[test]
fn dtls13_ml_dsa_87_flights_fragment_into_small_datagrams() {
    let setup = Setup::new(Set::MlDsa87, true);
    let mut pair = Pair::new(&setup.client, &setup.server);
    pair.set_mtu(256);
    let mut net = Net::perfect();
    pair.run(&mut net).unwrap();
    pair.assert_version(ProtocolVersion::DTLSv1_3);
    setup.assert_schemes(Set::MlDsa87);
    assert!(net.to_client.largest <= 256 && net.to_server.largest <= 256);
    // Two certificates and a signature each way, in 256-byte datagrams.
    let min = (2 * 7_000 + 4627) / 256;
    assert!(net.to_client.sent > min, "{}", net.to_client.sent);
    assert!(net.to_server.sent > min, "{}", net.to_server.sent);
    println!(
        "MTU 256: to client {} datagrams {} bytes, to server {} datagrams {} bytes",
        net.to_client.sent, net.to_client.bytes, net.to_server.sent, net.to_server.bytes
    );
    pair.exchange(&mut net);
}

/// Which handshake-epoch datagrams a perfect handshake sends in each
/// direction, and how many datagrams in all (to client, to server).
fn handshake_epoch_datagrams(setup: &Setup) -> ([Vec<usize>; 2], [usize; 2]) {
    let seen = |log: &Arc<Mutex<Vec<usize>>>| {
        let log = log.clone();
        move |i: usize, d: &[u8]| {
            if handshake_epoch(d) {
                log.lock().unwrap().push(i);
            }
            true
        }
    };
    let (to_client, to_server) = (Arc::default(), Arc::default());
    let mut net = Net::new(Link::new(seen(&to_server)), Link::new(seen(&to_client)));
    Pair::new(&setup.client, &setup.server)
        .run(&mut net)
        .unwrap();
    let take = |log: Arc<Mutex<Vec<usize>>>| std::mem::take(&mut *log.lock().unwrap());
    (
        [take(to_client), take(to_server)],
        [net.to_client.sent, net.to_server.sent],
    )
}

/// Losing any one datagram of either side's encrypted flight (fragments of
/// Certificate, CertificateVerify or Finished) is repaired by the
/// retransmission timer or the peer's ACKs (RFC 9147 §5.8, §7).
#[test]
fn dtls13_ml_dsa_87_lost_fragments_are_retransmitted() {
    let setup = Setup::new(Set::MlDsa87, true);
    let (flights, perfect) = handshake_epoch_datagrams(&setup);
    // At the default MTU each flight takes more than 15 datagrams.
    for flight in &flights {
        assert!(flight.len() > 15, "{flight:?}");
    }
    for (direction, flight) in flights.iter().enumerate() {
        for &lost in flight {
            let drop = move |i: usize, _: &[u8]| i != lost;
            let mut net = match direction {
                0 => Net::new(Link::perfect(), Link::new(drop)),
                _ => Net::new(Link::new(drop), Link::perfect()),
            };
            let mut pair = Pair::new(&setup.client, &setup.server);
            pair.run(&mut net)
                .unwrap_or_else(|e| panic!("direction {direction}, datagram {lost}: {e:?}"));
            pair.assert_version(ProtocolVersion::DTLSv1_3);
            // The lost datagram's records were sent again.
            let sent = [net.to_client.sent, net.to_server.sent];
            assert!(sent[direction] > perfect[direction], "{sent:?} {perfect:?}");
            pair.exchange(&mut net);
        }
    }
    // Each verifier checked one signature per handshake, all ML-DSA-87.
    let handshakes = 1 + flights[0].len() + flights[1].len();
    assert_eq!(
        setup.server_auth.seen(),
        vec![SignatureScheme::ML_DSA_87; handshakes]
    );
    let client_auth = setup.client_auth.as_ref().unwrap();
    assert_eq!(
        client_auth.seen(),
        vec![SignatureScheme::ML_DSA_87; handshakes]
    );
}

/// A resumed DTLS 1.3 connection authenticates with the ticket's PSK: no
/// second ML-DSA signature.
#[test]
fn dtls13_resumption_after_ml_dsa_authentication() {
    let setup = Setup::new(Set::MlDsa44, true);
    let server = {
        // One ticketer for both connections.
        let mut server = (*setup.server).clone();
        server.ticketer = crate::prov::Ticketer::new().unwrap();
        server.hello_retry_cookies = Some(crate::prov::Ticketer::new().unwrap());
        Arc::new(server)
    };
    let connect = || {
        let mut pair = Pair {
            client: dtls::ClientConnection::new(setup.client.clone(), server_name()).unwrap(),
            server: dtls::ServerConnection::new(server.clone(), PEER).unwrap(),
        };
        let mut net = Net::perfect();
        pair.run(&mut net).unwrap();
        pair.exchange(&mut net);
        pair
    };
    let first = connect();
    assert!(first.client.tls13_tickets_received() > 0);
    let resumed = connect();
    assert_eq!(
        resumed.server.handshake_kind(),
        Some(HandshakeKind::Resumed)
    );
    setup.assert_schemes(Set::MlDsa44);
}

/// Runs `pair` until the server fails, hands the client whatever the
/// server sent after that, and drives the client's timers for a while (or
/// until the client gives up). Returns the server's error, after checking
/// that the client neither completed its handshake nor can send
/// application data; how the client ends (the error it reports, if any,
/// and how often it retransmits) is not pinned.
fn server_failure(pair: &mut Pair) -> Error {
    let mut net = Net::perfect();
    let failure = pair.run(&mut net).unwrap_err();
    let Failure::Server(server_error) = failure else {
        panic!("{failure:?}");
    };
    let mut datagram = Vec::new();
    while pair.server.write_datagram(&mut datagram, net.now).unwrap() {
        if let Ok(got) = pair.client.read_datagram(&mut datagram, net.now) {
            assert!(got.app_data().is_empty());
        }
        datagram.clear();
    }
    let mut more = Vec::new();
    for _ in 0..32 {
        let Some(now) = pair.client.next_timeout() else {
            break;
        };
        if pair.client.handle_timeout(now).is_err() {
            break;
        }
        while pair.client.write_datagram(&mut more, now).unwrap_or(false) {
            more.clear();
        }
    }
    assert!(pair.client.is_handshaking());
    assert!(pair.client.peer_certificates().is_none());
    let mut out = Vec::new();
    assert!(pair.client.send(b"too early", &mut out).is_err());
    assert!(out.is_empty());
    server_error
}

/// A DTLS 1.3 client without the opt-in offers no ML-DSA scheme: the
/// server finds none to sign with and fails with handshake_failure. The
/// same with a classical server key and a client offering no scheme that
/// key can sign with.
///
/// Only the server's error is pinned. The client's outcome is not: how a
/// failing server's alert reaches a client that has not yet processed the
/// ServerHello is a known limitation of the DTLS 1.3 layer, independent of
/// ML-DSA. The client only has to stay short of a completed handshake.
#[test]
fn dtls13_client_without_the_opt_in_fails() {
    let setup = Setup::new(Set::MlDsa87, false);
    let provider = browntls_core::crypto::native::default_provider();
    let client = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(setup.server_id.chain.roots())
        .with_no_client_auth();
    let mut pair = Pair::new(&Arc::new(client), &setup.server);
    assert_eq!(
        server_failure(&mut pair),
        Error::PeerIncompatible(PeerIncompatible::NoSignatureSchemesInCommon)
    );

    // The same with an ECDSA server and a client offering only Ed25519.
    let chain = crate::common::server_chain(KeyType::EcdsaP256);
    let verifier = crate::common::SchemeRecordingServerVerifier::new(
        PinnedServerVerifier::new(&chain),
        &[SignatureScheme::ED25519],
    );
    let client = ClientConfig::builder_with_provider(opt_in())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(opt_in())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let mut pair = Pair::new(&Arc::new(client), &Arc::new(server));
    assert_eq!(
        server_failure(&mut pair),
        Error::PeerIncompatible(PeerIncompatible::NoSignatureSchemesInCommon)
    );
}

// ------------------------------------------------------------- DTLS 1.2

#[cfg(feature = "tls12")]
mod dtls12 {
    use browntls_core::client::ResolvesClientCert;
    use browntls_core::server::{ClientHello, ResolvesServerCert};
    use browntls_core::sign::CertifiedKey;
    use browntls_core::version::TLS12;

    use super::*;
    use crate::common::{SchemeRecordingClientVerifier, client_chain};
    use crate::identity::{Identity, scheme};
    use crate::support::Purpose;

    /// Records the `signature_algorithms` of each ClientHello, then resolves
    /// with the inner resolver.
    #[derive(Debug)]
    struct HelloRecorder {
        inner: Arc<dyn ResolvesServerCert>,
        seen: Mutex<Vec<Vec<SignatureScheme>>>,
    }

    impl ResolvesServerCert for HelloRecorder {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            self.seen
                .lock()
                .unwrap()
                .push(client_hello.signature_schemes().to_vec());
            self.inner.resolve(client_hello)
        }
    }

    /// Records the schemes of each CertificateRequest, answering with `key`.
    #[derive(Debug)]
    struct RequestRecorder {
        key: Arc<CertifiedKey>,
        seen: Mutex<Vec<Vec<SignatureScheme>>>,
    }

    impl ResolvesClientCert for RequestRecorder {
        fn resolve(
            &self,
            _root_hint_subjects: &[&[u8]],
            sigschemes: &[SignatureScheme],
        ) -> Option<Arc<CertifiedKey>> {
            self.seen.lock().unwrap().push(sigschemes.to_vec());
            Some(self.key.clone())
        }

        fn has_certs(&self) -> bool {
            true
        }
    }

    fn has_ml_dsa(schemes: &[SignatureScheme]) -> bool {
        SETS.iter().any(|set| schemes.contains(&scheme(*set)))
    }

    /// An opt-in client limited to DTLS 1.2 against a server whose only key
    /// is ML-DSA: the ClientHello lists no ML-DSA scheme (it does not offer
    /// DTLS 1.3) and the server has no TLS 1.2 credential to use.
    #[test]
    fn dtls12_client_with_the_opt_in_and_an_ml_dsa_server_fail() {
        for set in SETS {
            let setup = Setup::new(set, false);
            let mut server = ServerConfig::builder_with_provider(opt_in())
                .with_protocol_versions(&[&TLS13, &TLS12])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(setup.server_id.served(), setup.server_id.private_key())
                .unwrap();
            let recorder = Arc::new(HelloRecorder {
                inner: server.cert_resolver.clone(),
                seen: Mutex::default(),
            });
            server.cert_resolver = recorder.clone();
            let client = ClientConfig::builder_with_provider(opt_in())
                .with_protocol_versions(&[&TLS13, &TLS12])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(setup.server_auth.clone())
                .with_no_client_auth();
            let mut pair = Pair::with_versions(
                &Arc::new(client),
                &Arc::new(server),
                dtls::Versions::V1_2,
                dtls::Versions::V1_2And1_3,
            );
            let failure = pair.run(&mut Net::perfect()).unwrap_err();
            let Failure::Server(error) = failure else {
                panic!("{set:?}: {failure:?}");
            };
            // The key's TLS 1.2 `SignatureAlgorithm` is no assigned value, so
            // no TLS 1.2 suite suits it.
            assert_eq!(
                error,
                Error::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon),
                "{set:?}"
            );
            let seen = recorder.seen.lock().unwrap();
            assert!(
                !seen.is_empty() && seen.iter().all(|s| !has_ml_dsa(s)),
                "{seen:?}"
            );
            assert!(setup.server_auth.seen().is_empty());
        }
    }

    /// A server whose client verifier offers the ML-DSA schemes lists them in
    /// a DTLS 1.3 CertificateRequest and drops them from a DTLS 1.2 one.
    #[test]
    fn dtls12_certificate_request_lists_no_ml_dsa_scheme() {
        let server_id = Identity::new(Set::MlDsa65, Purpose::Server);
        // A classical client certificate, so that DTLS 1.2 can complete.
        let client = client_chain(KeyType::EcdsaP256);
        let key = Arc::new(
            CertifiedKey::from_der(client.cert_chain(), client.private_key(), &opt_in()).unwrap(),
        );
        let offer =
            browntls_core::crypto::native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13.supported_schemes();
        assert!(has_ml_dsa(&offer));
        for (versions, ml_dsa_listed) in
            [(dtls::Versions::V1_3, true), (dtls::Versions::V1_2, false)]
        {
            let client_auth = SchemeRecordingClientVerifier::new(
                crate::common::PinnedClientVerifier::new(&client, true),
                &offer,
            );
            // DTLS 1.2 needs a classical server key; DTLS 1.3 uses ML-DSA.
            let server = ServerConfig::builder_with_provider(opt_in())
                .with_protocol_versions(&[&TLS13, &TLS12])
                .unwrap()
                .with_client_cert_verifier(client_auth.clone());
            let (server, verifier) = if ml_dsa_listed {
                let server = server
                    .with_single_cert(server_id.served(), server_id.private_key())
                    .unwrap();
                (server, server_id.server_verifier())
            } else {
                let chain = crate::common::server_chain(KeyType::EcdsaP256);
                let server = server
                    .with_single_cert(chain.cert_chain(), chain.private_key())
                    .unwrap();
                let verifier = crate::common::SchemeRecordingServerVerifier::new(
                    PinnedServerVerifier::new(&chain),
                    &offer,
                );
                (server, verifier)
            };
            let requests = Arc::new(RequestRecorder {
                key: key.clone(),
                seen: Mutex::default(),
            });
            let client_config = ClientConfig::builder_with_provider(opt_in())
                .with_protocol_versions(&[&TLS13, &TLS12])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_cert_resolver(requests.clone());
            let mut pair = Pair::with_versions(
                &Arc::new(client_config),
                &Arc::new(server),
                versions,
                dtls::Versions::V1_2And1_3,
            );
            pair.run(&mut Net::perfect())
                .unwrap_or_else(|e| panic!("{versions:?}: {e:?}"));
            pair.assert_version(match versions {
                dtls::Versions::V1_3 => ProtocolVersion::DTLSv1_3,
                _ => ProtocolVersion::DTLSv1_2,
            });
            let seen = requests.seen.lock().unwrap();
            assert_eq!(seen.len(), 1, "{versions:?}");
            assert_eq!(
                has_ml_dsa(&seen[0]),
                ml_dsa_listed,
                "{versions:?}: {:?}",
                seen[0]
            );
            // The client signed with its ECDSA key either way.
            assert_eq!(
                client_auth.seen(),
                [SignatureScheme::ECDSA_NISTP256_SHA256],
                "{versions:?}"
            );
        }
    }

    /// A DTLS 1.2-only server with a classical key against a client that
    /// offers DTLS 1.2 and 1.3 and whose verifier has the opt-in (so its
    /// hello lists the ML-DSA schemes, for DTLS 1.3): the handshake goes
    /// through a HelloVerifyRequest (RFC 6347 §4.2.1) and completes over
    /// DTLS 1.2 with the classical scheme, and the server's certificate
    /// resolver sees no ML-DSA scheme.
    #[test]
    fn dtls12_server_with_a_classical_key_and_an_opt_in_client() {
        let chain = crate::common::server_chain(KeyType::EcdsaP256);
        let mut server = ServerConfig::builder_with_provider(opt_in())
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        let recorder = Arc::new(HelloRecorder {
            inner: server.cert_resolver.clone(),
            seen: Mutex::default(),
        });
        server.cert_resolver = recorder.clone();
        let offer =
            browntls_core::crypto::native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13.supported_schemes();
        assert!(has_ml_dsa(&offer));
        let verifier = crate::common::SchemeRecordingServerVerifier::new(
            PinnedServerVerifier::new(&chain),
            &offer,
        );
        let client = ClientConfig::builder_with_provider(opt_in())
            .with_protocol_versions(&[&TLS13, &TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        let mut pair = Pair::with_versions(
            &Arc::new(client),
            &Arc::new(server),
            dtls::Versions::V1_2And1_3,
            dtls::Versions::V1_2,
        );
        // DTLS 1.2 plaintext handshake records (type 22) whose first
        // message is a HelloVerifyRequest (type 3, after the 13-byte record
        // header).
        let verify_requests = Arc::new(Mutex::new(0));
        let count = verify_requests.clone();
        let to_client = Link::new(move |_, d: &[u8]| {
            if d.len() > 13 && d[0] == 22 && d[13] == 3 {
                *count.lock().unwrap() += 1;
            }
            true
        });
        let mut net = Net::new(Link::perfect(), to_client);
        pair.run(&mut net).unwrap();
        pair.assert_version(ProtocolVersion::DTLSv1_2);
        assert_eq!(*verify_requests.lock().unwrap(), 1);
        assert_eq!(verifier.seen(), [SignatureScheme::ECDSA_NISTP256_SHA256]);
        let seen = recorder.seen.lock().unwrap().clone();
        assert!(
            !seen.is_empty() && seen.iter().all(|s| !s.is_empty() && !has_ml_dsa(s)),
            "{seen:?}"
        );
        pair.exchange(&mut net);
    }
}

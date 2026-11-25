//! DTLS 1.3 (RFC 9147) with legacy RSA client authentication over a
//! simulated datagram network with a virtual clock, including a lost
//! datagram of the client's encrypted flight that is retransmitted
//! (§5.8). DTLS 1.2 never uses a legacy scheme: RFC 9963 defines them for
//! TLS 1.3 only, so a DTLS 1.2 CertificateRequest does not list them (read
//! from the datagrams) and the legacy key signs with a TLS 1.2 scheme
//! there.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use browntls_core::{
    ClientConfig, Error, HandshakeKind, ProtocolVersion, ServerConfig, SignatureScheme, dtls,
};

use crate::common::server_name;
use crate::identity::{Setup, rsa_client};

const PEER: &[u8] = b"192.0.2.1:4433";

/// Decides whether the n-th datagram of a direction is delivered.
type Policy = Box<dyn FnMut(usize, &[u8]) -> bool>;

/// One direction of the network.
struct Link {
    policy: Policy,
    sent: usize,
    inbox: VecDeque<Vec<u8>>,
}

impl Link {
    fn new(policy: impl FnMut(usize, &[u8]) -> bool + 'static) -> Self {
        Self {
            policy: Box::new(policy),
            sent: 0,
            inbox: VecDeque::new(),
        }
    }

    fn perfect() -> Self {
        Self::new(|_, _| true)
    }

    fn send(&mut self, datagram: Vec<u8>) {
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
}

impl Net {
    fn new(to_server: Link, to_client: Link) -> Self {
        Self {
            now: Duration::from_secs(1000),
            to_server,
            to_client,
            client_received: Vec::new(),
            server_received: Vec::new(),
        }
    }

    fn perfect() -> Self {
        Self::new(Link::perfect(), Link::perfect())
    }
}

/// A protected DTLS 1.3 record of epoch 2 (handshake traffic keys) starts
/// the datagram: unified header `001CSLEE` with `EE` = 2 (RFC 9147 §4).
/// From the client such datagrams carry its Certificate, CertificateVerify
/// and Finished.
fn handshake_epoch(datagram: &[u8]) -> bool {
    datagram[0] & 0xe0 == 0x20 && datagram[0] & 0x03 == 2
}

/// The legacy key authenticates a DTLS 1.3 client to an opted-in server:
/// after the cookie exchange (a HelloRetryRequest, RFC 9147 §5.1) the
/// server verifies exactly one `rsa_pkcs1_sha512_legacy` signature and
/// sees the client's chain, and data flows both ways.
#[test]
fn dtls13_mutual_authentication_with_the_legacy_key() {
    let setup = Setup::new(true);
    let mut pair = Pair::new(&setup.client, &setup.server);
    let mut net = Net::perfect();
    pair.run(&mut net).unwrap();
    pair.assert_version(ProtocolVersion::DTLSv1_3);
    assert_eq!(
        pair.client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    setup.assert_schemes();
    assert_eq!(
        pair.server.peer_certificates().unwrap(),
        rsa_client().cert_chain()
    );
    pair.exchange(&mut net);
}

/// Losing any one handshake-epoch datagram from the client (its
/// Certificate, legacy CertificateVerify or Finished) is repaired by
/// retransmission (RFC 9147 §5.8, §7); every handshake completes with the
/// legacy scheme.
#[test]
fn dtls13_lost_client_datagram_is_retransmitted() {
    let setup = Setup::new(true);
    // The handshake-epoch datagrams of a perfect handshake, to the server.
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    let to_server = Link::new(move |i, d: &[u8]| {
        if handshake_epoch(d) {
            seen.lock().unwrap().push(i);
        }
        true
    });
    let mut net = Net::new(to_server, Link::perfect());
    Pair::new(&setup.client, &setup.server)
        .run(&mut net)
        .unwrap();
    let perfect = net.to_server.sent;
    let flight = std::mem::take(&mut *log.lock().unwrap());
    assert!(!flight.is_empty());

    for &lost in &flight {
        let drop = move |i: usize, _: &[u8]| i != lost;
        let mut net = Net::new(Link::new(drop), Link::perfect());
        let mut pair = Pair::new(&setup.client, &setup.server);
        pair.run(&mut net)
            .unwrap_or_else(|e| panic!("datagram {lost}: {e:?}"));
        pair.assert_version(ProtocolVersion::DTLSv1_3);
        // The lost datagram's records were sent again.
        assert!(
            net.to_server.sent > perfect,
            "{} {perfect}",
            net.to_server.sent
        );
        assert_eq!(
            pair.server.peer_certificates().unwrap(),
            rsa_client().cert_chain()
        );
        pair.exchange(&mut net);
    }
    // One legacy signature verified per handshake.
    assert_eq!(
        setup.client_auth.seen(),
        vec![SignatureScheme::RSA_PKCS1_SHA512_LEGACY; 1 + flight.len()]
    );
}

/// Against a DTLS 1.3 server without the opt-in the legacy key does not
/// sign and the client sends an empty Certificate: the server fails
/// mandatory client authentication with `NoCertificatesPresented`, and
/// its `certificate_required` alert ends the client.
#[test]
fn dtls13_default_server_refuses_the_legacy_key() {
    let setup = Setup::new(false);
    let mut pair = Pair::new(&setup.client, &setup.server);
    let mut net = Net::perfect();
    let failure = pair.run(&mut net).unwrap_err();
    let Failure::Server(error) = failure else {
        panic!("{failure:?}");
    };
    assert_eq!(error, Error::NoCertificatesPresented);
    assert!(setup.client_auth.seen().is_empty());
    assert!(pair.server.peer_certificates().is_none());

    // The server's alert, delivered to the client.
    let mut client_error = None;
    let mut datagram = Vec::new();
    while pair.server.write_datagram(&mut datagram, net.now).unwrap() {
        if let Err(e) = pair.client.read_datagram(&mut datagram, net.now) {
            client_error = Some(e);
        }
        datagram.clear();
    }
    assert_eq!(
        client_error,
        Some(Error::AlertReceived(
            browntls_core::AlertDescription::CertificateRequired
        ))
    );
}

// ------------------------------------------------------------- DTLS 1.2

#[cfg(feature = "tls12")]
mod dtls12 {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use browntls_core::client::ResolvesClientCert;
    use browntls_core::server::{ClientHello, ResolvesServerCert};
    use browntls_core::sign::CertifiedKey;
    use browntls_core::version::{TLS12, TLS13};

    use super::*;
    use crate::common::SchemeRecordingServerVerifier;
    use crate::identity::{
        OPT_IN_ORDER, client_config, client_verifier, is_legacy, legacy_certified_key, opt_in,
        server_config, server_verifier,
    };

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

    fn be24(bytes: &[u8]) -> usize {
        usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2])
    }

    /// The bodies of the handshake messages of type `typ` in the
    /// unprotected records (epoch 0) of DTLS 1.2 `datagrams`, each
    /// reassembled from its fragments (RFC 6347 §4.1 and §4.2.2), in the
    /// order of their message sequence numbers.
    fn dtls12_messages(datagrams: &[Vec<u8>], typ: u8) -> Vec<Vec<u8>> {
        let mut messages: BTreeMap<[u8; 2], (Vec<u8>, Vec<bool>)> = BTreeMap::new();
        for datagram in datagrams {
            let mut rest = &datagram[..];
            while !rest.is_empty() {
                // type, version, epoch, sequence number, length
                let len = usize::from(u16::from_be_bytes([rest[11], rest[12]]));
                let (record, tail) = rest[13..].split_at(len);
                let unprotected_handshake = rest[0] == 22 && rest[3..5] == [0, 0];
                rest = tail;
                let mut fragments = if unprotected_handshake { record } else { &[] };
                while !fragments.is_empty() {
                    // msg_type, length, message_seq, fragment_offset,
                    // fragment_length
                    let total = be24(&fragments[1..4]);
                    let (offset, len) = (be24(&fragments[6..9]), be24(&fragments[9..12]));
                    let (fragment, tail) = fragments[12..].split_at(len);
                    if fragments[0] == typ {
                        let (body, have) = messages
                            .entry([fragments[4], fragments[5]])
                            .or_insert_with(|| (vec![0; total], vec![false; total]));
                        body[offset..offset + len].copy_from_slice(fragment);
                        have[offset..offset + len].fill(true);
                    }
                    fragments = tail;
                }
            }
        }
        messages
            .into_values()
            .map(|(body, have)| {
                assert!(have.iter().all(|have| *have), "a fragment is missing");
                body
            })
            .collect()
    }

    /// The code points of a `SignatureSchemeList` at the start of `list`.
    fn schemes(list: &[u8]) -> Vec<u16> {
        let len = usize::from(u16::from_be_bytes([list[0], list[1]]));
        list[2..2 + len]
            .chunks(2)
            .map(|scheme| u16::from_be_bytes([scheme[0], scheme[1]]))
            .collect()
    }

    /// The `supported_signature_algorithms` of the one DTLS 1.2
    /// CertificateRequest in the server's `datagrams`, as sent.
    fn request_schemes(datagrams: &[Vec<u8>]) -> Vec<u16> {
        let requests = dtls12_messages(datagrams, 13);
        assert_eq!(requests.len(), 1, "one CertificateRequest");
        // certificate_types<1..2^8-1>, supported_signature_algorithms
        schemes(&requests[0][1 + usize::from(requests[0][0])..])
    }

    /// The `signature_algorithms` of each DTLS 1.2 ClientHello in the
    /// client's `datagrams` (the one answered with a HelloVerifyRequest and
    /// the one with its cookie), as sent.
    fn hello_schemes(datagrams: &[Vec<u8>]) -> Vec<Vec<u16>> {
        dtls12_messages(datagrams, 1)
            .iter()
            .map(|hello| {
                // client_version, random, session_id, cookie
                let mut at = 2 + 32;
                at += 1 + usize::from(hello[at]);
                at += 1 + usize::from(hello[at]);
                // cipher_suites, compression_methods
                at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
                at += 1 + usize::from(hello[at]);
                let mut extensions = &hello[at + 2..];
                loop {
                    let len = usize::from(u16::from_be_bytes([extensions[2], extensions[3]]));
                    if extensions[..2] == [0, 13] {
                        return schemes(&extensions[4..4 + len]);
                    }
                    extensions = &extensions[4 + len..];
                }
            })
            .collect()
    }

    /// Both sides opted in everywhere and allow DTLS 1.2 and 1.3, the
    /// client offering one version at a time, and the client's verifier
    /// advertises the legacy schemes. In DTLS 1.3 the CertificateRequest
    /// ends with the three legacy schemes and the key signs with
    /// `rsa_pkcs1_sha512_legacy`; the hello's list, which the server's
    /// resolver sees as sent, holds no legacy scheme. In DTLS 1.2 the same
    /// key signs with `rsa_pkcs1_sha512`, a TLS 1.2 scheme, and neither the
    /// CertificateRequest nor a ClientHello lists a legacy scheme: read
    /// from the datagrams, since in TLS 1.2 both sides drop the legacy
    /// schemes from a peer's list before a resolver sees it.
    #[test]
    fn dtls12_and_dtls13_with_the_legacy_key_and_an_opted_in_server() {
        let cases = [
            (
                dtls::Versions::V1_3,
                ProtocolVersion::DTLSv1_3,
                SignatureScheme::RSA_PKCS1_SHA512_LEGACY,
            ),
            (
                dtls::Versions::V1_2,
                ProtocolVersion::DTLSv1_2,
                SignatureScheme::RSA_PKCS1_SHA512,
            ),
        ];
        for (versions, version, expected) in cases {
            let client_auth = client_verifier(opt_in());
            // The client's verifier advertises the legacy schemes too, as
            // only a custom verifier does (the library's leaves them out of
            // its list): a ClientHello must still not list them.
            let library = server_verifier(opt_in());
            let advertised = [&library.offer[..], &OPT_IN_ORDER[..]].concat();
            let server_auth = SchemeRecordingServerVerifier::new(library, &advertised);
            let mut server = server_config(opt_in(), &client_auth, &[&TLS13, &TLS12]);
            let hellos = Arc::new(HelloRecorder {
                inner: server.cert_resolver.clone(),
                seen: Mutex::default(),
            });
            server.cert_resolver = hellos.clone();
            let requests = Arc::new(RequestRecorder {
                key: Arc::new(legacy_certified_key()),
                seen: Mutex::default(),
            });
            let mut client = client_config(opt_in(), &server_auth, &[&TLS13, &TLS12]);
            client.client_auth_cert_resolver = requests.clone();
            let mut pair = Pair::with_versions(
                &Arc::new(client),
                &Arc::new(server),
                versions,
                dtls::Versions::V1_2And1_3,
            );
            let sent = [(); 2].map(|()| Rc::new(RefCell::new(Vec::new())));
            let [to_server, to_client] = sent.clone().map(|sent| {
                Link::new(move |_, datagram: &[u8]| {
                    sent.borrow_mut().push(datagram.to_vec());
                    true
                })
            });
            let mut net = Net::new(to_server, to_client);
            pair.run(&mut net)
                .unwrap_or_else(|e| panic!("{versions:?}: {e:?}"));
            pair.assert_version(version);
            if version == ProtocolVersion::DTLSv1_2 {
                let [from_client, from_server] = sent.map(|sent| sent.borrow().clone());
                let listed = request_schemes(&from_server);
                assert!(
                    listed.contains(&u16::from(SignatureScheme::RSA_PKCS1_SHA512))
                        && listed.iter().all(|s| !is_legacy(&(*s).into())),
                    "{listed:04x?}"
                );
                let hellos = hello_schemes(&from_client);
                assert!(
                    !hellos.is_empty()
                        && hellos
                            .iter()
                            .all(|s| !s.is_empty() && s.iter().all(|s| !is_legacy(&(*s).into()))),
                    "{hellos:04x?}"
                );
            }
            assert_eq!(client_auth.seen(), [expected], "{versions:?}");
            assert_eq!(
                is_legacy(&client_auth.seen()[0]),
                version == ProtocolVersion::DTLSv1_3
            );
            assert_eq!(
                server_auth.seen(),
                [SignatureScheme::ECDSA_NISTP256_SHA256],
                "{versions:?}"
            );
            assert_eq!(
                pair.server.peer_certificates().unwrap(),
                rsa_client().cert_chain()
            );

            let requests = requests.seen.lock().unwrap().clone();
            assert_eq!(requests.len(), 1, "{versions:?}");
            if version == ProtocolVersion::DTLSv1_3 {
                assert!(requests[0].ends_with(&OPT_IN_ORDER), "{:?}", requests[0]);
            } else {
                assert!(
                    requests[0].iter().all(|s| !is_legacy(s)),
                    "{:?}",
                    requests[0]
                );
                assert!(requests[0].contains(&SignatureScheme::RSA_PKCS1_SHA512));
            }
            let hellos = hellos.seen.lock().unwrap().clone();
            assert!(
                !hellos.is_empty()
                    && hellos
                        .iter()
                        .all(|s| !s.is_empty() && s.iter().all(|s| !is_legacy(s))),
                "{versions:?}: {hellos:?}"
            );
            pair.exchange(&mut net);
        }
    }
}

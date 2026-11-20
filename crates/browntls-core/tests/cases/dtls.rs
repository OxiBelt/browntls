// Shared cases, included by `tests/dtls.rs` (RustCrypto provider) and
// `tests/dtls_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.
//
// DTLS 1.3 (RFC 9147) between two browntls endpoints over a simulated
// datagram network with a virtual clock: handshakes with and without the
// cookie exchange, loss, duplication, reordering, corruption, small
// datagrams, resumption, key updates, closure and timeouts.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::dtls;
use browntls_core::{ClientConfig, Error, HandshakeKind, ProtocolVersion, ServerConfig, SideData};
use common::*;

// ------------------------------------------------------------- simulation

/// What the network does with one datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fate {
    Deliver,
    Drop,
    Duplicate,
    /// Delivered after the next datagram in the same direction.
    Hold,
    /// One byte flipped (the receiver must drop the damaged record).
    Corrupt,
}

/// Decides the fate of the n-th datagram of a direction.
type Policy = Box<dyn FnMut(usize, &[u8]) -> Fate>;

/// One direction of the network.
struct Link {
    policy: Policy,
    sent: usize,
    held: Option<Vec<u8>>,
    inbox: VecDeque<Vec<u8>>,
}

impl Link {
    fn new(policy: impl FnMut(usize, &[u8]) -> Fate + 'static) -> Self {
        Self {
            policy: Box::new(policy),
            sent: 0,
            held: None,
            inbox: VecDeque::new(),
        }
    }

    fn perfect() -> Self {
        Self::new(|_, _| Fate::Deliver)
    }

    fn send(&mut self, mut datagram: Vec<u8>) {
        let fate = (self.policy)(self.sent, &datagram);
        self.sent += 1;
        match fate {
            Fate::Deliver => {
                self.inbox.push_back(datagram);
                self.release();
            }
            Fate::Drop => {}
            Fate::Duplicate => {
                self.inbox.push_back(datagram.clone());
                self.inbox.push_back(datagram);
                self.release();
            }
            Fate::Hold => {
                if let Some(held) = self.held.replace(datagram) {
                    self.inbox.push_back(held);
                }
            }
            // Unprotected records cannot be told from forgeries: damaged
            // hellos fail the handshake as they must (RFC 9147 §5.1), so
            // only protected records are damaged.
            Fate::Corrupt if datagram[0] & 0xe0 != 0x20 => {
                self.inbox.push_back(datagram);
                self.release();
            }
            Fate::Corrupt => {
                let at = datagram.len() - 1;
                datagram[at] ^= 0x10;
                self.inbox.push_back(datagram);
                self.release();
            }
        }
    }

    fn release(&mut self) {
        if let Some(held) = self.held.take() {
            self.inbox.push_back(held);
        }
    }
}

/// A DTLS endpoint as the simulation drives it.
trait Endpoint {
    fn write(&mut self, out: &mut Vec<u8>, now: Duration) -> bool;
    fn read(&mut self, datagram: &mut [u8], now: Duration) -> Result<Vec<Vec<u8>>, Error>;
    fn timeout(&self) -> Option<Duration>;
    fn on_timeout(&mut self, now: Duration) -> Result<(), Error>;
    fn handshaking(&self) -> bool;
}

impl<D: SideData> Endpoint for dtls::ConnectionCommon<D> {
    fn write(&mut self, out: &mut Vec<u8>, now: Duration) -> bool {
        self.write_datagram(out, now).unwrap()
    }

    fn read(&mut self, datagram: &mut [u8], now: Duration) -> Result<Vec<Vec<u8>>, Error> {
        let received = self.read_datagram(datagram, now)?;
        Ok(received
            .app_data()
            .iter()
            .map(|range| datagram[range.clone()].to_vec())
            .collect())
    }

    fn timeout(&self) -> Option<Duration> {
        self.next_timeout()
    }

    fn on_timeout(&mut self, now: Duration) -> Result<(), Error> {
        self.handle_timeout(now)
    }

    fn handshaking(&self) -> bool {
        self.is_handshaking()
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

/// The network between a client and a server, and the virtual clock.
struct Sim {
    now: Duration,
    to_server: Link,
    to_client: Link,
    client_received: Vec<Vec<u8>>,
    server_received: Vec<Vec<u8>>,
    datagrams: usize,
}

impl Sim {
    fn new(to_server: Link, to_client: Link) -> Self {
        Self {
            now: Duration::from_secs(1000),
            to_server,
            to_client,
            client_received: Vec::new(),
            server_received: Vec::new(),
            datagrams: 0,
        }
    }

    fn perfect() -> Self {
        Self::new(Link::perfect(), Link::perfect())
    }

    /// Runs until neither side has anything to send, nothing is in flight
    /// and no timer is armed (or only `until` holds), advancing the clock
    /// to the next timer whenever the network is quiet.
    fn run(
        &mut self,
        client: &mut dyn Endpoint,
        server: &mut dyn Endpoint,
        until: impl Fn(&dyn Endpoint, &dyn Endpoint) -> bool,
    ) -> Result<(), Failure> {
        for _ in 0..100_000 {
            let mut moved = false;
            let mut out = Vec::new();
            while client.write(&mut out, self.now) {
                assert!(out.len() <= 65_507);
                self.to_server.send(std::mem::take(&mut out));
                self.datagrams += 1;
                moved = true;
            }
            while server.write(&mut out, self.now) {
                self.to_client.send(std::mem::take(&mut out));
                self.datagrams += 1;
                moved = true;
            }
            while let Some(mut datagram) = self.to_server.inbox.pop_front() {
                moved = true;
                let data = server
                    .read(&mut datagram, self.now)
                    .map_err(Failure::Server)?;
                self.server_received.extend(data);
            }
            while let Some(mut datagram) = self.to_client.inbox.pop_front() {
                moved = true;
                let data = client
                    .read(&mut datagram, self.now)
                    .map_err(Failure::Client)?;
                self.client_received.extend(data);
            }
            if moved {
                continue;
            }
            if self.to_server.held.is_some() || self.to_client.held.is_some() {
                self.to_server.release();
                self.to_client.release();
                continue;
            }
            if until(client, server) {
                return Ok(());
            }
            let next = match (client.timeout(), server.timeout()) {
                (Some(a), Some(b)) => a.min(b),
                (a, b) => match a.or(b) {
                    Some(t) => t,
                    None => return Err(Failure::Stalled),
                },
            };
            self.now = self.now.max(next);
            client.on_timeout(self.now).map_err(Failure::Client)?;
            server.on_timeout(self.now).map_err(Failure::Server)?;
        }
        panic!("the simulation did not settle");
    }

    /// Runs until both handshakes are complete and every flight is
    /// acknowledged.
    fn handshake(
        &mut self,
        client: &mut dyn Endpoint,
        server: &mut dyn Endpoint,
    ) -> Result<(), Failure> {
        self.run(client, server, settled)
    }
}

fn settled(client: &dyn Endpoint, server: &dyn Endpoint) -> bool {
    !client.handshaking()
        && !server.handshaking()
        && client.timeout().is_none()
        && server.timeout().is_none()
}

// ----------------------------------------------------------------- configs

const PEER: &[u8] = b"192.0.2.1:4433";

fn dtls_server_config(chain: &Chain) -> ServerConfig {
    let mut config = server_config(chain);
    config.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
    config.ticketer = prov::Ticketer::new().unwrap();
    config
}

struct Pair {
    client: dtls::ClientConnection,
    server: dtls::ServerConnection,
}

impl Pair {
    fn new(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Self {
        Self {
            client: dtls::ClientConnection::new(client.clone(), server_name()).unwrap(),
            server: dtls::ServerConnection::new(server.clone(), PEER).unwrap(),
        }
    }

    fn default_pair() -> (Self, Arc<ClientConfig>, Arc<ServerConfig>) {
        let chain = server_chain(KeyType::EcdsaP256);
        let client = Arc::new(client_config(&chain));
        let server = Arc::new(dtls_server_config(&chain));
        (Self::new(&client, &server), client, server)
    }

    fn run(
        &mut self,
        sim: &mut Sim,
        until: impl Fn(&dyn Endpoint, &dyn Endpoint) -> bool,
    ) -> Result<(), Failure> {
        sim.run(&mut *self.client, &mut *self.server, until)
    }

    fn handshake(&mut self, sim: &mut Sim) -> Result<(), Failure> {
        sim.handshake(&mut *self.client, &mut *self.server)
    }

    /// Sends one datagram of application data each way and checks both
    /// arrive.
    fn exchange(&mut self, sim: &mut Sim, tag: &str) {
        let to_server = format!("client says {tag}").into_bytes();
        let to_client = format!("server says {tag}").into_bytes();
        let mut out = Vec::new();
        // The data itself is not lost: the policies apply to the protocol.
        self.client.send(&to_server, &mut out).unwrap();
        sim.to_server.inbox.push_back(std::mem::take(&mut out));
        self.server.send(&to_client, &mut out).unwrap();
        sim.to_client.inbox.push_back(out);
        self.run(sim, settled).unwrap();
        assert!(sim.server_received.contains(&to_server), "{tag}");
        assert!(sim.client_received.contains(&to_client), "{tag}");
    }
}

fn assert_dtls13(pair: &Pair) {
    for common in [
        &**pair.client as &browntls_core::CommonState,
        &**pair.server,
    ] {
        assert_eq!(common.protocol_version(), Some(ProtocolVersion::DTLSv1_3));
        assert!(!common.is_handshaking());
    }
}

// ------------------------------------------------------------------ cases

#[test]
fn handshake_with_cookie_and_data_every_key_type() {
    for key_type in KeyType::ALL {
        if key_type == KeyType::Rsa2048 && !prov::SIGNS_RSA {
            continue;
        }
        let chain = server_chain(key_type);
        let client = Arc::new(client_config(&chain));
        let server = Arc::new(dtls_server_config(&chain));
        let mut pair = Pair::new(&client, &server);
        let mut sim = Sim::perfect();
        pair.handshake(&mut sim).unwrap();
        assert_dtls13(&pair);
        // The server always checks the client's address with a cookie.
        assert_eq!(
            pair.client.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_eq!(pair.server.server_name(), Some("localhost"));
        pair.exchange(&mut sim, &format!("{key_type:?}"));
    }
}

#[test]
fn handshake_every_dtls_suite() {
    let chain = server_chain(KeyType::EcdsaP256);
    let suites: Vec<_> = prov::default_provider()
        .cipher_suites
        .iter()
        .copied()
        .filter(|s| *s.version() == browntls_core::version::TLS13)
        .collect();
    let mut tested = 0;
    for suite in suites {
        let mut provider = prov::default_provider();
        provider.cipher_suites = vec![suite];
        let client = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
                .with_no_client_auth(),
        );
        let server = Arc::new(dtls_server_config(&chain));
        let result = dtls::ClientConnection::new(client.clone(), server_name());
        if format!("{:?}", suite.suite()).contains("CCM_8") {
            // RFC 9147 §4.5.3: no DTLS 1.3 record protection for it.
            assert!(result.is_err());
            continue;
        }
        let mut pair = Pair::new(&client, &server);
        let mut sim = Sim::perfect();
        pair.handshake(&mut sim).unwrap();
        assert_eq!(pair.client.negotiated_cipher_suite(), Some(suite));
        pair.exchange(&mut sim, &format!("{:?}", suite.suite()));
        tested += 1;
    }
    assert!(tested >= 3);
}

#[test]
fn handshake_without_cookie_exchange() {
    let chain = server_chain(KeyType::Ed25519);
    // A key share that fits the first ClientHello: no HelloRetryRequest.
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::X25519];
    let client = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth(),
    );
    let mut server = server_config(&chain);
    server.ticketer = prov::Ticketer::new().unwrap();
    let server = Arc::new(server);
    let mut pair = Pair {
        client: dtls::ClientConnection::new(client, server_name()).unwrap(),
        server: dtls::ServerConnection::new_without_cookie_exchange(server, PEER).unwrap(),
    };
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    assert_dtls13(&pair);
    assert_eq!(pair.client.handshake_kind(), Some(HandshakeKind::Full));
    pair.exchange(&mut sim, "no cookie");
}

#[test]
fn a_server_without_cookie_sealer_is_refused() {
    let chain = server_chain(KeyType::Ed25519);
    let server = Arc::new(server_config(&chain));
    assert!(dtls::ServerConnection::new(server, PEER).is_err());
}

#[test]
fn small_datagrams_fragment_the_flights() {
    // The largest certificate chain the provider signs with.
    let key_type = match prov::SIGNS_RSA {
        true => KeyType::Rsa2048,
        false => KeyType::EcdsaP384,
    };
    let chain = server_chain(key_type);
    let client = Arc::new(client_config(&chain));
    let server = Arc::new(dtls_server_config(&chain));
    let mut pair = Pair::new(&client, &server);
    pair.client.set_mtu(256).unwrap();
    pair.server.set_mtu(256).unwrap();
    assert!(pair.client.set_mtu(255).is_err());
    let mut sim = Sim::new(
        Link::new(|_, d| {
            assert!(d.len() <= 256);
            Fate::Deliver
        }),
        Link::new(|_, d| {
            assert!(d.len() <= 256);
            Fate::Deliver
        }),
    );
    pair.handshake(&mut sim).unwrap();
    assert!(sim.datagrams > 10);
    assert!(pair.client.max_application_data().unwrap() < 256);
    pair.exchange(&mut sim, "small");
}

#[test]
fn every_single_datagram_loss_is_recovered() {
    // Lose the n-th datagram of the handshake in either direction.
    for direction in 0..2 {
        for n in 0..12 {
            let (mut pair, ..) = Pair::default_pair();
            let lose = move |i: usize, _: &[u8]| if i == n { Fate::Drop } else { Fate::Deliver };
            let mut sim = match direction {
                0 => Sim::new(Link::new(lose), Link::perfect()),
                _ => Sim::new(Link::perfect(), Link::new(lose)),
            };
            pair.handshake(&mut sim)
                .unwrap_or_else(|e| panic!("direction {direction}, datagram {n}: {e:?}"));
            assert_dtls13(&pair);
            pair.exchange(&mut sim, &format!("{direction}/{n}"));
        }
    }
}

#[test]
fn heavy_loss_duplication_reordering_and_corruption() {
    for seed in 1..=12u64 {
        let (mut pair, ..) = Pair::default_pair();
        pair.client.set_mtu(400).unwrap();
        pair.server.set_mtu(400).unwrap();
        let policy = move |salt: u64| {
            let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ salt;
            move |_: usize, _: &[u8]| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                match state % 10 {
                    0 | 1 => Fate::Drop,
                    2 => Fate::Duplicate,
                    3 => Fate::Hold,
                    4 => Fate::Corrupt,
                    _ => Fate::Deliver,
                }
            }
        };
        let mut sim = Sim::new(Link::new(policy(1)), Link::new(policy(2)));
        pair.handshake(&mut sim)
            .unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        assert_dtls13(&pair);
        // Data may be lost: send until both directions got through once.
        let mut sim2 = Sim::new(Link::perfect(), Link::perfect());
        sim2.now = sim.now;
        pair.exchange(&mut sim2, &format!("seed {seed}"));
    }
}

#[test]
fn resumption_with_a_ticket() {
    let (mut pair, client, server) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    assert!(pair.client.tls13_tickets_received() > 0);

    let mut resumed = Pair::new(&client, &server);
    let mut sim = Sim::perfect();
    resumed.handshake(&mut sim).unwrap();
    assert_eq!(
        resumed.server.handshake_kind(),
        Some(HandshakeKind::Resumed)
    );
    assert_dtls13(&resumed);
    resumed.exchange(&mut sim, "resumed");
}

#[test]
fn tls_tickets_are_not_offered_over_dtls() {
    // A TLS connection fills the client's session store first.
    let chain = server_chain(KeyType::EcdsaP256);
    let client = Arc::new(client_config(&chain));
    let server = Arc::new(dtls_server_config(&chain));
    let mut tls_client =
        browntls_core::ClientConnection::new(client.clone(), server_name()).unwrap();
    let mut tls_server = browntls_core::ServerConnection::new(server.clone()).unwrap();
    do_handshake(&mut tls_client, &mut tls_server).unwrap();
    send_and_receive(&mut tls_server, &mut tls_client, b"ticket");

    let mut pair = Pair::new(&client, &server);
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    assert_eq!(
        pair.server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
}

#[test]
fn key_updates_in_both_directions() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    for round in 0..6 {
        if round % 2 == 0 {
            pair.client.refresh_traffic_keys().unwrap();
        } else {
            pair.server.refresh_traffic_keys().unwrap();
        }
        // A second request while the first awaits its ACK just waits.
        pair.client.refresh_traffic_keys().unwrap();
        pair.run(&mut sim, settled).unwrap();
        pair.exchange(&mut sim, &format!("after update {round}"));
    }
}

#[test]
fn key_update_survives_loss() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    let mut lossy = Sim::new(
        Link::new(|i, _| {
            if i % 3 == 0 {
                Fate::Drop
            } else {
                Fate::Deliver
            }
        }),
        Link::new(|i, _| {
            if i % 2 == 0 {
                Fate::Drop
            } else {
                Fate::Deliver
            }
        }),
    );
    lossy.now = sim.now;
    pair.client.refresh_traffic_keys().unwrap();
    pair.run(&mut lossy, settled).unwrap();
    let mut sim = Sim::perfect();
    sim.now = lossy.now;
    pair.exchange(&mut sim, "after lossy update");
}

#[test]
fn exporters_agree_and_differ_from_tls() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client = Arc::new(client_config(&chain));
    let server = Arc::new(dtls_server_config(&chain));
    let mut pair = Pair::new(&client, &server);
    pair.handshake(&mut Sim::perfect()).unwrap();
    let a = pair
        .client
        .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"ctx"))
        .unwrap();
    let b = pair
        .server
        .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"ctx"))
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn close_notify_reaches_the_peer() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    pair.client.send_close_notify();
    pair.run(&mut sim, settled).unwrap();
    assert!(pair.server.peer_has_closed());
    let mut out = Vec::new();
    assert!(pair.client.send(b"late", &mut out).is_err());

    // The server can still send, but nothing it would retransmit, such
    // as a KeyUpdate, can be acknowledged by a peer whose records it no
    // longer reads: it waits for nothing.
    pair.server.refresh_traffic_keys().unwrap();
    pair.server.send(b"after close", &mut out).unwrap();
    sim.to_client.inbox.push_back(out);
    pair.run(&mut sim, settled).unwrap();
    assert!(sim.client_received.contains(&b"after close".to_vec()));
    assert_eq!(pair.server.next_timeout(), None);
}

#[test]
fn an_unanswered_client_gives_up() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::new(Link::new(|_, _| Fate::Drop), Link::perfect());
    match pair.handshake(&mut sim) {
        Err(Failure::Client(Error::General(_))) => {}
        other => panic!("{other:?}"),
    }
    // Within a few minutes of virtual time.
    assert!(sim.now < Duration::from_secs(1000 + 600));
}

#[test]
fn application_data_must_fit_one_datagram() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    let mut out = Vec::new();
    assert!(pair.client.send(b"early", &mut out).is_err());
    pair.handshake(&mut sim).unwrap();
    let max = pair.client.max_application_data().unwrap();
    assert!(pair.client.send(&vec![7; max], &mut out).is_ok());
    assert!(out.len() <= pair.client.mtu());
    out.clear();
    assert!(pair.client.send(&vec![7; max + 1], &mut out).is_err());
    assert!(out.is_empty());
}

#[test]
fn garbage_datagrams_are_ignored() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    for garbage in [
        vec![],
        vec![0x2f; 40],
        vec![0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
        vec![0x17, 0xfe, 0xfd, 0, 3, 0, 0, 0, 0, 0, 1, 0, 1, 0],
        vec![0x2c; 100],
    ] {
        let mut d = garbage.clone();
        pair.client.read_datagram(&mut d, sim.now).unwrap();
        let mut d = garbage;
        pair.server.read_datagram(&mut d, sim.now).unwrap();
    }
    pair.exchange(&mut sim, "after garbage");
}

/// Sends every datagram the client has to `deliver`.
fn client_datagrams(client: &mut dtls::ClientConnection, now: Duration) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    let mut out = Vec::new();
    while client.write_datagram(&mut out, now).unwrap() {
        datagrams.push(std::mem::take(&mut out));
    }
    datagrams
}

#[test]
fn stateless_acceptor_keeps_nothing_until_the_cookie_returns() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = Arc::new(client_config(&chain));
    let server_config = Arc::new(dtls_server_config(&chain));
    let acceptor = dtls::Acceptor::new(server_config).unwrap();
    let now = Duration::from_secs(5);
    let mut client = dtls::ClientConnection::new(client_config, server_name()).unwrap();

    let mut first = client_datagrams(&mut client, now);
    assert_eq!(first.len(), 1, "the first ClientHello fits one datagram");
    let mut retry = Vec::new();
    match acceptor
        .accept(&mut first[0].clone(), PEER, &mut retry, now)
        .unwrap()
    {
        dtls::Accepted::Retry => {}
        other => panic!("{other:?}"),
    }
    // Answering the same ClientHello again keeps nothing either.
    let mut again = Vec::new();
    assert!(matches!(
        acceptor
            .accept(&mut first[0], PEER, &mut again, now)
            .unwrap(),
        dtls::Accepted::Retry
    ));
    // Noise is ignored.
    assert!(matches!(
        acceptor
            .accept(&mut [0x16; 30], PEER, &mut Vec::new(), now)
            .unwrap(),
        dtls::Accepted::Ignored
    ));

    client.read_datagram(&mut retry, now).unwrap();
    let second = client_datagrams(&mut client, now);

    // From another address the cookie does not verify.
    let mut stolen = second.clone();
    let mut conn = match acceptor
        .accept(&mut stolen[0], b"198.51.100.7:9", &mut Vec::new(), now)
        .unwrap()
    {
        dtls::Accepted::Connection(conn) => Some(*conn),
        dtls::Accepted::Ignored => None,
        other => panic!("{other:?}"),
    };
    if let Some(conn) = &mut conn {
        let failed = stolen[1..]
            .iter_mut()
            .any(|d| conn.read_datagram(d, now).is_err());
        assert!(failed);
    }

    // From the right address the handshake continues.
    let mut datagrams = second.into_iter();
    let mut first = datagrams.next().unwrap();
    let mut server = match acceptor
        .accept(&mut first, PEER, &mut Vec::new(), now)
        .unwrap()
    {
        dtls::Accepted::Connection(conn) => *conn,
        other => panic!("{other:?}"),
    };
    for mut datagram in datagrams {
        server.read_datagram(&mut datagram, now).unwrap();
    }
    let mut pair = Pair { client, server };
    let mut sim = Sim::perfect();
    sim.now = now;
    pair.handshake(&mut sim).unwrap();
    assert_dtls13(&pair);
    assert_eq!(
        pair.server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    pair.exchange(&mut sim, "accepted");
}

#[test]
fn a_key_update_lost_before_the_peer_closes_keeps_the_old_keys() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    // The server's KeyUpdate is lost, then the client closes.
    pair.server.refresh_traffic_keys().unwrap();
    let mut out = Vec::new();
    while pair.server.write_datagram(&mut out, sim.now).unwrap() {
        out.clear();
    }
    pair.client.send_close_notify();
    while pair.client.write_datagram(&mut out, sim.now).unwrap() {
        pair.server.read_datagram(&mut out, sim.now).unwrap();
        out.clear();
    }
    assert!(pair.server.peer_has_closed());
    // What the server still sends reaches the client.
    pair.server.send(b"after close", &mut out).unwrap();
    sim.to_client.inbox.push_back(out);
    pair.run(&mut sim, settled).unwrap();
    assert!(sim.client_received.contains(&b"after close".to_vec()));
}

#[test]
fn a_key_update_read_with_close_notify_is_still_acknowledged() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    let now = sim.now;
    // The client's KeyUpdate and close_notify arrive together.
    pair.client.refresh_traffic_keys().unwrap();
    pair.client.send_close_notify();
    let mut datagrams = Vec::new();
    let mut out = Vec::new();
    while pair.client.write_datagram(&mut out, now).unwrap() {
        datagrams.push(core::mem::take(&mut out));
    }
    // Having closed, the client retransmits nothing.
    assert_eq!(pair.client.next_timeout(), None);
    for datagram in &mut datagrams {
        pair.server.read_datagram(datagram, now).unwrap();
    }
    assert!(pair.server.peer_has_closed());
    // The server still owes, and sends, the ACK.
    assert!(pair.server.write_datagram(&mut out, now).unwrap());
}

#[test]
fn a_key_update_sent_with_close_notify_is_read_first() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    let now = sim.now;
    pair.server.refresh_traffic_keys().unwrap();
    pair.server.send_close_notify();
    let mut out = Vec::new();
    while pair.server.write_datagram(&mut out, now).unwrap() {
        pair.client.read_datagram(&mut out, now).unwrap();
        out.clear();
    }
    assert_eq!(pair.server.next_timeout(), None);
    assert!(pair.client.peer_has_closed());
    // The KeyUpdate came ahead of close_notify: the client acknowledges it.
    assert!(pair.client.write_datagram(&mut out, now).unwrap());
}

/// Every datagram `from` has to send now, delivered to `to`.
fn flush_to<A: SideData, B: SideData>(
    from: &mut dtls::ConnectionCommon<A>,
    to: &mut dtls::ConnectionCommon<B>,
    now: Duration,
) {
    let mut out = Vec::new();
    while from.write_datagram(&mut out, now).unwrap() {
        to.read_datagram(&mut out, now).unwrap();
        out.clear();
    }
}

#[test]
fn a_client_closing_right_after_its_finished_still_finishes_the_handshake() {
    let (mut pair, ..) = Pair::default_pair();
    let now = Duration::from_secs(1000);
    // ClientHello, HelloRetryRequest, ClientHello, the server's flight.
    for _ in 0..2 {
        flush_to(&mut pair.client, &mut pair.server, now);
        flush_to(&mut pair.server, &mut pair.client, now);
    }
    assert!(!pair.client.is_handshaking());
    pair.client.send_close_notify();
    // Finished and close_notify are lost.
    let mut out = Vec::new();
    while pair.client.write_datagram(&mut out, now).unwrap() {
        out.clear();
    }
    let mut sim = Sim::perfect();
    sim.now = now;
    pair.run(&mut sim, |client, server| {
        !server.handshaking() && client.timeout().is_none() && server.timeout().is_none()
    })
    .unwrap();
    assert!(pair.server.peer_has_closed());
}

#[test]
fn close_notify_waits_for_the_messages_queued_before_it() {
    for mtu in 256..=320 {
        let (mut pair, ..) = Pair::default_pair();
        pair.client.set_mtu(mtu).unwrap();
        pair.server.set_mtu(mtu).unwrap();
        let now = Duration::from_secs(1000);
        loop {
            flush_to(&mut pair.client, &mut pair.server, now);
            if !pair.server.is_handshaking() {
                break;
            }
            flush_to(&mut pair.server, &mut pair.client, now);
        }
        // The server's tickets are queued, then it closes.
        pair.server.send_close_notify();
        flush_to(&mut pair.server, &mut pair.client, now);
        assert!(pair.client.peer_has_closed());
        assert_eq!(pair.client.tls13_tickets_received(), 2, "MTU {mtu}");
    }
}

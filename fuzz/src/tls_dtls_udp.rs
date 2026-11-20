//! The blocking DTLS 1.3 API over UDP, `dtls::UdpClient` and
//! `dtls::UdpServer` (`fuzz_targets/tls_dtls_udp.rs`).
//!
//! Reaches every public function of both over loopback sockets: one server
//! per input, run in the harness's thread with short read timeouts, and up
//! to [`MAX_CLIENTS`] clients. A client connects either with the blocking
//! `UdpClient::connect` while a scoped thread runs the server, or with
//! `UdpClient::from_connection` (optionally with a fuzz-chosen MTU) and a
//! fuzz-chosen number of `complete_handshake` rounds, between which the
//! server runs. Fuzz-chosen operations then send and receive fuzz-chosen
//! data both ways (also into short buffers, and too much for one
//! datagram), close either side, refresh traffic keys through either
//! side's `connection_mut`, remove clients from the server, change the
//! handshake limit, the handshake timeout and the read timeouts (zero
//! included), split clients with `into_parts` and pair the parts again
//! with `from_connection`, and send fuzzed datagrams shaped like DTLS
//! records (the shapes of `tls_dtls`) to the server, from other sockets
//! and from clients' sockets, and to clients from the server's socket.
//! Some clients' certificate verifiers ask for a live OCSP check, which
//! `UdpClient` refuses, and a server configuration without a cookie
//! sealer is refused by `UdpServer::new`.
//!
//! Checked properties: nothing panics; the server reports events only for
//! clients that completed a handshake (`Connected` once, for one of the
//! harness's clients; `Received` and `Closed` for connected clients only,
//! `Closed` only after the client sent close_notify), never `Failed`, and
//! its connected peers are those its events announced; application data
//! arrives intact and at most once each way, and does arrive while both
//! sides hold the connection, as does close_notify; `handshakes()` never
//! exceeds the limit (after the limit is lowered, the count it had then,
//! which may only fall); `next_event`, `recv` and `complete_handshake`
//! sleep no longer than their read timeout and [`SLACK`], also under a
//! flood of junk (time spent running or waiting for a CPU does not count,
//! so that a loaded machine raises no false alarm); junk (from other
//! addresses, and from or to a client once the server holds its
//! connection) never fails a connection, and calls on a client fail only
//! as documented unless junk or the server's close reached its handshake.
//!
//! Input: a header byte (bit 0: server on RustCrypto, bit 1: client on
//! RustCrypto, bits 2-3: key type, bit 4: try a server without a cookie
//! sealer first), the server's read timeout in milliseconds (modulo 4),
//! then up to [`MAX_OPS`] operations (see [`run`]). Loopback does not lose
//! or reorder datagrams, so the harness can expect what it sent to
//! arrive. An input takes tens to hundreds of milliseconds: every wait
//! that times out lasts at least the kernel's timer tick (a 1 ms socket
//! timeout lasts 8 ms with a 250 Hz tick), and each handshake takes a few.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use browntls_core::dtls::{ServerEvent, UdpServer};
use browntls_core::{ClientConfig, ProtocolVersion};

use crate::input::Input;
use crate::tls_dtls::setup;

mod client;
mod client_ops;
mod seeds;
#[cfg(test)]
mod tests;

pub use self::seeds::seeds;
use client::Client;

/// Operations per input.
const MAX_OPS: usize = 24;

/// Clients per input; each keeps its port until the input ends.
const MAX_CLIENTS: usize = 4;

/// How much longer than its read timeout a blocking call may sleep: the
/// last looks at the socket, each rounded up to the kernel's timer tick.
const SLACK: Duration = Duration::from_millis(250);

/// How long a blocking call may take in all, however loaded the machine.
const WALL_LIMIT: Duration = Duration::from_secs(30);

/// How long the harness waits for what loopback must deliver.
const BUDGET: Duration = Duration::from_secs(5);

/// The shortest handshake timeout during `UdpClient::connect`, which has
/// no read timeout. A shorter one can drop every handshake (the second
/// ClientHello can take two datagrams, and a zero timeout expires the
/// connection between them), and `connect` would then wait for its
/// retransmissions to run out, for minutes.
const CONNECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a junk operation sends its datagrams.
const MAX_REPEAT: usize = 100;

/// The largest UDP payload.
const MAX_DATAGRAM: usize = 65535;

/// An address no client has.
const UNKNOWN: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));

fn ms(n: usize) -> Duration {
    Duration::from_millis(n as u64)
}

fn loopback() -> UdpSocket {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback socket")
}

/// Times a blocking call: how long its thread slept, which a read timeout
/// bounds.
struct Stopwatch {
    start: Instant,
    busy: Option<Duration>,
}

impl Stopwatch {
    fn start() -> Self {
        Self {
            busy: busy(),
            start: Instant::now(),
        }
    }

    /// Whether the call slept at most `timeout` and [`SLACK`] and took at
    /// most [`WALL_LIMIT`]; otherwise what it did.
    fn verdict(&self, timeout: Duration) -> Result<(), String> {
        let wall = self.start.elapsed();
        // Without schedstat a loaded machine cannot be told from a long
        // sleep: only the wall-clock backstop applies.
        let asleep = match (self.busy, busy()) {
            (Some(before), Some(after)) => Some(wall.saturating_sub(after.saturating_sub(before))),
            _ => None,
        };
        if asleep.is_none_or(|asleep| asleep <= timeout + SLACK) && wall <= WALL_LIMIT {
            return Ok(());
        }
        Err(format!(
            "slept {asleep:?} (took {wall:?}) with a read timeout of {timeout:?}"
        ))
    }

    fn check(&self, timeout: Duration, what: &str) {
        if let Err(err) = self.verdict(timeout) {
            panic!("{what} {err}");
        }
    }
}

/// How long the calling thread has run or waited for a CPU, where Linux
/// says (`/proc/thread-self/schedstat`).
fn busy() -> Option<Duration> {
    let stat = std::fs::read_to_string("/proc/thread-self/schedstat").ok()?;
    let mut fields = stat.split_whitespace().map(str::parse::<u64>);
    let run = fields.next()?.ok()?;
    let wait = fields.next()?.ok()?;
    Some(Duration::from_nanos(run.saturating_add(wait)))
}

/// Records that the seeds reached `what` (see `tests.rs`).
fn reached(what: &'static str) {
    #[cfg(test)]
    tests::reached(what);
    #[cfg(not(test))]
    let _ = what;
}

/// The `tls_dtls_udp` fuzz target.
///
/// Operations (first byte modulo 16); a slot byte below the number of
/// clients names one, any other names no client (an address the server
/// does not know):
///
/// 0. connect: flags (bit 0: live OCSP); `UdpClient::connect`;
/// 1. start: flags (bit 0: live OCSP, bit 1: set the MTU), 16-bit MTU,
///    read timeout, rounds (8: until done, at most 16); `from_connection`;
/// 2. continue: slot, rounds;
/// 3. client send: slot, 16-bit-prefixed data;
/// 4. server send: slot, 16-bit-prefixed data, whether the client reads it;
/// 5. client recv: slot, 16-bit buffer length;
/// 6. close: side (bit 0: server), slot, whether the client reads it;
/// 7. key update: side, slot, whether the client sends and reads;
/// 8. remove: slot;
/// 9. limits: handshake limit (modulo 5), handshake timeout in
///    milliseconds (255: 30 seconds);
/// 10. read timeout: side, slot, milliseconds (modulo 4), whether to set
///     `None` first;
/// 11. split: slot; `into_parts`, then `from_connection`;
/// 12. junk to the server: source (bit 2: a client's socket, slot in bits
///     0-1; otherwise one of two other sockets), repetitions, one to three
///     shaped datagrams;
/// 13. junk to a client: slot, one to three shaped datagrams;
/// 14. accessors;
/// 15. wait: milliseconds (modulo 16) for one `next_event`.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let mut state = State::new(&mut input);
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        state.op(&mut input);
        state.check();
    }
}

/// The server, its clients and what the harness expects of them.
struct State {
    server: UdpServer,
    server_addr: SocketAddr,
    /// The server's read timeout.
    timeout: Duration,
    /// The handshake limit.
    limit: usize,
    /// The handshake timeout.
    handshake_timeout: Duration,
    /// The most handshakes the server may hold now: the limit, or more
    /// while a lowered limit has not caught up.
    ceiling: usize,
    header: u8,
    config: Arc<ClientConfig>,
    /// The client configuration asking for live OCSP, once needed.
    defer: Option<Arc<ClientConfig>>,
    clients: Vec<Client>,
    /// The clients the server reported connected, and has not reported
    /// gone or been told to forget.
    connected: HashSet<SocketAddr>,
    /// Other sockets sending junk.
    junk: Vec<UdpSocket>,
}

fn configs(header: u8, cookies: bool, defer: bool) -> setup::Configs {
    let side = |rustcrypto| setup::Side {
        rustcrypto,
        suites: 0xff,
        versions: 0,
    };
    let configs = setup::configs(&setup::Choice {
        client: side(header & 2 != 0),
        server: side(header & 1 != 0),
        key_type: usize::from(header >> 2 & 3),
        server_group: None,
        cookies,
        defer,
    });
    assert!(configs.compatible);
    configs
}

impl State {
    fn new(input: &mut Input) -> Self {
        let header = input.byte();
        let timeout = ms(input.choose(4));
        if header & 16 != 0 {
            let config = configs(header, false, false).server.expect("server");
            let err = UdpServer::new(config, loopback()).expect_err("no cookie sealer");
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            reached("no cookie sealer");
        }
        let configs = configs(header, true, false);
        let server_config = configs.server.expect("server");
        let mut server = UdpServer::new(server_config, loopback()).expect("server");
        server.set_read_timeout(Some(timeout));
        let server_addr = server.socket().local_addr().expect("address");
        Self {
            server,
            server_addr,
            timeout,
            limit: 256,
            handshake_timeout: Duration::from_secs(30),
            ceiling: 256,
            header,
            config: configs.client.expect("client"),
            defer: None,
            clients: Vec::new(),
            connected: HashSet::new(),
            junk: Vec::new(),
        }
    }

    fn op(&mut self, input: &mut Input) {
        match input.choose(16) {
            0 => {
                let defer = input.bool();
                self.connect(defer);
            }
            1 => self.start(input),
            2 => {
                let slot = self.slot(input);
                let rounds = input.choose(9);
                if let Some(i) = slot {
                    self.rounds(i, rounds);
                }
            }
            3 => {
                let slot = self.slot(input);
                let data = input.field();
                if let Some(i) = slot {
                    self.client_send(i, data);
                }
            }
            4 => {
                let slot = self.slot(input);
                let data = input.field();
                let follow = input.bool();
                self.server_send(slot, data, follow);
            }
            5 => {
                let slot = self.slot(input);
                let len = input.u16();
                if let Some(i) = slot {
                    self.client_recv(i, usize::from(len));
                }
            }
            6 => {
                let server = input.bool();
                let slot = self.slot(input);
                let follow = input.bool();
                if server {
                    self.server_close(slot, follow);
                } else if let Some(i) = slot {
                    self.client_close(i);
                }
            }
            7 => {
                let server = input.bool();
                let slot = self.slot(input);
                let follow = input.bool();
                if server {
                    self.server_key_update(slot);
                } else if let Some(i) = slot {
                    self.client_key_update(i, follow);
                }
            }
            8 => {
                let slot = self.slot(input);
                self.remove(slot);
            }
            9 => {
                let max = input.choose(5);
                let timeout = match input.byte() {
                    255 => Duration::from_secs(30),
                    n => ms(n.into()),
                };
                self.limits(max, timeout);
            }
            10 => {
                let server = input.bool();
                let slot = self.slot(input);
                let timeout = ms(input.choose(4));
                let none = input.bool();
                self.read_timeout(server, slot, timeout, none);
            }
            11 => {
                if let Some(i) = self.slot(input) {
                    self.split(i);
                }
            }
            12 => self.junk_to_server(input),
            13 => self.junk_to_client(input),
            14 => self.accessors(),
            _ => {
                let wait = ms(input.choose(16));
                self.next_with(wait);
                self.drain();
                reached("wait");
            }
        }
    }

    fn slot(&self, input: &mut Input) -> Option<usize> {
        let n = usize::from(input.byte());
        (n < self.clients.len()).then_some(n)
    }

    fn addr(&self, slot: Option<usize>) -> SocketAddr {
        slot.map_or(UNKNOWN, |i| self.clients[i].addr)
    }

    fn client_config(&mut self, defer: bool) -> Arc<ClientConfig> {
        if !defer {
            return self.config.clone();
        }
        let header = self.header;
        self.defer
            .get_or_insert_with(|| configs(header, true, true).client.expect("client"))
            .clone()
    }

    /// A socket connected to the server, and a second handle on it that
    /// keeps its port until the input ends: a later client on the same
    /// port would be taken for this one.
    fn client_socket(&self) -> (UdpSocket, UdpSocket) {
        let socket = loopback();
        socket.connect(self.server_addr).expect("connect");
        let port = socket.try_clone().expect("clone");
        (socket, port)
    }

    // ------------------------------------------------------------ server

    /// The checks after each operation: the handshake limit, and the
    /// connected peers against the events.
    fn check(&mut self) {
        self.observe();
        let peers: HashSet<SocketAddr> = self.server.peers().collect();
        assert_eq!(peers, self.connected, "connected peers");
    }

    fn observe(&mut self) {
        let handshakes = self.server.handshakes();
        self.ceiling = observe(handshakes, self.limit, self.ceiling);
    }

    /// One `next_event` with the server's read timeout; whether it
    /// returned an event.
    fn next(&mut self) -> bool {
        self.next_with(self.timeout)
    }

    fn next_with(&mut self, timeout: Duration) -> bool {
        self.server.set_read_timeout(Some(timeout));
        let watch = Stopwatch::start();
        let result = self.server.next_event();
        watch.check(timeout, "next_event");
        self.server.set_read_timeout(Some(self.timeout));
        self.observe();
        match result {
            Ok(event) => {
                self.event(event);
                true
            }
            Err(err) => {
                assert_eq!(err.kind(), ErrorKind::TimedOut, "next_event: {err}");
                false
            }
        }
    }

    /// Runs the server, with a zero read timeout, while datagrams wait on
    /// its socket. A `next_event` that times out has reported every event.
    fn drain(&mut self) {
        for _ in 0..64 {
            if !pending(self.server.socket()) {
                return;
            }
            while self.next_with(Duration::ZERO) {}
        }
    }

    /// Runs the server until `done` or [`BUDGET`] passes.
    fn await_server(&mut self, what: &str, done: impl Fn(&Self) -> bool) {
        let deadline = Instant::now() + BUDGET;
        while !done(self) {
            assert!(Instant::now() < deadline, "{what} did not arrive");
            self.next();
        }
    }

    fn event(&mut self, event: ServerEvent) {
        match event {
            ServerEvent::Connected(addr) => {
                assert!(
                    self.clients.iter().any(|c| c.addr == addr),
                    "Connected for {addr}, not a client"
                );
                assert!(self.connected.insert(addr), "{addr} connected twice");
                reached("connected");
            }
            ServerEvent::Received(addr, data) => {
                assert!(self.connected.contains(&addr), "data from {addr}");
                let client = self.client(addr);
                let at = client.to_server.iter().position(|d| *d == data);
                let at =
                    at.unwrap_or_else(|| panic!("{addr} did not send these {} bytes", data.len()));
                client.to_server.remove(at);
                reached("received");
            }
            ServerEvent::Closed(addr) => {
                assert!(self.connected.remove(&addr), "{addr} closed");
                assert!(self.client(addr).closed, "{addr} did not close");
                reached("closed");
            }
            ServerEvent::Failed(addr, err) => panic!("the connection with {addr} failed: {err}"),
            other => panic!("unknown event {other:?}"),
        }
    }

    fn client(&mut self, addr: SocketAddr) -> &mut Client {
        self.clients
            .iter_mut()
            .find(|c| c.addr == addr)
            .expect("a client")
    }

    fn server_send(&mut self, slot: Option<usize>, data: &[u8], follow: bool) {
        let addr = self.addr(slot);
        let connected = self.connected.contains(&addr);
        let max = self
            .server
            .connection(addr)
            .and_then(|conn| conn.max_application_data());
        assert_eq!(max.is_some(), connected);
        let result = self.server.send_to(data, addr);
        if !connected {
            assert_eq!(
                result.expect_err("not connected").kind(),
                ErrorKind::NotConnected
            );
            reached("not connected");
            return;
        }
        if max.is_some_and(|max| data.len() > max) {
            assert_eq!(
                result.expect_err("too large").kind(),
                ErrorKind::InvalidData
            );
            reached("too large");
            return;
        }
        result.expect("send_to a connected client");
        let i = slot.expect("a client");
        // `recv` skips empty datagrams.
        if !data.is_empty() {
            self.clients[i].to_client.push(data.to_vec());
        }
        if follow && !data.is_empty() && !self.clients[i].closed {
            self.await_client(i, data);
        }
    }

    fn server_close(&mut self, slot: Option<usize>, follow: bool) {
        let addr = self.addr(slot);
        let connected = self.connected.remove(&addr);
        if let Some(i) = slot {
            self.clients[i].touch_handshake();
        }
        self.server.close(addr);
        assert!(self.server.connection(addr).is_none());
        if let (Some(i), true) = (slot, connected) {
            reached("server close");
            if follow && !self.clients[i].closed {
                self.await_close(i);
            }
        }
    }

    fn server_key_update(&mut self, slot: Option<usize>) {
        let addr = self.addr(slot);
        let conn = self.server.connection_mut(addr);
        assert_eq!(conn.is_some(), self.connected.contains(&addr));
        if let Some(conn) = conn {
            conn.refresh_traffic_keys().expect("server key update");
            reached("server key update");
        }
        // The next `next_event` sends the KeyUpdate.
        self.next();
        self.drain();
    }

    fn remove(&mut self, slot: Option<usize>) {
        let addr = self.addr(slot);
        let connected = self.connected.remove(&addr);
        let before = self.server.handshakes();
        let conn = self.server.remove(addr);
        match &conn {
            Some(conn) if connected => {
                assert!(!conn.is_handshaking());
                assert_eq!(self.server.handshakes(), before);
                reached("removed connection");
            }
            Some(conn) => {
                assert!(conn.is_handshaking());
                assert_eq!(self.server.handshakes(), before - 1);
                reached("removed handshake");
            }
            None => assert!(!connected, "{addr} was connected"),
        }
        assert!(self.server.remove(addr).is_none());
    }

    fn limits(&mut self, max: usize, timeout: Duration) {
        self.server.set_max_handshakes(max);
        self.server.set_handshake_timeout(timeout);
        self.handshake_timeout = timeout;
        self.limit = max.max(1);
        self.ceiling = self.limit.max(self.server.handshakes());
    }

    fn read_timeout(&mut self, server: bool, slot: Option<usize>, timeout: Duration, none: bool) {
        if server {
            self.timeout = timeout;
            self.server.set_read_timeout(Some(timeout));
        } else if let Some(i) = slot {
            self.clients[i].set_read_timeout(timeout, none);
        }
    }

    fn accessors(&mut self) {
        assert_eq!(
            self.server.socket().local_addr().ok(),
            Some(self.server_addr)
        );
        assert!(self.server.connection(UNKNOWN).is_none());
        let _ = format!("{:?}", self.server);
        for c in &self.clients {
            let conn = self.server.connection(c.addr);
            assert_eq!(conn.is_some(), self.connected.contains(&c.addr));
            if let Some(conn) = conn {
                assert!(!conn.is_handshaking());
                assert_eq!(conn.protocol_version(), Some(ProtocolVersion::DTLSv1_3));
            }
            c.accessors(self.server_addr);
        }
        reached("accessors");
    }
}

/// Checks `handshakes` against the ceiling and returns the next ceiling.
fn observe(handshakes: usize, limit: usize, ceiling: usize) -> usize {
    assert!(
        handshakes <= ceiling,
        "{handshakes} handshakes, limit {limit}, ceiling {ceiling}"
    );
    limit.max(handshakes)
}

/// Whether a datagram waits on `socket`.
fn pending(socket: &UdpSocket) -> bool {
    socket.set_nonblocking(true).expect("non-blocking");
    let result = socket.peek_from(&mut [0; 1]);
    socket.set_nonblocking(false).expect("blocking");
    !matches!(result, Err(err) if err.kind() == ErrorKind::WouldBlock)
}

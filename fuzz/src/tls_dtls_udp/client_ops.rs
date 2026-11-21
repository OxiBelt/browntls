//! The operations of the `tls_dtls_udp` target on its clients: connecting
//! them (`connect` with the server on a scoped thread, or handshake
//! rounds), their calls, and junk.

use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use browntls_core::dtls::{self, ServerEvent, UdpClient, UdpServer};

use super::client::{Client, Outcome, count, outcome, received};
use super::{
    BUDGET, CONNECT_HANDSHAKE_TIMEOUT, MAX_CLIENTS, MAX_REPEAT, State, Stopwatch, loopback, ms,
    reached,
};
use crate::input::Input;
use crate::tls_dtls::{setup, shape};

impl State {
    /// `UdpClient::connect`, with the server running on a scoped thread
    /// meanwhile.
    pub(super) fn connect(&mut self, defer: bool) {
        if self.clients.len() == MAX_CLIENTS {
            return;
        }
        let config = self.client_config(defer);
        let (socket, port) = self.client_socket();
        self.drain();
        let short = self.handshake_timeout < CONNECT_HANDSHAKE_TIMEOUT;
        if short {
            self.server.set_handshake_timeout(CONNECT_HANDSHAKE_TIMEOUT);
        }
        let stop = AtomicBool::new(false);
        let (timeout, limit, ceiling) = (self.timeout, self.limit, self.ceiling);
        let server = &mut self.server;
        let (result, pumped) = std::thread::scope(|scope| {
            let stop = &stop;
            let pump = scope.spawn(move || pump(server, timeout, limit, ceiling, stop));
            let result = {
                let _stop = Stop(stop);
                UdpClient::connect(config, setup::localhost(), socket)
            };
            (result, pump.join().expect("the server thread"))
        });
        if short {
            // From the next handshake on.
            self.server.set_handshake_timeout(self.handshake_timeout);
        }
        self.clients.push(Client::new(port, Duration::ZERO, defer));
        if let Some(err) = pumped.overslept {
            panic!("next_event {err}");
        }
        assert_eq!(pumped.over, None, "handshakes above the limit {limit}");
        self.ceiling = pumped.ceiling;
        for event in pumped.events {
            self.event(event.expect("next_event"));
        }
        let client = self.clients.last_mut().expect("the client");
        match result {
            Ok(udp) => {
                assert!(!defer, "a live OCSP check passed");
                assert!(!udp.connection().is_handshaking());
                assert_eq!(udp.read_timeout(), None);
                client.attach(udp);
                reached("connect");
            }
            Err(err) => {
                assert!(defer, "connect: {err}");
                assert_eq!(err.kind(), ErrorKind::Unsupported, "{err}");
                reached("live OCSP refused");
            }
        }
        self.drain();
    }

    /// `UdpClient::from_connection`, then handshake rounds.
    pub(super) fn start(&mut self, input: &mut Input) {
        let flags = input.byte();
        let mtu = input.u16();
        let timeout = ms(input.choose(4));
        let rounds = input.choose(9);
        if self.clients.len() == MAX_CLIENTS {
            return;
        }
        let defer = flags & 1 != 0;
        let config = self.client_config(defer);
        let mut conn = dtls::ClientConnection::new(config, setup::localhost()).expect("client");
        if flags & 2 != 0 {
            let mtu = 256 + usize::from(mtu) % 1245;
            conn.set_mtu(mtu).expect("MTU in range");
        }
        let (socket, port) = self.client_socket();
        let mut client = Client::new(port, timeout, defer);
        client.attach(UdpClient::from_connection(conn, socket));
        self.clients.push(client);
        self.rounds(self.clients.len() - 1, rounds);
    }

    /// Up to `rounds` (8: 16) calls of `complete_handshake`, each followed
    /// by the server's answer.
    pub(super) fn rounds(&mut self, i: usize, rounds: usize) {
        let rounds = if rounds == 8 { 16 } else { rounds };
        for _ in 0..rounds {
            let c = &mut self.clients[i];
            let Some(udp) = c.udp.as_mut() else { return };
            if !udp.connection().is_handshaking() {
                reached("handshake rounds");
                return;
            }
            let watch = Stopwatch::start();
            let result = udp.complete_handshake();
            if let Outcome::Failed = outcome(c, result, &watch, |_| false) {
                return;
            }
            self.drain();
        }
    }

    pub(super) fn client_send(&mut self, i: usize, data: &[u8]) {
        let c = &mut self.clients[i];
        let addr = c.addr;
        let Some(udp) = c.udp.as_mut() else { return };
        let before = count(&c.to_server, data);
        c.to_server.push(data.to_vec());
        let watch = Stopwatch::start();
        let result = udp.send(data);
        let max = udp.connection().max_application_data();
        let too_large = max.is_some_and(|max| data.len() > max);
        let closed = c.closed;
        let refused = |kind| kind == ErrorKind::InvalidData && (too_large || closed);
        match outcome(c, result, &watch, refused) {
            Outcome::Done(()) => assert!(!too_large && !closed, "send went through"),
            Outcome::Failed => return,
            Outcome::TimedOut | Outcome::Refused => {
                // Nothing was sent.
                let at = c.to_server.iter().rposition(|d| d == data);
                c.to_server.remove(at.expect("pushed"));
                if too_large {
                    reached("too large");
                }
                return;
            }
        }
        self.drain();
        if !data.is_empty() && self.connected.contains(&addr) {
            self.await_server("data from a client", |s| {
                count(&s.clients[i].to_server, data) == before
            });
        }
    }

    pub(super) fn client_recv(&mut self, i: usize, len: usize) {
        let c = &mut self.clients[i];
        let Some(udp) = c.udp.as_mut() else { return };
        let mut buf = vec![0; len];
        let watch = Stopwatch::start();
        let result = udp.recv(&mut buf);
        let closed = udp.connection().peer_has_closed();
        match outcome(c, result, &watch, |k| k == ErrorKind::InvalidInput) {
            Outcome::Done(n) => received(&mut c.to_client, &buf[..n], closed),
            Outcome::Refused => {
                assert!(c.to_client.iter().any(|d| d.len() > len));
                reached("short buffer");
            }
            Outcome::TimedOut | Outcome::Failed => {}
        }
        self.drain();
    }

    /// Reads from client `i` until `data` arrives.
    pub(super) fn await_client(&mut self, i: usize, data: &[u8]) {
        let deadline = Instant::now() + BUDGET;
        let want = count(&self.clients[i].to_client, data) - 1;
        while count(&self.clients[i].to_client, data) > want {
            if !self.clients[i].recv_once(deadline, "data from the server") {
                return;
            }
        }
        reached("client received");
    }

    /// Reads from client `i` until it sees the server's close_notify.
    pub(super) fn await_close(&mut self, i: usize) {
        let deadline = Instant::now() + BUDGET;
        while !self.clients[i].saw_close() {
            if !self.clients[i].recv_once(deadline, "close_notify from the server") {
                return;
            }
        }
        reached("client saw close");
    }

    pub(super) fn client_close(&mut self, i: usize) {
        let c = &mut self.clients[i];
        let addr = c.addr;
        let Some(udp) = c.udp.as_mut() else { return };
        if udp.connection().is_handshaking() {
            c.may_fail = true;
        }
        let first = !std::mem::replace(&mut c.closed, true);
        let watch = Stopwatch::start();
        let result = udp.close();
        if let Outcome::Failed = outcome(c, result, &watch, |_| false) {
            return;
        }
        let connected = self.connected.contains(&addr);
        self.drain();
        if connected && first {
            self.await_server("close_notify from a client", |s| {
                !s.connected.contains(&addr)
            });
        }
    }

    pub(super) fn client_key_update(&mut self, i: usize, follow: bool) {
        let c = &mut self.clients[i];
        let Some(udp) = c.udp.as_mut() else { return };
        let result = udp.connection_mut().refresh_traffic_keys();
        if !udp.connection().is_handshaking() && !c.closed {
            result.expect("client key update");
            reached("client key update");
        }
        if follow {
            // Send the KeyUpdate, let the server acknowledge it, read the
            // acknowledgement.
            c.recv_once(Instant::now() + BUDGET, "");
            self.drain();
            self.clients[i].recv_once(Instant::now() + BUDGET, "");
            self.drain();
        }
    }

    pub(super) fn split(&mut self, i: usize) {
        self.clients[i].split();
        reached("split");
    }

    // --------------------------------------------------------------- junk

    pub(super) fn junk_to_server(&mut self, input: &mut Input) {
        let source = input.byte();
        let repeat = 1 + input.choose(MAX_REPEAT);
        let count = 1 + input.choose(3);
        let datagrams: Vec<Vec<u8>> = (0..count).map(|_| shape::datagram(input)).collect();
        let client = usize::from(source & 3);
        let socket = if source & 4 != 0 && client < self.clients.len() {
            let c = &mut self.clients[client];
            if !self.connected.contains(&c.addr) {
                // The acceptor or the handshake may answer the client.
                c.may_fail = true;
            }
            c.port.try_clone().expect("clone")
        } else {
            let n = usize::from(source & 1);
            while self.junk.len() <= n {
                self.junk.push(loopback());
            }
            self.junk[n].try_clone().expect("clone")
        };
        for _ in 0..repeat {
            for datagram in &datagrams {
                // A full receive buffer drops junk, as it may.
                let _ = socket.send_to(datagram, self.server_addr);
            }
        }
        // One timed look while the junk waits, then the rest.
        self.next();
        self.drain();
        reached("junk to the server");
    }

    pub(super) fn junk_to_client(&mut self, input: &mut Input) {
        let slot = self.slot(input);
        let count = 1 + input.choose(3);
        let datagrams: Vec<Vec<u8>> = (0..count).map(|_| shape::datagram(input)).collect();
        let Some(i) = slot else { return };
        let c = &mut self.clients[i];
        c.touch_handshake();
        for datagram in &datagrams {
            let _ = self.server.socket().send_to(datagram, c.addr);
        }
        c.recv_once(Instant::now() + BUDGET, "");
        self.drain();
        reached("junk to a client");
    }
}

/// What the server thread saw while a client connected.
struct Pumped {
    events: Vec<io::Result<ServerEvent>>,
    /// How a `next_event` broke its read timeout, if one did.
    overslept: Option<String>,
    ceiling: usize,
    /// The handshakes the server held above the ceiling, if it did.
    over: Option<usize>,
}

/// Runs `server` until `stop` and it has nothing more to report. It does
/// not panic, which would leave the client waiting: the caller checks.
fn pump(
    server: &mut UdpServer,
    timeout: Duration,
    limit: usize,
    mut ceiling: usize,
    stop: &AtomicBool,
) -> Pumped {
    let mut events = Vec::new();
    let mut overslept = None;
    let mut over = None;
    server.set_read_timeout(Some(timeout));
    loop {
        let watch = Stopwatch::start();
        let result = server.next_event();
        if let Err(err) = watch.verdict(timeout) {
            overslept.get_or_insert(err);
        }
        let handshakes = server.handshakes();
        if handshakes > ceiling {
            over = over.or(Some(handshakes));
        }
        ceiling = limit.max(handshakes);
        let idle = matches!(&result, Err(err) if err.kind() == ErrorKind::TimedOut);
        if !idle {
            events.push(result);
        } else if stop.load(Ordering::Acquire) {
            return Pumped {
                events,
                overslept,
                ceiling,
                over,
            };
        }
    }
}

/// Tells the server thread to stop, also when the client panics.
struct Stop<'a>(&'a AtomicBool);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

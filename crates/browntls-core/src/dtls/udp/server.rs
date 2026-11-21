//! [`UdpServer`]: many DTLS 1.3 clients on one UDP socket.

use alloc::collections::{BinaryHeap, VecDeque};
use alloc::vec::Vec;
use core::cmp::Reverse;
use core::fmt;
use core::time::Duration;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use super::{
    LAST_LOOKS, MAX_DATAGRAM, address_bytes, flush, io_error, is_transient, timed_out, wait_until,
};
use crate::dtls::{Accepted, Acceptor, ServerConnection};
use crate::error::Error;
use crate::log::debug;
use crate::sync::Arc;

/// How many handshakes [`UdpServer`] runs at once by default.
const DEFAULT_MAX_HANDSHAKES: usize = 256;

/// How long a handshake may take by default.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// What [`UdpServer::next_event`] reports.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerEvent {
    /// A client completed its handshake; its connection is available.
    Connected(SocketAddr),
    /// A datagram of application data from a connected client, possibly
    /// empty (only `UdpClient::recv` skips empty datagrams).
    Received(SocketAddr, Vec<u8>),
    /// A connected client sent `close_notify`; its connection is gone.
    Closed(SocketAddr),
    /// The connection of a connected client failed, and is gone.
    Failed(SocketAddr, Error),
}

/// A DTLS 1.3 server for many clients over one UDP socket.
///
/// Clients are told apart by their address. A client's first ClientHello
/// gets a HelloRetryRequest with a cookie and leaves no state behind (see
/// [`Acceptor`]); a connection exists only for a client that answered it.
/// Handshakes that do not complete within the handshake timeout are
/// dropped, and when the handshake limit is reached a new one replaces
/// the oldest.
///
/// [`Self::next_event`] blocks until something happens: a client
/// connects, sends application data, closes or fails. While blocked it
/// runs every connection's retransmissions and acknowledgements. The
/// server keeps connected clients until they close or fail, or until
/// [`Self::close`] or [`Self::remove`]; drop the ones that stay silent
/// for too long.
///
/// Handshakes are bounded, connected clients are not: the application
/// decides how many to keep. The bound counts addresses, so one host
/// using many ports can take the place of others' handshakes; filter
/// such hosts before the server if that matters.
///
/// Live OCSP checks ([`crate::revocation`]) are not supported: a
/// handshake that would wait for one fails.
///
/// While a client's connection exists, a new ClientHello from its address
/// (a client restarted on the same port) is ignored: remove the old
/// connection to let it connect again.
pub struct UdpServer {
    socket: UdpSocket,
    acceptor: Acceptor,
    peers: HashMap<SocketAddr, Peer>,
    timers: BinaryHeap<Reverse<(Duration, SocketAddr)>>,
    events: VecDeque<ServerEvent>,
    /// Peers changed through [`Self::connection_mut`], to flush.
    touched: Vec<SocketAddr>,
    handshakes: usize,
    max_handshakes: usize,
    handshake_timeout: Duration,
    read_timeout: Option<Duration>,
    start: Instant,
    buf: Vec<u8>,
    out: Vec<u8>,
}

struct Peer {
    conn: ServerConnection,
    /// When its connection was created.
    started: Duration,
    /// When its handshake times out.
    expires: Duration,
    /// Whether [`ServerEvent::Connected`] was reported for it.
    connected: bool,
    /// The due time of its entry in the timer queue, if it has one.
    scheduled: Option<Duration>,
}

impl Peer {
    /// When this peer next needs attention: its connection's timer, or
    /// the end of its handshake time.
    fn next_due(&self) -> Option<Duration> {
        let timer = self.conn.next_timeout();
        // after_input flushes before announcing handshake completion.
        if self.connected || !self.conn.is_handshaking() {
            return timer;
        }
        Some(timer.map_or(self.expires, |timer| timer.min(self.expires)))
    }
}

impl UdpServer {
    /// A server for clients on `socket`, with `config`, which must set
    /// `hello_retry_cookies` (see [`Acceptor::new`]).
    ///
    /// The socket is put in blocking mode.
    pub fn new(config: Arc<crate::ServerConfig>, socket: UdpSocket) -> io::Result<Self> {
        let acceptor = Acceptor::new(config)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        socket.set_nonblocking(false)?;
        Ok(Self {
            socket,
            acceptor,
            peers: HashMap::new(),
            timers: BinaryHeap::new(),
            events: VecDeque::new(),
            touched: Vec::new(),
            handshakes: 0,
            max_handshakes: DEFAULT_MAX_HANDSHAKES,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            read_timeout: None,
            start: Instant::now(),
            buf: alloc::vec![0; MAX_DATAGRAM],
            out: Vec::new(),
        })
    }

    /// Sets how many handshakes run at once (256 by default, at least 1).
    pub fn set_max_handshakes(&mut self, max: usize) {
        self.max_handshakes = max.max(1);
    }

    /// Sets how long a handshake may take (30 seconds by default), from
    /// the next handshake on.
    pub fn set_handshake_timeout(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    /// Sets how long [`Self::next_event`] waits for an event; `None` (the
    /// default) waits forever. Even a zero timeout reads what arrives within a
    /// moment of the deadline, up to 64 datagrams.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// Blocks until the next event, or fails with
    /// [`io::ErrorKind::TimedOut`] once the read timeout passes.
    /// Queued events are returned before further socket or timer work.
    pub fn next_event(&mut self) -> io::Result<ServerEvent> {
        let deadline = self
            .read_timeout
            .map(|timeout| self.now().saturating_add(timeout));
        let mut late = 0;
        loop {
            if let Some(event) = self.pop_event() {
                return Ok(event);
            }
            for peer in core::mem::take(&mut self.touched) {
                self.flush_peer(peer);
            }
            self.run_timers();
            if let Some(event) = self.pop_event() {
                return Ok(event);
            }
            let now = self.now();
            // Once the deadline passed, one last look at the socket.
            let expired = deadline.is_some_and(|deadline| deadline <= now);
            let timer = self.timers.peek().map(|Reverse((due, _))| *due);
            self.socket
                .set_read_timeout(wait_until(now, [timer, deadline]))?;
            match self.socket.recv_from(&mut self.buf) {
                Ok((len, peer)) => {
                    self.handle_datagram(peer, len);
                    if expired {
                        // A stream of datagrams must not keep the read
                        // timeout from passing.
                        late += 1;
                        if late >= LAST_LOOKS {
                            if let Some(event) = self.pop_event() {
                                return Ok(event);
                            }
                            self.run_timers();
                            return self.pop_event().ok_or_else(timed_out);
                        }
                    }
                }
                Err(err) if is_transient(&err) && expired => return Err(timed_out()),
                Err(err) if is_transient(&err) => {}
                Err(err) => return Err(err),
            }
        }
    }

    /// Sends `data` to the connected client `peer` as one datagram of
    /// application data.
    pub fn send_to(&mut self, data: &[u8], peer: SocketAddr) -> io::Result<()> {
        let conn = match self.peers.get_mut(&peer) {
            Some(Peer {
                conn,
                connected: true,
                ..
            }) => conn,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no DTLS connection with this address",
                ));
            }
        };
        let mut datagram = Vec::new();
        conn.send(data, &mut datagram).map_err(io_error)?;
        self.socket.send_to(&datagram, peer)?;
        // The confidentiality limit may have queued a KeyUpdate.
        self.flush_peer(peer);
        Ok(())
    }

    /// Sends `close_notify` to `peer` and forgets its connection.
    pub fn close(&mut self, peer: SocketAddr) {
        if let Some(entry) = self.peers.get_mut(&peer) {
            entry.conn.send_close_notify();
            self.flush_peer(peer);
            self.remove(peer);
        }
    }

    /// Forgets the connection with `peer`, without telling it, and
    /// discards its queued events.
    pub fn remove(&mut self, peer: SocketAddr) -> Option<ServerConnection> {
        self.events.retain(|event| match event {
            ServerEvent::Connected(addr)
            | ServerEvent::Received(addr, _)
            | ServerEvent::Closed(addr)
            | ServerEvent::Failed(addr, _) => *addr != peer,
        });
        self.touched.retain(|addr| *addr != peer);
        let entry = self.peers.remove(&peer)?;
        if !entry.connected {
            self.handshakes -= 1;
        }
        Some(entry.conn)
    }

    /// The connection with `peer`, once it connected.
    pub fn connection(&self, peer: SocketAddr) -> Option<&ServerConnection> {
        self.peers
            .get(&peer)
            .filter(|entry| entry.connected)
            .map(|entry| &entry.conn)
    }

    /// The connection with `peer`, once it connected, for example to
    /// refresh its traffic keys. What the change queues is sent by
    /// [`Self::send_to`] or by [`Self::next_event`] after queued events
    /// have been returned.
    pub fn connection_mut(&mut self, peer: SocketAddr) -> Option<&mut ServerConnection> {
        let entry = self.peers.get_mut(&peer).filter(|entry| entry.connected)?;
        if !self.touched.contains(&peer) {
            self.touched.push(peer);
        }
        Some(&mut entry.conn)
    }

    /// The addresses of the connected clients.
    pub fn peers(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.peers
            .iter()
            .filter(|(_, entry)| entry.connected)
            .map(|(addr, _)| *addr)
    }

    /// How many handshakes are in progress.
    pub fn handshakes(&self) -> usize {
        self.handshakes
    }

    /// The socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    /// Keeps negotiated state available through Connected and Received,
    /// then removes the peer when its Closed event is returned.
    fn pop_event(&mut self) -> Option<ServerEvent> {
        let event = self.events.pop_front()?;
        if let ServerEvent::Closed(peer) = &event {
            self.remove(*peer);
        }
        Some(event)
    }

    fn handle_datagram(&mut self, peer: SocketAddr, len: usize) {
        let now = self.now();
        let datagram = &mut self.buf[..len];
        if let Some(entry) = self.peers.get_mut(&peer) {
            let result = entry.conn.read_datagram(datagram, now);
            let result = result.map(|received| received.app_data().to_vec());
            self.after_input(peer, result);
            return;
        }
        self.out.clear();
        let accepted = self
            .acceptor
            .accept(datagram, &address_bytes(&peer), &mut self.out, now);
        match accepted {
            Ok(Accepted::Retry) => {
                if let Err(err) = self.socket.send_to(&self.out, peer) {
                    debug!("DTLS: could not send a HelloRetryRequest: {err}");
                }
            }
            Ok(Accepted::Connection(conn)) => {
                while self.handshakes >= self.max_handshakes {
                    if !self.drop_oldest_handshake() {
                        break;
                    }
                }
                self.handshakes += 1;
                self.peers.insert(
                    peer,
                    Peer {
                        conn: *conn,
                        started: now,
                        expires: now.saturating_add(self.handshake_timeout),
                        connected: false,
                        scheduled: None,
                    },
                );
                // The acceptor processed the datagram, which cannot hold
                // application data yet.
                self.after_input(peer, Ok(Vec::new()));
            }
            Ok(Accepted::Ignored) => {}
            Err(err) => debug!("DTLS: datagram not accepted: {err}"),
        }
    }

    /// Reports what reading a datagram from `peer` did, and sends what its
    /// connection queued in response.
    fn after_input(
        &mut self,
        peer: SocketAddr,
        result: Result<Vec<core::ops::Range<usize>>, Error>,
    ) {
        let Some(entry) = self.peers.get_mut(&peer) else {
            return;
        };
        let app_data = match result {
            Ok(app_data) => app_data,
            Err(err) => {
                self.fail(peer, err);
                return;
            }
        };
        if !entry.connected && entry.conn.pending_revocation().is_some() {
            // Nothing here would answer the query.
            self.fail(
                peer,
                Error::General("live OCSP checks are not supported by UdpServer".into()),
            );
            return;
        }
        // Flush before announcing new events: a sealing failure removes
        // the peer, so no event may promise its connection afterwards.
        self.flush_peer(peer);
        let Some(entry) = self.peers.get_mut(&peer) else {
            return;
        };
        if !entry.connected && !entry.conn.is_handshaking() {
            entry.connected = true;
            self.handshakes -= 1;
            self.events.push_back(ServerEvent::Connected(peer));
        }
        for range in app_data {
            self.events
                .push_back(ServerEvent::Received(peer, self.buf[range].to_vec()));
        }
        if entry.conn.peer_has_closed() {
            if entry.connected {
                // Connected and any Received events still need the
                // connection. pop_event removes it when returning Closed.
                self.events.push_back(ServerEvent::Closed(peer));
            } else {
                self.remove(peer);
            }
        }
    }

    /// Sends the alert of `peer`'s failed connection, forgets it, and
    /// reports the failure if it had connected.
    fn fail(&mut self, peer: SocketAddr, err: Error) {
        self.flush_peer(peer);
        if let Some(entry) = self.peers.get(&peer) {
            let connected = entry.connected;
            self.remove(peer);
            if connected {
                self.events.push_back(ServerEvent::Failed(peer, err));
            } else {
                debug!("DTLS: handshake with a client failed: {err}");
            }
        }
    }

    /// Sends what `peer`'s connection queued, and schedules its next
    /// timer.
    fn flush_peer(&mut self, peer: SocketAddr) {
        let now = self.now();
        let Some(entry) = self.peers.get_mut(&peer) else {
            return;
        };
        let socket = &self.socket;
        let result = flush(&mut entry.conn, &mut self.out, now, |datagram| {
            // A datagram that cannot be sent is as good as lost.
            if let Err(err) = socket.send_to(datagram, peer) {
                debug!("DTLS: could not send a datagram: {err}");
            }
            Ok(())
        });
        let due = entry.next_due();
        let scheduled = due != entry.scheduled && due.is_some();
        if due != entry.scheduled {
            entry.scheduled = due;
            if let Some(due) = due {
                self.timers.push(Reverse((due, peer)));
            }
        }
        if let Err(err) = result {
            // Only a connection that cannot seal fails here.
            debug!("DTLS: connection failed while sending: {err}");
            let connected = entry.connected;
            self.remove(peer);
            if connected {
                self.events.push_back(ServerEvent::Failed(
                    peer,
                    Error::General(alloc::format!("{err}")),
                ));
            }
        }
        if scheduled {
            self.compact_timers();
        }
    }

    /// Acts on the timers that are due.
    fn run_timers(&mut self) {
        let now = self.now();
        while let Some(Reverse((due, peer))) = self.timers.peek().copied() {
            if due > now {
                return;
            }
            self.timers.pop();
            let Some(entry) = self.peers.get_mut(&peer) else {
                continue;
            };
            // Each change of a peer's timer pushes a new entry: skip the
            // ones that no longer match.
            if entry.scheduled != Some(due) {
                continue;
            }
            entry.scheduled = None;
            if !entry.connected && entry.expires <= now {
                debug!("DTLS: handshake timed out");
                self.remove(peer);
                continue;
            }
            match entry.conn.handle_timeout(now) {
                Ok(()) => self.flush_peer(peer),
                Err(err) => self.fail(peer, err),
            }
        }
    }

    /// Drops the entries of the timer queue that no longer match a
    /// peer's timer once they outnumber the peers, so that the queue stays
    /// in proportion to the peers.
    fn compact_timers(&mut self) {
        if self.timers.len() <= 2 * self.peers.len() + 64 {
            return;
        }
        self.timers = self
            .peers
            .iter()
            .filter_map(|(addr, entry)| entry.scheduled.map(|due| Reverse((due, *addr))))
            .collect();
    }

    /// Makes room for one more handshake; returns whether there was one
    /// to drop.
    fn drop_oldest_handshake(&mut self) -> bool {
        let oldest = self
            .peers
            .iter()
            .filter(|(_, entry)| !entry.connected)
            .min_by_key(|(_, entry)| entry.started)
            .map(|(addr, _)| *addr);
        let Some(peer) = oldest else {
            return false;
        };
        debug!("DTLS: too many handshakes, dropping the oldest");
        self.remove(peer);
        true
    }
}

impl fmt::Debug for UdpServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls::UdpServer")
            .field("socket", &self.socket)
            .field("peers", &self.peers.len())
            .field("handshakes", &self.handshakes)
            .finish_non_exhaustive()
    }
}

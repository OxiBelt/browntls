//! Event-driven DTLS associations on a caller-created Tokio UDP socket.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::ops::Bound::{Excluded, Unbounded};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use browntls_core::dtls::{
    Accepted, Acceptor, CidDemux, ServerConnection, Settings, UdpPathValidation, Versions,
    rrc::Selection,
};
use browntls_core::{Error, ServerConfig};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::time::{Instant, Sleep};

use super::{IO_BURST, MAX_DATAGRAM, io_error, poll_send_datagram};

const DEFAULT_MAX_HANDSHAKES: usize = 256;
const DEFAULT_MAX_PEERS: usize = 1024;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
// A cancelled close or a failed peer must not retain a slot forever if
// the socket never becomes writable again.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// An association event from [`UdpServer::next_event`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerEvent {
    /// A peer completed its authenticated handshake.
    Connected(SocketAddr),
    /// One whole application record, including an empty record.
    Received(SocketAddr, Vec<u8>),
    /// An established peer sent authenticated `close_notify`.
    Closed(SocketAddr),
    /// An established peer failed; other associations remain usable.
    Failed(SocketAddr, Error),
    /// The validated physical address changed for this stable handle.
    PeerAddressChanged(SocketAddr, SocketAddr),
}

/// Many DTLS 1.3 associations on a caller-created, unconnected UDP socket.
///
/// The caller supplies the runtime, socket, I/O driver and time driver.
/// No background task is started: poll an operation to advance the server.
/// Events and methods use the original address as a stable handle.
/// Negotiated CID/RRC may validate a new physical address.
/// Cookie validation through [`Acceptor`] precedes handshake allocation.
/// There are at most 256 handshakes and 1024 established peers by default;
/// a new validated handshake evicts the oldest pending handshake, and a
/// handshake completing at the established-peer limit is rejected.
///
/// Each peer has at most one sealed ordinary output and one protected
/// path probe in the adapter, plus one stateless cookie reply overall.
/// A new probe generated while its slot is occupied is dropped like a
/// lost UDP datagram; its existing destination and ciphertext are retained.
/// Core bounds its own protocol queues. Application input is buffered for
/// one UDP datagram;
/// its events are consumed before another receive. Events from timers are
/// bounded by the peer slots. Unauthenticated input cannot grow a queue
/// across receives. Live OCSP queries are unsupported and fail that peer.
pub struct UdpServer {
    socket: UdpSocket,
    acceptor: Acceptor,
    peers: BTreeMap<SocketAddr, Peer>,
    physical: BTreeMap<SocketAddr, SocketAddr>,
    cids: CidDemux<SocketAddr>,
    touched: BTreeSet<SocketAddr>,
    path_selection: Selection,
    events: VecDeque<ServerEvent>,
    retry: Option<(SocketAddr, Vec<u8>)>,
    send_cursor: Option<SocketAddr>,
    max_handshakes: usize,
    max_peers: usize,
    handshake_timeout: Duration,
    read_timeout: Option<Duration>,
    start: Instant,
    timer: Option<Pin<Box<Sleep>>>,
    buf: Vec<u8>,
}

struct Peer {
    conn: ServerConnection,
    started: Duration,
    expires: Duration,
    connected: bool,
    retiring: bool,
    // Core leaves an expired delayed-ACK timer due until output can be
    // written. Service that timer once, then wait for send readiness rather
    // than repeatedly waking on the same expired deadline.
    serviced_timeout: Option<Duration>,
    // Never call write_datagram or send while this is nonempty. It is
    // already sealed and belongs to the association until sent or removed.
    out: Vec<u8>,
    active: SocketAddr,
    paths: Option<UdpPathValidation>,
    probe: Option<(SocketAddr, Vec<u8>)>,
}

impl Peer {
    fn next_due(&self) -> Option<Duration> {
        if self.retiring {
            return Some(self.expires);
        }
        let timer = self
            .conn
            .next_timeout()
            .filter(|due| Some(*due) != self.serviced_timeout)
            .into_iter()
            .chain(
                self.paths
                    .as_ref()
                    .and_then(UdpPathValidation::next_timeout),
            )
            .min();
        if self.connected {
            timer
        } else {
            Some(timer.map_or(self.expires, |due| due.min(self.expires)))
        }
    }
}

impl UdpServer {
    /// Uses `socket` without changing its options. `config` must enable
    /// hello-retry cookies; the socket must be unconnected.
    pub fn new(config: Arc<ServerConfig>, socket: UdpSocket) -> io::Result<Self> {
        Self::new_with_versions(config, socket, Versions::default())
    }

    /// Creates a server with an explicit DTLS version policy.
    /// Peer admission remains stateless until its address cookie is verified.
    pub fn new_with_versions(
        config: Arc<ServerConfig>,
        socket: UdpSocket,
        versions: Versions,
    ) -> io::Result<Self> {
        Self::new_with_settings(config, socket, Settings::default().with_versions(versions))
    }

    /// Creates a server with explicit CID and return-routability settings.
    pub fn new_with_settings(
        config: Arc<ServerConfig>,
        socket: UdpSocket,
        settings: Settings,
    ) -> io::Result<Self> {
        if socket.peer_addr().is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a DTLS server requires an unconnected UDP socket",
            ));
        }
        let acceptor = Acceptor::new_with_settings(config, settings)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        Ok(Self {
            socket,
            acceptor,
            peers: BTreeMap::new(),
            physical: BTreeMap::new(),
            cids: CidDemux::default(),
            touched: BTreeSet::new(),
            path_selection: Selection::Enhanced,
            events: VecDeque::new(),
            retry: None,
            send_cursor: None,
            max_handshakes: DEFAULT_MAX_HANDSHAKES,
            max_peers: DEFAULT_MAX_PEERS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            read_timeout: None,
            start: Instant::now(),
            timer: None,
            buf: vec![0; MAX_DATAGRAM],
        })
    }

    /// Selects basic or enhanced validation for newly initialized paths.
    pub fn set_path_selection(&mut self, selection: Selection) {
        self.path_selection = selection;
    }

    /// Returns the current validated physical address for a stable handle.
    pub fn peer_addr(&self, peer: SocketAddr) -> Option<SocketAddr> {
        self.peers
            .get(&peer)
            .filter(|entry| entry.connected && !entry.retiring)
            .map(|entry| entry.active)
    }

    /// Bounds pending handshakes (at least one), evicting the oldest
    /// immediately if the limit is reduced below the current count.
    pub fn set_max_handshakes(&mut self, max: usize) {
        self.max_handshakes = max.max(1);
        while self.handshakes() > self.max_handshakes {
            self.drop_oldest_handshake();
        }
    }

    /// Bounds established associations (at least one). A reduced limit
    /// applies to subsequent admissions; existing peers remain connected.
    pub fn set_max_peers(&mut self, max: usize) {
        self.max_peers = max.max(1);
    }

    /// Sets the lifetime of newly admitted handshakes (default 30 seconds).
    pub fn set_handshake_timeout(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    /// Sets the timeout of each subsequent `next_event` call. Timers use
    /// Tokio's monotonic clock; traffic does not extend this deadline.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// Waits for an event while driving protocol output and timers.
    ///
    /// Cancellation preserves received events and pending ciphertext in
    /// the server. No receive is left running after this future is dropped.
    /// A zero timeout still checks the socket once for a waiting event.
    pub async fn next_event(&mut self) -> io::Result<ServerEvent> {
        let deadline = self
            .read_timeout
            .and_then(|timeout| Instant::now().checked_add(timeout));
        poll_fn(|cx| self.poll_next_event(cx, deadline)).await
    }

    /// Sends one whole application datagram to an established peer.
    /// Oversized plaintext returns `InvalidInput` without sealing it.
    ///
    /// Once sealed, ciphertext survives cancellation and is sent by the
    /// next operation. Calling `send_to` again submits a new datagram;
    /// cancellation cannot tell the caller whether the old one was sent.
    pub async fn send_to(&mut self, data: &[u8], peer: SocketAddr) -> io::Result<()> {
        poll_fn(|cx| self.poll_flushed(cx, peer, false)).await?;
        let entry = self.peers.get_mut(&peer).ok_or_else(not_connected)?;
        if entry
            .conn
            .max_application_data()
            .is_some_and(|max| data.len() > max)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "application data does not fit one DTLS datagram",
            ));
        }
        if let Err(err) = entry.conn.send(data, &mut entry.out) {
            // An error may have appended an incomplete record. Only a
            // successful sealing operation produces transport output.
            entry.out.clear();
            self.fail(peer, err.clone());
            return Err(io_error(err));
        }
        poll_fn(|cx| self.poll_flushed(cx, peer, false)).await
    }

    /// Queues `close_notify`, drains output, and removes the association.
    /// A cancelled close is completed by subsequent operations. If output
    /// remains blocked, the association is removed after one second.
    pub async fn close(&mut self, peer: SocketAddr) -> io::Result<()> {
        let now = self.now();
        if let Some(entry) = self.peers.get_mut(&peer)
            && !entry.retiring
        {
            entry.conn.send_close_notify();
            entry.retiring = true;
            entry.expires = now.saturating_add(DRAIN_TIMEOUT);
        }
        poll_fn(|cx| self.poll_flushed(cx, peer, true)).await
    }

    /// Removes a peer immediately, discarding its pending output.
    pub fn remove(&mut self, peer: SocketAddr) -> Option<ServerConnection> {
        let entry = self.peers.remove(&peer)?;
        self.physical.remove(&entry.active);
        self.cids.remove(peer);
        self.touched.remove(&peer);
        Some(entry.conn)
    }

    /// The established connection for an address.
    pub fn connection(&self, peer: SocketAddr) -> Option<&ServerConnection> {
        self.peers
            .get(&peer)
            .filter(|entry| entry.connected && !entry.retiring)
            .map(|entry| &entry.conn)
    }

    /// Mutates an established connection, for example to request new keys.
    /// Subsequent operations drive any protocol output it queues.
    pub fn connection_mut(&mut self, peer: SocketAddr) -> Option<&mut ServerConnection> {
        let entry = self
            .peers
            .get_mut(&peer)
            .filter(|entry| entry.connected && !entry.retiring)?;
        self.touched.insert(peer);
        Some(&mut entry.conn)
    }

    /// Addresses of the established, usable associations.
    pub fn peers(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.peers
            .iter()
            .filter(|(_, entry)| entry.connected && !entry.retiring)
            .map(|(peer, _)| *peer)
    }

    /// Pending handshake slots, including ones draining a fatal alert.
    pub fn handshakes(&self) -> usize {
        self.peers.values().filter(|entry| !entry.connected).count()
    }

    /// The socket supplied by the caller.
    ///
    /// Receiving from it or polling it concurrently with the server can
    /// consume protocol datagrams or replace the server's registered waker.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub(super) fn has_queued_events(&self) -> bool {
        !self.events.is_empty()
    }

    #[cfg(test)]
    pub(super) fn queue_event_for_test(&mut self, event: ServerEvent) {
        self.events.push_back(event);
    }

    fn now(&self) -> Duration {
        Instant::now().saturating_duration_since(self.start)
    }

    fn poll_next_event(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<io::Result<ServerEvent>> {
        let mut budget = IO_BURST;
        let mut looked = false;
        loop {
            // Check timers before consuming even an already-ready event or
            // socket. Continuous successful receives cannot starve expiry.
            for peer in std::mem::take(&mut self.touched) {
                self.refresh_peer(peer);
            }
            self.run_timers();
            // Reserve receive work even when many associations have
            // continuously ready output.
            let mut output_budget = budget.saturating_sub(1).min(IO_BURST / 2);
            let available = output_budget;
            self.poll_output(cx, &mut output_budget, None)?;
            budget -= available - output_budget;
            if let Some(event) = self.events.pop_front() {
                return Poll::Ready(Ok(event));
            }
            let expired = deadline.is_some_and(|due| due <= Instant::now());
            if expired && looked {
                return Poll::Ready(Err(timed_out()));
            }
            if budget == 0 {
                cx.waker().wake_by_ref();
                self.poll_timer(cx, deadline);
                return Poll::Pending;
            }
            let mut buf = ReadBuf::new(&mut self.buf);
            match self.socket.poll_recv_from(cx, &mut buf) {
                Poll::Ready(Ok(peer)) => {
                    let len = buf.filled().len();
                    budget -= 1;
                    looked = true;
                    self.handle_datagram(peer, len);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending if expired => return Poll::Ready(Err(timed_out())),
                Poll::Pending => {
                    self.poll_timer(cx, deadline);
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_flushed(
        &mut self,
        cx: &mut Context<'_>,
        peer: SocketAddr,
        closing: bool,
    ) -> Poll<io::Result<()>> {
        self.run_timers();
        let mut budget = IO_BURST;
        self.poll_output(cx, &mut budget, Some(peer))?;
        match self.peers.get(&peer) {
            None if closing => return Poll::Ready(Ok(())),
            None => return Poll::Ready(Err(not_connected())),
            Some(entry) if !closing && (!entry.connected || entry.retiring) => {
                return Poll::Ready(Err(not_connected()));
            }
            Some(entry)
                if entry.probe.is_none()
                    && entry.out.is_empty()
                    && !entry.conn.wants_write(self.now()) =>
            {
                return Poll::Ready(Ok(()));
            }
            _ => {}
        }
        self.poll_timer(cx, None);
        Poll::Pending
    }

    fn poll_timer(&mut self, cx: &mut Context<'_>, deadline: Option<Instant>) {
        let due = self
            .peers
            .values()
            .filter_map(Peer::next_due)
            .filter_map(|due| self.start.checked_add(due))
            .chain(deadline)
            .min();
        if let Some(due) = due {
            let timer = self
                .timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(due)));
            timer.as_mut().reset(due);
            if timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
    }

    fn handle_datagram(&mut self, peer: SocketAddr, len: usize) {
        let now = self.now();
        let source = peer;
        let has_cid = CidDemux::<SocketAddr>::has_cid(&self.buf[..len]);
        let owner = if has_cid {
            self.cids.lookup(&self.buf[..len])
        } else {
            self.physical.get(&source).copied()
        };
        if let Some(peer) = owner {
            if (source != peer && self.peers.contains_key(&source))
                || self
                    .physical
                    .get(&source)
                    .is_some_and(|owner| *owner != peer)
            {
                return;
            }
            let Some(entry) = self.peers.get_mut(&peer) else {
                return;
            };
            if entry.retiring
                || (source != entry.active
                    && (!entry.connected
                        || !has_cid
                        || entry.paths.is_none()
                        || entry
                            .paths
                            .as_ref()
                            .and_then(UdpPathValidation::pending)
                            .is_some_and(|pending| pending != source)))
            {
                return;
            }
            let datagram = &mut self.buf[..len];
            let result = entry
                .conn
                .read_datagram(datagram, now)
                .and_then(|received| {
                    if entry.paths.is_none()
                        && entry.conn.return_routability_checks_negotiated()
                        && !entry.conn.peer_has_closed()
                        && !entry.conn.local_close_notify_queued()
                    {
                        entry.paths = Some(UdpPathValidation::new(
                            &entry.conn,
                            entry.active,
                            self.path_selection,
                        )?);
                    }
                    if let Some(paths) = &mut entry.paths {
                        paths.input(
                            &mut entry.conn,
                            &received,
                            datagram,
                            source,
                            now,
                            &mut |data, destination| {
                                if entry.probe.is_none() {
                                    entry.probe = Some((destination, data.to_vec()));
                                }
                            },
                        )
                    } else {
                        Ok(received.app_data().to_vec())
                    }
                });
            if result.is_ok() {
                self.refresh_peer(peer);
            }
            self.after_input(peer, result);
            return;
        }
        if has_cid || self.peers.contains_key(&source) {
            return;
        }
        let mut out = Vec::new();
        match self
            .acceptor
            .accept(&mut self.buf[..len], &address_bytes(peer), &mut out, now)
        {
            Ok(Accepted::Retry) if self.retry.is_none() => self.retry = Some((peer, out)),
            Ok(Accepted::Connection(conn)) => {
                while self.handshakes() >= self.max_handshakes {
                    self.drop_oldest_handshake();
                }
                self.peers.insert(
                    peer,
                    Peer {
                        conn: *conn,
                        started: now,
                        expires: now.saturating_add(self.handshake_timeout),
                        connected: false,
                        retiring: false,
                        serviced_timeout: None,
                        out: Vec::new(),
                        active: peer,
                        paths: None,
                        probe: None,
                    },
                );
                self.physical.insert(peer, peer);
                self.after_input(peer, Ok(Vec::new()));
                self.refresh_peer(peer);
            }
            // Unvalidated traffic has no association to fail. A full
            // cookie-reply slot behaves like UDP packet loss.
            _ => {}
        }
    }

    fn after_input(
        &mut self,
        peer: SocketAddr,
        result: Result<Vec<std::ops::Range<usize>>, Error>,
    ) {
        let now = self.now();
        let ranges = match result {
            Ok(ranges) => ranges,
            Err(err) => return self.fail(peer, err),
        };
        // Include retiring established slots in admission accounting.
        let established = self.peers.values().filter(|entry| entry.connected).count();
        let Some(entry) = self.peers.get_mut(&peer) else {
            return;
        };
        if !entry.connected && entry.conn.pending_revocation().is_some() {
            return self.fail(
                peer,
                Error::General("live OCSP queries are unsupported by UdpServer".into()),
            );
        }
        if !entry.connected && !entry.conn.is_handshaking() {
            if established >= self.max_peers {
                return self.fail(peer, Error::General("DTLS peer limit reached".into()));
            }
            entry.connected = true;
            self.events.push_back(ServerEvent::Connected(peer));
        }
        for range in ranges {
            self.events
                .push_back(ServerEvent::Received(peer, self.buf[range].to_vec()));
        }
        if entry.conn.peer_has_closed() {
            if entry.connected {
                self.events.push_back(ServerEvent::Closed(peer));
            }
            entry.retiring = true;
            entry.expires = now.saturating_add(DRAIN_TIMEOUT);
        }
    }

    fn refresh_peer(&mut self, peer: SocketAddr) {
        if let Some(entry) = self.peers.get_mut(&peer) {
            self.cids.replace(peer, entry.conn.local_connection_ids());
            if let Some(paths) = &entry.paths {
                let active = paths.active();
                if active != entry.active {
                    self.physical.remove(&entry.active);
                    self.physical.insert(active, peer);
                    entry.active = active;
                    self.events
                        .push_back(ServerEvent::PeerAddressChanged(peer, active));
                }
            }
        }
    }

    fn fail(&mut self, peer: SocketAddr, err: Error) {
        let expires = self.now().saturating_add(DRAIN_TIMEOUT);
        if let Some(entry) = self.peers.get_mut(&peer) {
            if entry.retiring {
                return;
            }
            if entry.connected {
                self.events.push_back(ServerEvent::Failed(peer, err));
            }
            entry.retiring = true;
            entry.expires = expires;
        }
    }

    fn run_timers(&mut self) {
        let now = self.now();
        let due: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, entry)| entry.next_due().is_some_and(|due| due <= now))
            .map(|(peer, _)| *peer)
            .collect();
        for peer in due {
            let Some(entry) = self.peers.get_mut(&peer) else {
                continue;
            };
            if (!entry.connected || entry.retiring) && entry.expires <= now {
                self.remove(peer);
            } else {
                if let Some(paths) = &mut entry.paths {
                    if let Err(err) = paths.poll(&mut entry.conn, now, &mut |data, destination| {
                        if entry.probe.is_none() {
                            entry.probe = Some((destination, data.to_vec()));
                        }
                    }) {
                        self.fail(peer, err);
                        continue;
                    }
                }
                let previous = entry.conn.next_timeout();
                if !previous.is_some_and(|due| due <= now && Some(due) != entry.serviced_timeout) {
                    self.refresh_peer(peer);
                    continue;
                }
                match entry.conn.handle_timeout(now) {
                    Ok(()) => {
                        entry.serviced_timeout = previous
                            .filter(|previous| Some(*previous) == entry.conn.next_timeout());
                    }
                    Err(err) => self.fail(peer, err),
                }
            }
        }
    }

    // Visit peers in rotating address order. One peer can send at most one
    // datagram per pass; send failures remove only the affected peer.
    fn poll_output(
        &mut self,
        cx: &mut Context<'_>,
        budget: &mut usize,
        target: Option<SocketAddr>,
    ) -> io::Result<()> {
        if *budget > 0
            && let Some((peer, out)) = self.retry.as_mut()
            && poll_send_datagram(out, |out| self.socket.poll_send_to(cx, out, *peer)).is_ready()
        {
            self.retry = None;
            *budget -= 1;
        }
        let keys: Vec<_> = if let Some(cursor) = self.send_cursor {
            self.peers
                .range((Excluded(cursor), Unbounded))
                .chain(self.peers.range(..=cursor))
                .map(|(peer, _)| *peer)
                .collect()
        } else {
            self.peers.keys().copied().collect()
        };
        let now = self.now();
        let mut more = false;
        for peer in keys {
            if *budget == 0 {
                more = true;
                break;
            }
            self.send_cursor = Some(peer);
            let Some(entry) = self.peers.get_mut(&peer) else {
                continue;
            };
            self.cids.replace(peer, entry.conn.local_connection_ids());
            if let Some((destination, probe)) = &mut entry.probe {
                match poll_send_datagram(probe, |out| {
                    self.socket.poll_send_to(cx, out, *destination)
                }) {
                    Poll::Ready(Ok(())) => {
                        entry.probe = None;
                        *budget -= 1;
                    }
                    Poll::Ready(Err(err)) => {
                        self.fail(peer, Error::General(format!("DTLS UDP send failed: {err}")));
                        self.remove(peer);
                        if target == Some(peer) {
                            return Err(err);
                        }
                        continue;
                    }
                    Poll::Pending => continue,
                }
                if *budget == 0 {
                    more = true;
                    continue;
                }
            }
            if entry.out.is_empty() {
                if let Err(err) = entry.conn.write_datagram(&mut entry.out, now) {
                    entry.out.clear();
                    self.fail(peer, err);
                    continue;
                }
                entry.serviced_timeout = None;
            }
            if !entry.out.is_empty() {
                match poll_send_datagram(&mut entry.out, |out| {
                    self.socket.poll_send_to(cx, out, entry.active)
                }) {
                    Poll::Ready(Ok(())) => {
                        entry.serviced_timeout = None;
                        *budget -= 1;
                    }
                    Poll::Ready(Err(err)) => {
                        self.fail(peer, Error::General(format!("DTLS UDP send failed: {err}")));
                        self.remove(peer);
                        if target == Some(peer) {
                            return Err(err);
                        }
                        continue;
                    }
                    Poll::Pending => continue,
                }
            }
            let Some(entry) = self.peers.get(&peer) else {
                continue;
            };
            if entry.retiring && entry.out.is_empty() && !entry.conn.wants_write(now) {
                self.remove(peer);
            } else if entry.out.is_empty() && entry.conn.wants_write(now) {
                more = true;
            }
        }
        if more {
            cx.waker().wake_by_ref();
        }
        Ok(())
    }

    fn drop_oldest_handshake(&mut self) {
        let oldest = self
            .peers
            .iter()
            .filter(|(_, entry)| !entry.connected)
            .min_by_key(|(_, entry)| entry.started)
            .map(|(peer, _)| *peer);
        if let Some(peer) = oldest {
            self.remove(peer);
        }
    }
}

fn address_bytes(peer: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(23);
    match peer {
        SocketAddr::V4(peer) => {
            bytes.push(4);
            bytes.extend_from_slice(&peer.ip().octets());
        }
        SocketAddr::V6(peer) => {
            bytes.push(6);
            bytes.extend_from_slice(&peer.ip().octets());
            bytes.extend_from_slice(&peer.scope_id().to_be_bytes());
        }
    }
    bytes.extend_from_slice(&peer.port().to_be_bytes());
    bytes
}

fn not_connected() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "no DTLS association with this address",
    )
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "DTLS read timeout")
}

impl fmt::Debug for UdpServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls::UdpServer")
            .field("socket", &self.socket)
            .field("peers", &self.peers.len())
            .field("handshakes", &self.handshakes())
            .finish_non_exhaustive()
    }
}

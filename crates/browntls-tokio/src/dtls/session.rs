//! Bounded DTLS session handles driven by one caller-run event server.
//!
//! No task is spawned. The caller must poll [`SessionDriver::run`] alongside
//! listener and session operations, with Tokio's I/O and time drivers enabled.
#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;

use browntls_core::ServerConfig;
use browntls_core::dtls::{Settings, Versions, rrc::Selection};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};

use super::MAX_DATAGRAM;
use super::server::{ServerEvent, UdpServer};

const MAX_SESSIONS: usize = 1024;
const RECEIVE_BYTES: usize = 64 * 1024 * 1024;
const COMMAND_BYTES: usize = 4 * 1024 * 1024;

/// Datagram counts for every session-layer queue.
///
/// Construction rejects zero counts, more than 1024 session handles, an
/// accept queue larger than the handle limit, or receive/command budgets
/// above 64 MiB/4 MiB respectively. Every datagram is charged at 65,535
/// bytes, including empty datagrams. Receive accounting is
/// `max_sessions * receive_queue * 65_535`; command accounting includes
/// the active command: `(command_queue + 1) * 65_535`.
///
/// These are payload limits, excluding channel bookkeeping, the event
/// server's bounded protocol state, and datagrams returned to the caller.
/// Accepted, unaccepted and closed-but-retained handles all consume a
/// session slot until dropped. The accept queue holds handles, without
/// another payload copy. Pending send callers allocate no payload copy
/// until they acquire a command slot.
#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    /// Maximum number of retained handles, also bounding live peers.
    pub max_sessions: usize,
    /// Completed handshakes waiting for `accept`.
    pub accept_queue: usize,
    /// Whole received application datagrams per handle.
    pub receive_queue: usize,
    /// Send/close requests waiting for the driver, plus one active request.
    pub command_queue: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_sessions: 128,
            accept_queue: 32,
            receive_queue: 8,
            command_queue: 32,
        }
    }
}

impl SessionLimits {
    fn validate(self) -> io::Result<Self> {
        let receive_bytes = self
            .max_sessions
            .checked_mul(self.receive_queue)
            .and_then(|count| count.checked_mul(MAX_DATAGRAM));
        let command_bytes = self
            .command_queue
            .checked_add(1)
            .and_then(|count| count.checked_mul(MAX_DATAGRAM));
        if self.max_sessions == 0
            || self.max_sessions > MAX_SESSIONS
            || self.accept_queue == 0
            || self.accept_queue > self.max_sessions
            || self.receive_queue == 0
            || self.command_queue == 0
            || !receive_bytes.is_some_and(|bytes| bytes <= RECEIVE_BYTES)
            || !command_bytes.is_some_and(|bytes| bytes <= COMMAND_BYTES)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DTLS session limits exceed the count or payload budget",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone)]
enum Terminal {
    Closed,
    Failed(Arc<io::Error>),
}

impl Terminal {
    fn error(&self) -> io::Error {
        match self {
            Self::Closed => disconnected(),
            Self::Failed(error) => io::Error::new(error.kind(), error.to_string()),
        }
    }
}

struct Identity;

struct Peer {
    identity: Arc<Identity>,
    received: mpsc::Sender<Vec<u8>>,
    terminal: watch::Sender<Option<Terminal>>,
    current_address: watch::Sender<SocketAddr>,
}

enum Request {
    Send(Vec<u8>),
    Close,
}

struct Command {
    peer: SocketAddr,
    identity: Arc<Identity>,
    request: Request,
    reply: oneshot::Sender<io::Result<()>>,
}

/// An accept queue for authenticated DTLS associations.
///
/// Dropping the listener stops admissions while existing handles continue
/// to work. A full accept queue rejects the newly connected association;
/// it does not evict an existing handle or block other peers.
pub struct UdpListener {
    accepted: mpsc::Receiver<UdpSession>,
    terminal: watch::Receiver<Option<Terminal>>,
    wake: Arc<Notify>,
}

impl UdpListener {
    /// Wraps an unconnected socket and cookie-enabled server configuration.
    /// Returns the listener and its driver without starting any task.
    pub fn new(
        config: Arc<ServerConfig>,
        socket: UdpSocket,
        limits: SessionLimits,
    ) -> io::Result<(Self, SessionDriver)> {
        Self::new_with_versions(config, socket, Versions::default(), limits)
    }

    /// Wraps an unconnected socket with an explicit DTLS version policy.
    /// Returns the listener and its driver without starting any task.
    pub fn new_with_versions(
        config: Arc<ServerConfig>,
        socket: UdpSocket,
        versions: Versions,
        limits: SessionLimits,
    ) -> io::Result<(Self, SessionDriver)> {
        Self::new_with_settings(
            config,
            socket,
            Settings::default().with_versions(versions),
            Selection::Enhanced,
            limits,
        )
    }

    /// Constructs a listener with explicit endpoint settings and path mode.
    pub fn new_with_settings(
        config: Arc<ServerConfig>,
        socket: UdpSocket,
        settings: Settings,
        selection: Selection,
        limits: SessionLimits,
    ) -> io::Result<(Self, SessionDriver)> {
        let limits = limits.validate()?;
        let mut server = UdpServer::new_with_settings(config, socket, settings)?;
        server.set_path_selection(selection);
        server.set_max_peers(limits.max_sessions);
        let (accepted_tx, accepted) = mpsc::channel(limits.accept_queue);
        let (commands_tx, commands) = mpsc::channel(limits.command_queue);
        let (terminal_tx, terminal) = watch::channel(None);
        let wake = Arc::new(Notify::new());
        let listener = Self {
            accepted,
            terminal,
            wake: wake.clone(),
        };
        let driver = SessionDriver {
            server,
            accepted: accepted_tx,
            terminal: terminal_tx,
            commands,
            commands_tx,
            wake,
            slots: Arc::new(Semaphore::new(limits.max_sessions)),
            peers: BTreeMap::new(),
            limits,
            event_first: true,
        };
        Ok((listener, driver))
    }

    /// Waits for a session. Cancellation leaves the next handle queued.
    /// The driver must run concurrently; driver failure is returned here.
    pub async fn accept(&mut self) -> io::Result<UdpSession> {
        self.accepted.recv().await.ok_or_else(|| {
            self.terminal
                .borrow()
                .as_ref()
                .map_or_else(driver_gone, Terminal::error)
        })
    }
}

impl Drop for UdpListener {
    fn drop(&mut self) {
        // Close before notifying: the driver may run on another thread.
        self.accepted.close();
        self.wake.notify_one();
    }
}

/// One association, identified by its address and a unique handle identity.
///
/// No socket or protocol state is shared with this handle. Address reuse
/// never lets an old handle send to or close a replacement association.
/// Dropping the handle discards its queued input and requests immediate
/// removal without `close_notify`; use [`Self::close`] for graceful close.
pub struct UdpSession {
    peer: SocketAddr,
    identity: Arc<Identity>,
    received: Option<mpsc::Receiver<Vec<u8>>>,
    terminal: watch::Receiver<Option<Terminal>>,
    current_address: watch::Receiver<SocketAddr>,
    commands: mpsc::Sender<Command>,
    wake: Arc<Notify>,
    slot: Option<OwnedSemaphorePermit>,
}

impl UdpSession {
    /// The latest validated physical address of the peer.
    pub fn peer_addr(&self) -> SocketAddr {
        *self.current_address.borrow()
    }

    /// The stable address that identified this association at admission.
    pub fn original_peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Waits for a validated address change. Changes are coalesced and
    /// cancellation does not consume a notification.
    pub async fn peer_addr_changed(&mut self) -> io::Result<SocketAddr> {
        self.current_address
            .changed()
            .await
            .map_err(|_| disconnected())?;
        Ok(*self.current_address.borrow_and_update())
    }

    /// Receives a whole datagram, including an empty one, or `None` after
    /// graceful close. Buffered data is drained before close or failure.
    /// A saturated queue drops only the newest arriving application
    /// datagram; terminal state has a separate channel and cannot be lost.
    /// Cancellation consumes no datagram. Returned data belongs to the
    /// caller and is outside the layer's retained-payload budget.
    pub async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        let received = self.received.as_mut().ok_or_else(driver_gone)?;
        if let Some(data) = received.recv().await {
            return Ok(Some(data));
        }
        match self.terminal.borrow().as_ref() {
            Some(Terminal::Closed) => Ok(None),
            Some(terminal) => Err(terminal.error()),
            None => Err(driver_gone()),
        }
    }

    /// Sends one whole application datagram with command-queue backpressure.
    /// Payloads larger than 65,535 bytes are rejected before allocation;
    /// the protocol may impose a smaller MTU-dependent limit.
    ///
    /// Cancellation while waiting for queue capacity submits nothing. A
    /// queued request whose caller has already cancelled is skipped. Once
    /// execution starts, cancellation or error cannot establish whether a
    /// datagram reached the socket; retrying may duplicate application data.
    /// A handle/listener drop interrupts blocked output with `Interrupted`
    /// so the driver can prune handles. Sealed output survives interruption
    /// in the event server unless its association is removed.
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DTLS application datagram exceeds the session byte cap",
            ));
        }
        self.submit(|| Request::Send(data.to_vec())).await
    }

    /// Sends `close_notify` and closes both directions locally. Input
    /// already queued remains readable. This does not wait for the peer's
    /// acknowledgement. Cancellation before execution submits no close;
    /// once started, the event server continues its bounded close drain
    /// while the driver runs.
    /// Lifecycle interruption can return `Interrupted` after close started.
    pub async fn close(&self) -> io::Result<()> {
        if matches!(*self.terminal.borrow(), Some(Terminal::Closed)) {
            return Ok(());
        }
        self.submit(|| Request::Close).await
    }

    async fn submit(&self, request: impl FnOnce() -> Request) -> io::Result<()> {
        self.check_open()?;
        let mut terminal = self.terminal.clone();
        let permit = {
            let mut changed = pin!(terminal.changed());
            let mut reservation = pin!(self.commands.reserve());
            poll_fn(|cx| {
                if let Err(error) = self.check_open() {
                    return Poll::Ready(Err(error));
                }
                if let Poll::Ready(result) = reservation.as_mut().poll(cx) {
                    return Poll::Ready(result.map_err(|_| driver_gone()));
                }
                if changed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(self.check_open().err().unwrap_or_else(driver_gone)));
                }
                Poll::Pending
            })
            .await?
        };
        self.check_open()?;
        let (reply, response) = oneshot::channel();
        permit.send(Command {
            peer: self.peer,
            identity: self.identity.clone(),
            request: request(),
            reply,
        });
        response.await.map_err(|_| driver_gone())?
    }

    fn check_open(&self) -> io::Result<()> {
        if let Some(terminal) = self.terminal.borrow().as_ref() {
            return Err(terminal.error());
        }
        if self.terminal.has_changed().is_err() {
            return Err(driver_gone());
        }
        Ok(())
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        // Destroy the data queue before releasing its payload-budget slot.
        // Publish both changes before another thread observes the wake.
        drop(self.received.take());
        drop(self.slot.take());
        self.wake.notify_one();
    }
}

/// Sole owner of the UDP socket, protocol state and session admission.
///
/// Socket-output operations are serialized through the event server. A
/// blocked send/close temporarily pauses network input; a lifecycle wake
/// interrupts it to allow pruning and shutdown. Events and queued commands
/// alternate priority so ready traffic cannot starve commands or vice versa.
/// The event server retains its own cookie/handshake limits and timers.
pub struct SessionDriver {
    server: UdpServer,
    accepted: mpsc::Sender<UdpSession>,
    terminal: watch::Sender<Option<Terminal>>,
    commands: mpsc::Receiver<Command>,
    commands_tx: mpsc::Sender<Command>,
    wake: Arc<Notify>,
    slots: Arc<Semaphore>,
    peers: BTreeMap<SocketAddr, Peer>,
    limits: SessionLimits,
    event_first: bool,
}

enum Work {
    Changed,
    Command(Command),
    Event(io::Result<ServerEvent>),
}

impl SessionDriver {
    /// Runs until the listener and every retained session are gone, or a
    /// socket-level error occurs. Peer errors terminate only that session.
    /// Dropping this future also drops the driver: all handles become
    /// failed and pending requests wake with an error. It cannot be resumed.
    /// No background task is started or left running on cancellation.
    pub async fn run(mut self) -> io::Result<()> {
        let result = self.run_inner().await;
        let terminal = match &result {
            Ok(()) => Terminal::Closed,
            Err(error) => {
                Terminal::Failed(Arc::new(io::Error::new(error.kind(), error.to_string())))
            }
        };
        self.finish(terminal);
        result
    }

    async fn run_inner(&mut self) -> io::Result<()> {
        loop {
            self.prune();
            if self.accepted.is_closed()
                && self.slots.available_permits() == self.limits.max_sessions
            {
                return Ok(());
            }
            match self.next_work().await {
                Work::Changed => {}
                Work::Command(command) => self.command(command).await,
                Work::Event(event) => self.event(event?),
            }
        }
    }

    async fn next_work(&mut self) -> Work {
        let mut changed = pin!(self.wake.notified());
        // Deliver already-observed events before commands can retire a
        // session. Alternate only when selecting new work from the socket.
        let event_first = self.event_first || self.server.has_queued_events();
        let mut event = pin!(self.server.next_event());
        self.event_first = !self.event_first;
        poll_fn(|cx| {
            if changed.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Work::Changed);
            }
            if event_first && let Poll::Ready(event) = event.as_mut().poll(cx) {
                return Poll::Ready(Work::Event(event));
            }
            if let Poll::Ready(Some(command)) = self.commands.poll_recv(cx) {
                return Poll::Ready(Work::Command(command));
            }
            if !event_first && let Poll::Ready(event) = event.as_mut().poll(cx) {
                return Poll::Ready(Work::Event(event));
            }
            Poll::Pending
        })
        .await
    }

    fn prune(&mut self) {
        self.peers.retain(|address, peer| {
            if peer.received.is_closed() {
                self.server.remove(*address);
                false
            } else {
                true
            }
        });
    }

    fn event(&mut self, event: ServerEvent) {
        match event {
            ServerEvent::Connected(address) => self.admit(address),
            ServerEvent::PeerAddressChanged(address, current) => {
                if let Some(peer) = self.peers.get(&address) {
                    peer.current_address.send_replace(current);
                }
            }
            ServerEvent::Received(address, data) => {
                if let Some(peer) = self.peers.get(&address) {
                    if data.len() > MAX_DATAGRAM {
                        self.retire(
                            address,
                            Terminal::Failed(Arc::new(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "DTLS event exceeds the session byte cap",
                            ))),
                        );
                        self.server.remove(address);
                    } else {
                        // Full means UDP-style loss of this newest record.
                        // Closed is pruned before the next driver operation.
                        let _ = peer.received.try_send(data);
                    }
                }
            }
            ServerEvent::Closed(address) => self.retire(address, Terminal::Closed),
            ServerEvent::Failed(address, error) => self.retire(
                address,
                Terminal::Failed(Arc::new(io::Error::new(io::ErrorKind::InvalidData, error))),
            ),
        }
    }

    fn admit(&mut self, address: SocketAddr) {
        if self.accepted.is_closed() || self.accepted.capacity() == 0 {
            self.server.remove(address);
            return;
        }
        let Ok(slot) = self.slots.clone().try_acquire_owned() else {
            self.server.remove(address);
            return;
        };
        let (received_tx, received) = mpsc::channel(self.limits.receive_queue);
        let (terminal_tx, terminal) = watch::channel(None);
        let identity = Arc::new(Identity);
        let (current_address_tx, current_address) = watch::channel(address);
        let session = UdpSession {
            peer: address,
            identity: identity.clone(),
            received: Some(received),
            terminal,
            current_address,
            commands: self.commands_tx.clone(),
            wake: self.wake.clone(),
            slot: Some(slot),
        };
        // No address may silently replace an existing handle identity.
        self.retire(address, Terminal::Closed);
        self.peers.insert(
            address,
            Peer {
                identity,
                received: received_tx,
                terminal: terminal_tx,
                current_address: current_address_tx,
            },
        );
        if self.accepted.try_send(session).is_err() {
            self.peers.remove(&address);
            self.server.remove(address);
        }
    }

    async fn command(&mut self, command: Command) {
        if command.reply.is_closed() {
            return;
        }
        let current = self.peers.get(&command.peer).is_some_and(|peer| {
            Arc::ptr_eq(&peer.identity, &command.identity) && !peer.received.is_closed()
        });
        if !current {
            let _ = command.reply.send(Err(disconnected()));
            return;
        }
        let result = match command.request {
            Request::Send(data) => {
                interruptible(self.server.send_to(&data, command.peer), self.wake.as_ref()).await
            }
            Request::Close => {
                let result = interruptible(self.server.close(command.peer), &self.wake).await;
                // A cancelled close remains owned by the event server and
                // is drained by its subsequent operations/timer.
                let terminal = match &result {
                    Err(error) if error.kind() != io::ErrorKind::Interrupted => {
                        Terminal::Failed(Arc::new(io::Error::new(error.kind(), error.to_string())))
                    }
                    _ => Terminal::Closed,
                };
                self.retire(command.peer, terminal);
                result
            }
        };
        let _ = command.reply.send(result);
    }

    fn retire(&mut self, address: SocketAddr, terminal: Terminal) {
        if let Some(peer) = self.peers.remove(&address) {
            peer.terminal.send_replace(Some(terminal));
            // Dropping the data sender exposes terminal after queued data.
        }
    }

    fn finish(&mut self, terminal: Terminal) {
        self.terminal.send_replace(Some(terminal.clone()));
        for (_, peer) in std::mem::take(&mut self.peers) {
            peer.terminal.send_replace(Some(terminal.clone()));
        }
        self.commands.close();
    }
}

// Poll the operation first so a close interrupted by a stored notification
// has actually started; a pending send may already own sealed ciphertext.
async fn interruptible(
    operation: impl Future<Output = io::Result<()>>,
    wake: &Notify,
) -> io::Result<()> {
    let mut operation = pin!(operation);
    let mut changed = pin!(wake.notified());
    poll_fn(|cx| {
        if let Poll::Ready(result) = operation.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        if changed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "DTLS output interrupted for session lifecycle cleanup",
            )));
        }
        Poll::Pending
    })
    .await
}

impl Drop for SessionDriver {
    fn drop(&mut self) {
        if self.terminal.borrow().is_none() {
            self.finish(Terminal::Failed(Arc::new(driver_gone())));
        }
    }
}

fn disconnected() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "DTLS session is closed or stale",
    )
}

fn driver_gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "DTLS session driver stopped")
}

impl fmt::Debug for UdpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls::UdpListener").finish_non_exhaustive()
    }
}

impl fmt::Debug for UdpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls::UdpSession")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SessionDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls::SessionDriver")
            .field("peers", &self.peers.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, any(feature = "native", feature = "rustcrypto")))]
mod tests;

//! A DTLS client driven by its caller, without a background task.

use std::collections::VecDeque;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use browntls_core::dtls::{
    ClientConnection, Settings, UdpPathValidation, Versions, rrc::Selection,
};
use browntls_core::pki_types::ServerName;
use browntls_core::{ClientConfig, ClientServerIdentity, Error};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::time::{Instant, Sleep, sleep_until};

use super::{IO_BURST, MAX_DATAGRAM, Recv, io_error, poll_send_datagram};

/// A DTLS 1.3 client over a UDP socket the caller bound and connected.
///
/// Calls borrow the client exclusively. No task runs while it is idle:
/// drive a handshake or receive to process peer messages and timers. DTLS
/// preserves application datagrams; it does not reliably deliver them.
///
/// Cancelling an operation preserves protocol state, received plaintext and
/// any pending ciphertext in this object. A cancelled `send` may already
/// have accepted its application datagram: subsequent operations finish
/// sending that same ciphertext before doing other I/O. Do not blindly
/// retry the plaintext, since that would enqueue another application
/// datagram. Dropping the client discards all of this state.
pub struct UdpClient {
    conn: ClientConnection,
    socket: UdpSocket,
    start: Instant,
    timeout: Option<Duration>,
    // Ranges refer to `input`, which is never overwritten while any remain.
    received: VecDeque<Range<usize>>,
    input: Vec<u8>,
    // Exactly one sealed datagram, never a stream or a queue of plaintext.
    out: Vec<u8>,
    paths: Option<UdpPathValidation>,
    probes: VecDeque<Vec<u8>>,
    closing: bool,
    // Protocol errors are terminal, even if sending their alert blocks.
    failure: Option<Error>,
}

impl UdpClient {
    /// Creates a client without doing I/O. `socket` must already be
    /// connected to its server. Use [`Self::complete_handshake`] to drive
    /// a handshake that can be cancelled and resumed on this object.
    pub fn new(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        socket: UdpSocket,
    ) -> io::Result<Self> {
        Self::new_with_versions(config, name, socket, Versions::default())
    }

    /// Creates a client with an explicit DTLS version policy.
    /// The supplied TLS configuration must also permit each usable version.
    pub fn new_with_versions(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        socket: UdpSocket,
        versions: Versions,
    ) -> io::Result<Self> {
        Self::new_with_settings(
            config,
            name,
            socket,
            Settings::default().with_versions(versions),
        )
    }

    /// Creates a client with explicit CID and return-routability settings.
    pub fn new_with_settings(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        socket: UdpSocket,
        settings: Settings,
    ) -> io::Result<Self> {
        Self::from_connection(
            ClientConnection::new_with_settings(config, name, settings).map_err(io_error)?,
            socket,
        )
    }

    /// Creates a client using RFC 9525 service identity matching. The UDP
    /// socket must already be connected to its server.
    pub fn new_with_identity(
        config: Arc<ClientConfig>,
        identity: ClientServerIdentity,
        socket: UdpSocket,
    ) -> io::Result<Self> {
        Self::new_with_identity_and_settings(config, identity, socket, Settings::default())
    }

    /// Creates a client using RFC 9525 service identity matching and
    /// explicit CID and return-routability settings. The socket must already
    /// be connected to its server.
    pub fn new_with_identity_and_settings(
        config: Arc<ClientConfig>,
        identity: ClientServerIdentity,
        socket: UdpSocket,
        settings: Settings,
    ) -> io::Result<Self> {
        Self::from_connection(
            ClientConnection::new_with_identity_and_settings(config, identity, settings)
                .map_err(io_error)?,
            socket,
        )
    }

    /// Replaces the local socket of a live CID/RRC association. The new
    /// socket must be connected to the same server. Pending ciphertext and
    /// the connection clock are retained. Drive receive to answer probes;
    /// application data sent before path validation can be discarded.
    pub fn replace_socket(&mut self, socket: UdpSocket) -> io::Result<UdpSocket> {
        if !self.conn.return_routability_checks_negotiated()
            || self.conn.peer_has_closed()
            || self.conn.local_close_notify_queued()
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "a live CID/RRC association is required",
            ));
        }
        if self.conn.outbound_connection_id().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a peer receiving CID is required",
            ));
        }
        if socket.peer_addr()? != self.socket.peer_addr()? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "replacement socket has a different remote address",
            ));
        }
        Ok(std::mem::replace(&mut self.socket, socket))
    }

    /// Takes a freshly created connection, configured as needed (for
    /// example its MTU), without doing I/O. It must not already have been
    /// driven using another clock origin. Rejects an unconnected socket.
    pub fn from_connection(conn: ClientConnection, socket: UdpSocket) -> io::Result<Self> {
        socket.peer_addr()?;
        Ok(Self {
            conn,
            socket,
            start: Instant::now(),
            timeout: None,
            received: VecDeque::new(),
            input: vec![0; MAX_DATAGRAM],
            out: Vec::new(),
            paths: None,
            probes: VecDeque::new(),
            closing: false,
            failure: None,
        })
    }

    /// Creates a client and completes its handshake. Cancelling this
    /// convenience constructor drops the client and socket; use
    /// [`Self::new`] to retain state across cancellation instead.
    pub async fn connect(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        socket: UdpSocket,
    ) -> io::Result<Self> {
        let mut client = Self::new(config, name, socket)?;
        client.complete_handshake().await?;
        Ok(client)
    }

    /// Completes the handshake and sends its queued output. Calling again
    /// after cancellation or an operation timeout continues the handshake.
    /// Closing before the handshake finishes causes `ConnectionAborted`.
    /// Live OCSP queries return `Unsupported`.
    pub async fn complete_handshake(&mut self) -> io::Result<()> {
        let mut wait = self.wait();
        self.handshake_until(&mut wait).await
    }

    /// Sends `data` as one application datagram, completing the handshake
    /// first. Its size must not exceed `connection().max_application_data()`.
    /// Oversized data returns `InvalidInput` without accepting it.
    ///
    /// Cancellation or an I/O error after sealing leaves the ciphertext
    /// pending for the next operation; see the type's cancellation contract.
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        if self.closing {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DTLS client is closed",
            ));
        }
        let mut wait = self.wait();
        self.handshake_until(&mut wait).await?;
        wait.check(self.now())?;
        if self
            .conn
            .max_application_data()
            .is_some_and(|max| data.len() > max)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "application data does not fit one DTLS datagram",
            ));
        }
        // handshake_until drained `out`; sealing happens exactly once,
        // before the cancellable flush, into state owned by the client.
        self.conn.send(data, &mut self.out).map_err(io_error)?;
        self.flush_until(&mut wait).await
    }

    /// Receives one whole application datagram or the peer's close notice.
    /// `Recv::Data(0)` is an empty record, not a close. A short destination
    /// returns `InvalidInput` and keeps that record for the next call.
    /// Received data precedes a close notice from the same UDP datagram.
    /// The deadline includes any implicit handshake and protocol writes.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<Recv> {
        let mut wait = self.wait();
        self.handshake_until(&mut wait).await?;
        poll_fn(|cx| self.poll_run(cx, &mut wait, Goal::Receive)).await?;
        if let Some(range) = self.received.front() {
            let Some(dest) = buf.get_mut(..range.len()) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer shorter than the received DTLS datagram",
                ));
            };
            dest.copy_from_slice(&self.input[range.clone()]);
            let len = range.len();
            self.received.pop_front();
            return Ok(Recv::Data(len));
        }
        Ok(Recv::Closed)
    }

    /// Sends `close_notify` after pending ciphertext. Repeated calls are
    /// harmless and resume a cancelled close. Does not await a peer reply
    /// or confirm delivery. Future sends fail with `BrokenPipe`; receiving
    /// remains possible after the handshake. Closing before completion
    /// aborts subsequent handshake and receive operations.
    pub async fn close(&mut self) -> io::Result<()> {
        let mut wait = self.wait();
        self.closing = true;
        self.conn.send_close_notify();
        self.flush_until(&mut wait).await
    }

    /// Sets the maximum elapsed time for each I/O operation, including all
    /// its handshake, reads and writes. `None` (default) adds no deadline;
    /// core's retransmission limit still applies. Zero expires immediately.
    /// A timeout returns `TimedOut` and retains state just like cancellation.
    /// A new call starts a new operation deadline, using the same core clock.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    /// The operation timeout, if configured.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Direct inspection of handshake progress and negotiated parameters.
    pub fn connection(&self) -> &ClientConnection {
        &self.conn
    }

    /// The transport, for addresses and socket options. Do not receive,
    /// send or reconnect through it while this adapter owns protocol state.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    fn wait(&self) -> Wait {
        Wait {
            deadline: self
                .timeout
                .map(|timeout| self.now().saturating_add(timeout)),
            sleep: None,
        }
    }

    async fn handshake_until(&mut self, wait: &mut Wait) -> io::Result<()> {
        if self.closing && self.conn.is_handshaking() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "DTLS client closed during the handshake",
            ));
        }
        poll_fn(|cx| self.poll_run(cx, wait, Goal::Handshake)).await
    }

    async fn flush_until(&mut self, wait: &mut Wait) -> io::Result<()> {
        poll_fn(|cx| {
            let mut budget = IO_BURST;
            self.poll_flush(cx, wait, &mut budget)
        })
        .await
    }

    fn poll_flush(
        &mut self,
        cx: &mut Context<'_>,
        wait: &mut Wait,
        budget: &mut usize,
    ) -> Poll<io::Result<()>> {
        loop {
            wait.check(self.now())?;
            if *budget == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            *budget -= 1;
            if let Some(probe) = self.probes.front_mut() {
                match poll_send_datagram(probe, |data| self.socket.poll_send(cx, data)) {
                    Poll::Pending => {
                        wait.poll_wake(cx, self.start, None);
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Poll::Ready(result) => result?,
                }
                self.probes.pop_front();
                continue;
            }
            if self.out.is_empty() {
                let now = self.now();
                if !self
                    .conn
                    .write_datagram(&mut self.out, now)
                    .map_err(io_error)?
                {
                    return Poll::Ready(Ok(()));
                }
            }
            match poll_send_datagram(&mut self.out, |data| self.socket.poll_send(cx, data)) {
                Poll::Pending => {
                    // Do not advance core timers while this exact datagram
                    // still waits for the socket. The operation timer must
                    // still wake an unwritable socket at its deadline.
                    wait.poll_wake(cx, self.start, None);
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Poll::Ready(result) => result?,
            }
        }
    }

    fn poll_run(
        &mut self,
        cx: &mut Context<'_>,
        wait: &mut Wait,
        goal: Goal,
    ) -> Poll<io::Result<()>> {
        let mut budget = IO_BURST;
        loop {
            if let Some(error) = self.failure.clone() {
                // Best effort to send the alert without hiding the
                // original failure behind blocked I/O or another error.
                let _ = self.poll_flush(cx, wait, &mut budget);
                return Poll::Ready(Err(io_error(error)));
            }
            ready!(self.poll_flush(cx, wait, &mut budget))?;
            let now = self.now();
            wait.check(now)?;
            if let Some(paths) = &mut self.paths {
                paths
                    .poll(&mut self.conn, now, &mut |data, _| {
                        self.probes.push_back(data.to_vec())
                    })
                    .map_err(io_error)?;
                if !self.probes.is_empty() {
                    continue;
                }
            }
            // Even a send-only caller must service elapsed retransmission
            // and ACK timers before considering the operation complete.
            if self.conn.next_timeout().is_some_and(|timer| timer <= now) {
                if budget == 0 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                budget -= 1;
                if let Err(error) = self.conn.handle_timeout(now) {
                    self.failure = Some(error);
                }
                continue;
            }
            if !self.conn.is_handshaking()
                && (matches!(goal, Goal::Handshake)
                    || !self.received.is_empty()
                    || self.conn.peer_has_closed())
            {
                return Poll::Ready(Ok(()));
            }
            if self.conn.is_handshaking() && self.conn.peer_has_closed() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "peer closed during the DTLS handshake",
                )));
            }
            if self.conn.pending_revocation().is_some() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "live OCSP checks are not supported by DTLS UdpClient",
                )));
            }
            if budget == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            budget -= 1;
            let now = self.now();
            wait.check(now)?;
            // Application data cannot precede handshake completion (DTLS
            // has no 0-RTT here); the goal check above then stops reading
            // while any plaintext ranges remain in this input buffer.
            let mut input = ReadBuf::new(&mut self.input);
            match self.socket.poll_recv(cx, &mut input) {
                Poll::Pending => {
                    wait.poll_wake(
                        cx,
                        self.start,
                        self.conn
                            .next_timeout()
                            .into_iter()
                            .chain(
                                self.paths
                                    .as_ref()
                                    .and_then(UdpPathValidation::next_timeout),
                            )
                            .min(),
                    );
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) if transient(&error) => continue,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let len = input.filled().len();
                    let now = self.now();
                    let source = self.socket.peer_addr()?;
                    let datagram = &mut self.input[..len];
                    let result = self.conn.read_datagram(datagram, now).and_then(|received| {
                        if self.paths.is_none()
                            && self.conn.return_routability_checks_negotiated()
                            && !self.conn.peer_has_closed()
                            && !self.conn.local_close_notify_queued()
                        {
                            self.paths = Some(UdpPathValidation::new(
                                &self.conn,
                                source,
                                Selection::Basic,
                            )?);
                        }
                        if let Some(paths) = &mut self.paths {
                            paths.input(
                                &mut self.conn,
                                &received,
                                datagram,
                                source,
                                now,
                                &mut |data, _| self.probes.push_back(data.to_vec()),
                            )
                        } else {
                            Ok(received.app_data().to_vec())
                        }
                    });
                    match result {
                        Ok(ranges) => self.received.extend(ranges),
                        Err(error) => self.failure = Some(error),
                    }
                }
            }
        }
    }
}

impl fmt::Debug for UdpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls::UdpClient")
            .field("conn", &self.conn)
            .field("socket", &self.socket)
            .field("closing", &self.closing)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum Goal {
    Handshake,
    Receive,
}

// Owned by an operation future, never by the connection: dropping a
// future releases its timer but preserves the client's fixed clock origin.
struct Wait {
    deadline: Option<Duration>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl Wait {
    fn check(&self, now: Duration) -> io::Result<()> {
        if self.deadline.is_some_and(|deadline| deadline <= now) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DTLS operation timeout",
            ));
        }
        Ok(())
    }

    fn poll_wake(&mut self, cx: &mut Context<'_>, origin: Instant, timer: Option<Duration>) {
        let Some(deadline) = self.deadline.into_iter().chain(timer).min() else {
            return;
        };
        // A duration beyond Instant's range is not a reachable wakeup;
        // avoid panicking for caller-supplied Duration::MAX timeouts.
        let Some(instant) = origin.checked_add(deadline) else {
            return;
        };
        let sleep = self
            .sleep
            .get_or_insert_with(|| Box::pin(sleep_until(instant)));
        if sleep.deadline() != instant {
            sleep.as_mut().reset(instant);
        }
        if sleep.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
    }
}

fn transient(error: &io::Error) -> bool {
    // ICMP is unauthenticated and must not masquerade as close_notify.
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn pending_ciphertext_survives_backpressure_errors_and_short_sends() {
        let ciphertext = vec![23, 0, 255, 7, 8, 9];
        let mut out = ciphertext.clone();
        // Each closure stands for a new poll after cancelling the previous
        // operation. None may change the ciphertext until a whole send.
        assert!(
            poll_send_datagram(&mut out, |data| {
                assert_eq!(data, ciphertext);
                Poll::Pending
            })
            .is_pending()
        );
        assert_eq!(out, ciphertext);
        assert!(matches!(
            poll_send_datagram(&mut out, |_| {
                Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into()))
            }),
            Poll::Ready(Err(_))
        ));
        assert_eq!(out, ciphertext);
        assert!(matches!(
            poll_send_datagram(&mut out, |_| Poll::Ready(Ok(2))),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
        ));
        assert_eq!(out, ciphertext);
        assert!(matches!(
            poll_send_datagram(&mut out, |data| {
                assert_eq!(data, ciphertext);
                Poll::Ready(Ok(data.len()))
            }),
            Poll::Ready(Ok(()))
        ));
        assert!(out.is_empty());
    }

    #[cfg(any(feature = "native", feature = "rustcrypto"))]
    #[tokio::test]
    async fn cancelling_a_budget_yield_and_timing_out_preserves_sealed_output() {
        #[cfg(feature = "native")]
        let provider = browntls_core::crypto::native::default_provider();
        #[cfg(not(feature = "native"))]
        let provider = browntls_core::crypto::rustcrypto::default_provider();
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&browntls_core::version::TLS13])
            .unwrap()
            .with_root_certificates(browntls_core::RootCertStore::empty())
            .with_no_client_auth();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(peer.local_addr().unwrap()).await.unwrap();
        let mut client = UdpClient::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
            socket,
        )
        .unwrap();
        let now = client.now();
        assert!(client.conn.write_datagram(&mut client.out, now).unwrap());
        let ciphertext = client.out.clone();
        let mut wait = client.wait();
        let mut flushing = Box::pin(poll_fn(|cx| {
            // No I/O may occur after the budget is exhausted, even if the
            // socket would be writable. Cancelling this yield must not
            // discard the datagram already removed from core.
            client.poll_flush(cx, &mut wait, &mut 0)
        }));
        poll_fn(|cx| {
            assert!(flushing.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(flushing);
        assert_eq!(client.out, ciphertext);

        client.set_timeout(Some(Duration::ZERO));
        assert_eq!(
            client.complete_handshake().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(client.out, ciphertext);
        client.set_timeout(None);
        let mut wait = client.wait();
        tokio::time::timeout(Duration::from_secs(5), client.flush_until(&mut wait))
            .await
            .unwrap()
            .unwrap();
        let mut input = vec![0; MAX_DATAGRAM];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut input))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&input[..len], ciphertext);
    }

    #[tokio::test(start_paused = true)]
    async fn operation_timer_wakes_at_elapsed_deadline_and_does_not_restart() {
        let origin = Instant::now();
        let mut wait = Wait {
            deadline: Some(Duration::from_millis(100)),
            sleep: None,
        };
        // Register an earlier core wakeup, then move it later. The fixed
        // operation deadline must still win over the moved core timer.
        poll_fn(|cx| {
            wait.poll_wake(cx, origin, Some(Duration::from_millis(20)));
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_millis(30)).await;
        assert!(wait.check(origin.elapsed()).is_ok());
        poll_fn(|cx| {
            wait.poll_wake(cx, origin, Some(Duration::from_secs(1)));
            Poll::Ready(())
        })
        .await;
        assert_eq!(
            wait.sleep.as_ref().unwrap().deadline(),
            origin + Duration::from_millis(100)
        );
        tokio::time::advance(Duration::from_millis(70)).await;
        assert_eq!(
            wait.check(origin.elapsed()).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_timeout_beyond_instants_range_does_not_panic() {
        let origin = Instant::now();
        let mut wait = Wait {
            deadline: Some(Duration::MAX),
            sleep: None,
        };
        poll_fn(|cx| {
            wait.poll_wake(cx, origin, None);
            Poll::Ready(())
        })
        .await;
        assert!(wait.check(origin.elapsed()).is_ok());
    }
}

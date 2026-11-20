//! Blocking DTLS 1.3 over `std::net::UdpSocket`: [`UdpClient`] for one
//! server, [`UdpServer`] for many clients on one socket.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use browntls_pki::ServerName;

use super::connection::{ClientConnection, ConnectionCommon};
use crate::conn::SideData;
use crate::error::Error;
use crate::log::debug;
use crate::sync::Arc;

mod server;

pub use server::{ServerEvent, UdpServer};

/// The largest UDP payload over IPv4 or IPv6 (without jumbograms).
const MAX_DATAGRAM: usize = 65535;

/// The shortest wait on a socket: a read timeout of zero means "forever".
const MIN_WAIT: Duration = Duration::from_millis(1);

/// How many datagrams that have already arrived are still read once the
/// read timeout has passed.
const LAST_LOOKS: usize = 64;

/// A DTLS 1.3 client over a UDP socket connected to its server.
///
/// Its calls block: [`Self::connect`] until the handshake completes,
/// [`Self::recv`] until a datagram of application data arrives or the
/// read timeout passes. While blocked it retransmits and acknowledges as
/// the connection asks. Each [`Self::send`] is one datagram, and each
/// [`Self::recv`] returns one: DTLS keeps datagram boundaries and, like
/// UDP, does not deliver lost or replayed application data.
pub struct UdpClient {
    conn: ClientConnection,
    socket: UdpSocket,
    start: Instant,
    read_timeout: Option<Duration>,
    received: VecDeque<Vec<u8>>,
    buf: Vec<u8>,
    out: Vec<u8>,
}

impl UdpClient {
    /// Connects to `name` over `socket`, which must be connected (with
    /// [`UdpSocket::connect`]) to the server's address, and completes the
    /// handshake.
    ///
    /// A handshake the server never answers fails after its
    /// retransmissions run out, after about five minutes; set a read
    /// timeout with [`Self::from_connection`] and
    /// [`Self::set_read_timeout`] to give up sooner. The socket is put in
    /// blocking mode.
    pub fn connect(
        config: Arc<crate::ClientConfig>,
        name: ServerName<'static>,
        socket: UdpSocket,
    ) -> io::Result<Self> {
        socket.set_nonblocking(false)?;
        let conn = ClientConnection::new(config, name).map_err(io_error)?;
        let mut client = Self::from_connection(conn, socket);
        client.complete_handshake()?;
        Ok(client)
    }

    /// Pairs `conn`, configured as needed (for example its MTU), with
    /// `socket`, connected to the server, without doing any I/O yet. The
    /// socket must be in blocking mode (the default).
    pub fn from_connection(conn: ClientConnection, socket: UdpSocket) -> Self {
        Self {
            conn,
            socket,
            start: Instant::now(),
            read_timeout: None,
            received: VecDeque::new(),
            buf: alloc::vec![0; MAX_DATAGRAM],
            out: Vec::new(),
        }
    }

    /// Blocks until the handshake is complete.
    ///
    /// Fails with [`io::ErrorKind::TimedOut`] when the read timeout passes
    /// first; calling it again continues the handshake.
    pub fn complete_handshake(&mut self) -> io::Result<()> {
        let deadline = self.deadline();
        self.handshake_until(deadline)
    }

    fn handshake_until(&mut self, deadline: Option<Duration>) -> io::Result<()> {
        let mut late = 0;
        while self.conn.is_handshaking() {
            if self.conn.peer_has_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the server closed the connection during the handshake",
                ));
            }
            if self.conn.pending_revocation().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "live OCSP checks are not supported by UdpClient",
                ));
            }
            let expired = self.expired(deadline);
            let read = self.wait(deadline)?;
            if expired {
                late += 1;
                if (!read || late >= LAST_LOOKS) && self.conn.is_handshaking() {
                    return Err(timed_out());
                }
            }
        }
        self.flush()
    }

    /// Sends `data` as one datagram of application data, completing the
    /// handshake first if needed.
    ///
    /// `data` must fit one datagram: at most
    /// [`ConnectionCommon::max_application_data`] bytes. An error the
    /// network reported for an earlier datagram (such as
    /// [`io::ErrorKind::ConnectionRefused`]) may surface here, in which
    /// case this datagram was not sent.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.complete_handshake()?;
        let mut datagram = Vec::new();
        self.conn.send(data, &mut datagram).map_err(io_error)?;
        self.socket.send(&datagram)?;
        // The confidentiality limit may have queued a KeyUpdate.
        self.flush()
    }

    /// Blocks until a datagram of application data arrives, copies it to
    /// `buf` and returns its length.
    ///
    /// Returns 0 once the server closed the connection; empty datagrams
    /// are skipped. Fails with
    /// [`io::ErrorKind::TimedOut`] when the read timeout passes first,
    /// and with [`io::ErrorKind::InvalidInput`] when `buf` is shorter than
    /// the datagram, which stays queued for a larger buffer.
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self.deadline();
        self.handshake_until(deadline)?;
        let mut late = 0;
        loop {
            if let Some(data) = self.received.front() {
                let Some(dest) = buf.get_mut(..data.len()) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "buffer shorter than the received datagram",
                    ));
                };
                dest.copy_from_slice(data);
                let len = data.len();
                self.received.pop_front();
                return Ok(len);
            }
            if self.conn.peer_has_closed() {
                return Ok(0);
            }
            let expired = self.expired(deadline);
            let read = self.wait(deadline)?;
            if expired {
                late += 1;
                if (!read || late >= LAST_LOOKS)
                    && self.received.is_empty()
                    && !self.conn.peer_has_closed()
                {
                    return Err(timed_out());
                }
            }
        }
    }

    /// Sends `close_notify`. The server is not obliged to answer it, and
    /// nothing confirms it arrived.
    pub fn close(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.flush()
    }

    /// Sets how long [`Self::recv`] and the handshake wait for the server;
    /// `None` (the default) waits as long as the connection does. Even a
    /// zero timeout reads what arrives within a moment of the deadline, up
    /// to 64 datagrams.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// The read timeout set with [`Self::set_read_timeout`].
    pub fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    /// The connection, for its negotiated parameters.
    pub fn connection(&self) -> &ClientConnection {
        &self.conn
    }

    /// The connection, for example to refresh its traffic keys. What the
    /// change queues is sent by the next call that does I/O.
    pub fn connection_mut(&mut self) -> &mut ClientConnection {
        &mut self.conn
    }

    /// The socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// The connection and the socket. Application data received but not
    /// yet returned by [`Self::recv`] is lost.
    pub fn into_parts(self) -> (ClientConnection, UdpSocket) {
        (self.conn, self.socket)
    }

    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    /// Whether `deadline` has passed: the next wait is the last look.
    fn expired(&self, deadline: Option<Duration>) -> bool {
        deadline.is_some_and(|deadline| deadline <= self.now())
    }

    fn deadline(&self) -> Option<Duration> {
        self.read_timeout
            .map(|timeout| self.now().saturating_add(timeout))
    }

    /// Sends what the connection has queued.
    fn flush(&mut self) -> io::Result<()> {
        let now = self.now();
        flush(&mut self.conn, &mut self.out, now, |datagram| {
            match self.socket.send(datagram) {
                Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
                result => result.map(|_| ()),
            }
        })
    }

    /// Sends what is queued, acts on a timer that is due, then waits for
    /// one datagram, or for the next timer or `deadline`, and processes it.
    /// Returns whether a datagram was read.
    fn wait(&mut self, deadline: Option<Duration>) -> io::Result<bool> {
        self.flush()?;
        let now = self.now();
        if let Some(timer) = self.conn.next_timeout()
            && timer <= now
        {
            self.conn.handle_timeout(now).map_err(io_error)?;
            self.flush()?;
        }
        // Past the deadline this waits briefly: the caller's last look.
        let wait = wait_until(now, [self.conn.next_timeout(), deadline]);
        self.socket.set_read_timeout(wait)?;
        let len = match self.socket.recv(&mut self.buf) {
            Ok(len) => len,
            // ICMP errors are not authenticated: an unreachable port
            // during the handshake is worth another retransmission.
            Err(err) if is_transient(&err) => return Ok(false),
            Err(err) => return Err(err),
        };
        let now = self.now();
        let datagram = &mut self.buf[..len];
        let received = match self.conn.read_datagram(datagram, now) {
            Ok(received) => received,
            Err(err) => {
                // Send the alert, then report the failure.
                let _ = self.flush();
                return Err(io_error(err));
            }
        };
        // An empty datagram carries nothing, and `recv` returning 0 means
        // that the server closed.
        for range in received.app_data().iter().filter(|r| !r.is_empty()) {
            self.received.push_back(datagram[range.clone()].to_vec());
        }
        Ok(true)
    }
}

impl fmt::Debug for UdpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls::UdpClient")
            .field("conn", &self.conn)
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

/// Hands each datagram `conn` has queued to `send`.
fn flush<Data: SideData>(
    conn: &mut ConnectionCommon<Data>,
    out: &mut Vec<u8>,
    now: Duration,
    mut send: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    loop {
        out.clear();
        if !conn.write_datagram(out, now).map_err(io_error)? {
            return Ok(());
        }
        send(out)?;
    }
}

/// How long to wait from `now` for the earliest of `deadlines`; `None`
/// is forever.
fn wait_until(
    now: Duration,
    deadlines: impl IntoIterator<Item = Option<Duration>>,
) -> Option<Duration> {
    deadlines
        .into_iter()
        .flatten()
        .min()
        .map(|deadline| deadline.saturating_sub(now).max(MIN_WAIT))
}

/// Socket errors that leave the socket usable: a read timeout, an
/// interruption, or an ICMP error from an earlier send.
fn is_transient(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
    )
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "DTLS read timeout")
}

fn io_error(err: Error) -> io::Error {
    debug!("DTLS connection failed: {err}");
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// The bytes a cookie binds a client to: its address family, address and
/// port.
fn address_bytes(addr: &SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(19);
    match addr {
        SocketAddr::V4(v4) => {
            bytes.push(4);
            bytes.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            bytes.push(6);
            bytes.extend_from_slice(&v6.ip().octets());
        }
    }
    bytes.extend_from_slice(&addr.port().to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_for_the_earliest_deadline() {
        let now = Duration::from_secs(10);
        assert_eq!(wait_until(now, [None, None]), None);
        assert_eq!(
            wait_until(now, [Some(Duration::from_secs(12)), None]),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            wait_until(
                now,
                [Some(Duration::from_secs(12)), Some(Duration::from_secs(11))]
            ),
            Some(Duration::from_secs(1))
        );
        // A deadline already passed still waits a little, never forever.
        assert_eq!(
            wait_until(now, [Some(Duration::from_secs(9))]),
            Some(MIN_WAIT)
        );
    }

    #[test]
    fn address_bytes_tell_families_apart() {
        let v4: SocketAddr = "1.2.3.4:5".parse().unwrap();
        let v6: SocketAddr = "[::ffff:1.2.3.4]:5".parse().unwrap();
        assert_eq!(address_bytes(&v4), [4, 1, 2, 3, 4, 0, 5]);
        assert_ne!(address_bytes(&v4), address_bytes(&v6));
        assert_eq!(address_bytes(&v6).len(), 19);
    }
}

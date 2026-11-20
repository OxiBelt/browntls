//! One client of the `tls_dtls_udp` target and what the harness expects of
//! it.

use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use browntls_core::ProtocolVersion;
use browntls_core::dtls::UdpClient;

use super::{MAX_DATAGRAM, Stopwatch, reached};

pub(super) struct Client {
    /// `None` before `connect` returns, or once it failed.
    pub(super) udp: Option<UdpClient>,
    pub(super) addr: SocketAddr,
    /// A second handle on its socket, which keeps the port.
    pub(super) port: UdpSocket,
    pub(super) timeout: Duration,
    /// Whether its calls may fail: its verifier asks for live OCSP, or
    /// junk, its own close_notify or the server's reached its handshake.
    pub(super) may_fail: bool,
    /// Whether it sent close_notify.
    pub(super) closed: bool,
    /// Application data it sent that the server has not reported.
    pub(super) to_server: Vec<Vec<u8>>,
    /// Application data the server sent that it has not returned.
    pub(super) to_client: Vec<Vec<u8>>,
}

/// What a call of a client came to.
pub(super) enum Outcome<T> {
    Done(T),
    TimedOut,
    /// An error the operation expects.
    Refused,
    /// An error a client that may fail reported; it is dropped.
    Failed,
}

impl Client {
    pub(super) fn new(port: UdpSocket, timeout: Duration, may_fail: bool) -> Self {
        Self {
            udp: None,
            addr: port.local_addr().expect("address"),
            port,
            timeout,
            may_fail,
            closed: false,
            to_server: Vec::new(),
            to_client: Vec::new(),
        }
    }

    pub(super) fn attach(&mut self, mut udp: UdpClient) {
        udp.set_read_timeout(Some(self.timeout));
        self.udp = Some(udp);
    }

    /// Notes that something other than its peer reached it: allowed to
    /// fail if it is still handshaking.
    pub(super) fn touch_handshake(&mut self) {
        if self
            .udp
            .as_ref()
            .is_some_and(|udp| udp.connection().is_handshaking())
        {
            self.may_fail = true;
        }
    }

    pub(super) fn set_read_timeout(&mut self, timeout: Duration, none: bool) {
        self.timeout = timeout;
        let Some(udp) = self.udp.as_mut() else { return };
        if none {
            udp.set_read_timeout(None);
            assert_eq!(udp.read_timeout(), None);
        }
        udp.set_read_timeout(Some(timeout));
        assert_eq!(udp.read_timeout(), Some(timeout));
        reached("client read timeout");
    }

    /// `into_parts`, then `from_connection`: what was received and not
    /// returned is lost, which only leaves entries in `to_client`.
    pub(super) fn split(&mut self) {
        let Some(udp) = self.udp.take() else { return };
        let handshaking = udp.connection().is_handshaking();
        let (conn, socket) = udp.into_parts();
        assert_eq!(conn.is_handshaking(), handshaking);
        assert_eq!(socket.local_addr().ok(), Some(self.addr));
        self.attach(UdpClient::from_connection(conn, socket));
    }

    pub(super) fn accessors(&self, server: SocketAddr) {
        let Some(udp) = &self.udp else { return };
        assert_eq!(udp.socket().local_addr().ok(), Some(self.addr));
        assert_eq!(udp.socket().peer_addr().ok(), Some(server));
        assert_eq!(udp.read_timeout(), Some(self.timeout));
        let conn = udp.connection();
        if !conn.is_handshaking() {
            assert_eq!(conn.protocol_version(), Some(ProtocolVersion::DTLSv1_3));
        }
        let _ = format!("{udp:?}");
    }

    /// Whether it saw the server's close_notify and has nothing left to
    /// return.
    pub(super) fn saw_close(&self) -> bool {
        self.udp
            .as_ref()
            .is_some_and(|udp| udp.connection().peer_has_closed())
    }

    /// One `recv` into a buffer for any datagram; `what` (when not empty)
    /// must arrive by `deadline`. Returns whether the client is still
    /// there.
    pub(super) fn recv_once(&mut self, deadline: Instant, what: &str) -> bool {
        let Some(udp) = self.udp.as_mut() else {
            return false;
        };
        let mut buf = vec![0; MAX_DATAGRAM];
        let watch = Stopwatch::start();
        let result = udp.recv(&mut buf);
        let closed = udp.connection().peer_has_closed();
        match outcome(self, result, &watch, |_| false) {
            Outcome::Done(n) => {
                if n == 0 && closed && self.saw_close() {
                    return true;
                }
                received(&mut self.to_client, &buf[..n], closed);
            }
            Outcome::TimedOut => {
                assert!(
                    what.is_empty() || Instant::now() < deadline,
                    "{what} did not arrive"
                );
                if what.is_empty() {
                    return false;
                }
            }
            Outcome::Refused => unreachable!("no error is expected"),
            Outcome::Failed => return false,
        }
        true
    }
}

/// How many entries of `list` are `data`.
pub(super) fn count(list: &[Vec<u8>], data: &[u8]) -> usize {
    list.iter().filter(|d| *d == data).count()
}

/// Checks what `recv` returned against what the server sent: data it sent
/// and the client did not return yet, or nothing once it closed.
pub(super) fn received(to_client: &mut Vec<Vec<u8>>, data: &[u8], closed: bool) {
    if let Some(at) = to_client.iter().position(|d| d == data) {
        to_client.remove(at);
        return;
    }
    assert!(
        data.is_empty() && closed,
        "the server did not send these {} bytes, or they arrived twice",
        data.len()
    );
}

/// Checks the result of a call of `client`, timed by `watch`: it keeps to
/// the read timeout, `refused` errors are expected, and other errors only
/// from a client that may fail, which is then dropped.
pub(super) fn outcome<T>(
    client: &mut Client,
    result: io::Result<T>,
    watch: &Stopwatch,
    refused: impl Fn(ErrorKind) -> bool,
) -> Outcome<T> {
    watch.check(client.timeout, "a client call");
    let err = match result {
        Ok(value) => return Outcome::Done(value),
        Err(err) => err,
    };
    if err.kind() == ErrorKind::TimedOut {
        return Outcome::TimedOut;
    }
    if refused(err.kind()) {
        return Outcome::Refused;
    }
    assert!(client.may_fail, "client {}: {err}", client.addr);
    if err.kind() == ErrorKind::Unsupported {
        reached("live OCSP refused");
    }
    client.udp = None;
    Outcome::Failed
}

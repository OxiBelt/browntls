//! Starting inputs for `tls_dtls_udp`: programs that reach every operation
//! and every public function of `dtls::UdpClient` and `dtls::UdpServer`.

use crate::input::put_field;
use crate::tls_dtls::shape;

/// Header bits.
const RUSTCRYPTO: u8 = 3;
const NO_SEALER: u8 = 16;

/// Slot byte for an address the server does not know.
const NOBODY: u8 = 0xff;

/// A program of operations (see `run`).
struct Program(Vec<u8>);

impl Program {
    fn new(header: u8, timeout: u8) -> Self {
        Self(vec![header, timeout])
    }

    fn push(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    fn connect(&mut self, defer: bool) -> &mut Self {
        self.push(&[0, u8::from(defer)])
    }

    fn start(&mut self, flags: u8, mtu: u16, timeout: u8, rounds: u8) -> &mut Self {
        self.push(&[1, flags]);
        self.push(&mtu.to_be_bytes());
        self.push(&[timeout, rounds])
    }

    fn rounds(&mut self, slot: u8, rounds: u8) -> &mut Self {
        self.push(&[2, slot, rounds])
    }

    fn send(&mut self, slot: u8, data: &[u8]) -> &mut Self {
        self.push(&[3, slot]);
        put_field(&mut self.0, data);
        self
    }

    fn server_send(&mut self, slot: u8, data: &[u8], follow: bool) -> &mut Self {
        self.push(&[4, slot]);
        put_field(&mut self.0, data);
        self.push(&[u8::from(follow)])
    }

    fn recv(&mut self, slot: u8, len: u16) -> &mut Self {
        self.push(&[5, slot]);
        self.push(&len.to_be_bytes())
    }

    fn close(&mut self, server: bool, slot: u8, follow: bool) -> &mut Self {
        self.push(&[6, u8::from(server), slot, u8::from(follow)])
    }

    fn key_update(&mut self, server: bool, slot: u8, follow: bool) -> &mut Self {
        self.push(&[7, u8::from(server), slot, u8::from(follow)])
    }

    fn remove(&mut self, slot: u8) -> &mut Self {
        self.push(&[8, slot])
    }

    fn limits(&mut self, max: u8, timeout: u8) -> &mut Self {
        self.push(&[9, max, timeout])
    }

    fn read_timeout(&mut self, server: bool, slot: u8, ms: u8, none: bool) -> &mut Self {
        self.push(&[10, u8::from(server), slot, ms, u8::from(none)])
    }

    fn split(&mut self, slot: u8) -> &mut Self {
        self.push(&[11, slot])
    }

    /// Junk to the server from `source`, `repeat + 1` times, in datagrams
    /// shaped by [`shape::seed`] with each of `flags`.
    fn junk(&mut self, source: u8, repeat: u8, flags: &[u8]) -> &mut Self {
        self.push(&[12, source, repeat, flags.len() as u8 - 1]);
        for f in flags {
            self.0.extend_from_slice(&shape::seed(*f));
        }
        self
    }

    fn junk_to_client(&mut self, slot: u8, flags: &[u8]) -> &mut Self {
        self.push(&[13, slot, flags.len() as u8 - 1]);
        for f in flags {
            self.0.extend_from_slice(&shape::seed(*f));
        }
        self
    }

    fn accessors(&mut self) -> &mut Self {
        self.push(&[14])
    }

    fn wait(&mut self, ms: u8) -> &mut Self {
        self.push(&[15, ms])
    }

    /// Data both ways, also into a short buffer and too large.
    fn traffic(&mut self, slot: u8) -> &mut Self {
        self.send(slot, b"hello")
            .server_send(slot, b"world", true)
            .server_send(slot, b"0123456789", false)
            .recv(slot, 4)
            .recv(slot, 2048)
            .recv(slot, 2048)
            .send(slot, &[0x55; 1600])
            .server_send(slot, &[0xaa; 1600], true)
            .send(slot, b"")
            .server_send(slot, b"", false)
            .recv(slot, 16)
    }
}

/// Starting inputs for `tls_dtls_udp`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();

    // A blocking connect on each provider and key type: traffic, key
    // updates on both sides, read timeouts, a split client, accessors,
    // and the client's close_notify.
    for header in [0, RUSTCRYPTO, 4, 8 | 1] {
        let mut p = Program::new(header, 1);
        p.connect(false)
            .traffic(0)
            .key_update(false, 0, true)
            .key_update(true, 0, false)
            .send(0, b"after the key updates")
            .server_send(0, b"after the key updates", true)
            .read_timeout(false, 0, 0, true)
            .read_timeout(true, NOBODY, 0, false)
            .server_send(0, b"before the split", false)
            .split(0)
            .send(0, b"after the split")
            .server_send(0, b"after the split", true)
            .accessors()
            .close(false, 0, false)
            .accessors()
            .close(false, 0, false);
        seeds.push(p.0);
    }

    // Handshakes in rounds, with every read timeout; the server closes,
    // removes and refuses.
    for timeout in 0..4u8 {
        let mut p = Program::new(0, timeout);
        p.start(0, 0, timeout, 8)
            .start(0, 0, 3 - timeout, 8)
            .traffic(1)
            .close(true, 0, true)
            .send(0, b"to a closed server")
            .remove(1)
            .send(1, b"to a server that forgot")
            .server_send(1, b"to a forgotten client", true)
            .key_update(true, 1, false)
            .server_send(NOBODY, b"to nobody", false)
            .close(true, NOBODY, false)
            .remove(NOBODY)
            .accessors();
        seeds.push(p.0);
    }

    // The handshake limit: the second handshake evicts the first, which
    // then completes on its side only; the limit lowered below the
    // handshakes in progress; handshakes that time out; a handshake
    // removed.
    let mut p = Program::new(0, 0);
    p.limits(1, 255)
        .start(0, 0, 0, 2)
        .start(0, 0, 0, 2)
        .accessors()
        .rounds(0, 8)
        .rounds(1, 8)
        .send(0, b"evicted")
        .send(1, b"admitted")
        .limits(4, 255)
        .start(0, 0, 0, 2)
        .start(0, 0, 0, 2)
        .limits(0, 5)
        .accessors()
        .wait(15)
        .accessors()
        .remove(2)
        .remove(3);
    seeds.push(p.0);
    let mut p = Program::new(0, 0);
    p.limits(2, 0)
        .start(0, 0, 0, 2)
        .wait(3)
        .rounds(0, 8)
        .limits(2, 255)
        .start(0, 0, 0, 2)
        .remove(1)
        .rounds(1, 8)
        .accessors();
    seeds.push(p.0);

    // Junk: floods from other sockets (with a zero read timeout), from a
    // connected client's socket and from a handshaking one, and from the
    // server's socket to clients; the connections carry on.
    let mut p = Program::new(0, 0);
    p.connect(false)
        .junk(0, 99, &[0x0c, 0x1f, 0x03])
        .junk(1, 30, &[0x00])
        .junk(4, 20, &[0x1c, 0x04])
        .junk_to_client(0, &[0x0f, 0x10])
        .traffic(0)
        .start(0, 0, 1, 1)
        .junk(5, 0, &[0x08])
        .junk_to_client(1, &[0x02])
        .rounds(1, 8)
        .read_timeout(true, NOBODY, 3, false)
        .junk(0, 64, &[0x14, 0x18])
        .key_update(false, 0, true)
        .traffic(0)
        .accessors()
        .close(false, 0, false);
    seeds.push(p.0);

    // Live OCSP, which neither side supports; a server configuration
    // without a cookie sealer; small and large datagrams.
    let mut p = Program::new(NO_SEALER, 0);
    p.connect(true)
        .start(1, 0, 1, 8)
        .start(2, 0, 1, 8)
        .start(2, 744, 1, 8)
        .accessors()
        .traffic(3)
        .wait(1);
    seeds.push(p.0);

    // close_notify during the handshake, from either side.
    let mut p = Program::new(0, 0);
    p.start(0, 0, 1, 1)
        .close(false, 0, false)
        .rounds(0, 8)
        .start(0, 0, 1, 2)
        .close(true, 1, true)
        .rounds(1, 8)
        .accessors();
    seeds.push(p.0);

    seeds
}

//! Kernel TLS offload (`browntls_core::kernel`): a genuine client and server in
//! the same process (real cryptography, both providers), one of them,
//! buffered or unbuffered, handed over to a userspace stand-in for Linux
//! kernel TLS (`sim`) that protects its records with the extracted secrets
//! and passes it the records the kernel does not handle itself.
//!
//! Input: a 3-byte header (cipher suite and provider, which side is handed
//! over and through which API, secret extraction, post-handshake client
//! authentication, the peer's record size limit, the maximum fragment
//! size), then up to 64 operations. Before the handover (see [`PreOp`]):
//! handshake steps, delivery of a fuzzed amount of the peer's records
//! (`read_tls`, `bytes_to_record_boundary`), application data, reads, key
//! updates, close_notify, post-handshake authentication requests, the
//! handover blocker, and the handover itself. After it (see `post::Op`):
//! data, KeyUpdate, close_notify and authentication requests from the peer,
//! records through the simulated kernel in fuzzed amounts, and every
//! `KernelConnection` call (`records_sent` up to the confidentiality limit
//! and beyond, `handle_record` with fuzzed types and payloads, key
//! refreshes, closure, accessors).
//!
//! Checked properties:
//! * `kernel_handoff_blocker` reports something exactly when the handover
//!   fails, and the error names it; secret extraction disabled and suites
//!   with no kernel form always block;
//! * `bytes_to_record_boundary` matches a model computed from the record
//!   headers of the peer's stream, and reading that many bytes inside a
//!   record body reaches the boundary;
//! * application data received on either side is a prefix of what the
//!   other side sent; once both sides are idle, with nothing failed,
//!   closed or fuzzed into the connection, it is all of it, which also
//!   checks the extracted secrets and sequence numbers;
//! * a KeyUpdate in a record yields RxKeys after everything else that
//!   record caused, and only the owed answer may follow: a KeyUpdate record
//!   then TxKeys; every TxKeys follows a KeyUpdate record; TLS 1.2 never
//!   rekeys; the kernel never reads past a KeyUpdate without new keys;
//! * after a failed `handle_record` nothing but alerts is output, and
//!   nothing follows the fatal alert; after our close_notify only alerts
//!   and receive keys; application data is refused without failing the
//!   connection; records respect the maximum payload length;
//! * `Debug` of the connection and of every output shows no key handed out;
//! * nothing panics.

mod post;
mod seeds;
mod sim;

pub use seeds::seeds;

use std::io::{Read, Write};
use std::sync::Arc;

use browntls_core::client::{ClientConnection, UnbufferedClientConnection};
use browntls_core::crypto::{CryptoProvider, native, rustcrypto};
use browntls_core::kernel::{KernelConnection, KernelHandoffBlocker};
use browntls_core::server::{ServerConnection, UnbufferedServerConnection};
use browntls_core::unbuffered::{
    ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedConnectionCommon,
};
use browntls_core::{
    ClientConfig, Connection, Error, ExtractedSecrets, ServerConfig, SideData, SupportedCipherSuite,
};

use crate::input::Input;
use crate::tls_conn::setup::{Knobs, assert_prefix, server_name};
use post::KernelSide;
use sim::Offloaded;

const MAX_OPS: usize = 64;
/// Connections per input: a blocked handover drops the connection, and the
/// operations go on with a new pair.
const MAX_PAIRS: usize = 3;

/// Application data one way.
#[derive(Default)]
struct Flow {
    sent: Vec<u8>,
    recv: Vec<u8>,
}

/// The suites the header chooses from: (RustCrypto provider, suite). The
/// last ones have no kernel form, or no certificate to match.
fn suites() -> [(bool, SupportedCipherSuite); 16] {
    use native::cipher_suite as n;
    use rustcrypto::cipher_suite as r;
    [
        (false, n::TLS13_AES_128_GCM_SHA256),
        (false, n::TLS13_AES_256_GCM_SHA384),
        (false, n::TLS13_CHACHA20_POLY1305_SHA256),
        (false, n::TLS13_AES_128_CCM_SHA256),
        (false, n::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        (false, n::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        (false, n::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        (true, r::TLS13_AES_128_GCM_SHA256),
        (true, r::TLS13_AES_256_GCM_SHA384),
        (true, r::TLS13_CHACHA20_POLY1305_SHA256),
        (true, r::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        (true, r::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        (true, r::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        // No kernel form.
        (false, n::TLS13_AES_128_CCM_8_SHA256),
        (false, n::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
        // The certificate is ECDSA: the handshake fails.
        (false, n::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    ]
}

/// How many entries of [`suites`] can be handed over.
const KERNEL_SUITES: usize = 13;

/// The peer's `record_size_limit` choices.
const LIMITS: [Option<u16>; 4] = [None, Some(64), Some(1000), Some(16385)];

/// The input header (3 bytes).
///
/// Byte 0: the suite (index into [`suites`]). Byte 1: bit 0 the server is
/// handed over (otherwise the client), bit 1 through the unbuffered API,
/// bit 2 secret extraction disabled, bit 3 post-handshake client
/// authentication, bits 4-5 the peer's record size limit ([`LIMITS`]).
/// Byte 2: the maximum fragment size of both sides (`Knobs::fragment`).
#[derive(Clone, Copy)]
struct Header {
    suite: usize,
    flags: u8,
    fragment: u8,
}

impl Header {
    fn read(input: &mut Input<'_>) -> Self {
        Self {
            suite: input.choose(suites().len()),
            flags: input.byte(),
            fragment: input.byte(),
        }
    }

    fn server(self) -> bool {
        self.flags & 1 != 0
    }

    fn unbuffered(self) -> bool {
        self.flags & 2 != 0
    }

    fn extraction(self) -> bool {
        self.flags & 4 == 0
    }

    fn kernel_form(self) -> bool {
        self.suite < KERNEL_SUITES
    }

    fn configs(self) -> Option<(Arc<ClientConfig>, Arc<ServerConfig>)> {
        let (rust, suite) = suites()[self.suite];
        let provider: CryptoProvider = if rust {
            rustcrypto::default_provider()
        } else {
            native::default_provider()
        };
        let index = provider
            .cipher_suites
            .iter()
            .position(|s| s.suite() == suite.suite())?;
        let knobs = Knobs {
            // Providers; the suite's version only, or a server would pick
            // TLS 1.3 and find no suite in common.
            flags: if rust { 0x0c } else { 0 }
                | match suite {
                    SupportedCipherSuite::Tls13(_) => 1,
                    SupportedCipherSuite::Tls12(_) => 2,
                },
            auth: if self.extraction() { 4 } else { 0 } | if self.flags & 8 != 0 { 3 } else { 0 },
            suite: u8::try_from(index + 1).ok()?,
            groups: 0,
            fragment: self.fragment,
        };
        let mut client = knobs.client_config()?;
        let mut server = knobs.server_config()?;
        let limit = LIMITS[usize::from(self.flags >> 4) & 3];
        if limit.is_some() {
            if self.server() {
                client.record_size_limit = limit;
            } else {
                server.record_size_limit = limit;
            }
        }
        Some((Arc::new(client), Arc::new(server)))
    }
}

/// The operations before the handover; the selector byte is reduced modulo
/// their number.
#[derive(Clone, Copy)]
#[repr(u8)]
enum PreOp {
    /// Exchange everything until both sides are idle.
    Pump,
    /// `flags, amount (u16, 0: all)`: the peer's records to the subject.
    /// Bit 0: only up to `bytes_to_record_boundary` (buffered). Bit 1:
    /// process them. Bit 2: read the plaintext.
    PeerToSubject,
    /// `flush`: the subject's records to the peer (bit 0: write or encode
    /// what is queued first).
    SubjectToPeer,
    /// `side, data (short field)`: application data (side 0: the subject).
    Write,
    /// Read the plaintext on both sides.
    Read,
    /// `side`: `refresh_traffic_keys`.
    Refresh,
    /// `side`: `send_close_notify`.
    Close,
    /// Process the subject's input.
    Drive,
    /// `kernel_handoff_blocker` on both sides.
    Blocker,
    /// The peer, a server, asks for a client certificate.
    PeerAuth,
    /// The handover; the rest of the input drives the result.
    Handover,
}

const PRE_OPS: usize = PreOp::Handover as usize + 1;

const ALL_PRE_OPS: [PreOp; PRE_OPS] = [
    PreOp::Pump,
    PreOp::PeerToSubject,
    PreOp::SubjectToPeer,
    PreOp::Write,
    PreOp::Read,
    PreOp::Refresh,
    PreOp::Close,
    PreOp::Drive,
    PreOp::Blocker,
    PreOp::PeerAuth,
    PreOp::Handover,
];

/// The side to hand over.
enum Subject {
    Buffered(Connection),
    Client(UnbufferedClientConnection),
    Server(UnbufferedServerConnection),
}

/// Runs `$body` with `$c` bound to the buffered connection's
/// `ConnectionCommon`.
macro_rules! buffered {
    ($conn:expr, $c:ident => $body:expr) => {
        match $conn {
            Connection::Client($c) => $body,
            Connection::Server($c) => $body,
        }
    };
}

/// The unbuffered subject's buffers and pending actions.
#[derive(Default)]
struct Unbuffered {
    inbuf: Vec<u8>,
    /// Application data to encrypt at the next `WriteTraffic`.
    data: Vec<u8>,
    close: bool,
    refresh: bool,
}

struct Pre {
    header: Header,
    subject: Subject,
    peer: Connection,
    unbuffered: Unbuffered,
    /// Every byte the peer wrote toward the subject (whole records).
    peer_stream: Vec<u8>,
    /// How much of `peer_stream` the subject has taken.
    fed: usize,
    /// The subject's bytes not yet delivered to the peer.
    to_peer: Vec<u8>,
    /// Subject to peer, and peer to subject.
    up: Flow,
    down: Flow,
    subject_failed: bool,
    peer_failed: bool,
}

/// Runs the harness on one input.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let header = Header::read(&mut input);
    let Some((client_config, server_config)) = header.configs() else {
        return;
    };
    let mut ops = 0;
    for _ in 0..MAX_PAIRS {
        let Some(mut pre) = Pre::new(header, &client_config, &server_config) else {
            return;
        };
        loop {
            if input.is_empty() || ops >= MAX_OPS {
                return;
            }
            ops += 1;
            match ALL_PRE_OPS[input.choose(PRE_OPS)] {
                PreOp::Handover => {
                    pre.handover(&mut input, &mut ops);
                    break;
                }
                op => pre.op(op, &mut input),
            }
            assert_prefix(&pre.down.recv, &pre.down.sent, "peer to subject");
            assert_prefix(&pre.up.recv, &pre.up.sent, "subject to peer");
        }
    }
}

/// What `bytes_to_record_boundary` must answer at `pos` of `stream` (whole
/// records), and whether `pos` is inside a record header.
fn boundary_model(stream: &[u8], pos: usize) -> (usize, bool) {
    let mut at = 0;
    while at < pos {
        let into = pos - at;
        if into < 5 {
            return (5 - into, true);
        }
        let len = usize::from(u16::from_be_bytes([stream[at + 3], stream[at + 4]]));
        if into < 5 + len {
            return (5 + len - into, false);
        }
        at += 5 + len;
    }
    (0, false)
}

/// Runs `f` with a buffer, growing it once to the size asked for.
fn into_vec<E>(
    mut f: impl FnMut(&mut [u8]) -> Result<usize, E>,
    insufficient: impl Fn(&E) -> Option<usize>,
) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 512];
    for _ in 0..2 {
        match f(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return Some(buf);
            }
            Err(err) => buf = vec![0u8; insufficient(&err)?],
        }
    }
    None
}

fn encrypt_insufficient(err: &EncryptError) -> Option<usize> {
    match err {
        EncryptError::InsufficientSize(InsufficientSizeError { required_size }) => {
            Some(*required_size)
        }
        _ => None,
    }
}

/// Processes the unbuffered subject's input until it waits; acts on
/// `WriteTraffic` with the pending actions. Returns `false` on failure.
fn drive<D: SideData>(
    conn: &mut UnbufferedConnectionCommon<D>,
    state: &mut Unbuffered,
    out: &mut Vec<u8>,
    sent: &mut Vec<u8>,
    recv: &mut Vec<u8>,
) -> bool {
    let Unbuffered {
        inbuf,
        data,
        close,
        refresh,
    } = state;
    for _ in 0..64 {
        let status = conn.process_tls_records(inbuf);
        let discard = status.discard;
        let (done, ok) = match status.state {
            Err(err) => {
                let _ = err.to_string();
                (true, false)
            }
            Ok(ConnectionState::ReadTraffic(record)) => {
                recv.extend_from_slice(record.payload());
                (false, true)
            }
            Ok(ConnectionState::EncodeTlsData(mut encode)) => {
                for _ in 0..64 {
                    let Some(bytes) = into_vec(
                        |buf| encode.encode(buf),
                        |err: &EncodeError| match err {
                            EncodeError::InsufficientSize(InsufficientSizeError {
                                required_size,
                            }) => Some(*required_size),
                            _ => None,
                        },
                    ) else {
                        break;
                    };
                    if bytes.is_empty() {
                        break;
                    }
                    out.extend_from_slice(&bytes);
                }
                (false, true)
            }
            Ok(ConnectionState::TransmitTlsData(transmit)) => {
                transmit.done();
                (false, true)
            }
            Ok(ConnectionState::WriteTraffic(mut write)) => {
                if !data.is_empty() {
                    if let Some(bytes) =
                        into_vec(|buf| write.encrypt(data, buf), encrypt_insufficient)
                    {
                        out.extend_from_slice(&bytes);
                        sent.append(data);
                    }
                    data.clear();
                }
                if std::mem::take(close)
                    && let Some(bytes) =
                        into_vec(|buf| write.queue_close_notify(buf), encrypt_insufficient)
                {
                    out.extend_from_slice(&bytes);
                }
                if std::mem::take(refresh) {
                    let _ = write.refresh_traffic_keys();
                }
                (true, true)
            }
            Ok(_) => (true, true),
        };
        inbuf.drain(..discard);
        if done {
            return ok;
        }
    }
    true
}

impl Pre {
    fn new(header: Header, client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Option<Self> {
        let (subject, peer) = match (header.server(), header.unbuffered()) {
            (false, false) => (
                Subject::Buffered(
                    ClientConnection::new(client.clone(), server_name())
                        .ok()?
                        .into(),
                ),
                ServerConnection::new(server.clone()).ok()?.into(),
            ),
            (true, false) => (
                Subject::Buffered(ServerConnection::new(server.clone()).ok()?.into()),
                ClientConnection::new(client.clone(), server_name())
                    .ok()?
                    .into(),
            ),
            (false, true) => (
                Subject::Client(
                    UnbufferedClientConnection::new(client.clone(), server_name()).ok()?,
                ),
                ServerConnection::new(server.clone()).ok()?.into(),
            ),
            (true, true) => (
                Subject::Server(UnbufferedServerConnection::new(server.clone()).ok()?),
                ClientConnection::new(client.clone(), server_name())
                    .ok()?
                    .into(),
            ),
        };
        Some(Self {
            header,
            subject,
            peer,
            unbuffered: Unbuffered::default(),
            peer_stream: Vec::new(),
            fed: 0,
            to_peer: Vec::new(),
            up: Flow::default(),
            down: Flow::default(),
            subject_failed: false,
            peer_failed: false,
        })
    }

    fn op(&mut self, op: PreOp, input: &mut Input<'_>) {
        match op {
            PreOp::Pump => self.pump(),
            PreOp::PeerToSubject => {
                let flags = input.byte();
                let amount = input.u16();
                self.peer_to_subject(usize::from(amount), flags);
            }
            PreOp::SubjectToPeer => {
                if input.byte() & 1 != 0 {
                    self.subject_flush();
                }
                self.subject_to_peer();
            }
            PreOp::Write => {
                let side = input.byte();
                let data = input.short_field();
                self.write(side & 1 == 0, data);
            }
            PreOp::Read => self.read(),
            PreOp::Refresh => {
                if input.byte() & 1 == 0 {
                    match &mut self.subject {
                        Subject::Buffered(conn) => {
                            let _ = conn.refresh_traffic_keys();
                        }
                        _ => self.unbuffered.refresh = true,
                    }
                } else {
                    let _ = self.peer.refresh_traffic_keys();
                }
            }
            PreOp::Close => {
                if input.byte() & 1 == 0 {
                    match &mut self.subject {
                        Subject::Buffered(conn) => conn.send_close_notify(),
                        _ => self.unbuffered.close = true,
                    }
                } else {
                    self.peer.send_close_notify();
                }
            }
            PreOp::Drive => self.drive(),
            PreOp::Blocker => {
                let _ = self.blocker();
            }
            PreOp::PeerAuth => {
                if let Connection::Server(server) = &mut self.peer {
                    let _ = server.request_client_auth();
                }
            }
            PreOp::Handover => {}
        }
    }

    fn peer_flush(&mut self) {
        while self.peer.wants_write() {
            if self.peer.write_tls(&mut self.peer_stream).is_err() {
                break;
            }
        }
    }

    fn subject_flush(&mut self) {
        match &mut self.subject {
            Subject::Buffered(conn) => {
                while conn.wants_write() {
                    if conn.write_tls(&mut self.to_peer).is_err() {
                        break;
                    }
                }
            }
            _ => self.drive(),
        }
    }

    /// Processes the subject's input.
    fn drive(&mut self) {
        if self.subject_failed {
            return;
        }
        let ok = match &mut self.subject {
            Subject::Buffered(conn) => conn.process_new_packets().is_ok(),
            Subject::Client(conn) => drive(
                &mut **conn,
                &mut self.unbuffered,
                &mut self.to_peer,
                &mut self.up.sent,
                &mut self.down.recv,
            ),
            Subject::Server(conn) => drive(
                &mut **conn,
                &mut self.unbuffered,
                &mut self.to_peer,
                &mut self.up.sent,
                &mut self.down.recv,
            ),
        };
        self.subject_failed = !ok;
    }

    fn read(&mut self) {
        if let Subject::Buffered(conn) = &mut self.subject {
            let _ = conn.reader().read_to_end(&mut self.down.recv);
        }
        let _ = self.peer.reader().read_to_end(&mut self.up.recv);
    }

    fn write(&mut self, subject: bool, data: &[u8]) {
        if !subject {
            if let Ok(n) = self.peer.writer().write(data) {
                self.down.sent.extend_from_slice(&data[..n]);
            }
            return;
        }
        match &mut self.subject {
            Subject::Buffered(conn) => {
                if let Ok(n) = conn.writer().write(data) {
                    self.up.sent.extend_from_slice(&data[..n]);
                }
            }
            _ => self.unbuffered.data.extend_from_slice(data),
        }
    }

    fn peer_to_subject(&mut self, amount: usize, flags: u8) {
        self.peer_flush();
        let avail = self.peer_stream.len() - self.fed;
        match &mut self.subject {
            Subject::Buffered(conn) => {
                let boundary = buffered!(conn, c => c.bytes_to_record_boundary());
                let want = match (flags & 1 != 0, amount) {
                    (true, _) => boundary,
                    (false, 0) => avail,
                    (false, n) => n,
                };
                let n = want.min(avail);
                if n > 0 {
                    let (_, in_header) = boundary_model(&self.peer_stream, self.fed);
                    let mut bytes = &self.peer_stream[self.fed..self.fed + n];
                    let read = conn.read_tls(&mut bytes).unwrap_or(0);
                    self.fed += read;
                    if !self.subject_failed {
                        let now = buffered!(conn, c => c.bytes_to_record_boundary());
                        let (model, _) = boundary_model(&self.peer_stream, self.fed);
                        assert_eq!(now, model, "bytes_to_record_boundary");
                        if read == boundary && !in_header {
                            assert_eq!(now, 0, "reading to the boundary inside a record");
                        }
                    }
                }
            }
            _ => {
                let n = if amount == 0 {
                    avail
                } else {
                    amount.min(avail)
                };
                let bytes = &self.peer_stream[self.fed..self.fed + n];
                self.unbuffered.inbuf.extend_from_slice(bytes);
                self.fed += n;
            }
        }
        if flags & 2 != 0 {
            self.drive();
        }
        if flags & 4 != 0 {
            self.read();
        }
    }

    fn subject_to_peer(&mut self) {
        let bytes = std::mem::take(&mut self.to_peer);
        if !self.peer_failed {
            self.peer_failed = !post::peer_receive(&mut self.peer, &bytes, &mut self.up.recv);
        }
    }

    fn pump(&mut self) {
        for _ in 0..32 {
            self.peer_flush();
            self.subject_flush();
            let moved = self.fed < self.peer_stream.len() || !self.to_peer.is_empty();
            self.peer_to_subject(0, 2 | 4);
            self.subject_flush();
            self.subject_to_peer();
            if !moved {
                break;
            }
        }
    }

    /// The subject's handover blocker, with the properties it must have;
    /// the peer's too.
    fn blocker(&self) -> Option<KernelHandoffBlocker> {
        let blocker = match &self.subject {
            Subject::Buffered(conn) => {
                let blocker = buffered!(conn, c => c.kernel_handoff_blocker());
                if buffered!(conn, c => c.bytes_to_record_boundary()) > 0 {
                    assert!(blocker.is_some(), "a partial record does not block");
                }
                blocker
            }
            Subject::Client(conn) => conn.kernel_handoff_blocker(),
            Subject::Server(conn) => conn.kernel_handoff_blocker(),
        };
        if let Some(b) = blocker {
            let _ = format!("{b} {b:?}");
        }
        // A handover needs a record size Linux takes (64 bytes of payload,
        // less the TLS 1.3 content type).
        let common: &browntls_core::CommonState = match &self.subject {
            Subject::Buffered(conn) => conn,
            Subject::Client(conn) => conn,
            Subject::Server(conn) => conn,
        };
        if blocker.is_none()
            && let Some(max) = common.max_tx_payload_len()
        {
            assert!(max >= 63, "a {max}-byte record limit does not block");
        }
        if !self.header.extraction() {
            assert_eq!(
                blocker,
                Some(KernelHandoffBlocker::SecretExtractionDisabled)
            );
        } else if !self.header.kernel_form() {
            assert!(
                blocker.is_some(),
                "a suite with no kernel form does not block"
            );
        }
        let peer = buffered!(&self.peer, c => c.kernel_handoff_blocker());
        if !self.header.extraction() {
            assert_eq!(peer, Some(KernelHandoffBlocker::SecretExtractionDisabled));
        }
        blocker
    }

    fn handover(self, input: &mut Input<'_>, ops: &mut usize) {
        let blocker = self.blocker();
        let Self {
            header,
            subject,
            peer,
            mut unbuffered,
            peer_stream,
            fed,
            to_peer,
            up,
            down,
            ..
        } = self;
        // Bytes the subject did not take reach the kernel: an unbuffered
        // subject's unprocessed input, then the peer's records.
        unbuffered.inbuf.extend_from_slice(&peer_stream[fed..]);
        let rest = Rest {
            peer,
            peer_wire: unbuffered.inbuf,
            to_peer,
            up,
            down,
            // Fragmented handshake messages may be partly buffered.
            joiner_known: header.fragment == 0,
        };
        match subject {
            Subject::Buffered(Connection::Client(conn)) => {
                let handoff = conn.dangerous_into_kernel_connection();
                if let Ok((_, kernel)) = &handoff {
                    let _ = kernel.matched_service_identity();
                }
                rest.go(blocker, handoff, input, ops);
            }
            Subject::Buffered(Connection::Server(conn)) => {
                rest.go(blocker, conn.dangerous_into_kernel_connection(), input, ops);
            }
            Subject::Client(conn) => {
                rest.go(blocker, conn.dangerous_into_kernel_connection(), input, ops);
            }
            Subject::Server(conn) => {
                rest.go(blocker, conn.dangerous_into_kernel_connection(), input, ops);
            }
        }
    }
}

/// What the handover passes on to the kernel and its peer.
struct Rest {
    peer: Connection,
    peer_wire: Vec<u8>,
    to_peer: Vec<u8>,
    up: Flow,
    down: Flow,
    joiner_known: bool,
}

impl Rest {
    fn go<D: KernelSide>(
        self,
        blocker: Option<KernelHandoffBlocker>,
        result: Result<(ExtractedSecrets, KernelConnection<D>), Error>,
        input: &mut Input<'_>,
        ops: &mut usize,
    ) {
        let (secrets, conn) = match (blocker, result) {
            (None, Ok(handed)) => handed,
            (Some(blocker), Err(err)) => {
                let text = err.to_string();
                assert!(
                    text.contains(&blocker.to_string()),
                    "{text} for {blocker:?}"
                );
                return;
            }
            (None, Err(err)) => panic!("no blocker, but the handover failed: {err}"),
            (Some(blocker), Ok(_)) => panic!("{blocker:?} did not block the handover"),
        };
        assert_eq!(
            conn.max_tx_payload_len(),
            conn.common_state().max_tx_payload_len()
        );
        let mut off = Offloaded::new(conn, &secrets, self.down.recv, self.joiner_known);
        drop(secrets);
        off.wire_out = self.to_peer;
        post::run(
            off,
            self.peer,
            self.peer_wire,
            self.down.sent,
            self.up,
            input,
            ops,
        );
    }
}

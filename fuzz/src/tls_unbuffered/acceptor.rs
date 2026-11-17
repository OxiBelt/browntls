//! The `UnbufferedAcceptor` operation of the `tls_unbuffered` target: the
//! server's pending input is read by a fresh acceptor, fed in fuzzed chunks,
//! and the connection it makes replaces the server.
//!
//! Checked properties:
//! * the buffered `Acceptor` fed the same bytes (the model) reaches the same
//!   outcome: still waiting, the same ClientHello as seen through every
//!   `ClientHello` accessor, or the same error with the same alert bytes;
//! * a configuration that `UnbufferedServerConnection::new` refuses is
//!   refused by both acceptors' `into_connection` with the same error and an
//!   `internal_error` alert (other refusals may depend on the session cache,
//!   which the two would share, so they are not compared);
//! * `discard` never exceeds the input; a spent acceptor discards nothing
//!   and fails with an empty alert; an alert buffer that is too small is
//!   reported with the size needed and nothing is consumed;
//! * the connection made from the ClientHello then satisfies every property
//!   of the target (data, exporters, secrets, agreement with the client).

use std::sync::Arc;

use browntls::server::{
    Acceptor, ClientHello, UnbufferedAcceptedAlert, UnbufferedAcceptor, UnbufferedServerConnection,
};
use browntls::unbuffered::{EncodeError, InsufficientSizeError};
use browntls::{CipherSuite, Error, NamedGroup, ServerConfig, SignatureScheme};

use super::{CLIENT, Op, SERVER, Seed, World};
use crate::input::Input;

/// Flag: build the acceptor with `Default` rather than `new`.
const DEFAULT: u8 = 1;
/// Flag: offer a configuration with an invalid `max_fragment_size`.
const BAD_CONFIG: u8 = 2;
/// Flag: `set_resumption_data` on the connection made.
const RESUMPTION_DATA: u8 = 4;
/// Flag: `reject_early_data` on the connection made.
const REJECT_EARLY_DATA: u8 = 8;
/// Flag: offer a one-byte buffer to the alert first.
const SHORT_ALERT: u8 = 0x10;
/// Flag: format every status with `Debug`.
const DEBUG: u8 = 0x80;

/// What an acceptor made of all the bytes it was given.
enum Outcome<A> {
    Waiting,
    Hello(A),
    Refused(Error, Vec<u8>),
}

/// Everything [`ClientHello`] exposes, owned and comparable.
#[derive(Debug, PartialEq)]
struct HelloView {
    server_name: Option<String>,
    signature_schemes: Vec<SignatureScheme>,
    alpn: Option<Vec<Vec<u8>>>,
    cipher_suites: Vec<CipherSuite>,
    certificate_authorities: Option<Vec<Vec<u8>>>,
    named_groups: Option<Vec<NamedGroup>>,
    client_cert_types: Option<Vec<u8>>,
    server_cert_types: Option<Vec<u8>>,
}

impl HelloView {
    fn of(hello: &ClientHello<'_>) -> Self {
        Self {
            server_name: hello.server_name().map(str::to_owned),
            signature_schemes: hello.signature_schemes().to_vec(),
            alpn: hello.alpn().map(|a| a.map(<[u8]>::to_vec).collect()),
            cipher_suites: hello.cipher_suites().to_vec(),
            certificate_authorities: hello
                .certificate_authorities()
                .map(|cas| cas.iter().map(|ca| ca.as_ref().to_vec()).collect()),
            named_groups: hello.named_groups().map(<[_]>::to_vec),
            client_cert_types: hello
                .client_cert_types()
                .map(|t| t.iter().map(|&t| u8::from(t)).collect()),
            server_cert_types: hello
                .server_cert_types()
                .map(|t| t.iter().map(|&t| u8::from(t)).collect()),
        }
    }
}

/// Copies all of `alert` out, through the `InsufficientSize` path first
/// when `short`.
fn encode_all(alert: &mut UnbufferedAcceptedAlert, short: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; if short { 1 } else { 1 << 15 }];
    for _ in 0..64 {
        if alert.is_empty() {
            break;
        }
        match alert.encode(&mut buf) {
            Ok(n) => {
                assert!(n > 0, "an alert that is not empty encodes something");
                out.extend_from_slice(&buf[..n]);
            }
            Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                assert!(required_size > buf.len(), "the buffer was big enough");
                assert!(!alert.is_empty(), "a refused encode consumes nothing");
                buf.resize(required_size, 0);
            }
            Err(err) => panic!("alert encoding failed: {err:?}"),
        }
    }
    assert!(alert.is_empty());
    assert_eq!(alert.encode(&mut []), Ok(0));
    out
}

/// The model: a buffered `Acceptor` fed `bytes` in pieces of at most
/// `step`, or `None` when its receive buffer filled up (not comparable).
fn model(bytes: &[u8], step: usize) -> Option<Outcome<browntls::server::Accepted>> {
    let mut acceptor = Acceptor::default();
    let mut fed = 0;
    for _ in 0..bytes.len() + 2 {
        let end = bytes.len().min(fed + step);
        let mut piece = &bytes[fed..end];
        acceptor.read_tls(&mut piece).ok()?;
        fed = end - piece.len();
        match acceptor.accept() {
            Ok(None) if fed == bytes.len() => return Some(Outcome::Waiting),
            Ok(None) => {}
            Ok(Some(accepted)) => return Some(Outcome::Hello(accepted)),
            Err((err, mut alert)) => {
                let mut out = Vec::new();
                alert.write_all(&mut out).ok()?;
                return Some(Outcome::Refused(err, out));
            }
        }
    }
    None
}

impl World {
    /// `chunk, flags`: reads `inbuf[SERVER]` with a fresh
    /// `UnbufferedAcceptor`, `chunk` bytes per call (0: all at once), and
    /// checks it against the model. Once a ClientHello is read, the
    /// connection `into_connection` makes replaces the server, with the
    /// bytes the acceptor did not discard as its input; a refusal leaves the
    /// world as it was.
    pub(super) fn accept(&mut self, input: &mut Input<'_>) {
        let chunk = usize::from(input.byte());
        let flags = input.byte();
        let bytes = self.inbuf[SERVER].clone();
        let step = if chunk == 0 {
            bytes.len().max(1)
        } else {
            chunk
        };

        let mut acceptor = if flags & DEFAULT != 0 {
            UnbufferedAcceptor::default()
        } else {
            UnbufferedAcceptor::new()
        };
        let mut incoming = Vec::new();
        let mut fed = 0;
        let mut outcome = Outcome::Waiting;
        for _ in 0..bytes.len() + 2 {
            let end = bytes.len().min(fed + step);
            incoming.extend_from_slice(&bytes[fed..end]);
            fed = end;
            let status = acceptor.accept(&mut incoming);
            if flags & DEBUG != 0 {
                let _ = format!("{status:?} {acceptor:?}");
            }
            assert!(status.discard <= incoming.len(), "discard beyond the input");
            incoming.drain(..status.discard);
            match status.state {
                Ok(None) if fed == bytes.len() => break,
                Ok(None) => {}
                Ok(Some(accepted)) => {
                    outcome = Outcome::Hello(accepted);
                    break;
                }
                Err((err, mut alert)) => {
                    outcome =
                        Outcome::Refused(err, encode_all(&mut alert, flags & SHORT_ALERT != 0));
                    break;
                }
            }
        }
        if !matches!(outcome, Outcome::Waiting) {
            // Spent: nothing is read any more.
            let status = acceptor.accept(&mut incoming);
            assert_eq!(status.discard, 0);
            match status.state {
                Err((Error::General(_), mut alert)) => {
                    assert!(alert.is_empty());
                    assert_eq!(alert.encode(&mut []), Ok(0));
                }
                _ => panic!("a spent UnbufferedAcceptor accepted more"),
            }
        }

        let model = model(&bytes, step);
        let (accepted, model) = match (outcome, model) {
            (_, None) => return,
            (Outcome::Waiting, Some(Outcome::Waiting)) => return,
            (Outcome::Refused(err, alert), Some(Outcome::Refused(m_err, m_alert))) => {
                assert_eq!(err, m_err, "the acceptors refuse differently");
                assert_eq!(alert, m_alert, "the acceptors send different alerts");
                return;
            }
            (Outcome::Hello(accepted), Some(Outcome::Hello(model))) => (accepted, model),
            _ => panic!("the unbuffered and buffered acceptors disagree"),
        };
        let view = HelloView::of(&accepted.client_hello());
        assert_eq!(view, HelloView::of(&model.client_hello()));
        if flags & DEBUG != 0 {
            let _ = format!("{accepted:?}");
        }

        let config = if flags & BAD_CONFIG != 0 {
            let mut config = ServerConfig::clone(&self.server_config);
            config.max_fragment_size = Some(1);
            Arc::new(config)
        } else {
            self.server_config.clone()
        };
        // A configuration refused up front touches no shared state, so the
        // model can be asked too.
        let refused_up_front = UnbufferedServerConnection::new(config.clone()).err();
        let mut conn = match accepted.into_connection(config.clone()) {
            Ok(conn) => {
                assert!(
                    refused_up_front.is_none(),
                    "a refused configuration was used"
                );
                conn
            }
            Err((err, mut alert)) => {
                let alert = encode_all(&mut alert, flags & SHORT_ALERT != 0);
                if let Some(refused) = refused_up_front {
                    assert_eq!(err, refused);
                    // One plaintext fatal internal_error alert.
                    assert_eq!(alert, [0x15, 3, 3, 0, 2, 2, 80], "{err:?}");
                    let (m_err, mut m_alert) = model.into_connection(config).unwrap_err();
                    let mut out = Vec::new();
                    m_alert.write_all(&mut out).unwrap();
                    assert_eq!((err, alert), (m_err, out));
                }
                return;
            }
        };
        if flags & RESUMPTION_DATA != 0 {
            conn.set_resumption_data(b"acceptor");
            self.resumption_data.push(b"acceptor".to_vec());
        }
        if flags & REJECT_EARLY_DATA != 0 {
            conn.reject_early_data();
        }
        incoming.extend_from_slice(&bytes[fed..]);
        self.inbuf[SERVER] = incoming;
        self.server = Some(conn);
        self.failed[SERVER] = false;
        self.closed[SERVER] = false;
    }
}

/// Seeds that read the ClientHello through the acceptor.
pub(super) fn seeds() -> Vec<Vec<u8>> {
    let hello_to_server = |seed: Seed| {
        seed.step(Op::Drive, CLIENT as u8, 1, 0, b"")
            .op(Op::Deliver, &[CLIENT as u8, 0, 0, 0, 0, 0])
    };
    let mut seeds = Vec::new();
    // Whole input, byte by byte and in small pieces; TLS 1.3 and 1.2.
    for (knobs, chunk, flags) in [
        ([0x01, 0x40, 0, 0, 0], 0, DEBUG | RESUMPTION_DATA),
        ([0x02, 0x00, 0, 0, 0], 1, DEFAULT | SHORT_ALERT),
        ([0x00, 0x80, 0, 0, 0], 7, DEBUG),
    ] {
        let seed = hello_to_server(Seed::new(knobs, &[0]))
            .op(Op::Accept, &[chunk, flags])
            .conversation()
            .op(Op::Accessors, &[]);
        seeds.push(seed.0);
    }

    // 0-RTT through the acceptor on a resumed connection: the early data
    // records stay in the input and are read in place by the connection.
    let seed = Seed::new([0x41, 0x04, 0, 0, 0], &[0])
        .op(Op::Pump, &[])
        .op(Op::Check, &[])
        .op(Op::Reconnect, &[0])
        .step(Op::Drive, CLIENT as u8, 1 | 8, 0, b"early")
        .op(Op::Deliver, &[CLIENT as u8, 0, 0, 0, 0, 0])
        .op(Op::Accept, &[0, DEBUG])
        .op(Op::Pump, &[])
        .op(Op::Accessors, &[])
        .op(Op::Check, &[])
        .op(Op::Extract, &[]);
    seeds.push(seed.0);

    // Refusals: a configuration refused up front, with a short alert
    // buffer; a server input that is not a ClientHello.
    let seed = hello_to_server(Seed::new([0x01, 0x00, 0, 0, 0], &[0]))
        .op(Op::Accept, &[3, BAD_CONFIG | SHORT_ALERT | DEBUG])
        .op(Op::Pump, &[]);
    seeds.push(seed.0);
    let seed = Seed::new([0x00, 0x00, 0, 0, 0], &[0])
        .op(Op::Inject, &[SERVER as u8, 0, 6, 0x14, 3, 3, 0, 1, 1])
        .op(Op::Accept, &[0, 0])
        .op(
            Op::Inject,
            &[SERVER as u8, 0, 9, 0x16, 3, 1, 0, 4, 0x0e, 0, 0, 0],
        )
        .op(Op::Accept, &[1, SHORT_ALERT]);
    seeds.push(seed.0);
    // Too late: the server already read the ClientHello.
    let seed = Seed::new([0x00, 0x00, 0, 0, 0], &[0])
        .op(Op::Pump, &[])
        .op(Op::Accept, &[0, DEBUG])
        .op(Op::Check, &[]);
    seeds.push(seed.0);
    seeds
}

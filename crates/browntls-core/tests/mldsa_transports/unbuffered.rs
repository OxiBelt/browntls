//! The unbuffered connection API with ML-DSA mutual authentication: the
//! caller owns every buffer, so the large Certificate and
//! CertificateVerify messages decide how much it must hold. Output
//! buffers start at one byte and grow to the `InsufficientSizeError`
//! size; input is handed over one record at a time.

use std::ops::DerefMut;

use browntls_core::client::UnbufferedClientConnection;
use browntls_core::server::UnbufferedServerConnection;
use browntls_core::unbuffered::{
    ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedConnectionCommon,
};
use browntls_core::{Error, HandshakeKind, SideData};

use crate::identity::{Setup, server_name};
use crate::ml_dsa::Set;

/// One side and the caller-side buffers.
struct Side<C> {
    conn: C,
    /// Received bytes not yet discarded.
    incoming: Vec<u8>,
    /// Received records not yet handed over.
    pending: Vec<u8>,
    outgoing: Vec<u8>,
    /// The output buffer size offered to `encode`, grown on demand.
    out_size: usize,
    /// The largest `encode` output, the largest `encrypt` output, and the
    /// most received bytes held at once.
    largest_encode: usize,
    largest_encrypt: usize,
    largest_held: usize,
    received: Vec<u8>,
    to_send: Vec<u8>,
    error: Option<Error>,
}

impl<C, D> Side<C>
where
    C: DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: SideData,
{
    fn new(conn: C) -> Self {
        Self {
            conn,
            incoming: Vec::new(),
            pending: Vec::new(),
            outgoing: Vec::new(),
            out_size: 1,
            largest_encode: 0,
            largest_encrypt: 0,
            largest_held: 0,
            received: Vec::new(),
            to_send: Vec::new(),
            error: None,
        }
    }

    /// Processes until the connection needs input.
    fn run(&mut self) {
        while self.error.is_none() {
            let status = self.conn.process_tls_records(&mut self.incoming);
            let discard = status.discard;
            let mut stop = false;
            match status.state {
                Ok(ConnectionState::ReadTraffic(r)) => self.received.extend_from_slice(r.payload()),
                Ok(ConnectionState::EncodeTlsData(mut e)) => {
                    let mut buf = vec![0; self.out_size];
                    match e.encode(&mut buf) {
                        Ok(n) => {
                            self.largest_encode = self.largest_encode.max(n);
                            self.outgoing.extend_from_slice(&buf[..n]);
                        }
                        Err(EncodeError::InsufficientSize(InsufficientSizeError {
                            required_size,
                        })) => self.out_size = required_size,
                        Err(e) => panic!("{e:?}"),
                    }
                }
                Ok(ConnectionState::TransmitTlsData(t)) => t.done(),
                Ok(ConnectionState::BlockedHandshake) => stop = true,
                Ok(ConnectionState::WriteTraffic(mut w)) => {
                    if self.to_send.is_empty() {
                        stop = true;
                    } else {
                        let data = std::mem::take(&mut self.to_send);
                        let mut buf = vec![0; 1];
                        let n = loop {
                            match w.encrypt(&data, &mut buf) {
                                Ok(n) => break n,
                                Err(EncryptError::InsufficientSize(InsufficientSizeError {
                                    required_size,
                                })) => buf.resize(required_size, 0),
                                Err(e) => panic!("{e:?}"),
                            }
                        };
                        self.largest_encrypt = self.largest_encrypt.max(n);
                        self.outgoing.extend_from_slice(&buf[..n]);
                    }
                }
                Ok(other) => panic!("unexpected state {other:?}"),
                Err(e) => {
                    self.error = Some(e);
                    stop = true;
                }
            }
            self.incoming.drain(..discard);
            self.largest_held = self.largest_held.max(self.incoming.len());
            if stop {
                return;
            }
        }
    }

    /// Hands the pending records over one at a time.
    fn feed(&mut self) {
        while self.pending.len() >= 5 && self.error.is_none() {
            let len = 5 + usize::from(u16::from_be_bytes([self.pending[3], self.pending[4]]));
            self.incoming.extend(self.pending.drain(..len));
            self.largest_held = self.largest_held.max(self.incoming.len());
            self.run();
        }
        assert!(self.pending.is_empty() || self.error.is_some());
    }
}

/// Moves records both ways until neither side has anything to send.
fn pump<A, B, DA, DB>(client: &mut Side<A>, server: &mut Side<B>)
where
    A: DerefMut<Target = UnbufferedConnectionCommon<DA>>,
    B: DerefMut<Target = UnbufferedConnectionCommon<DB>>,
    DA: SideData,
    DB: SideData,
{
    for _ in 0..32 {
        client.run();
        server.run();
        server.pending.append(&mut client.outgoing);
        let c = !server.pending.is_empty();
        server.feed();
        client.pending.append(&mut server.outgoing);
        let s = !client.pending.is_empty();
        client.feed();
        if !c && !s {
            return;
        }
    }
    panic!("pump did not settle");
}

/// ML-DSA mutual authentication and data over two unbuffered connections,
/// with the buffer sizes each side needed; with ML-DSA-87 also with the
/// roots sent, so that each Certificate message spans two records.
#[test]
fn unbuffered_mutual_authentication_and_data_with_every_parameter_set() {
    let cases = [
        (Set::MlDsa44, false),
        (Set::MlDsa65, false),
        (Set::MlDsa87, false),
        (Set::MlDsa87, true),
    ];
    for (set, roots) in cases {
        let setup = match roots {
            false => Setup::new(set, true),
            true => Setup::sending_roots(set, true),
        };
        let mut client = Side::new(
            UnbufferedClientConnection::new(setup.client.clone(), server_name()).unwrap(),
        );
        let mut server = Side::new(UnbufferedServerConnection::new(setup.server.clone()).unwrap());
        pump(&mut client, &mut server);
        assert!(client.error.is_none() && server.error.is_none());
        assert!(!client.conn.is_handshaking() && !server.conn.is_handshaking());
        assert_eq!(client.conn.handshake_kind(), Some(HandshakeKind::Full));
        setup.assert_schemes(set);
        let chain_len = 2 + usize::from(roots);
        assert_eq!(server.conn.peer_certificates().unwrap().len(), chain_len);
        assert_eq!(client.conn.peer_certificates().unwrap().len(), chain_len);

        let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        client.to_send = data.clone();
        pump(&mut client, &mut server);
        assert_eq!(server.received, data);
        server.to_send = b"reply".to_vec();
        pump(&mut client, &mut server);
        assert_eq!(client.received, b"reply");

        // `encode` writes one record at a time: the Certificate whole, or
        // its first 2^14 bytes when it is larger (roots sent).
        let certificate = chain_len * (set.public_key_len() + set.signature_len());
        for side in [client.largest_encode, server.largest_encode] {
            assert!(side > certificate.min(16_384), "{set:?}: {side}");
            assert!(side <= 5 + 16_384 + 256, "{set:?}: {side}");
        }
        // The received Certificate is joined outside the caller's buffer:
        // no more than one record is ever held.
        for held in [client.largest_held, server.largest_held] {
            assert!(held <= 5 + 16_384 + 256, "{set:?}: {held}");
        }
        println!(
            "{set:?} roots={roots}: encode client {} server {}, encrypt client {} server {}, \
             held client {} server {}",
            client.largest_encode,
            server.largest_encode,
            client.largest_encrypt,
            server.largest_encrypt,
            client.largest_held,
            server.largest_held,
        );
    }
}

//! The unbuffered connection API with legacy RSA client authentication:
//! the caller owns every buffer, output buffers start at one byte and grow
//! to the `InsufficientSizeError` size, and input is handed over one record
//! at a time.

use std::ops::DerefMut;

use browntls_core::client::UnbufferedClientConnection;
use browntls_core::server::UnbufferedServerConnection;
use browntls_core::unbuffered::{
    ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedConnectionCommon,
};
use browntls_core::{AlertDescription, Error, HandshakeKind, ProtocolVersion, SideData};

use crate::common::server_name;
use crate::identity::{Setup, rsa_client};

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
                        Ok(n) => self.outgoing.extend_from_slice(&buf[..n]),
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
        // Whether anything moved: after a failure, the failed side keeps
        // the records it no longer reads.
        let c = !client.outgoing.is_empty();
        server.pending.append(&mut client.outgoing);
        server.feed();
        let s = !server.outgoing.is_empty();
        client.pending.append(&mut server.outgoing);
        client.feed();
        if !c && !s {
            return;
        }
    }
    panic!("pump did not settle");
}

/// The legacy key authenticates a TLS 1.3 client over two unbuffered
/// connections to an opted-in server, which verifies exactly one
/// `rsa_pkcs1_sha512_legacy` signature and sees the client's chain;
/// application data then flows both ways.
#[test]
fn unbuffered_mutual_authentication_with_the_legacy_key() {
    let setup = Setup::new(true);
    let mut client =
        Side::new(UnbufferedClientConnection::new(setup.client.clone(), server_name()).unwrap());
    let mut server = Side::new(UnbufferedServerConnection::new(setup.server.clone()).unwrap());
    pump(&mut client, &mut server);
    assert!(client.error.is_none() && server.error.is_none());
    assert!(!client.conn.is_handshaking() && !server.conn.is_handshaking());
    assert_eq!(client.conn.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(
        client.conn.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    setup.assert_schemes();
    assert_eq!(
        server.conn.peer_certificates().unwrap(),
        rsa_client().cert_chain()
    );
    assert_eq!(
        client.conn.peer_certificates().unwrap(),
        crate::identity::server().cert_chain()
    );

    let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    client.to_send = data.clone();
    pump(&mut client, &mut server);
    assert_eq!(server.received, data);
    server.to_send = b"reply".to_vec();
    pump(&mut client, &mut server);
    assert_eq!(client.received, b"reply");
}

/// Against a server without the opt-in, the legacy key is offered no scheme
/// it signs with, so the client sends an empty Certificate: the server
/// fails mandatory client authentication with `NoCertificatesPresented`
/// and the client receives `certificate_required`.
#[test]
fn unbuffered_default_server_refuses_the_legacy_key() {
    let setup = Setup::new(false);
    let mut client =
        Side::new(UnbufferedClientConnection::new(setup.client.clone(), server_name()).unwrap());
    let mut server = Side::new(UnbufferedServerConnection::new(setup.server.clone()).unwrap());
    pump(&mut client, &mut server);
    assert_eq!(server.error, Some(Error::NoCertificatesPresented));
    assert_eq!(
        client.error,
        Some(Error::AlertReceived(AlertDescription::CertificateRequired))
    );
    assert!(server.conn.peer_certificates().is_none());
    assert!(setup.client_auth.seen().is_empty());
    assert!(server.received.is_empty() && client.received.is_empty());
}

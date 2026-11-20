// The unbuffered API of both sides.

use browntls_core::client::{ClientConnectionData, UnbufferedClientConnection};
use browntls_core::server::{ServerConnectionData, UnbufferedServerConnection};
use browntls_core::unbuffered::{
    ConnectionState, EncodeError, InsufficientSizeError, UnbufferedConnectionCommon,
};

/// Drives `conn` over `incoming` until it needs more input, appending what
/// it sends to `outgoing`.
fn ub_run<D: browntls_core::SideData>(
    conn: &mut UnbufferedConnectionCommon<D>,
    incoming: &mut Vec<u8>,
    outgoing: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut size = 1024;
    for _ in 0..1000 {
        let status = conn.process_tls_records(incoming);
        let discard = status.discard;
        let mut stop = false;
        match status.state? {
            ConnectionState::EncodeTlsData(mut e) => {
                let mut buf = vec![0u8; size];
                match e.encode(&mut buf) {
                    Ok(n) => outgoing.extend_from_slice(&buf[..n]),
                    Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                        size = required_size;
                    }
                    Err(e) => panic!("{e:?}"),
                }
            }
            ConnectionState::TransmitTlsData(t) => t.done(),
            ConnectionState::ReadTraffic(_) | ConnectionState::PeerClosed => {}
            ConnectionState::BlockedHandshake
            | ConnectionState::WriteTraffic(_)
            | ConnectionState::Closed => stop = true,
            other => panic!("unexpected state {other:?}"),
        }
        incoming.drain(..discard);
        if stop {
            return Ok(());
        }
    }
    panic!("unbuffered connection did not settle");
}

fn ub_handshake(
    client: &mut UnbufferedClientConnection,
    server: &mut UnbufferedServerConnection,
) -> Result<(), Error> {
    let (mut to_client, mut to_server) = (Vec::new(), Vec::new());
    for _ in 0..16 {
        ub_run::<ClientConnectionData>(client, &mut to_client, &mut to_server)?;
        ub_run::<ServerConnectionData>(server, &mut to_server, &mut to_client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("handshake did not complete");
}

#[test]
fn unbuffered_connections_on_both_sides() {
    let chain = server_chain(KeyType::EcdsaP384);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let store = new_store();
    let cc = client(&chain, &store, Some(&client_chain), &TLS12);
    let sc = server(&chain, policy(true, true), Some(&client_chain), &TLS12);
    for round in 0..2 {
        let mut c = UnbufferedClientConnection::new(cc.clone(), server_name()).unwrap();
        let mut s = UnbufferedServerConnection::new(sc.clone()).unwrap();
        ub_handshake(&mut c, &mut s).unwrap();
        for replaced in [c.cached_info_replaced(), s.cached_info_replaced()] {
            assert_eq!(replaced.contains(CERT), round == 1);
            assert_eq!(replaced.contains(CERT_REQ), round == 1);
        }
        assert_eq!(c.peer_certificates().unwrap(), chain.cert_chain());
        assert_eq!(s.peer_certificates().unwrap(), client_chain.cert_chain());
    }
    // Against a buffered server too.
    let mut c = UnbufferedClientConnection::new(cc.clone(), server_name()).unwrap();
    let mut s = ServerConnection::new(sc.clone()).unwrap();
    let (mut to_client, mut to_server) = (Vec::new(), Vec::new());
    for _ in 0..16 {
        ub_run::<ClientConnectionData>(&mut c, &mut to_client, &mut to_server).unwrap();
        let mut rest = &to_server[..];
        while !rest.is_empty() {
            s.read_tls(&mut rest).unwrap();
            s.process_new_packets().unwrap();
        }
        to_server.clear();
        to_client.extend_from_slice(&output(&mut s));
        if !c.is_handshaking() && !s.is_handshaking() {
            break;
        }
    }
    assert!(c.cached_info_replaced().contains(CERT) && s.cached_info_replaced().contains(CERT));
}

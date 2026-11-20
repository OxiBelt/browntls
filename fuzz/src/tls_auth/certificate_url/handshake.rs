//! TLS 1.2 handshakes with a client certificate URL pause, on a buffered
//! server (answered through `ConnectionCommon` or `Connection`) and on an
//! unbuffered one.

use std::io::{ErrorKind, Read};

use browntls_core::certificate_url::{ClientCertificateUrlQuery, ClientCertificateUrlResponse};
use browntls_core::pki_types::ServerName;
use browntls_core::server::UnbufferedServerConnection;
use browntls_core::unbuffered::{ConnectionState, EncodeError, InsufficientSizeError};
use browntls_core::{ClientConnection, Connection, Error, ServerConnection};

use super::{Answer, Plan, check};

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("name")
}

/// Checks a query against the URLs the client sent.
fn check_query(plan: &Plan, query: &ClientCertificateUrlQuery) {
    let urls = plan.urls.as_ref().expect("a query needs URLs");
    assert_eq!(query.chain_type(), urls.chain_type());
    assert_eq!(query.entries(), urls.entries());
}

/// An id that is not `id`.
fn wrong(id: u64) -> u64 {
    id ^ 1 << 40 ^ 1
}

/// Moves everything `from` has to send into `to`.
fn transfer(from: &mut Connection, to: &mut Connection) {
    let mut buf = Vec::new();
    while from.wants_write() {
        if from.write_tls(&mut buf).is_err() {
            break;
        }
    }
    let mut rest = &buf[..];
    while !rest.is_empty() {
        match to.read_tls(&mut rest) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// The paused server reads and yields nothing, and refuses a wrong id.
fn paused(server: &mut Connection, id: u64) {
    assert!(server.is_handshaking() && !server.wants_read());
    let io = server.process_new_packets().expect("still paused");
    assert!(io.client_certificate_url_pending());
    assert_eq!(io.plaintext_bytes_to_read(), 0);
    let err = server
        .read_tls(&mut &[22u8, 3, 3, 0, 0][..])
        .expect_err("no input while paused");
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
    let mut buf = [0u8; 8];
    assert!(!matches!(server.reader().read(&mut buf), Ok(n) if n > 0));
    let unobtainable = ClientCertificateUrlResponse::Unobtainable;
    assert!(
        server
            .resolve_client_certificate_url(wrong(id), unobtainable)
            .is_err()
    );
    assert_eq!(
        server.pending_client_certificate_url().map(|q| q.id()),
        Some(id)
    );
}

/// Answers the query `id` through `Connection` or `ConnectionCommon`.
fn answer(server: &mut Connection, plan: &Plan, id: u64, via_enum: bool) -> Result<(), Error> {
    let Connection::Server(conn) = server else {
        unreachable!("the server is a server");
    };
    if plan.answer == Answer::WrongIdFirst {
        let fetched = plan.response();
        assert!(
            conn.resolve_client_certificate_url(wrong(id), fetched)
                .is_err()
        );
        assert!(conn.pending_client_certificate_url().is_some());
    }
    if via_enum {
        server.resolve_client_certificate_url(id, plan.response())
    } else {
        conn.resolve_client_certificate_url(id, plan.response())
    }
}

pub(super) fn buffered(plan: &Plan, via_enum: bool) {
    let server = ServerConnection::new(plan.server_config());
    if !plan.valid() {
        assert!(server.is_err(), "an invalid policy was accepted");
        return;
    }
    let mut server = Connection::Server(server.expect("server"));
    let client = ClientConnection::new(plan.client_config(), localhost()).expect("client");
    let mut client = Connection::Client(client);
    // Client connections never pause.
    let unobtainable = ClientCertificateUrlResponse::Unobtainable;
    assert!(
        client
            .resolve_client_certificate_url(0, unobtainable)
            .is_err()
    );

    let mut surfaced = 0;
    let mut results = (Ok(()), Ok(()));
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        assert!(client.pending_client_certificate_url().is_none());
        transfer(&mut client, &mut server);
        let mut result = server.process_new_packets().map(|_| ());
        while result.is_ok()
            && let Some(query) = server.pending_client_certificate_url().cloned()
        {
            surfaced += 1;
            check_query(plan, &query);
            paused(&mut server, query.id());
            result = answer(&mut server, plan, query.id(), via_enum);
        }
        if let Err(err) = result {
            transfer(&mut server, &mut client);
            results = (client.process_new_packets().map(|_| ()), Err(err));
            break;
        }
        transfer(&mut server, &mut client);
        if let Err(err) = client.process_new_packets() {
            transfer(&mut client, &mut server);
            results = (Err(err), server.process_new_packets().map(|_| ()));
            break;
        }
    }
    check(
        plan,
        surfaced,
        results.0,
        results.1,
        server.peer_certificates(),
    );
}

/// Runs the unbuffered server over `incoming` until it needs more input;
/// what it sends goes to `outgoing`.
fn drive(
    server: &mut UnbufferedServerConnection,
    incoming: &mut Vec<u8>,
    outgoing: &mut Vec<u8>,
    plan: &Plan,
    surfaced: &mut usize,
) -> Result<(), Error> {
    let mut size = 1024;
    for _ in 0..64 {
        let status = server.process_tls_records(&mut incoming[..]);
        let discard = status.discard;
        let state = match status.state {
            Ok(state) => state,
            Err(err) => {
                incoming.drain(..discard);
                return Err(err);
            }
        };
        let blocked = match state {
            ConnectionState::EncodeTlsData(mut encode) => {
                let mut buf = vec![0u8; size];
                match encode.encode(&mut buf) {
                    Ok(n) => outgoing.extend_from_slice(&buf[..n]),
                    Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                        size = required_size;
                    }
                    Err(err) => panic!("encode: {err:?}"),
                }
                false
            }
            ConnectionState::TransmitTlsData(transmit) => {
                transmit.done();
                false
            }
            ConnectionState::PendingClientCertificateUrl => {
                incoming.drain(..discard);
                let query = server
                    .pending_client_certificate_url()
                    .expect("a pending query")
                    .clone();
                *surfaced += 1;
                check_query(plan, &query);
                // Nothing moves until the answer.
                let again = server.process_tls_records(&mut incoming[..]);
                assert!(matches!(
                    again.state,
                    Ok(ConnectionState::PendingClientCertificateUrl)
                ));
                let unobtainable = ClientCertificateUrlResponse::Unobtainable;
                assert!(
                    server
                        .resolve_client_certificate_url(wrong(query.id()), unobtainable)
                        .is_err()
                );
                assert_eq!(
                    server.pending_client_certificate_url().map(|q| q.id()),
                    Some(query.id())
                );
                // A failure is reported by the next call, after its alert.
                let _ = server.resolve_client_certificate_url(query.id(), plan.response());
                continue;
            }
            ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => true,
            other => panic!("unexpected state {other:?}"),
        };
        incoming.drain(..discard);
        if blocked {
            return Ok(());
        }
    }
    panic!("the unbuffered server did not settle");
}

pub(super) fn unbuffered(plan: &Plan) {
    let server = UnbufferedServerConnection::new(plan.server_config());
    if !plan.valid() {
        assert!(server.is_err(), "an invalid policy was accepted");
        return;
    }
    let mut server = server.expect("server");
    let mut client = ClientConnection::new(plan.client_config(), localhost()).expect("client");
    let mut incoming = Vec::new();
    let mut surfaced = 0;
    let (mut client_result, mut server_result) = (Ok(()), Ok(()));
    for _ in 0..16 {
        while client.wants_write() {
            if client.write_tls(&mut incoming).is_err() {
                break;
            }
        }
        let mut outgoing = Vec::new();
        server_result = drive(
            &mut server,
            &mut incoming,
            &mut outgoing,
            plan,
            &mut surfaced,
        );
        let mut rest = &outgoing[..];
        while !rest.is_empty() {
            match client.read_tls(&mut rest) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        client_result = client.process_new_packets().map(|_| ());
        if server_result.is_err()
            || client_result.is_err()
            || (!client.is_handshaking() && !server.is_handshaking())
        {
            break;
        }
    }
    check(
        plan,
        surfaced,
        client_result,
        server_result,
        server.peer_certificates(),
    );
}

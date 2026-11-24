//! Kernel TLS offload (`browntls_core::kernel`) of ML-DSA-authenticated
//! connections, through the userspace stand-in for Linux kernel TLS of
//! `cases/kernel/sim.rs` (no kernel needed).
//!
//! The handover needs a finished handshake, so the handshake signatures
//! are made and checked before it; afterwards the kernel only protects
//! records. Post-handshake authentication (RFC 9846 §4.6.2) is the one
//! signature after the handover: its Certificate and CertificateVerify
//! travel as kernel records and are handled by the `KernelConnection`.

use std::io::{Read, Write};

use browntls_core::server::PostHandshakeAuthStatus;
use browntls_core::{
    ClientConnection, ConnectionCommon, ContentType, Error, ServerConnection, SideData,
};

use crate::identity::{Setup, scheme, server_name};
use crate::ml_dsa::Set;
use crate::sim::Offloaded;

/// Both sides allow secret extraction; the server asks for the client's
/// certificate after the handshake.
fn setup() -> Setup {
    Setup::with(Set::MlDsa87, true, |client, server| {
        client.enable_secret_extraction = true;
        client.enable_post_handshake_auth = true;
        server.enable_secret_extraction = true;
        server.request_client_auth_after_handshake = true;
    })
}

/// Moves `from`'s records into `wire`, then as much of `wire` as `to`
/// takes, processing it. Unlike `common::transfer`, bytes `to` does not
/// take yet stay in `wire`: a connection with handshake records to send
/// stops reading (`wants_read`), and an ML-DSA-87 flight is larger than
/// one read buffer.
fn move_records<A: SideData, B: SideData>(
    from: &mut ConnectionCommon<A>,
    wire: &mut Vec<u8>,
    to: &mut ConnectionCommon<B>,
) -> bool {
    while from.wants_write() {
        from.write_tls(wire).unwrap();
    }
    let before = wire.len();
    while !wire.is_empty() && to.wants_read() {
        match to.read_tls(&mut &wire[..]) {
            Ok(n) => drop(wire.drain(..n)),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Other),
        }
        to.process_new_packets().unwrap();
    }
    wire.len() != before
}

fn connect(setup: &Setup) -> (ClientConnection, ServerConnection) {
    let mut client = ClientConnection::new(setup.client.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(setup.server.clone()).unwrap();
    let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
    for _ in 0..32 {
        let c = move_records(&mut client, &mut to_server, &mut server);
        let s = move_records(&mut server, &mut to_client, &mut client);
        if !c && !s && to_server.is_empty() && to_client.is_empty() {
            break;
        }
    }
    // Handshake done and the server's tickets read: nothing in flight.
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert!(!client.wants_write() && !server.wants_write());
    (client, server)
}

/// Moves the userspace peer's queued records to the offloaded side.
fn peer_to_kernel<A: SideData, B: SideData>(
    peer: &mut ConnectionCommon<A>,
    off: &mut Offloaded<B>,
) -> Result<(), Error> {
    let mut wire = Vec::new();
    while peer.wants_write() {
        peer.write_tls(&mut wire).unwrap();
    }
    off.receive(&wire)
}

/// Moves the offloaded side's records to the userspace peer; returns the
/// plaintext the peer read.
fn kernel_to_peer<A: SideData, B: SideData>(
    off: &mut Offloaded<A>,
    peer: &mut ConnectionCommon<B>,
) -> Vec<u8> {
    let wire = off.take_wire();
    let mut offset = 0;
    let mut out = Vec::new();
    while offset < wire.len() {
        offset += peer.read_tls(&mut &wire[offset..]).unwrap();
        peer.process_new_packets().unwrap();
        if let Err(e) = peer.reader().read_to_end(&mut out) {
            assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
        }
    }
    out
}

/// The ML-DSA-87 server is offloaded after the handshake, asks the
/// userspace client for its certificate through the kernel, and checks
/// the client's ML-DSA-87 CertificateVerify there.
#[test]
fn offloaded_server_authenticates_an_ml_dsa_client_after_the_handshake() {
    let setup = setup();
    let (mut client, server) = connect(&setup);
    // The handshake signature was checked before the handover.
    assert_eq!(setup.server_auth.seen(), [scheme(Set::MlDsa87)]);
    let client_auth = setup.client_auth.as_ref().unwrap();
    assert!(client_auth.seen().is_empty());

    let (secrets, conn) = server.dangerous_into_kernel_connection().unwrap();
    let mut off = Offloaded::new(conn, secrets);
    off.send(b"before");
    assert_eq!(kernel_to_peer(&mut off, &mut client), b"before");

    off.conn.request_client_auth().unwrap();
    off.flush();
    let _ = kernel_to_peer(&mut off, &mut client);
    assert_eq!(client.post_handshake_auth_responses(), 1);
    peer_to_kernel(&mut client, &mut off).unwrap();
    assert_eq!(
        off.conn.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
    assert_eq!(client_auth.seen(), [scheme(Set::MlDsa87)]);
    assert_eq!(
        off.conn.common_state().peer_certificates().unwrap().len(),
        2
    );

    client.writer().write_all(b"after").unwrap();
    peer_to_kernel(&mut client, &mut off).unwrap();
    assert_eq!(std::mem::take(&mut off.app_in), b"after");
}

/// The ML-DSA-87 client is offloaded and answers the userspace server's
/// request: Certificate (about 15 kB) and CertificateVerify are made and
/// signed in userspace and sent as handshake records through the kernel.
#[test]
fn offloaded_client_answers_with_an_ml_dsa_certificate_verify() {
    let setup = setup();
    let (client, mut server) = connect(&setup);
    let (secrets, conn) = client.dangerous_into_kernel_connection().unwrap();
    let mut off = Offloaded::new(conn, secrets);

    server.request_client_auth().unwrap();
    peer_to_kernel(&mut server, &mut off).unwrap();
    let kinds: Vec<_> = off
        .control_sent
        .iter()
        .map(|(typ, payload)| (*typ, payload[0], payload.len()))
        .collect();
    assert!(kinds.iter().all(|(typ, ..)| *typ == ContentType::Handshake));
    // Certificate (11), CertificateVerify (15) with the 4627-byte
    // signature, Finished (20).
    // Certificate is 25 (CompressedCertificate) when compression is built.
    let types: Vec<u8> = kinds.iter().map(|(_, t, _)| *t).collect();
    assert!(matches!(types[..], [11 | 25, 15, 20]), "{kinds:?}");
    assert_eq!(kinds[1].2, 4 + 2 + 2 + Set::MlDsa87.signature_len());
    let _ = kernel_to_peer(&mut off, &mut server);
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
    let client_auth = setup.client_auth.as_ref().unwrap();
    assert_eq!(client_auth.seen(), [scheme(Set::MlDsa87)]);
}

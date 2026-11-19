//! A peer that keeps asking for answers while it reads nothing: the control
//! records owed to it stay bounded, and reading resumes once they are
//! written.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use alloc::vec;
use alloc::vec::Vec;
use std::io::{Read as _, Write as _};

use crate::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use crate::enums::{ContentType, ProtocolVersion, SignatureScheme};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::base::Payload;
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::message::PlainMessage;
use crate::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use crate::sync::Arc;
use crate::verify::DigitallySignedStruct;
use crate::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

/// Accepts any server: these tests are about records, not authentication.
#[derive(Debug)]
struct AcceptAnything;

impl ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// A TLS 1.3 pair after the handshake; the server's tickets are delivered.
pub(super) fn connected() -> (ClientConnection, ServerConnection) {
    let provider = Arc::new(crate::crypto::native::default_provider());
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&crate::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&crate::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnything))
        .with_no_client_auth();
    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    for _ in 0..8 {
        deliver(&mut client, &mut server);
        server.process_new_packets().unwrap();
        deliver(&mut server, &mut client);
        client.process_new_packets().unwrap();
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    (client, server)
}

/// Moves everything `from` queued into `to`, ignoring `to`'s wishes.
fn deliver<A: crate::conn::SideData, B: crate::conn::SideData>(
    from: &mut crate::conn::ConnectionCommon<A>,
    to: &mut crate::conn::ConnectionCommon<B>,
) {
    let mut bytes = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut bytes).unwrap();
    }
    to.read_tls(&mut bytes.as_slice()).unwrap();
}

/// Queues on `client`, as a peer may send, a KeyUpdate(update_requested)
/// whatever RFC 9846 §4.7.3 lets a well-behaved sender do, followed by an
/// application data record carrying `data`.
pub(super) fn request_key_update(client: &mut ClientConnection, data: &[u8]) {
    let core = &mut client.core;
    core.state
        .as_mut()
        .unwrap()
        .send_key_update(&mut core.common_state, KeyUpdateRequest::UpdateRequested)
        .unwrap();
    core.common_state.send_msg_encrypt(PlainMessage {
        typ: ContentType::ApplicationData,
        version: ProtocolVersion::TLSv1_3,
        payload: Payload::new(data.to_vec()),
    });
}

/// Feeds `server` the attacker's bytes as a driver that honours
/// `wants_read` does, reading out any plaintext like an application that
/// keeps reading. Returns the bytes left unread.
fn feed(server: &mut ServerConnection, mut input: &[u8]) -> usize {
    let mut plaintext = [0u8; 64];
    while !input.is_empty() && server.wants_read() {
        let n = server.read_tls(&mut input).unwrap();
        assert_ne!(n, 0);
        server.process_new_packets().unwrap();
        while let Ok(n) = server.reader().read(&mut plaintext) {
            if n == 0 {
                break;
            }
        }
    }
    input.len()
}

const LIMIT: usize = 1024;

#[test]
fn key_update_answers_owed_to_a_peer_that_reads_nothing_stay_bounded() {
    let (mut client, mut server) = connected();
    server.set_buffer_limit(Some(LIMIT));

    // Each round asks for a KeyUpdate and sends one byte of data, which
    // keeps the request counter from tripping; the server's answers are
    // never written.
    let mut input = Vec::new();
    for _ in 0..400 {
        request_key_update(&mut client, b"x");
        while client.wants_write() {
            client.write_tls(&mut input).unwrap();
        }
    }
    // Small reads: one process_new_packets per round.
    let mut unread = 0;
    for round in input.chunks(64) {
        unread += feed(&mut server, round);
    }

    // The server stopped reading once the answers it owes exceeded the
    // limit, instead of queueing one answer per request.
    let queued = server.core.common_state.sendable_tls.len();
    assert!(queued <= LIMIT + 128, "queued {queued} bytes");
    assert!(!server.wants_read());
    assert!(unread > 0);
    let err = server.read_tls(&mut &input[..1]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Other);

    // Once the transport takes the answers, reading resumes.
    let mut written = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut written).unwrap();
    }
    assert!(server.wants_read());
    client.read_tls(&mut written.as_slice()).unwrap();
    client.process_new_packets().unwrap();
}

#[test]
fn application_data_does_not_count_towards_the_control_backlog() {
    let (_, mut server) = connected();
    server.set_buffer_limit(Some(LIMIT));
    // Plaintext the application wrote and the transport did not take yet
    // fills the buffer up to its limit; the connection still reads.
    let written = server.writer().write(&[0u8; 4 * LIMIT]).unwrap();
    assert!(written > 0);
    assert!(server.core.common_state.sendable_tls.len() >= LIMIT / 2);
    assert_eq!(server.core.common_state.sendable_tls.control_len(), 0);
    assert!(server.wants_read());
}

#[test]
fn empty_records_do_not_reset_the_key_update_request_counter() {
    let (mut client, mut server) = connected();
    let mut input = Vec::new();
    for _ in 0..9 {
        request_key_update(&mut client, b"");
        while client.wants_write() {
            client.write_tls(&mut input).unwrap();
        }
    }
    let mut input = input.as_slice();
    let mut result = Ok(());
    while !input.is_empty() && result.is_ok() {
        server.read_tls(&mut input).unwrap();
        result = server.process_new_packets().map(|_| ());
        let mut sink = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut sink).unwrap();
        }
    }
    assert_eq!(result, Err(PeerMisbehaved::TooManyKeyUpdateRequests.into()));
}

#[test]
fn data_resets_the_key_update_request_counter() {
    let (mut client, mut server) = connected();
    let mut input = Vec::new();
    for _ in 0..32 {
        request_key_update(&mut client, b"x");
        while client.wants_write() {
            client.write_tls(&mut input).unwrap();
        }
    }
    let mut input = input.as_slice();
    let mut plaintext = [0u8; 64];
    while !input.is_empty() {
        server.read_tls(&mut input).unwrap();
        server.process_new_packets().unwrap();
        while let Ok(n) = server.reader().read(&mut plaintext) {
            if n == 0 {
                break;
            }
        }
        let mut sink = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut sink).unwrap();
        }
    }
}

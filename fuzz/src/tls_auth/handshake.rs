//! The handshake operation of the `tls_auth` target: a TLS 1.3 handshake
//! with a delegated credential whose validity, the peers' clocks and an
//! optional tampering are fuzz-chosen.

use std::io::{Read, Write};
use std::sync::Arc;

use browntls_core::delegated_credential::{
    Credential, DelegatedCredential, MAX_VALIDITY, valid_time_until,
};
use browntls_core::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{
    ClientConfig, ClientConnection, Error, PeerMisbehaved, ServerConfig, ServerConnection, Side,
    SignatureScheme, version,
};

use super::{FixedTime, fixture, unix};
use crate::input::Input;

// --------------------------------------------------------------- handshakes

/// Moves everything `from` has to send into `to`.
fn send<A: browntls_core::SideData, B: browntls_core::SideData>(
    from: &mut browntls_core::ConnectionCommon<A>,
    to: &mut browntls_core::ConnectionCommon<B>,
) {
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

/// Runs the handshake; returns each side's first error.
fn pump(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> (Result<(), Error>, Result<(), Error>) {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        send(client, server);
        if let Err(e) = server.process_new_packets() {
            send(server, client);
            let client_res = client.process_new_packets().map(|_| ());
            return (client_res, Err(e));
        }
        send(server, client);
        if let Err(e) = client.process_new_packets() {
            send(client, server);
            let server_res = server.process_new_packets().map(|_| ());
            return (Err(e), server_res);
        }
    }
    (Ok(()), Ok(()))
}

/// Handshake input: the client's clock (offset into the certificate's
/// validity, 32 bits), the server's skew selector and value, the expiry
/// relative to the client's clock (selector and value), the credential
/// key, and the tampering selector.
pub(super) fn handshake(input: &mut Input) {
    let fixture = fixture();
    let nb = fixture.not_before;
    let na = fixture.not_after;
    let week = MAX_VALIDITY.as_secs();
    let now = nb + u64::from(input.u32()) % (na - nb);
    let skew: i64 = match input.choose(4) {
        0 | 1 => 0,
        2 => i64::from(input.byte()) - 128,
        _ => i64::from(input.u32() as i32) % (2 * 86_400),
    };
    let server_now = now.saturating_add_signed(skew);
    // The expiry, around the boundaries the peers check.
    let delta: i64 = match input.choose(8) {
        0 => 0,
        1 => 1,
        2 => -1,
        3 => week as i64,
        4 => week as i64 + 1,
        5 => week as i64 - 1,
        _ => i64::from(input.u32() % (9 * 86_400)) - 86_400,
    };
    let expiry = now.saturating_add_signed(delta);
    let Some(valid_time) = expiry
        .checked_sub(nb)
        .filter(|d| *d > 0)
        .and_then(|d| u32::try_from(d).ok())
    else {
        return;
    };
    assert_eq!(
        valid_time_until(&fixture.delegation, unix(expiry)).ok(),
        Some(valid_time)
    );
    let dc_key = &fixture.dc_keys[input.choose(fixture.dc_keys.len())];
    let tamper = input.choose(6);

    let mut dc = DelegatedCredential::issue(
        Side::Server,
        &fixture.delegation,
        &*fixture.delegation_key,
        &[SignatureScheme::ECDSA_NISTP256_SHA256],
        Credential {
            valid_time,
            dc_cert_verify_algorithm: dc_key.scheme,
            public_key: dc_key.spki.clone(),
        },
    )
    .expect("issue");
    let tampered = match tamper {
        0 => {
            let at = usize::from(input.u16()) % dc.signature.len();
            dc.signature[at] ^= 1 << (input.byte() % 8);
            true
        }
        1 => {
            dc.credential.valid_time = dc.credential.valid_time.wrapping_add(1);
            true
        }
        2 => {
            dc.algorithm = SignatureScheme::ED25519;
            true
        }
        _ => false,
    };
    let certified = CertifiedKey::from_der(
        vec![fixture.delegation.clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture.delegation_pkcs8.clone())),
        &fixture.provider,
    )
    .expect("certified key")
    .with_delegated_credential(dc.clone(), dc_key.key.clone())
    .expect("credential attaches");
    assert_eq!(certified.delegated_credentials().len(), 1);

    let server_config = ServerConfig::builder_with_details(
        fixture.provider.clone(),
        Arc::new(FixedTime(unix(server_now))),
    )
    .with_protocol_versions(&[&version::TLS13])
    .expect("versions")
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    let mut client_config = ClientConfig::builder_with_details(
        fixture.provider.clone(),
        Arc::new(FixedTime(unix(now))),
    )
    .with_protocol_versions(&[&version::TLS13])
    .expect("versions")
    .with_root_certificates(fixture.roots.clone())
    .with_no_client_auth();
    client_config.enable_delegated_credentials = true;
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(Arc::new(client_config), name).expect("client");
    let mut server = ServerConnection::new(Arc::new(server_config)).expect("server");
    let (client_res, server_res) = pump(&mut client, &mut server);

    // The server sends the credential only inside its own window, and
    // within the certificate's validity.
    let expiry = nb + u64::from(dc.credential.valid_time);
    let sent = server_now < expiry && expiry <= server_now + week && expiry <= na;
    if !sent {
        assert!(
            client_res.is_ok() && server_res.is_ok(),
            "{client_res:?} {server_res:?}"
        );
        assert!(client.delegated_credential().is_none());
        return;
    }
    if tampered {
        assert!(client_res.is_err(), "a tampered credential was accepted");
        assert!(server_res.is_err());
        return;
    }
    let expected = if now >= expiry {
        Some(PeerMisbehaved::DelegatedCredentialExpired)
    } else if expiry > now + week || expiry > na {
        Some(PeerMisbehaved::DelegatedCredentialValidityTooLong)
    } else {
        None
    };
    match expected {
        Some(error) => {
            assert_eq!(client_res, Err(Error::PeerMisbehaved(error)));
            assert!(server_res.is_err());
        }
        None => {
            assert!(
                client_res.is_ok() && server_res.is_ok(),
                "{client_res:?} {server_res:?}"
            );
            assert_eq!(client.delegated_credential(), Some(&dc));
            client.writer().write_all(b"dc").expect("write");
            send(&mut client, &mut server);
            server.process_new_packets().expect("server reads");
            let mut got = [0u8; 2];
            server.reader().read_exact(&mut got).expect("data");
            assert_eq!(&got, b"dc");
        }
    }
}

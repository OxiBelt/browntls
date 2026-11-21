//! Deterministic negotiation, extension placement and protected records.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::common_state::Side;
use crate::crypto::SecureRandom;
use crate::msgs::codec::Codec;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{ClientExtensions, ServerExtensions};
use crate::rand::GetRandomFailed;

#[derive(Debug)]
struct Fixed;
impl SecureRandom for Fixed {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        bytes.fill(0x42);
        Ok(())
    }
}

fn settings(enabled: bool) -> Settings {
    let cid = ConnectionIdPolicy::new(8, true).unwrap();
    if enabled {
        Settings::default().with_return_routability_checks(cid)
    } else {
        Settings::default().with_connection_ids(cid)
    }
}

fn pair(client_enabled: bool, server_enabled: bool) -> (Dtls, Dtls) {
    let mut client = Dtls::new(Side::Client, settings(client_enabled));
    let mut server = Dtls::new(Side::Server, settings(server_enabled));
    client.initialize_cids(&Fixed).unwrap();
    server.initialize_cids(&Fixed).unwrap();
    server
        .cid
        .select(client.cid.offer().as_ref(), true)
        .unwrap();
    server.select_rrc(client.rrc_offer().is_some());
    client
        .cid
        .select(server.cid.response().as_ref(), false)
        .unwrap();
    client.select_rrc(server.rrc_negotiated);
    (client, server)
}

#[test]
fn negotiation_needs_both_opt_ins_and_cid_selection() {
    for client_enabled in [false, true] {
        for server_enabled in [false, true] {
            let (client, server) = pair(client_enabled, server_enabled);
            assert_eq!(client.rrc_negotiated, client_enabled && server_enabled);
            assert_eq!(server.rrc_negotiated, client.rrc_negotiated);
        }
    }
    let mut server = Dtls::new(Side::Server, settings(true));
    server.initialize_cids(&Fixed).unwrap();
    server.select_rrc(true);
    assert!(!server.rrc_negotiated);
    assert!(
        Dtls::new(Side::Client, Settings::default())
            .rrc_offer()
            .is_none()
    );
}

#[test]
fn empty_extension_round_trips_with_exact_type_and_no_stream_offer() {
    assert_eq!(
        u16::from(ExtensionType::ReturnRoutabilityCheck),
        rrc::EXTENSION_TYPE
    );
    assert_eq!(
        u8::from(ContentType::ReturnRoutabilityCheck),
        rrc::CONTENT_TYPE
    );
    let extension = ServerExtensions {
        return_routability_check: Some(()),
        ..Default::default()
    };
    let bytes = extension.get_encoding();
    assert_eq!(bytes, [0, 4, 0, 61, 0, 0]);
    assert_eq!(ServerExtensions::read_bytes(&bytes).unwrap(), extension);
    assert_eq!(
        extension.present_types(),
        [ExtensionType::ReturnRoutabilityCheck]
    );
    let client = ClientExtensions::read_bytes(&bytes).unwrap();
    assert_eq!(client.return_routability_check, Some(()));
    assert_eq!(client.get_encoding(), [0, 0]);
    for bytes in [
        &[0, 5, 0, 61, 0, 1, 0][..],
        &[0, 8, 0, 61, 0, 0, 0, 61, 0, 0],
    ] {
        assert!(ClientExtensions::read_bytes(bytes).is_err());
        assert!(ServerExtensions::read_bytes(bytes).is_err());
    }
}

#[test]
fn extension_is_not_allowed_in_other_server_messages() {
    use crate::tls13::extensions::{Tls13Message, allowed_in};
    let extension = ExtensionType::ReturnRoutabilityCheck;
    assert_eq!(allowed_in(extension, Tls13Message::ClientHello), Some(true));
    // The client DTLS ServerHello hook supplies the sole exception.
    for message in [
        Tls13Message::ServerHello,
        Tls13Message::HelloRetryRequest,
        Tls13Message::EncryptedExtensions,
        Tls13Message::CertificateRequest,
        Tls13Message::Certificate,
        Tls13Message::NewSessionTicket,
    ] {
        assert_eq!(allowed_in(extension, message), Some(false));
    }
}

#[cfg(any(feature = "native", feature = "rustcrypto"))]
mod protected {
    use super::*;
    use crate::crypto::tls13::OkmBlock;
    use crate::dtls::state::Incoming;

    fn keyed_pair() -> (Dtls, Dtls) {
        #[cfg(feature = "native")]
        let suite = crate::crypto::native::cipher_suite::TLS13_AES_128_GCM_SHA256;
        #[cfg(all(not(feature = "native"), feature = "rustcrypto"))]
        let suite = crate::crypto::rustcrypto::cipher_suite::TLS13_AES_128_GCM_SHA256;
        let suite = suite.tls13().unwrap();
        let secret = OkmBlock::new(&[0x42; 32]);
        let (mut client, mut server) = pair(true, true);
        for dtls in [&mut client, &mut server] {
            for _ in 0..2 {
                dtls.set_write_secret(suite, &secret);
                dtls.set_read_secret(suite, &secret);
            }
        }
        (client, server)
    }

    #[test]
    fn protected_control_and_application_data_have_distinct_metadata() {
        let (mut client, mut server) = keyed_pair();
        let message = rrc::Message {
            kind: rrc::MessageType::Challenge,
            cookie: [7; 8],
        };
        let mut data = Vec::new();
        client
            .seal_application_record(
                &mut data,
                ContentType::ReturnRoutabilityCheck,
                &message.encode(),
            )
            .unwrap();
        let control_len = data.len();
        client
            .seal_application_data(&mut data, b"ordinary app")
            .unwrap();
        let mut at = 0;
        assert_eq!(
            server.read_record(&mut data, &mut at, false).unwrap(),
            Incoming::Handled
        );
        let metadata = server.authenticated_record.take().unwrap();
        assert_eq!(metadata.sequence_number(), 0);
        assert_eq!(metadata.range(), 0..control_len);
        assert_eq!(
            &data[metadata.rrc_payload_range().unwrap()],
            message.encode()
        );
        let rrc::Record::AuthenticatedFresh { dtls_bytes, rrc } =
            metadata.path_validation_record(&data).unwrap()
        else {
            panic!("authenticated metadata expected")
        };
        assert_eq!(dtls_bytes, control_len);
        assert_eq!(rrc.unwrap(), message.encode());
        let Incoming::ApplicationData(range) =
            server.read_record(&mut data, &mut at, false).unwrap()
        else {
            panic!("application data expected")
        };
        assert_eq!(&data[range], b"ordinary app");
        let metadata = server.authenticated_record.take().unwrap();
        assert_eq!(metadata.range(), control_len..data.len());
        assert_eq!(metadata.sequence_number(), 1);
        assert!(metadata.rrc_payload_range().is_none());
    }

    #[test]
    fn local_control_sends_share_usage_limit_and_request_rekey() {
        let (mut client, _) = keyed_pair();
        let write = client.write.last_mut().unwrap();
        let limit = write.keys.as_ref().unwrap().confidentiality_limit();
        write.next_seq = limit - 1;
        let mut out = Vec::new();
        assert!(
            client
                .seal_application_record(
                    &mut out,
                    ContentType::ReturnRoutabilityCheck,
                    &[0; rrc::WIRE_LEN],
                )
                .unwrap()
        );
        let original = out.clone();
        assert_eq!(
            client.seal_application_data(&mut out, b"app"),
            Err(Error::EncryptError)
        );
        assert_eq!(
            client.seal_application_record(
                &mut out,
                ContentType::ReturnRoutabilityCheck,
                &[0; rrc::WIRE_LEN],
            ),
            Err(Error::EncryptError)
        );
        assert_eq!(out, original);
    }
}

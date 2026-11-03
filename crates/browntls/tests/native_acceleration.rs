//! TLS handshakes under each acceleration policy of the native provider.
//!
//! The policy is process-wide, so everything runs in one test function (each
//! integration test file is a separate process).
#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

use std::sync::Arc;

use browntls::crypto::CryptoProvider;
use browntls::crypto::native::{self, accel};
use browntls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use common::*;

/// One handshake per native cipher suite plus a payload in each direction.
fn handshake_every_suite() {
    for &suite in native::ALL_CIPHER_SUITES {
        let key_type = if format!("{:?}", suite.suite()).contains("_RSA_") {
            KeyType::Rsa2048
        } else {
            KeyType::EcdsaP256
        };
        let chain = server_chain(key_type);
        let provider = Arc::new(CryptoProvider {
            cipher_suites: vec![suite],
            ..native::default_provider()
        });
        let versions = [suite.version()];
        let client = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        let server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        let mut client = ClientConnection::new(Arc::new(client), server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server)).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.negotiated_cipher_suite(), Some(suite));

        let request: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        assert_eq!(
            send_and_receive(&mut client, &mut server, &request),
            request
        );
        let response = vec![0x5a; 9000];
        assert_eq!(
            send_and_receive(&mut server, &mut client, &response),
            response
        );
    }
}

#[test]
fn handshakes_under_every_acceleration_policy() {
    use accel::{Acceleration, Kind, Policy};

    for s in accel::status_all() {
        println!("{s}");
    }

    let levels = [
        Acceleration::Required,
        Acceleration::Preferred,
        Acceleration::None,
    ];
    for simd in levels {
        for dedicated in levels {
            let policy = Policy::new(simd, dedicated);
            accel::set_policy_all(Policy::PREFERRED).unwrap();
            match native::default_provider_with_acceleration(policy) {
                Ok(_) => {
                    for s in accel::status_all() {
                        assert!(s.policy.permits(s.uses), "{s}");
                    }
                    handshake_every_suite();
                }
                // Refused: nothing changed.
                Err(_) => assert!(
                    accel::status_all()
                        .iter()
                        .all(|s| s.policy == Policy::PREFERRED)
                ),
            }
        }
    }

    // Each kind disabled on its own is always satisfiable.
    for kind in Kind::ALL {
        accel::set_policy_all(Policy::PREFERRED).unwrap();
        accel::set_kind_all(kind, Acceleration::None).unwrap();
        assert_eq!(accel::accelerated_by(kind).count(), 0);
        handshake_every_suite();
    }

    accel::set_policy_all(Policy::PREFERRED).unwrap();
}

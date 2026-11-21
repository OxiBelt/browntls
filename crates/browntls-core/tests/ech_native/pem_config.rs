//! PEM configuration at the TLS handshake boundary.

use super::*;
use browntls_core::ech::pem::{EchPem, EchPemError, NATIVE_PKCS8_CODEC};

fn list(entries: &[&[u8]]) -> Vec<u8> {
    let len = u16::try_from(entries.iter().map(|entry| entry.len()).sum::<usize>()).unwrap();
    let mut list = len.to_be_bytes().to_vec();
    for entry in entries {
        list.extend_from_slice(entry);
    }
    list
}

fn decryption_pem(key: &EchServerKey) -> EchPem {
    EchPem::from_server_key(key, &list(&[key.ech_config()]), &NATIVE_PKCS8_CODEC).unwrap()
}

fn mode(pem: &EchPem) -> Option<EchMode> {
    Some(
        EchConfig::from_pem(pem, ALL_SUPPORTED_SUITES)
            .unwrap()
            .into(),
    )
}

#[test]
fn authenticated_retry_can_move_to_a_different_shared_server() {
    let certs = Certs::new();
    let stale = decryption_pem(&server_key(1));
    let decrypt_only = decryption_pem(&server_key(2));
    let published_key = server_key(3);
    let opaque = [0xfe, 0x0c, 0, 3, 0xde, 0xad, 0x00];
    let published_pem = EchPem::from_server_key(
        &published_key,
        &list(&[&opaque, published_key.ech_config()]),
        &NATIVE_PKCS8_CODEC,
    )
    .unwrap();
    let later_key = server_key(4);
    let later_pem = EchPem::from_config_list(&list(&[later_key.ech_config()])).unwrap();
    let published = list(&[&opaque, published_key.ech_config(), later_key.ech_config()]);
    let initial = Arc::new(
        EchServerConfig::from_pems(
            core::slice::from_ref(&decrypt_only),
            &[published_pem, later_pem],
            ALL_SUPPORTED_SUITES,
        )
        .unwrap(),
    );
    let offered = EchPem::from_config_list(&published).unwrap();
    let retry = Arc::new(
        EchServerConfig::from_pems(
            &[decryption_pem(&published_key)],
            core::slice::from_ref(&offered),
            ALL_SUPPORTED_SUITES,
        )
        .unwrap(),
    );
    assert_eq!(initial.ech_config_list(), published);
    let groups = [prov::kx_group::SECP256R1];
    for groups in [None, Some(groups.as_slice())] {
        let first_server = server_config(&certs, Some(&initial), groups);
        // A key left out of the retry list remains usable on direct offers.
        let (mut client, mut server) = connect(
            client_config(&certs, mode(&decrypt_only)),
            first_server.clone(),
        );
        assert_accepted(&mut client, &mut server);

        // Neither a stale key nor the published key decrypts here. In both
        // cases the client authenticates the public certificate to get the
        // exact retry list and can then connect to the second server.
        for pem in [&stale, &offered] {
            let (mut client, mut server) =
                connect(client_config(&certs, mode(pem)), first_server.clone());
            let Error::RejectedEch(rejected) = expect_rejected(&mut client, &mut server) else {
                panic!("expected authenticated ECH rejection");
            };
            assert_eq!(server.server_name(), Some(PUBLIC));
            assert_eq!(rejected.retry_configs(), Some(published.as_slice()));
            let retry_pem = EchPem::from_config_list(rejected.retry_configs().unwrap()).unwrap();
            let client_ech = EchConfig::from_pem(&retry_pem, ALL_SUPPORTED_SUITES).unwrap();
            assert_eq!(client_ech.config_id(), 3);
            let (mut client, mut server) = connect(
                client_config(&certs, Some(client_ech.into())),
                server_config(&certs, Some(&retry), groups),
            );
            assert_accepted(&mut client, &mut server);
        }
    }
}

#[test]
fn split_fallback_and_no_offer_hrr_with_separate_retry_list() {
    let certs = Certs::new();
    let decrypt_only = decryption_pem(&server_key(5));
    let published = decryption_pem(&server_key(6));
    let front = Arc::new(
        EchServerConfig::from_pems(
            core::slice::from_ref(&decrypt_only),
            core::slice::from_ref(&published),
            ALL_SUPPORTED_SUITES,
        )
        .unwrap(),
    );
    let groups = [prov::kx_group::SECP256R1];
    let backend = backend_config(&certs, Some(&groups));
    let fallback = Arc::new(server_config(&certs, Some(&front), Some(&groups)));

    let (mut client, mut server) = connect(client_config(&certs, None), backend.clone());
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.ech_status(), EchStatus::NotOffered);
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest),
    );

    let mut split = Split::new(
        &certs,
        client_config(&certs, mode(&decrypt_only)),
        &front,
        backend.clone(),
    );
    split.pump();
    split.assert_forwarded();
    assert_eq!(
        split.client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );

    let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap();
    for (mode, client_status, server_status) in [
        (None, EchStatus::NotOffered, EchStatus::NotOffered),
        (Some(grease.into()), EchStatus::Grease, EchStatus::Rejected),
    ] {
        let mut split = Split::new(&certs, client_config(&certs, mode), &front, backend.clone());
        split.local_config = fallback.clone();
        split.pump();
        assert!(split.errors.client.is_none(), "{:?}", split.errors);
        assert!(split.errors.server.is_none(), "{:?}", split.errors);
        assert!(split.backend.is_none());
        assert_eq!(split.client.ech_status(), client_status);
        assert_eq!(split.server().ech_status(), server_status);
        assert_eq!(
            split.client.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        split.exchange();
    }

    let mut split = Split::new(
        &certs,
        client_config(&certs, mode(&published)),
        &front,
        backend,
    );
    split.local_config = fallback;
    split.pump();
    assert!(split.backend.is_none());
    let Some(Error::RejectedEch(rejected)) = split.errors.client else {
        panic!("{:?}", split.errors);
    };
    assert_eq!(rejected.retry_configs(), Some(published.ech_config_list()));
}

/// A valid list of the given size with an opaque configuration.
fn opaque_retry(list_len: usize) -> EchPem {
    let mut entry = vec![0xab; list_len - 2];
    entry[..2].copy_from_slice(&0xfe0cu16.to_be_bytes());
    let body_len = u16::try_from(entry.len() - 4).unwrap();
    entry[2..4].copy_from_slice(&body_len.to_be_bytes());
    EchPem::from_config_list(&list(&[&entry])).unwrap()
}

#[test]
fn encrypted_extensions_respects_combined_wire_and_handshake_limits() {
    let certs = Certs::new();
    let stale = decryption_pem(&server_key(7));
    let local = decryption_pem(&server_key(8));
    let standalone_max = usize::from(u16::MAX) - 2 - 4;
    // Besides ECH, the rejected ClientHello gets an empty SNI acknowledgment
    // (four bytes including its header). ALPN is hidden in the inner hello.
    let with_sni_max = standalone_max - 4;
    for len in [with_sni_max, with_sni_max + 1, standalone_max] {
        let ech = Arc::new(
            EchServerConfig::from_pems(
                core::slice::from_ref(&local),
                &[opaque_retry(len)],
                ALL_SUPPORTED_SUITES,
            )
            .unwrap(),
        );
        let mut client = client_config(&certs, mode(&stale));
        client.record_size_limit = None;
        let (mut client, mut server) = connect(client, server_config(&certs, Some(&ech), None));
        transfer(&mut client, &mut server);
        let server_result = server.process_new_packets().map(|_| ());
        // Retain the entire flight even if the client queues a compatibility
        // CCS while reading fragmented EncryptedExtensions.
        let flight = drain(&mut server);
        let client_result = flight.chunks(1024).try_for_each(|mut chunk| {
            let len = chunk.len();
            assert_eq!(client.read_tls(&mut chunk).unwrap(), len);
            client.process_new_packets().map(|_| ())
        });
        if len == with_sni_max {
            assert_eq!(server_result, Ok(()));
            let Err(Error::RejectedEch(rejected)) = client_result else {
                panic!("expected authenticated ECH rejection, got {client_result:?}");
            };
            assert_eq!(rejected.retry_configs(), Some(ech.ech_config_list()));
            transfer(&mut client, &mut server);
            assert!(matches!(
                server.process_new_packets(),
                Err(Error::AlertReceived(
                    AlertDescription::EncryptedClientHelloRequired
                ))
            ));
        } else {
            assert_eq!(
                server_result,
                Err(Error::General("EncryptedExtensions too long".into()))
            );
            assert_eq!(
                client_result,
                Err(Error::AlertReceived(AlertDescription::InternalError))
            );
        }
    }

    let half_with_prefix = (standalone_max + 3) / 2;
    assert_eq!(
        EchServerConfig::from_pems(
            core::slice::from_ref(&local),
            &[
                opaque_retry(half_with_prefix),
                opaque_retry(half_with_prefix)
            ],
            ALL_SUPPORTED_SUITES,
        )
        .unwrap_err(),
        EchPemError::InvalidRetryList,
    );
    assert_eq!(
        EchServerConfig::from_pems(
            &[local],
            &[opaque_retry(standalone_max + 1)],
            ALL_SUPPORTED_SUITES
        )
        .unwrap_err(),
        EchPemError::InvalidRetryList,
    );
}

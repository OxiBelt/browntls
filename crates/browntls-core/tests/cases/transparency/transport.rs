// Public QUIC-TLS and DTLS handshake entry points use the same CT offer
// requirement as stream TLS. Both clients receive an identical certificate
// containing a valid precertificate SCT with no TLS CT response.

use std::time::Duration;

use browntls_core::{ProtocolVersion, dtls, quic};

fn transport_ct_client(
    fx: &Fixture,
    version: &'static SupportedProtocolVersion,
    offer: bool,
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Flipping {
            inner: verifier(&fx.pki, Some(fx.requirements(&[&fx.log_a]))),
            offer: offer.into(),
            forward_context: true,
        }))
        .with_no_client_auth()
}

fn transfer_quic_ct<From: browntls_core::SideData, To: browntls_core::SideData>(
    from: &mut quic::ConnectionCommon<From>,
    to: &mut quic::ConnectionCommon<To>,
) -> Result<(), Error> {
    loop {
        let mut bytes = Vec::new();
        let keys = from.write_hs(&mut bytes);
        if !bytes.is_empty() {
            to.read_hs(&bytes)?;
        }
        if keys.is_none() {
            return Ok(());
        }
    }
}

#[test]
fn quic_ct_requires_the_client_hello_offer() {
    let fx = Fixture::new();
    let chain = fx.pki.embedded(&[fx.pki.precert_sct(&fx.log_a)]);
    let v = &version::TLS13;
    let alpn = vec![b"ct-test".to_vec()];
    let mut server_config = server(&chain, None, None, v);
    Arc::get_mut(&mut server_config).unwrap().alpn_protocols = alpn.clone();

    for offer in [true, false] {
        let mut client_config = transport_ct_client(&fx, v, offer);
        client_config.alpn_protocols = alpn.clone();
        let mut client = quic::ClientConnection::new(
            Arc::new(client_config),
            quic::Version::V1,
            server_name(),
            Vec::new(),
        )
        .unwrap();
        let mut server =
            quic::ServerConnection::new(server_config.clone(), quic::Version::V1, Vec::new())
                .unwrap();

        transfer_quic_ct(&mut client, &mut server).unwrap();
        let authenticated = transfer_quic_ct(&mut server, &mut client);
        if offer {
            authenticated.unwrap();
            transfer_quic_ct(&mut client, &mut server).unwrap();
            assert!(!client.is_handshaking() && !server.is_handshaking());
            assert_eq!(client.alpn_protocol(), Some(&b"ct-test"[..]));
        } else {
            assert_eq!(
                authenticated,
                Err(Error::InvalidCertificate(
                    CertificateError::TransparencyOfferRequired
                ))
            );
            assert_eq!(client.alert(), Some(AlertDescription::CertificateUnknown));
            assert!(server.is_handshaking());
        }
    }
}

fn transfer_dtls_ct<From: browntls_core::SideData, To: browntls_core::SideData>(
    from: &mut dtls::ConnectionCommon<From>,
    to: &mut dtls::ConnectionCommon<To>,
    now: Duration,
) -> Result<(), Error> {
    let mut datagram = Vec::new();
    while from.write_datagram(&mut datagram, now).unwrap() {
        to.read_datagram(&mut datagram, now)?;
        datagram.clear();
    }
    Ok(())
}

#[test]
fn dtls_ct_requires_the_client_hello_offer_after_cookie_retry() {
    let fx = Fixture::new();
    let chain = fx.pki.embedded(&[fx.pki.precert_sct(&fx.log_a)]);
    for (v, versions, negotiated) in [
        (
            &version::TLS12,
            dtls::Versions::V1_2,
            ProtocolVersion::DTLSv1_2,
        ),
        (
            &version::TLS13,
            dtls::Versions::V1_3,
            ProtocolVersion::DTLSv1_3,
        ),
    ] {
        let mut server_config = server(&chain, None, None, v);
        Arc::get_mut(&mut server_config)
            .unwrap()
            .hello_retry_cookies = Some(prov::Ticketer::new().unwrap());

        for offer in [true, false] {
            let mut client = dtls::ClientConnection::new_with_versions(
                Arc::new(transport_ct_client(&fx, v, offer)),
                server_name(),
                versions,
            )
            .unwrap();
            let mut server = dtls::ServerConnection::new_with_versions(
                server_config.clone(),
                b"test client address",
                versions,
            )
            .unwrap();

            let now = Duration::from_secs(1);
            let mut result = None;
            for _ in 0..12 {
                transfer_dtls_ct(&mut client, &mut server, now).unwrap();
                if let Err(error) = transfer_dtls_ct(&mut server, &mut client, now) {
                    result = Some(Err(error));
                    break;
                }
                if !client.is_handshaking() && !server.is_handshaking() {
                    result = Some(Ok(()));
                    break;
                }
            }
            let result = result.expect("DTLS handshake stalled");
            if offer {
                result.unwrap();
                assert_eq!(client.protocol_version(), Some(negotiated));
            } else {
                assert_refused(
                    result,
                    transfer_dtls_ct(&mut client, &mut server, now),
                    CertificateError::TransparencyOfferRequired,
                );
            }
        }
    }
}

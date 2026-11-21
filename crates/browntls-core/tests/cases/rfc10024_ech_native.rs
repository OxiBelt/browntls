use std::sync::Arc;

use browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
use browntls_core::ech::{EchConfig, EchMode, EchServerConfig, EchServerKey, EchStatus};
use browntls_core::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, version};
use common::*;

#[test]
fn accepted_ech_handshakes_use_each_rfc10024_group() {
    let chain = server_chain(KeyType::EcdsaP256);
    for (config_id, group) in [
        (1, prov::kx_group::SECP256R1MLKEM768),
        (2, prov::kx_group::SECP384R1MLKEM1024),
        (3, prov::kx_group::X25519MLKEM768),
    ] {
        let ech = Arc::new(
            EchServerConfig::new(vec![
                EchServerKey::generate(config_id, "public.example", 32, ALL_SUPPORTED_SUITES)
                    .unwrap(),
            ])
            .unwrap(),
        );
        let ech_client = EchConfig::new(ech.ech_config_list(), ALL_SUPPORTED_SUITES).unwrap();

        let mut client_provider = prov::default_provider();
        client_provider.kx_groups = vec![group];
        let mut client_config = ClientConfig::builder_with_provider(Arc::new(client_provider))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        client_config.ech_mode = Some(EchMode::Enable(ech_client));

        let mut server_provider = prov::default_provider();
        server_provider.kx_groups = vec![group];
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        server_config.ech = Some(ech);

        let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.ech_status(), EchStatus::Accepted);
        assert_eq!(server.ech_status(), EchStatus::Accepted);
        assert_eq!(
            client.negotiated_key_exchange_group().unwrap().name(),
            group.name()
        );
        assert_eq!(
            server.negotiated_key_exchange_group().unwrap().name(),
            group.name()
        );
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"accepted ECH"),
            b"accepted ECH"
        );
    }
}

//! TLS 1.3 external PSKs, the PSK importer and certificate authentication
//! with an external PSK, between a browntls client and server.
//!
//! This target runs the cases in `cases/external_psk.rs` with the native
//! provider; `external_psk.rs` runs them with the RustCrypto provider. The
//! cross-provider cases at the end need both providers.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/external_psk.rs");

/// A native client with a RustCrypto server and the reverse, for direct
/// and imported PSKs of both hashes: the binders, the importer and the key
/// schedule agree across providers.
#[cfg(feature = "rustcrypto")]
#[test]
fn external_psks_across_providers() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let native = Arc::new(prov::default_provider());
    let rustcrypto = Arc::new(browntls_core::crypto::rustcrypto::default_provider());
    let keys: [fn() -> ExternalPsk; 4] = [
        || psk(b"direct-256", HashAlgorithm::SHA256),
        || psk(b"direct-384", HashAlgorithm::SHA384),
        || imported(b"imported-256", HashAlgorithm::SHA256, b"ctx"),
        || imported(b"imported-384", HashAlgorithm::SHA384, b""),
    ];
    for (client_provider, server_provider) in
        [(native.clone(), rustcrypto.clone()), (rustcrypto, native)]
    {
        for key in keys {
            let (mut client, mut server) = connect(
                client_with_provider(&chain, vec![key()], client_provider.clone()),
                psk_only_server_with_provider(vec![key()], server_provider.clone()),
            );
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(server.external_psk_identity(), Some(key().identity()));
            exchange_data(&mut client, &mut server);
        }
    }
}

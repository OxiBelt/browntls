//! TLS 1.3 delegated credentials (RFC 9345) between a browntls client and
//! server.
//!
//! This target runs the cases in `cases/delegated_credentials.rs` with the
//! native provider, plus the native provider's credential issuing helper;
//! `delegated_credentials.rs` runs the cases with the RustCrypto provider.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

include!("cases/delegated_credentials.rs");

/// `crypto::native::delegated_credential::generate` creates the key pair
/// and the credential; every key type it supports authenticates.
#[test]
fn native_issuing_helper() {
    use browntls::crypto::native::delegated_credential::generate;

    for &cert_type in KeyType::SIGNING {
        let chain = delegation_server_chain(cert_type);
        let cert_key = provider()
            .key_provider
            .load_private_key(chain.private_key())
            .unwrap();
        for dc_scheme in [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ] {
            let issued = generate(
                Side::Server,
                &chain.end_entity,
                &*cert_key,
                chain.key_type.schemes(),
                dc_scheme,
                valid_time_until(&chain.end_entity, shifted(6 * 24 * 3600)).unwrap(),
            )
            .unwrap();
            // The private key reloads to the same signing key.
            let reloaded = provider()
                .key_provider
                .load_private_key(issued.private_key.clone_key())
                .unwrap();
            assert_eq!(
                reloaded.public_key().unwrap().as_ref(),
                issued.credential.credential.public_key.as_ref()
            );
            let ck = certified_key(&chain)
                .with_delegated_credential(issued.credential.clone(), issued.signing_key)
                .unwrap();
            let (mut client, mut server) = connect(dc_client(&chain), server_with(ck));
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(
                client.delegated_credential(),
                Some(&issued.credential),
                "{cert_type:?} {dc_scheme:?}"
            );
        }
    }
    // RSA credential keys are not generated.
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let cert_key = provider()
        .key_provider
        .load_private_key(chain.private_key())
        .unwrap();
    assert!(
        generate(
            Side::Server,
            &chain.end_entity,
            &*cert_key,
            chain.key_type.schemes(),
            SignatureScheme::RSA_PSS_SHA256,
            3600,
        )
        .is_err()
    );
}

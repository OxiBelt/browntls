//! The RustCrypto ML-DSA opt-in in path validation and in a TLS 1.3
//! handshake: chains with ML-DSA CA certificates and an ECDSA end
//! entity are accepted with the opt-in table and refused as unsupported by
//! the default RustCrypto provider, and the advertised signature schemes
//! do not change.

use std::sync::Arc;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::ServerCertVerifier;
use browntls_core::crypto::{CryptoProvider, native, rustcrypto};
use browntls_core::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::version::TLS13;
use browntls_core::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, Error, ServerConfig,
    ServerConnection, SignatureScheme,
};

use crate::common::{SchemeRecordingServerVerifier, do_handshake, do_handshake_until_error};
use crate::ml_dsa::{Key, SETS, Set};
use crate::x509::flip;
use crate::{
    BAD_SIGNATURE, Chain, Impl, Issuer, MlKey, Purpose, UNSUPPORTED, build_chain, default_provider,
    opt_in_provider,
};

/// The native provider with its own ML-DSA opt-in table.
fn native_opt_in() -> Arc<CryptoProvider> {
    let mut provider = native::default_provider();
    provider.signature_verification_algorithms = native::SUPPORTED_SIG_ALGS_WITH_ML_DSA;
    Arc::new(provider)
}

#[test]
fn paths_verify_with_the_opt_in_only() {
    let ee = Key::p256();
    for set in SETS {
        let root = MlKey::new(set, "root");
        let int = MlKey::new(set, "intermediate");
        for by in [Impl::Native, Impl::Oracle] {
            let root = Issuer::MlDsa(&root, by);
            let ints = [(Issuer::MlDsa(&int, by), None)];
            let server = build_chain(root, &ints, &ee, Purpose::Server);
            let client = build_chain(root, &ints, &ee, Purpose::Client);
            let what = format!("{set:?} by {by:?}");
            assert_eq!(
                server.verify_server(opt_in_provider(), &[]),
                Ok(()),
                "{what}"
            );
            assert_eq!(client.verify_client(opt_in_provider()), Ok(()), "{what}");
            assert_eq!(
                server.verify_server(default_provider(), &[]),
                Err(UNSUPPORTED),
                "{what}"
            );
            assert_eq!(
                client.verify_client(default_provider()),
                Err(UNSUPPORTED),
                "{what}"
            );
            // The native opt-in agrees.
            assert_eq!(server.verify_server(native_opt_in(), &[]), Ok(()), "{what}");
        }
    }
}

#[test]
fn mixed_sets_and_tampered_signatures() {
    let ee = Key::p256();
    let k87 = MlKey::new(Set::MlDsa87, "root");
    let k65 = MlKey::new(Set::MlDsa65, "intermediate");
    let k44 = MlKey::new(Set::MlDsa44, "intermediate");
    let chain = build_chain(
        Issuer::MlDsa(&k87, Impl::Native),
        &[
            (Issuer::MlDsa(&k65, Impl::Oracle), None),
            (Issuer::MlDsa(&k44, Impl::Native), None),
        ],
        &ee,
        Purpose::Server,
    );
    assert_eq!(chain.verify_server(opt_in_provider(), &[]), Ok(()));
    // A flipped bit in each ML-DSA signature (the certificates end with
    // it): a bad signature for both providers' opt-in tables.
    for (i, int) in chain.intermediates.iter().enumerate() {
        let mut intermediates = chain.intermediates.clone();
        intermediates[i] = flip(int.clone(), int.len() - 1);
        let bad = Chain {
            root: chain.root.clone(),
            intermediates,
            ee: chain.ee.clone(),
        };
        for provider in [opt_in_provider(), native_opt_in()] {
            assert_eq!(bad.verify_server(provider, &[]), Err(BAD_SIGNATURE), "{i}");
        }
    }
    let bad = Chain {
        root: chain.root.clone(),
        intermediates: chain.intermediates.clone(),
        ee: flip(chain.ee.clone(), chain.ee.len() - 1),
    };
    for provider in [opt_in_provider(), native_opt_in()] {
        assert_eq!(bad.verify_server(provider, &[]), Err(BAD_SIGNATURE));
    }
}

#[test]
fn verifiers_advertise_the_same_schemes() {
    let ee = Key::p256();
    let root = MlKey::new(Set::MlDsa65, "root");
    let chain = build_chain(
        Issuer::MlDsa(&root, Impl::Native),
        &[],
        &ee,
        Purpose::Server,
    );
    let schemes = rustcrypto::SUPPORTED_SIG_ALGS.supported_schemes();
    let opt_in = WebPkiServerVerifier::builder_with_provider(chain.roots(), opt_in_provider())
        .build()
        .unwrap();
    let default = WebPkiServerVerifier::builder_with_provider(chain.roots(), default_provider())
        .build()
        .unwrap();
    assert_eq!(opt_in.supported_verify_schemes(), schemes);
    assert_eq!(default.supported_verify_schemes(), schemes);
    let client_opt_in =
        WebPkiClientVerifier::builder_with_provider(chain.roots(), opt_in_provider())
            .build()
            .unwrap();
    let client_default =
        WebPkiClientVerifier::builder_with_provider(chain.roots(), default_provider())
            .build()
            .unwrap();
    assert_eq!(
        client_opt_in.supported_verify_schemes(),
        client_default.supported_verify_schemes()
    );
    for scheme in [
        SignatureScheme::ML_DSA_44,
        SignatureScheme::ML_DSA_65,
        SignatureScheme::ML_DSA_87,
    ] {
        assert!(!schemes.contains(&scheme), "{scheme:?}");
    }
}

fn served(chain: &Chain) -> Vec<CertificateDer<'static>> {
    std::iter::once(&chain.ee)
        .chain(&chain.intermediates)
        .map(|der| der.clone().into())
        .collect()
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    let name = ServerName::try_from("example.com").unwrap();
    (
        ClientConnection::new(Arc::new(client), name).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

#[test]
fn tls13_handshake_with_an_ml_dsa_ca_chain() {
    let ee_key = Key::p256();
    let root = MlKey::new(Set::MlDsa87, "root");
    let int = MlKey::new(Set::MlDsa44, "intermediate");
    let chain = build_chain(
        Issuer::MlDsa(&root, Impl::Oracle),
        &[(Issuer::MlDsa(&int, Impl::Native), None)],
        &ee_key,
        Purpose::Server,
    );
    let Key::P256(pair) = &ee_key else {
        unreachable!()
    };
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der()));
    let server = || {
        ServerConfig::builder_with_provider(default_provider())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(served(&chain), private_key.clone_key())
            .unwrap()
    };

    // The opt-in client accepts the chain; `CertificateVerify` is signed
    // with the end entity's ECDSA key.
    let inner = WebPkiServerVerifier::builder_with_provider(chain.roots(), opt_in_provider())
        .build()
        .unwrap();
    let schemes = rustcrypto::SUPPORTED_SIG_ALGS.supported_schemes();
    let recorder = SchemeRecordingServerVerifier::new(inner, &schemes);
    let client = ClientConfig::builder_with_provider(opt_in_provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    let (mut client, mut server_conn) = connect(client, server());
    do_handshake(&mut client, &mut server_conn).unwrap();
    assert_eq!(recorder.seen(), [SignatureScheme::ECDSA_NISTP256_SHA256]);
    assert_eq!(client.peer_certificates().unwrap().len(), 2);

    // The same through `with_root_certificates`, which builds the verifier
    // from the provider's table.
    let client = ClientConfig::builder_with_provider(opt_in_provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(chain.roots())
        .with_no_client_auth();
    let (mut client, mut server_conn) = connect(client, server());
    do_handshake(&mut client, &mut server_conn).unwrap();

    // The default RustCrypto client refuses the chain.
    let client = ClientConfig::builder_with_provider(default_provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(chain.roots())
        .with_no_client_auth();
    let (mut client, mut server_conn) = connect(client, server());
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server_conn);
    assert_eq!(
        client_res,
        Err(Error::InvalidCertificate(
            CertificateError::UnsupportedSignatureAlgorithm
        ))
    );
    assert_eq!(
        server_res,
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

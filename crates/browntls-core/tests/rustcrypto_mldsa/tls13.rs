//! TLS 1.3 handshakes authenticated with ML-DSA keys
//! (`draft-ietf-tls-mldsa-06`) between the two providers, through the
//! high-level API: a native server with a RustCrypto client and the
//! reverse, for each parameter set; mutual authentication; and a RustCrypto
//! client without the opt-in, which an ML-DSA-only server cannot serve.

use std::sync::Arc;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::crypto::{CryptoProvider, native, rustcrypto};
use browntls_core::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::version::TLS13;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, PeerIncompatible, ServerConfig,
    ServerConnection,
};
use browntls_crypto::mldsa::PrivateKeyFormat;

use crate::common::{SchemeRecordingServerVerifier, do_handshake, do_handshake_until_error};
use crate::ml_dsa::{Key, SETS, Set};
use crate::signing::{pkcs8, scheme};
use crate::{Chain, Impl, Issuer, MlKey, Purpose, build_chain};

#[derive(Clone, Copy, Debug)]
enum Provider {
    Native,
    RustCrypto,
}

/// `which` with both ML-DSA opt-ins (verification and key loading).
fn opt_in(which: Provider) -> Arc<CryptoProvider> {
    let provider = match which {
        Provider::Native => {
            let mut p = native::default_provider();
            p.signature_verification_algorithms = native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13;
            p.key_provider = native::KEY_PROVIDER_WITH_ML_DSA;
            p
        }
        Provider::RustCrypto => {
            let mut p = rustcrypto::default_provider();
            p.signature_verification_algorithms = rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13;
            p.key_provider = rustcrypto::KEY_PROVIDER_WITH_ML_DSA;
            p
        }
    };
    Arc::new(provider)
}

/// An ML-DSA end entity of `set` under an ML-DSA root of the same set, and
/// its private key (RFC 9881 PKCS #8 in `format`).
fn certified(
    set: Set,
    purpose: Purpose,
    format: PrivateKeyFormat,
) -> (Chain, PrivateKeyDer<'static>) {
    let root = MlKey::new(set, "tls13 root");
    let label = format!("tls13 end entity {purpose:?}");
    let seed = crate::signing::seed(set, &label);
    let ee = match set {
        Set::MlDsa44 => Key::MlDsa44(Box::new(::ml_dsa::SigningKey::from_seed(&seed.into()))),
        Set::MlDsa65 => Key::MlDsa65(Box::new(::ml_dsa::SigningKey::from_seed(&seed.into()))),
        Set::MlDsa87 => Key::MlDsa87(Box::new(::ml_dsa::SigningKey::from_seed(&seed.into()))),
    };
    let chain = build_chain(Issuer::MlDsa(&root, Impl::Native), &[], &ee, purpose);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8(set, &seed, format)));
    (chain, key)
}

fn served(chain: &Chain) -> Vec<CertificateDer<'static>> {
    vec![CertificateDer::from(chain.ee.clone())]
}

fn server_config(
    provider: Arc<CryptoProvider>,
    chain: &Chain,
    key: PrivateKeyDer<'static>,
) -> ServerConfig {
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(served(chain), key)
        .unwrap()
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    let name = ServerName::try_from("example.com").unwrap();
    (
        ClientConnection::new(Arc::new(client), name).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

#[test]
fn server_authentication_across_providers() {
    let formats = [
        PrivateKeyFormat::Seed,
        PrivateKeyFormat::Both,
        PrivateKeyFormat::Seed,
    ];
    for (set, format) in SETS.into_iter().zip(formats) {
        let (chain, key) = certified(set, Purpose::Server, format);
        for (server, client) in [
            (Provider::Native, Provider::RustCrypto),
            (Provider::RustCrypto, Provider::Native),
        ] {
            let what = format!("{set:?} {format:?}: {server:?} server, {client:?} client");
            let offer = match client {
                Provider::Native => native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13,
                Provider::RustCrypto => rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13,
            }
            .supported_schemes();
            let inner = WebPkiServerVerifier::builder_with_provider(chain.roots(), opt_in(client))
                .build()
                .unwrap();
            let recorder = SchemeRecordingServerVerifier::new(inner, &offer);
            let client_config = ClientConfig::builder_with_provider(opt_in(client))
                .with_protocol_versions(&[&TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(recorder.clone())
                .with_no_client_auth();
            let server_cfg = server_config(opt_in(server), &chain, key.clone_key());
            let (mut client_conn, mut server_conn) = connect(client_config, server_cfg);
            do_handshake(&mut client_conn, &mut server_conn)
                .unwrap_or_else(|e| panic!("{what}: {e:?}"));
            assert_eq!(recorder.seen(), [scheme(set)], "{what}");

            // And with the verifier the provider's table builds.
            let client_config = ClientConfig::builder_with_provider(opt_in(client))
                .with_protocol_versions(&[&TLS13])
                .unwrap()
                .with_root_certificates(chain.roots())
                .with_no_client_auth();
            let server_cfg = server_config(opt_in(server), &chain, key.clone_key());
            let (mut client_conn, mut server_conn) = connect(client_config, server_cfg);
            do_handshake(&mut client_conn, &mut server_conn)
                .unwrap_or_else(|e| panic!("{what}: {e:?}"));
        }
    }
}

#[test]
fn mutual_authentication_across_providers() {
    let (server_chain, server_key) =
        certified(Set::MlDsa65, Purpose::Server, PrivateKeyFormat::Seed);
    let (client_chain, client_key) =
        certified(Set::MlDsa87, Purpose::Client, PrivateKeyFormat::Both);
    for (server, client) in [
        (Provider::Native, Provider::RustCrypto),
        (Provider::RustCrypto, Provider::Native),
    ] {
        let verifier =
            WebPkiClientVerifier::builder_with_provider(client_chain.roots(), opt_in(server))
                .build()
                .unwrap();
        let server_cfg = ServerConfig::builder_with_provider(opt_in(server))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(served(&server_chain), server_key.clone_key())
            .unwrap();
        let client_config = ClientConfig::builder_with_provider(opt_in(client))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(server_chain.roots())
            .with_client_auth_cert(served(&client_chain), client_key.clone_key())
            .unwrap();
        let (mut client_conn, mut server_conn) = connect(client_config, server_cfg);
        do_handshake(&mut client_conn, &mut server_conn)
            .unwrap_or_else(|e| panic!("{server:?}: {e:?}"));
        let presented = server_conn.peer_certificates().unwrap();
        assert_eq!(presented[0].as_ref(), client_chain.ee.as_slice());
    }
}

#[test]
fn a_client_without_the_opt_in_fails_against_an_ml_dsa_only_server() {
    let (chain, key) = certified(Set::MlDsa44, Purpose::Server, PrivateKeyFormat::Seed);
    // The default provider, and the X.509-only opt-in: neither offers an
    // ML-DSA scheme, so the server has no signature scheme in common.
    let mut x509_only = rustcrypto::default_provider();
    x509_only.signature_verification_algorithms = rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA;
    for client in [
        Arc::new(rustcrypto::default_provider()),
        Arc::new(x509_only),
    ] {
        for server in [Provider::Native, Provider::RustCrypto] {
            let client_config = ClientConfig::builder_with_provider(client.clone())
                .with_protocol_versions(&[&TLS13])
                .unwrap()
                .with_root_certificates(chain.roots())
                .with_no_client_auth();
            let server_cfg = server_config(opt_in(server), &chain, key.clone_key());
            let (mut client_conn, mut server_conn) = connect(client_config, server_cfg);
            let (client_res, server_res) =
                do_handshake_until_error(&mut client_conn, &mut server_conn);
            assert_eq!(
                server_res,
                Err(Error::PeerIncompatible(
                    PeerIncompatible::NoSignatureSchemesInCommon
                )),
                "{server:?}"
            );
            assert_eq!(
                client_res,
                Err(Error::AlertReceived(AlertDescription::HandshakeFailure)),
                "{server:?}"
            );
        }
    }
}

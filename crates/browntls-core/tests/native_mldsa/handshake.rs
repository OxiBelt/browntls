//! What the X.509-only ML-DSA opt-in (`native::SUPPORTED_SIG_ALGS_WITH_ML_DSA`)
//! means in a TLS 1.3 handshake: a chain with ML-DSA CA certificates and an
//! ECDSA end entity is accepted, the `CertificateVerify` signature stays
//! classical, and an ML-DSA end entity cannot authenticate the handshake,
//! because this table neither offers nor accepts the TLS ML-DSA schemes.
//! TLS 1.3 authentication with ML-DSA keys is the separate opt-in
//! `native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13` (with
//! `native::KEY_PROVIDER_WITH_ML_DSA`), tested in `mldsa_tls13_native.rs`.

use std::sync::Arc;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::ServerCertVerifier;
use browntls_core::crypto::native;
use browntls_core::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::sign::{CertifiedKey, Signer, SigningKey};
use browntls_core::version::TLS13;
use browntls_core::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, Error, PeerIncompatible,
    PeerMisbehaved, ServerConfig, ServerConnection, SignatureAlgorithm, SignatureScheme,
};

use crate::common::{SchemeRecordingServerVerifier, do_handshake, do_handshake_until_error};
use crate::ml_dsa::{Key, Set};
use crate::{Chain, Impl, Issuer, MlKey, Purpose, build_chain, default_provider, opt_in_provider};

fn server_name() -> ServerName<'static> {
    ServerName::try_from("example.com").unwrap()
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

/// A TLS 1.3 client that verifies with `verifier`.
fn client_with(verifier: Arc<dyn ServerCertVerifier>) -> ClientConfig {
    ClientConfig::builder_with_provider(opt_in_provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// The library's verifier for `chain`'s root with the opt-in table.
fn opt_in_verifier(chain: &Chain) -> Arc<WebPkiServerVerifier> {
    WebPkiServerVerifier::builder_with_provider(chain.roots(), opt_in_provider())
        .build()
        .unwrap()
}

fn served(chain: &Chain) -> Vec<browntls_core::pki_types::CertificateDer<'static>> {
    std::iter::once(&chain.ee)
        .chain(&chain.intermediates)
        .map(|der| der.clone().into())
        .collect()
}

#[test]
fn ml_dsa_ca_chain_with_an_ecdsa_end_entity() {
    let ee_key = Key::p256();
    let root = MlKey::new(Set::MlDsa65, "root");
    let int = MlKey::new(Set::MlDsa44, "intermediate");
    let chain = build_chain(
        Issuer::MlDsa(&root, Impl::Native),
        &[(Issuer::MlDsa(&int, Impl::Oracle), None)],
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

    // The opt-in client: the verifier advertises what the default one
    // does, and accepts the chain.
    let inner = opt_in_verifier(&chain);
    let default_schemes = native::SUPPORTED_SIG_ALGS.supported_schemes();
    assert_eq!(inner.supported_verify_schemes(), default_schemes);
    let recorder = SchemeRecordingServerVerifier::new(inner.clone(), &default_schemes);
    let (mut client, mut server_conn) = connect(client_with(recorder.clone()), server());
    do_handshake(&mut client, &mut server_conn).unwrap();
    // `CertificateVerify` was signed with the end entity's ECDSA key.
    assert_eq!(recorder.seen(), [SignatureScheme::ECDSA_NISTP256_SHA256]);
    assert_eq!(client.peer_certificates().unwrap().len(), 2);

    // The default client refuses the chain: its table has no ML-DSA.
    let default_client = ClientConfig::builder_with_provider(default_provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(chain.roots())
        .with_no_client_auth();
    let (mut client, mut server_conn) = connect(default_client, server());
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server_conn);
    assert_eq!(
        client_res,
        Err(Error::InvalidCertificate(
            CertificateError::UnsupportedSignatureAlgorithm
        ))
    );
    // A signature inside the chain: bad_certificate (RFC 9846 §6.2).
    assert_eq!(
        server_res,
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

#[test]
fn rfc9881_key_usage_violation_in_a_handshake() {
    let ee_key = Key::p256();
    let root = MlKey::new(Set::MlDsa65, "root");
    let int = MlKey::new(Set::MlDsa65, "intermediate");
    let chain = build_chain(
        Issuer::MlDsa(&root, Impl::Native),
        &[(
            Issuer::MlDsa(&int, Impl::Native),
            Some(&[
                crate::x509::ku::KEY_CERT_SIGN,
                crate::x509::ku::KEY_AGREEMENT,
            ]),
        )],
        &ee_key,
        Purpose::Server,
    );
    let Key::P256(pair) = &ee_key else {
        unreachable!()
    };
    let server = ServerConfig::builder_with_provider(default_provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            served(&chain),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der())),
        )
        .unwrap();
    let (mut client, mut server_conn) = connect(client_with(opt_in_verifier(&chain)), server);
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server_conn);
    assert_eq!(
        crate::other_pki_error(client_res),
        browntls_pki::Error::KeyUsageNotPermittedForPublicKey
    );
    // `CertificateError::Other`: certificate_unknown.
    assert_eq!(
        server_res,
        Err(Error::AlertReceived(AlertDescription::CertificateUnknown))
    );
}

/// An ML-DSA-65 handshake signing key with the TLS code point of
/// `draft-ietf-tls-mldsa`, made here rather than loaded, so that the test
/// does not depend on the TLS 1.3 opt-in key loader.
#[derive(Debug)]
struct MlDsaHandshakeKey(Arc<MlKey>);

#[derive(Debug)]
struct MlDsaSigner(Arc<MlKey>);

impl SigningKey for MlDsaHandshakeKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ML_DSA_65)
            .then(|| Box::new(MlDsaSigner(self.0.clone())) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Unknown(0x05)
    }
}

impl Signer for MlDsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.sign_hedged(message))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ML_DSA_65
    }
}

/// With the X.509-only table, an ML-DSA end entity cannot sign
/// `CertificateVerify`: the client does not offer the ML-DSA schemes, and
/// a client that names one anyway has no algorithm to verify it with. (The
/// TLS 1.3 opt-in table offers and verifies them.)
#[test]
fn an_ml_dsa_end_entity_cannot_sign_certificate_verify() {
    let root = MlKey::new(Set::MlDsa65, "root");
    let ee = Arc::new(MlKey::new(Set::MlDsa65, "end entity"));
    let chain = build_chain(
        Issuer::MlDsa(&root, Impl::Native),
        &[],
        &ee.oracle,
        Purpose::Server,
    );
    let server = || {
        ServerConfig::builder_with_provider(default_provider())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_certified_key(CertifiedKey::new(
                served(&chain),
                Arc::new(MlDsaHandshakeKey(ee.clone())),
            ))
    };
    // The path itself validates with the opt-in table.
    assert_eq!(chain.verify_server(opt_in_provider(), &[]), Ok(()));

    // A client with the X.509-only table advertises no ML-DSA scheme, so
    // the server finds no scheme its key can sign with.
    let (mut client, mut server_conn) = connect(client_with(opt_in_verifier(&chain)), server());
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server_conn);
    assert_eq!(
        server_res,
        Err(Error::PeerIncompatible(
            PeerIncompatible::NoSignatureSchemesInCommon
        ))
    );
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );

    // Even if the client's offer named ML-DSA-65, the verifier's scheme
    // mapping has no algorithm for it: the certificate is accepted and the
    // `CertificateVerify` signature refused as unadvertised.
    let mut offer = native::SUPPORTED_SIG_ALGS.supported_schemes();
    offer.push(SignatureScheme::ML_DSA_65);
    let recorder = SchemeRecordingServerVerifier::new(opt_in_verifier(&chain), &offer);
    let (mut client, mut server_conn) = connect(client_with(recorder.clone()), server());
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server_conn);
    assert_eq!(
        client_res,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme
        ))
    );
    assert_eq!(recorder.seen(), [SignatureScheme::ML_DSA_65]);
}

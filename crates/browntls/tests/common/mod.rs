//! Shared helpers: a run-time generated certificate chain and configurations
//! built from it. Every browntls item is named through the `browntls` crate,
//! as an application that depends on nothing else names it.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::sync::Arc;

use browntls::crypto::CryptoProvider;
use browntls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls::{ClientConfig, RootCertStore, ServerConfig};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

/// The native provider, named explicitly: a build with both the `native` and
/// the `rustcrypto` feature has no process default to fall back on.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(browntls::crypto::native::default_provider())
}

/// A CA and a `localhost` server certificate it issued (ECDSA P-256).
pub struct Pki {
    ca: CertificateDer<'static>,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: Vec<u8>,
}

impl Pki {
    pub fn new() -> Self {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "browntls facade test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let ee_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ee_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        ee_params.is_ca = IsCa::NoCa;
        ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        ee_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        let ee_cert = ee_params.signed_by(&ee_key, &issuer).unwrap();

        let ca = CertificateDer::from(ca_cert.der().to_vec());
        Self {
            server_chain: vec![CertificateDer::from(ee_cert.der().to_vec()), ca.clone()],
            ca,
            server_key: ee_key.serialize_der(),
        }
    }

    /// A server configuration for every protocol version that is built.
    pub fn server_config(&self) -> ServerConfig {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key.clone()));
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(self.server_chain.clone(), key)
            .unwrap()
    }

    /// A client configuration that trusts the CA.
    pub fn client_config(&self) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }
}

pub fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

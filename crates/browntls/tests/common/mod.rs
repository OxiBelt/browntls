//! Shared helpers: run-time generated server and client certificate chains
//! and configurations built from them. Every browntls item is named through
//! the `browntls` crate, as an application that depends on nothing else
//! names it.
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
use browntls::server::WebPkiClientVerifier;
use browntls::{ClientConfig, RootCertStore, ServerConfig};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

/// The native provider, named explicitly: a build with both the `native` and
/// the `rustcrypto` feature has no process default to fall back on.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(browntls::crypto::native::default_provider())
}

/// One explicit provider policy for each RFC 10024 group it must implement.
pub fn hybrid_providers() -> Vec<(browntls::NamedGroup, CryptoProvider)> {
    use browntls::NamedGroup;
    use browntls::crypto::SupportedKxGroup;

    let mut cases = Vec::new();
    let mut add = |provider: CryptoProvider, groups: &[&'static dyn SupportedKxGroup]| {
        for name in [
            NamedGroup::X25519MLKEM768,
            NamedGroup::secp256r1MLKEM768,
            NamedGroup::secp384r1MLKEM1024,
        ] {
            let mut provider = provider.clone();
            provider.kx_groups = vec![*groups.iter().find(|group| group.name() == name).unwrap()];
            cases.push((name, provider));
        }
    };
    #[cfg(feature = "native")]
    add(
        browntls::crypto::native::default_provider(),
        browntls::crypto::native::ALL_KX_GROUPS,
    );
    #[cfg(feature = "rustcrypto")]
    add(
        browntls::crypto::rustcrypto::default_provider(),
        browntls::crypto::rustcrypto::ALL_KX_GROUPS,
    );
    cases
}

/// A CA, a `localhost` server certificate and a `client.example` client
/// certificate it issued (ECDSA P-256).
pub struct Pki {
    ca: CertificateDer<'static>,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: Vec<u8>,
    /// A client certificate the CA issued, then the CA.
    pub client_chain: Vec<CertificateDer<'static>>,
    client_key: Vec<u8>,
}

impl Pki {
    pub fn new() -> Self {
        Self::build(false)
    }

    /// Like [`Self::new`], with the `DelegationUsage` extension (RFC 9345
    /// §4.2) on the client certificate, so that it can sign delegated
    /// credentials.
    pub fn with_delegation() -> Self {
        Self::build(true)
    }

    fn build(delegation: bool) -> Self {
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

        let client_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut client_params = CertificateParams::new(vec!["client.example".to_string()]).unwrap();
        client_params.is_ca = IsCa::NoCa;
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params
            .distinguished_name
            .push(DnType::CommonName, "client.example");
        if delegation {
            // DelegationUsage: OID 1.3.6.1.4.1.44363.44, `NULL` value.
            client_params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 44363, 44],
                    vec![0x05, 0x00],
                ));
        }
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

        let ca = CertificateDer::from(ca_cert.der().to_vec());
        Self {
            server_chain: vec![CertificateDer::from(ee_cert.der().to_vec()), ca.clone()],
            client_chain: vec![CertificateDer::from(client_cert.der().to_vec()), ca.clone()],
            ca,
            server_key: ee_key.serialize_der(),
            client_key: client_key.serialize_der(),
        }
    }

    /// The client certificate's private key.
    pub fn client_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.client_key.clone()))
    }

    /// The trusted CA.
    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        roots
    }

    /// A server configuration for every protocol version that is built.
    pub fn server_config(&self) -> ServerConfig {
        self.server_config_with_provider(provider())
    }

    pub fn server_config_with_provider(&self, provider: Arc<CryptoProvider>) -> ServerConfig {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key.clone()));
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(self.server_chain.clone(), key)
            .unwrap()
    }

    /// The CA certificate.
    pub fn ca(&self) -> &CertificateDer<'static> {
        &self.ca
    }

    /// The server chain and its key, loaded with the provider.
    pub fn certified_key(&self) -> Arc<browntls::sign::CertifiedKey> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key.clone()));
        Arc::new(
            browntls::sign::CertifiedKey::from_der(self.server_chain.clone(), key, &provider())
                .unwrap(),
        )
    }

    /// Like [`Self::server_config`], verifying client certificates the CA
    /// issued.
    pub fn server_config_with_client_auth(&self) -> ServerConfig {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key.clone()));
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(self.roots()), provider())
                .build()
                .unwrap();
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.server_chain.clone(), key)
            .unwrap()
    }

    /// A client configuration that trusts the CA.
    pub fn client_config(&self) -> ClientConfig {
        self.client_config_with_provider(provider())
    }

    pub fn client_config_with_provider(&self, provider: Arc<CryptoProvider>) -> ClientConfig {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(self.roots())
            .with_no_client_auth()
    }

    /// Like [`Self::client_config`], presenting the client certificate.
    pub fn client_config_with_cert(&self) -> ClientConfig {
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(self.roots())
            .with_client_auth_cert(self.client_chain.clone(), self.client_key())
            .unwrap()
    }
}

pub fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

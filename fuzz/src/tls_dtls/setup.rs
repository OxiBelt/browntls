//! Certificates, providers, configurations and the deferring revocation
//! verifier of the `tls_dtls` target.

use std::sync::{Arc, OnceLock};

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use browntls_core::crypto::{CryptoProvider, SupportedKxGroup};
use browntls_core::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use browntls_core::revocation::{
    PeerEvidence, RevocationCheck, RevocationResponse, RevocationStatus,
};
use browntls_core::server::ProducesTickets;
use browntls_core::{
    CertificateError, CipherSuite, ClientConfig, DigitallySignedStruct, Error, RootCertStore,
    ServerConfig, SignatureScheme, SupportedCipherSuite, SupportedProtocolVersion, version,
};

use crate::input::Input;

/// The server certificate's key types (rcgen with ring generates no RSA
/// keys).
pub(crate) const KEY_TYPES: usize = 3;

/// A CA and a `localhost` certificate of one key type.
struct Pki {
    roots: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

fn generate(alg: &'static rcgen::SignatureAlgorithm) -> Pki {
    let ca_key = rcgen::KeyPair::generate_for(alg).expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let key = rcgen::KeyPair::generate_for(alg).expect("key");
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&key, &issuer).expect("certificate");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_cert.der().to_vec()))
        .expect("root");
    Pki {
        roots: Arc::new(roots),
        chain: vec![CertificateDer::from(cert.der().to_vec())],
        key: key.serialize_der(),
    }
}

/// The certificates of every key type, made once per process.
fn pki(key_type: usize) -> &'static Pki {
    static PKI: OnceLock<[Pki; KEY_TYPES]> = OnceLock::new();
    &PKI.get_or_init(|| {
        [
            generate(&rcgen::PKCS_ECDSA_P256_SHA256),
            generate(&rcgen::PKCS_ECDSA_P384_SHA384),
            generate(&rcgen::PKCS_ED25519),
        ]
    })[key_type % KEY_TYPES]
}

/// One of the two providers, built once per process.
pub(crate) fn provider(rustcrypto: bool) -> &'static CryptoProvider {
    static PROVIDERS: OnceLock<[CryptoProvider; 2]> = OnceLock::new();
    &PROVIDERS.get_or_init(|| {
        [
            browntls_core::crypto::native::default_provider(),
            browntls_core::crypto::rustcrypto::default_provider(),
        ]
    })[usize::from(rustcrypto)]
}

/// The HelloRetryRequest cookie sealer and the ticketer: two keys, made
/// once per process.
fn sealers() -> &'static (Arc<dyn ProducesTickets>, Arc<dyn ProducesTickets>) {
    static SEALERS: OnceLock<(Arc<dyn ProducesTickets>, Arc<dyn ProducesTickets>)> =
        OnceLock::new();
    SEALERS.get_or_init(|| {
        (
            browntls_core::crypto::rustcrypto::Ticketer::new().expect("cookie sealer"),
            browntls_core::crypto::rustcrypto::Ticketer::new().expect("ticketer"),
        )
    })
}

/// Whether DTLS 1.3 can use `suite`: every TLS 1.3 suite but CCM_8
/// (RFC 9147 §4.5.3).
fn dtls_suite(suite: &SupportedCipherSuite) -> bool {
    *suite.version() == version::TLS13 && suite.suite() != CipherSuite::TLS13_AES_128_CCM_8_SHA256
}

/// The protocol versions a configuration allows.
const VERSIONS: [&[&SupportedProtocolVersion]; 3] = [
    &[&version::TLS13],
    &[&version::TLS13, &version::TLS12],
    &[&version::TLS12],
];

/// One side's configuration choices.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Side {
    pub(crate) rustcrypto: bool,
    /// Which TLS 1.3 suites to keep, one bit each (TLS 1.2 suites stay).
    pub(crate) suites: u8,
    /// An index into [`VERSIONS`].
    pub(crate) versions: usize,
}

impl Side {
    pub(crate) fn read(input: &mut Input) -> Self {
        let byte = input.byte();
        Self {
            rustcrypto: byte & 1 != 0,
            versions: match byte >> 1 & 0x0f {
                0 => 2,
                1..=3 => 1,
                _ => 0,
            },
            suites: input.byte(),
        }
    }

    /// The provider with the chosen suites; whether DTLS 1.3 can use it.
    fn provider(&self) -> (CryptoProvider, bool) {
        let mut provider = provider(self.rustcrypto).clone();
        let mut tls13 = 0;
        provider.cipher_suites.retain(|suite| {
            if *suite.version() != version::TLS13 {
                return true;
            }
            tls13 += 1;
            self.suites & (1 << ((tls13 - 1) % 8)) != 0
        });
        let usable = VERSIONS[self.versions].contains(&&version::TLS13)
            && provider.cipher_suites.iter().any(dtls_suite);
        (provider, usable)
    }
}

/// The configurations of one session and what the harness expects of them.
pub(crate) struct Configs {
    pub(crate) client: Option<Arc<ClientConfig>>,
    pub(crate) server: Option<Arc<ServerConfig>>,
    /// Whether `dtls::ClientConnection::new` must succeed.
    pub(crate) client_usable: bool,
    /// Whether the server configuration suits DTLS 1.3 (cookies aside).
    pub(crate) server_usable: bool,
    /// Whether the server configuration has a cookie sealer.
    pub(crate) cookies: bool,
    /// Whether a handshake between the two can succeed.
    pub(crate) compatible: bool,
}

/// The configuration choices of a session.
pub(crate) struct Choice {
    pub(crate) client: Side,
    pub(crate) server: Side,
    pub(crate) key_type: usize,
    /// The one group the server keeps, if any.
    pub(crate) server_group: Option<usize>,
    pub(crate) cookies: bool,
    pub(crate) defer: bool,
}

pub(crate) fn configs(choice: &Choice) -> Configs {
    let pki = pki(choice.key_type);
    let (client_provider, client_usable) = choice.client.provider();
    let (mut server_provider, server_usable) = choice.server.provider();
    if let Some(group) = choice.server_group {
        let groups: Vec<&'static dyn SupportedKxGroup> = server_provider.kx_groups.clone();
        server_provider.kx_groups = vec![groups[group % groups.len()]];
    }
    let shared_suite = client_provider.cipher_suites.iter().any(|c| {
        dtls_suite(c)
            && server_provider
                .cipher_suites
                .iter()
                .any(|s| s.suite() == c.suite())
    });
    let shared_group = server_provider.kx_groups.iter().any(|s| {
        client_provider
            .kx_groups
            .iter()
            .any(|c| c.name() == s.name())
    });
    let compatible = client_usable && server_usable && shared_suite && shared_group;

    let client_provider = Arc::new(client_provider);
    let client = ClientConfig::builder_with_provider(client_provider.clone())
        .with_protocol_versions(VERSIONS[choice.client.versions])
        .ok()
        .map(|builder| {
            let config = if choice.defer {
                let verifier =
                    WebPkiServerVerifier::builder_with_provider(pki.roots.clone(), client_provider)
                        .build()
                        .expect("verifier");
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(Defer(verifier)))
                    .with_no_client_auth()
            } else {
                builder
                    .with_root_certificates(pki.roots.clone())
                    .with_no_client_auth()
            };
            Arc::new(config)
        });
    let server = ServerConfig::builder_with_provider(Arc::new(server_provider))
        .with_protocol_versions(VERSIONS[choice.server.versions])
        .ok()
        .and_then(|builder| {
            builder
                .with_no_client_auth()
                .with_single_cert(
                    pki.chain.clone(),
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.clone())),
                )
                .ok()
        })
        .map(|mut config| {
            let (cookies, ticketer) = sealers();
            if choice.cookies {
                config.hello_retry_cookies = Some(cookies.clone());
            }
            config.ticketer = ticketer.clone();
            Arc::new(config)
        });
    Configs {
        compatible: compatible && client.is_some() && server.is_some(),
        client,
        server,
        client_usable,
        server_usable,
        cookies: choice.cookies,
    }
}

pub(crate) fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("name")
}

/// A verifier that verifies, then asks for an OCSP response the harness
/// supplies: `[1]` is good, `[2]` asks once more (and anything then
/// passes as indeterminate), everything else fails.
#[derive(Debug)]
struct Defer(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for Defer {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        staple: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.0.verify_server_cert(end, chain, name, staple, now)
    }

    fn verify_server_cert_with_evidence(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        _evidence: PeerEvidence<'_>,
        now: UnixTime,
    ) -> Result<RevocationCheck, Error> {
        self.verify_server_cert(end, chain, name, &[], now)?;
        Ok(RevocationCheck::pending(
            [0; 32],
            vec![],
            vec![0x30, 0],
            |response| match response {
                RevocationResponse::Der(bytes) if bytes == [1] => {
                    Ok(RevocationCheck::Complete(Some(RevocationStatus::Good)))
                }
                RevocationResponse::Der(bytes) if bytes == [2] => Ok(RevocationCheck::pending(
                    [1; 32],
                    vec![],
                    vec![0x30, 0],
                    |_| {
                        Ok(RevocationCheck::Complete(Some(
                            RevocationStatus::Indeterminate,
                        )))
                    },
                )),
                _ => Err(CertificateError::UnknownRevocationStatus.into()),
            },
        ))
    }

    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls12_signature(msg, cert, sig)
    }

    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls13_signature(msg, cert, sig)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

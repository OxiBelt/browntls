//! Shared helpers for the integration tests: run-time generated certificate
//! chains, a pinned-certificate verifier (path validation in `browntls-pki`
//! is not implemented yet) and in-memory transport plumbing.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::io;
use std::sync::{Arc, OnceLock};

use browntls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use browntls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, rustcrypto};
use browntls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use browntls::server::danger::{ClientCertVerified, ClientCertVerifier};
use browntls::{
    CertificateError, ClientConfig, ClientConnection, ConnectionCommon, DigitallySignedStruct,
    DistinguishedName, Error, ServerConfig, ServerConnection, SideData, SignatureScheme,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256,
    SignatureAlgorithm,
};

/// The key algorithm of a generated chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
}

impl KeyType {
    pub const ALL: [KeyType; 4] = [
        KeyType::Ed25519,
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::Rsa2048,
    ];

    /// Key types the RustCrypto provider can *sign* with (RSA is verify-only).
    pub const SIGNING: [KeyType; 3] = [KeyType::Ed25519, KeyType::EcdsaP256, KeyType::EcdsaP384];

    fn algorithm(self) -> &'static SignatureAlgorithm {
        match self {
            KeyType::Ed25519 => &PKCS_ED25519,
            KeyType::EcdsaP256 => &PKCS_ECDSA_P256_SHA256,
            KeyType::EcdsaP384 => &PKCS_ECDSA_P384_SHA384,
            KeyType::Rsa2048 => &PKCS_RSA_SHA256,
        }
    }

    fn generate_key(self) -> KeyPair {
        match self {
            KeyType::Rsa2048 => {
                use rsa::pkcs8::EncodePrivateKey;
                static RSA_KEY: OnceLock<Vec<u8>> = OnceLock::new();
                let der = RSA_KEY.get_or_init(|| {
                    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
                    key.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec()
                });
                KeyPair::from_pkcs8_der_and_sign_algo(
                    &rustls_pki_types::PrivatePkcs8KeyDer::from(der.clone()),
                    &PKCS_RSA_SHA256,
                )
                .expect("rsa key pair")
            }
            other => KeyPair::generate_for(other.algorithm()).expect("keygen"),
        }
    }

    /// The TLS signature schemes this key type signs with.
    pub fn schemes(self) -> &'static [SignatureScheme] {
        match self {
            KeyType::Ed25519 => &[SignatureScheme::ED25519],
            KeyType::EcdsaP256 => &[SignatureScheme::ECDSA_NISTP256_SHA256],
            KeyType::EcdsaP384 => &[SignatureScheme::ECDSA_NISTP384_SHA384],
            KeyType::Rsa2048 => &[
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
            ],
        }
    }
}

/// A CA and an end-entity certificate issued by it.
#[derive(Clone, Debug)]
pub struct Chain {
    pub key_type: KeyType,
    pub ca: CertificateDer<'static>,
    pub end_entity: CertificateDer<'static>,
    pub end_entity_key: Vec<u8>,
    pub end_entity_spki: Vec<u8>,
}

impl Chain {
    /// The chain as a server or client presents it: end entity then CA.
    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.end_entity.clone(), self.ca.clone()]
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.end_entity_key.clone()))
    }

    pub fn spki(&self) -> SubjectPublicKeyInfoDer<'static> {
        SubjectPublicKeyInfoDer::from(self.end_entity_spki.clone())
    }
}

fn to_der(cert: &rcgen::Certificate) -> CertificateDer<'static> {
    CertificateDer::from(cert.der().to_vec())
}

/// Generates a fresh CA and an end-entity certificate for `names` (DNS SANs).
pub fn gen_chain(key_type: KeyType, names: &[&str], purpose: ExtendedKeyUsagePurpose) -> Chain {
    let ca_key = key_type.generate_key();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.distinguished_name.push(
        DnType::CommonName,
        format!("browntls test CA ({key_type:?})"),
    );
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let issuer = Issuer::new(ca_params, ca_key);

    let ee_key = key_type.generate_key();
    let mut ee_params =
        CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .expect("ee params");
    ee_params.is_ca = IsCa::NoCa;
    ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    ee_params.extended_key_usages = vec![purpose];
    ee_params.distinguished_name.push(
        DnType::CommonName,
        names.first().copied().unwrap_or("browntls test"),
    );
    let ee_cert = ee_params.signed_by(&ee_key, &issuer).expect("ee cert");

    Chain {
        key_type,
        ca: to_der(ca_cert_ref(&ca_cert)),
        end_entity: to_der(&ee_cert),
        end_entity_key: ee_key.serialize_der(),
        end_entity_spki: rcgen::PublicKeyData::subject_public_key_info(&ee_key),
    }
}

fn ca_cert_ref(c: &rcgen::Certificate) -> &rcgen::Certificate {
    c
}

/// A server chain for `localhost`.
pub fn server_chain(key_type: KeyType) -> Chain {
    gen_chain(
        key_type,
        &["localhost", "testserver.example"],
        ExtendedKeyUsagePurpose::ServerAuth,
    )
}

/// A client chain.
pub fn client_chain(key_type: KeyType) -> Chain {
    gen_chain(
        key_type,
        &["client.example"],
        ExtendedKeyUsagePurpose::ClientAuth,
    )
}

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustcrypto::default_provider())
}

pub fn server_name() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

/// Accepts exactly one pinned end-entity certificate and verifies handshake
/// signatures with the provider's algorithms against its public key.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    pub expected: CertificateDer<'static>,
    pub spki: SubjectPublicKeyInfoDer<'static>,
    pub algs: WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    pub fn new(chain: &Chain) -> Arc<Self> {
        Arc::new(Self {
            expected: chain.end_entity.clone(),
            spki: chain.spki(),
            algs: rustcrypto::SUPPORTED_SIG_ALGS,
        })
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity.as_ref() == self.expected.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(CertificateError::UnknownIssuer.into())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        browntls::crypto::verify_tls12_signature_with_raw_key(message, &self.spki, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        browntls::crypto::verify_tls13_signature_with_raw_key(message, &self.spki, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Accepts exactly one pinned client certificate.
#[derive(Debug)]
pub struct PinnedClientVerifier {
    pub expected: CertificateDer<'static>,
    pub spki: SubjectPublicKeyInfoDer<'static>,
    pub algs: WebPkiSupportedAlgorithms,
    pub mandatory: bool,
    pub hints: Vec<DistinguishedName>,
}

impl PinnedClientVerifier {
    pub fn new(chain: &Chain, mandatory: bool) -> Arc<Self> {
        Arc::new(Self {
            expected: chain.end_entity.clone(),
            spki: chain.spki(),
            algs: rustcrypto::SUPPORTED_SIG_ALGS,
            mandatory,
            hints: Vec::new(),
        })
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if end_entity.as_ref() == self.expected.as_ref() {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(CertificateError::UnknownIssuer.into())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        browntls::crypto::verify_tls12_signature_with_raw_key(message, &self.spki, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        browntls::crypto::verify_tls13_signature_with_raw_key(message, &self.spki, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A client configuration trusting `chain`'s end entity, all versions and suites.
pub fn client_config(chain: &Chain) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

/// A server configuration serving `chain`, no client auth.
pub fn server_config(chain: &Chain) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

/// Moves all queued TLS bytes from `from` into `to`; returns how many.
///
/// When `to`'s receive buffer fills up, its records are processed so the
/// transfer can continue; plaintext that piles up is left for the caller.
pub fn transfer<A: SideData, B: SideData>(
    from: &mut ConnectionCommon<A>,
    to: &mut ConnectionCommon<B>,
) -> usize {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    let mut total = 0;
    let mut offset = 0;
    while offset < buf.len() {
        match to.read_tls(&mut &buf[offset..]) {
            Ok(n) => {
                offset += n;
                total += n;
            }
            Err(e) if e.kind() == io::ErrorKind::Other => {
                to.process_new_packets().unwrap();
                if !to.wants_read() {
                    // plaintext is waiting; the caller must drain it
                    break;
                }
            }
            Err(e) => panic!("read_tls failed: {e}"),
        }
    }
    total
}

/// Drives both sides until neither is handshaking; fails on either side's error.
pub fn do_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), Error> {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
        transfer(client, server);
        server.process_new_packets()?;
        transfer(server, client);
        client.process_new_packets()?;
    }
    assert!(
        !client.is_handshaking() && !server.is_handshaking(),
        "handshake did not complete"
    );
    Ok(())
}

/// Runs the handshake expecting an error on one side; returns `(client, server)` results.
pub fn do_handshake_until_error(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> (Result<(), Error>, Result<(), Error>) {
    let mut client_res = Ok(());
    let mut server_res = Ok(());
    for _ in 0..16 {
        if (!client.is_handshaking() && !server.is_handshaking())
            || client_res.is_err()
            || server_res.is_err()
        {
            break;
        }
        transfer(client, server);
        if let Err(e) = server.process_new_packets() {
            server_res = Err(e);
            transfer(server, client);
            client_res = client.process_new_packets().map(|_| ());
            break;
        }
        transfer(server, client);
        if let Err(e) = client.process_new_packets() {
            client_res = Err(e);
            transfer(client, server);
            server_res = server.process_new_packets().map(|_| ());
            break;
        }
    }
    (client_res, server_res)
}

/// Sends `data` from `from` to `to` and returns what `to` received.
pub fn send_and_receive<A: SideData, B: SideData>(
    from: &mut ConnectionCommon<A>,
    to: &mut ConnectionCommon<B>,
    data: &[u8],
) -> Vec<u8> {
    use std::io::Write;
    let mut out = Vec::new();
    let mut written = 0;
    while written < data.len() || from.wants_write() {
        written += from.writer().write(&data[written..]).unwrap();
        let mut tls = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut tls).unwrap();
        }
        let mut offset = 0;
        while offset < tls.len() {
            match to.read_tls(&mut &tls[offset..]) {
                Ok(n) => offset += n,
                Err(e) if e.kind() == io::ErrorKind::Other => {}
                Err(e) => panic!("read_tls failed: {e}"),
            }
            to.process_new_packets().unwrap();
            drain(to, &mut out);
        }
    }
    out
}

fn drain<B: SideData>(conn: &mut ConnectionCommon<B>, out: &mut Vec<u8>) {
    use std::io::Read;
    match conn.reader().read_to_end(out) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => panic!("read failed: {e}"),
    }
}

/// Initialises `env_logger` once so `RUST_LOG=trace` shows protocol traces.
pub fn init_logging() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = env_logger::Builder::from_default_env()
            .is_test(true)
            .try_init();
    });
}

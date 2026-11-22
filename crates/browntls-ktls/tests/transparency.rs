//! CT certificate verification while completing TLS for kernel handoff.

#![cfg(all(target_os = "linux", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::{
    CertificateIdentity, HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    ServerCertificateVerification,
};
use browntls_core::pki_types::{Cert, CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use browntls_core::revocation::{PeerEvidence, RevocationDigests};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::transparency::{CtV2LogConfig, CtV2Requirements};
use browntls_core::{
    CertificateError, CipherSuite, ClientConfig, ClientConnection, DigitallySignedStruct, Error,
    RootCertStore, ServerConfig, ServerConnection, SignatureScheme, StreamOwned, version,
};
use browntls_ktls::{HandoffError, KtlsStream};
use common::{kernel_tls, localhost, provider, tcp_pair};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData as _, SigningKey as _,
};

/// A wrapper using the legacy verifier methods even when it offers CT.
#[derive(Debug)]
struct LegacyVerifier(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for LegacyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_server_cert_with_identity(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        identity: CertificateIdentity<'_>,
        evidence: PeerEvidence<'_>,
        now: UnixTime,
        allow_live: bool,
    ) -> Result<ServerCertificateVerification, Error> {
        self.0.verify_server_cert_with_identity(
            end_entity,
            intermediates,
            identity,
            evidence,
            now,
            allow_live,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn requests_transparency_info(&self) -> bool {
        self.0.requests_transparency_info()
    }
}

/// Generate a certificate and a signed RFC 9162 X.509 SCT for that exact leaf.
fn ct_peer() -> (Arc<WebPkiServerVerifier>, Arc<ServerConfig>) {
    let mut provider = provider();
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256);
    let provider = Arc::new(provider);

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&leaf_key, &issuer).unwrap();
    let ca = CertificateDer::from(ca.der().to_vec());
    let leaf = CertificateDer::from(leaf.der().to_vec());

    #[cfg(feature = "native")]
    let digests = RevocationDigests::native();
    #[cfg(not(feature = "native"))]
    let digests = RevocationDigests::rustcrypto();
    let log = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let id = [0x2b, 0x65, 0x50, 1];
    let ca_cert = Cert::try_from(&ca).unwrap();
    let issuer_hash = (digests.sha256)(ca_cert.subject_public_key_info().as_ref());
    let leaf_cert = Cert::try_from(&leaf).unwrap();
    let tbs = leaf_cert.signed_data().message();
    let timestamp = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3600)
        * 1000;
    let mut entry = vec![1, 0];
    entry.extend(timestamp.to_be_bytes());
    entry.push(32);
    entry.extend(issuer_hash);
    entry.extend(&u32::try_from(tbs.len()).unwrap().to_be_bytes()[1..]);
    entry.extend(tbs);
    entry.extend([0, 0]);
    let signature = log.sign(&entry).unwrap();
    let mut sct = vec![1, 2, 4];
    sct.extend(id);
    sct.extend(timestamp.to_be_bytes());
    sct.extend([0, 0]);
    sct.extend(u16::try_from(signature.len()).unwrap().to_be_bytes());
    sct.extend(signature);
    let mut list = Vec::new();
    list.extend(u16::try_from(sct.len() + 2).unwrap().to_be_bytes());
    list.extend(u16::try_from(sct.len()).unwrap().to_be_bytes());
    list.extend(sct);

    let requirements = CtV2Requirements::new(
        digests,
        vec![CtV2LogConfig::new(
            id.to_vec(),
            log.subject_public_key_info(),
        )],
    );
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .with_certificate_transparency(requirements)
        .build()
        .unwrap();
    let mut certified = CertifiedKey::from_der(
        vec![leaf],
        PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        &provider,
    )
    .unwrap();
    certified.set_transparency_info(Some(list)).unwrap();
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    (verifier, Arc::new(server))
}

#[test]
fn ct_authentication_gates_blocking_kernel_handoff() {
    if !kernel_tls() {
        return;
    }

    let (verifier, server_config) = ct_peer();
    for forward_context in [true, false] {
        let verifier: Arc<dyn ServerCertVerifier> = if forward_context {
            verifier.clone()
        } else {
            Arc::new(LegacyVerifier(verifier.clone()))
        };
        let mut client_config = ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        client_config.enable_secret_extraction = true;
        let client = ClientConnection::new(Arc::new(client_config), localhost()).unwrap();
        let server = ServerConnection::new(server_config.clone()).unwrap();
        let (client_tcp, server_tcp) = tcp_pair();
        for tcp in [&client_tcp, &server_tcp] {
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        }

        thread::scope(|scope| {
            let peer = scope.spawn(move || {
                let mut server = StreamOwned::new(server, server_tcp);
                let mut received = [0; 2];
                server.read_exact(&mut received)?;
                server.write_all(&received)?;
                server.flush()
            });
            let handoff = KtlsStream::new(client, client_tcp);
            if forward_context {
                let mut stream = handoff.unwrap();
                stream.write_all(b"CT").unwrap();
                stream.flush().unwrap();
                let mut reply = [0; 2];
                stream.read_exact(&mut reply).unwrap();
                assert_eq!(&reply, b"CT");
                peer.join().unwrap().unwrap();
            } else {
                let Err(HandoffError::Refused {
                    conn,
                    socket,
                    received,
                    error,
                }) = handoff
                else {
                    panic!("expected certificate verification to refuse kTLS handoff");
                };
                assert!(received.is_empty());
                assert_eq!(conn.peer_transparency_status(), None);
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<Error>()),
                    Some(&Error::InvalidCertificate(
                        CertificateError::TransparencyOfferRequired
                    ))
                );
                drop(socket);
                assert!(peer.join().unwrap().is_err());
            }
        });
    }
}

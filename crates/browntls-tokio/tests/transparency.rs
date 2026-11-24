//! Certificate Transparency 2.0 (RFC 9162 §6.5) through the streams: a
//! server whose certificate carries a `TransItemList` in `transparency_info`
//! and a client whose WebPKI verifier requires an SCT, over
//! `TlsConnector`/`TlsAcceptor`, `LazyConfigAcceptor` and
//! `browntls_tokio::unbuffered`; and a failed policy, which surfaces as an
//! I/O error carrying the certificate error.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::{
    CertificateIdentity, HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    ServerCertificateVerification,
};
use browntls_core::pki_types::{Cert, CertificateDer, ServerName, UnixTime};
use browntls_core::revocation::{PeerEvidence, RevocationDigests};
use browntls_core::server::Acceptor;
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::transparency::{CtV2LogConfig, CtV2Requirements, TransparencyStatus};
use browntls_core::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme,
    SupportedProtocolVersion,
};
use browntls_tokio::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};
use common::*;
use rcgen::{KeyPair, PublicKeyData as _, SigningKey as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

fn digests() -> RevocationDigests {
    #[cfg(feature = "native")]
    return RevocationDigests::native();
    #[cfg(not(feature = "native"))]
    return RevocationDigests::rustcrypto();
}

fn vec8(out: &mut Vec<u8>, data: &[u8]) {
    out.push(u8::try_from(data.len()).unwrap());
    out.extend_from_slice(data);
}

fn vec16(out: &mut Vec<u8>, data: &[u8]) {
    out.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
}

/// A CT 2.0 log (ECDSA P-256, ID 1.3.101.80.1) and its key.
struct Log {
    id: Vec<u8>,
    key: KeyPair,
}

impl Log {
    fn new() -> Self {
        Self {
            id: vec![0x2b, 0x65, 0x50, 1],
            key: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
        }
    }

    fn requirements(&self) -> CtV2Requirements {
        let log = CtV2LogConfig::new(self.id.clone(), self.key.subject_public_key_info());
        CtV2Requirements::new(digests(), vec![log])
    }

    /// A `TransItemList` (RFC 9162 §6.3) of one `x509_sct_v2` (§4.8) of
    /// this log for the server certificate of `pki`.
    fn list(&self, pki: &Pki) -> Vec<u8> {
        let ts_ms = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600)
            * 1000;
        let leaf = Cert::try_from(&pki.server_chain[0]).unwrap();
        let ca = Cert::try_from(&pki.ca).unwrap();
        let tbs = leaf.signed_data().message();
        // The `x509_entry_v2` the SCT signs (§4.7).
        let mut entry = vec![1, 0];
        entry.extend(ts_ms.to_be_bytes());
        vec8(
            &mut entry,
            &(digests().sha256)(ca.subject_public_key_info().as_ref()),
        );
        entry.extend(&u32::try_from(tbs.len()).unwrap().to_be_bytes()[1..]);
        entry.extend_from_slice(tbs);
        vec16(&mut entry, &[]);

        let mut sct = vec![1, 2];
        vec8(&mut sct, &self.id);
        sct.extend(ts_ms.to_be_bytes());
        vec16(&mut sct, &[]);
        vec16(&mut sct, &self.key.sign(&entry).unwrap());

        let mut items = Vec::new();
        vec16(&mut items, &sct);
        let mut list = Vec::new();
        vec16(&mut list, &items);
        list
    }
}

fn ct_verifier(pki: &Pki, log: &Log) -> Arc<WebPkiServerVerifier> {
    WebPkiServerVerifier::builder_with_provider(Arc::new(pki.roots()), provider())
        .with_certificate_transparency(log.requirements())
        .build()
        .unwrap()
}

fn ct_client(pki: &Pki, log: &Log, version: &'static SupportedProtocolVersion) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_webpki_verifier(ct_verifier(pki, log))
        .with_no_client_auth()
}

fn ct_server(
    pki: &Pki,
    list: Option<Vec<u8>>,
    version: &'static SupportedProtocolVersion,
) -> ServerConfig {
    let mut key =
        CertifiedKey::from_der(pki.server_chain.clone(), pki.server_key(), &provider()).unwrap();
    key.set_transparency_info(list).unwrap();
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(key)))
}

#[tokio::test]
async fn policy_met_through_connector_and_acceptor() {
    let pki = Pki::new();
    let log = Log::new();
    let list = log.list(&pki);
    for version in versions() {
        let connector = TlsConnector::from(Arc::new(ct_client(&pki, &log, version)));
        let acceptor = TlsAcceptor::from(Arc::new(ct_server(&pki, Some(list.clone()), version)));
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(connector.connect(localhost(), c), acceptor.accept(s));
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        let conn = client.get_ref().1;
        assert_eq!(conn.peer_transparency_info(), Some(&list[..]));
        assert_eq!(
            conn.peer_transparency_status(),
            Some(TransparencyStatus::new(1, 1, 0))
        );
        client.write_all(b"ct").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 2];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ct");
    }
}

#[tokio::test]
async fn policy_met_through_the_lazy_acceptor() {
    let pki = Pki::new();
    let log = Log::new();
    let list = log.list(&pki);
    for version in versions() {
        let connector = TlsConnector::from(Arc::new(ct_client(&pki, &log, version)));
        let config = Arc::new(ct_server(&pki, Some(list.clone()), version));
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(connector.connect(localhost(), c), async {
            let start = LazyConfigAcceptor::new(Acceptor::default(), s).await?;
            start.into_stream(config).await
        });
        server.unwrap();
        assert_eq!(
            client.unwrap().get_ref().1.peer_transparency_status(),
            Some(TransparencyStatus::new(1, 1, 0))
        );
    }
}

#[tokio::test]
async fn policy_met_through_the_unbuffered_streams() {
    use browntls_tokio::unbuffered;

    let pki = Pki::new();
    let log = Log::new();
    let list = log.list(&pki);
    for version in versions() {
        let connector = unbuffered::TlsConnector::from(Arc::new(ct_client(&pki, &log, version)));
        let acceptor =
            unbuffered::TlsAcceptor::from(Arc::new(ct_server(&pki, Some(list.clone()), version)));
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(connector.connect(localhost(), c), acceptor.accept(s));
        server.unwrap();
        let client = client.unwrap();
        assert_eq!(client.get_ref().1.peer_transparency_info(), Some(&list[..]));
        assert_eq!(
            client.get_ref().1.peer_transparency_status(),
            Some(TransparencyStatus::new(1, 1, 0))
        );
    }
}

#[tokio::test]
async fn failed_policy_is_an_io_error() {
    let pki = Pki::new();
    let log = Log::new();
    let expected = Error::InvalidCertificate(CertificateError::InsufficientTransparency {
        counted_scts: 0,
        distinct_logs: 0,
    });
    for version in versions() {
        let connector = TlsConnector::from(Arc::new(ct_client(&pki, &log, version)));
        let acceptor = TlsAcceptor::from(Arc::new(ct_server(&pki, None, version)));
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(connector.connect(localhost(), c), acceptor.accept(s));
        let err = client.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(tls_error(&err), Some(&expected));
        assert!(server.is_err());

        let connector = browntls_tokio::unbuffered::TlsConnector::from(Arc::new(ct_client(
            &pki, &log, version,
        )));
        let acceptor =
            browntls_tokio::unbuffered::TlsAcceptor::from(Arc::new(ct_server(&pki, None, version)));
        let (c, s) = duplex(64 * 1024);
        let (client, _server) = tokio::join!(connector.connect(localhost(), c), acceptor.accept(s));
        let err = client.unwrap_err();
        assert_eq!(tls_error(&err), Some(&expected));
    }
}

/// A wrapper that requests CT, but uses the legacy verification entry point.
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

#[tokio::test]
async fn unknown_offer_context_is_an_io_error_on_each_stream_path() {
    use browntls_tokio::unbuffered;

    let pki = Pki::new();
    let log = Log::new();
    let list = log.list(&pki);
    let expected = Error::InvalidCertificate(CertificateError::TransparencyOfferRequired);
    for version in versions() {
        let verifier = Arc::new(LegacyVerifier(ct_verifier(&pki, &log)));
        let client_config = Arc::new(
            ClientConfig::builder_with_provider(provider())
                .with_protocol_versions(&[version])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
        );
        let server_config = Arc::new(ct_server(&pki, Some(list.clone()), version));
        let connector = TlsConnector::from(client_config.clone());
        let acceptor = TlsAcceptor::from(server_config.clone());
        let (c, s) = duplex(64 * 1024);
        let (buffered, _) = tokio::join!(connector.connect(localhost(), c), acceptor.accept(s));

        let (c, s) = duplex(64 * 1024);
        let (lazy, _) = tokio::join!(connector.connect(localhost(), c), async {
            let start = LazyConfigAcceptor::new(Acceptor::default(), s).await?;
            start.into_stream(server_config.clone()).await
        });

        let connector = unbuffered::TlsConnector::from(client_config);
        let acceptor = unbuffered::TlsAcceptor::from(server_config);
        let (c, s) = duplex(64 * 1024);
        let (unbuffered, _) = tokio::join!(connector.connect(localhost(), c), acceptor.accept(s));

        for err in [
            buffered.unwrap_err(),
            lazy.unwrap_err(),
            unbuffered.unwrap_err(),
        ] {
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(tls_error(&err), Some(&expected));
        }
    }
}

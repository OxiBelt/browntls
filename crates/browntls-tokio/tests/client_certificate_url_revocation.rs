//! A TLS 1.2 acceptor with both a client certificate URL fetcher (RFC 6066
//! §5) and an OCSP fetcher: the chain is fetched by URL first, then its
//! revocation status is looked up, each through its own fetcher. The
//! fetches are simulated; nothing here opens a connection to a URL.

#![cfg(all(
    any(feature = "native", feature = "rustcrypto"),
    feature = "tls12",
    feature = "ocsp"
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use browntls_core::certificate_url::{
    CertificateUrl, ClientCertificateUrlPolicy, ClientCertificateUrlQuery, UrlAndHash,
};
use browntls_core::client::danger::HandshakeSignatureValid;
use browntls_core::pki_types::{CertificateDer, UnixTime};
use browntls_core::revocation::{
    PeerEvidence, RevocationCheck, RevocationQuery, RevocationResponse, RevocationStatus,
};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::server::danger::{ClientCertVerified, ClientCertVerifier};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig,
    SignatureScheme, version,
};
use browntls_tokio::revocation::{FetchLimits, RevocationFetcher};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::duplex;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);
const EE_URL: &str = "http://certs.example/client.der";
const GOOD: &[u8] = b"good";

#[cfg(feature = "native")]
const SHA1: fn(&[u8]) -> [u8; 20] = browntls_core::crypto::native::sha1;
#[cfg(not(feature = "native"))]
const SHA1: fn(&[u8]) -> [u8; 20] = browntls_core::crypto::rustcrypto::sha1;

/// Verifies the client's chain, then asks for one status lookup and takes
/// `GOOD` only.
#[derive(Debug)]
struct AsksForStatus(Arc<dyn ClientCertVerifier>);

impl ClientCertVerifier for AsksForStatus {
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.0.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_client_cert_with_evidence(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _evidence: PeerEvidence<'_>,
        now: UnixTime,
    ) -> Result<RevocationCheck, Error> {
        self.0.verify_client_cert(end_entity, intermediates, now)?;
        Ok(RevocationCheck::pending(
            [7; 32],
            vec!["http://ocsp.invalid/".into()],
            vec![0x30, 0x01, 0x07],
            |response| match response {
                RevocationResponse::Der(der) if der == GOOD => {
                    Ok(RevocationCheck::Complete(Some(RevocationStatus::Good)))
                }
                _ => Err(CertificateError::Revoked.into()),
            },
        ))
    }

    fn revocation_enabled(&self) -> bool {
        true
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
}

#[tokio::test]
async fn the_acceptor_fetches_the_chain_then_its_status() {
    let pki = Pki::new();
    let key = provider()
        .key_provider
        .load_private_key(pki.client_key())
        .unwrap();
    let mut key = CertifiedKey::new(Vec::new(), key);
    let entry = UrlAndHash::for_object(EE_URL, &pki.client_chain[0], SHA1).unwrap();
    key.set_certificate_url(Some(CertificateUrl::individual_certs(vec![entry]).unwrap()));
    let mut client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_root_certificates(pki.roots())
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
    client.enable_client_certificate_url = true;
    let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(pki.roots()), provider())
        .build()
        .unwrap();
    let mut server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_client_cert_verifier(Arc::new(AsksForStatus(inner)))
        .with_single_cert(pki.server_chain.clone(), pki.server_key())
        .unwrap();
    server.client_certificate_url = Some(ClientCertificateUrlPolicy::new(SHA1));

    // Each fetcher records the order it ran in.
    let order = Arc::new(AtomicUsize::new(0));
    let (url_at, ocsp_at) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let url_fetcher = {
        let (order, at, object) = (order.clone(), url_at.clone(), pki.client_chain[0].to_vec());
        Arc::new(move |query: ClientCertificateUrlQuery| {
            at.store(order.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            assert_eq!(query.entries()[0].url(), EE_URL);
            let object = object.clone();
            async move { Ok(vec![object]) }
        })
    };
    let ocsp_fetcher = {
        let (order, at) = (order.clone(), ocsp_at.clone());
        Arc::new(RevocationFetcher::new(
            move |_: RevocationQuery, _: FetchLimits| {
                at.store(order.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                async { Ok(GOOD.to_vec()) }
            },
        ))
    };
    let acceptor = TlsAcceptor::from(Arc::new(server))
        .client_certificate_url_fetcher(url_fetcher)
        .revocation_fetcher(ocsp_fetcher);

    let (client_io, server_io) = duplex(1 << 16);
    let accepted = tokio::spawn(async move {
        let tls = acceptor.accept(server_io).await.unwrap();
        let conn = tls.get_ref().1;
        (
            conn.peer_certificates().map(<[_]>::to_vec),
            conn.peer_revocation_status(),
        )
    });
    let tls = timeout(
        LIMIT,
        TlsConnector::from(Arc::new(client)).connect(localhost(), client_io),
    )
    .await
    .unwrap()
    .unwrap();
    let (chain, status) = timeout(LIMIT, accepted).await.unwrap().unwrap();
    drop(tls);
    assert_eq!(chain.as_deref(), Some(&pki.client_chain[..1]));
    assert_eq!(status, Some(RevocationStatus::Good));
    assert_eq!(
        (
            url_at.load(Ordering::SeqCst),
            ocsp_at.load(Ordering::SeqCst)
        ),
        (1, 2)
    );
}

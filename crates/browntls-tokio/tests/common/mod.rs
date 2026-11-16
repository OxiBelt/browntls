//! Shared helpers: run-time generated certificates, configurations for
//! either provider, and transports that misbehave on purpose.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use browntls::crypto::CryptoProvider;
use browntls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// The provider under test: the native one when built, else RustCrypto.
pub fn provider() -> Arc<CryptoProvider> {
    #[cfg(feature = "native")]
    let provider = browntls::crypto::native::default_provider();
    #[cfg(not(feature = "native"))]
    let provider = browntls::crypto::rustcrypto::default_provider();
    Arc::new(provider)
}

/// The protocol versions to run each case under.
pub fn versions() -> Vec<&'static SupportedProtocolVersion> {
    vec![
        &browntls::version::TLS13,
        #[cfg(feature = "tls12")]
        &browntls::version::TLS12,
    ]
}

/// A CA and a `localhost` server certificate it issued (ECDSA P-256).
pub struct Pki {
    pub ca: CertificateDer<'static>,
    pub ca_pem: String,
    pub server_chain: Vec<CertificateDer<'static>>,
    pub server_key: Vec<u8>,
}

impl Pki {
    pub fn new() -> Self {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "browntls-tokio test CA");
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
            ca_pem: ca_cert.pem(),
            server_chain: vec![CertificateDer::from(ee_cert.der().to_vec()), ca.clone()],
            ca,
            server_key: ee_key.serialize_der(),
        }
    }

    pub fn server_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key.clone()))
    }

    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        roots
    }

    pub fn server_config(&self, version: &'static SupportedProtocolVersion) -> ServerConfig {
        ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(self.server_chain.clone(), self.server_key())
            .unwrap()
    }

    pub fn client_config(&self, version: &'static SupportedProtocolVersion) -> ClientConfig {
        ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(self.roots())
            .with_no_client_auth()
    }

    pub fn acceptor(&self, version: &'static SupportedProtocolVersion) -> TlsAcceptor {
        TlsAcceptor::from(Arc::new(self.server_config(version)))
    }

    pub fn connector(&self, version: &'static SupportedProtocolVersion) -> TlsConnector {
        TlsConnector::from(Arc::new(self.client_config(version)))
    }
}

pub fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

/// The `browntls::Error` inside an `io::Error`, if any.
pub fn tls_error(err: &io::Error) -> Option<&browntls::Error> {
    err.get_ref()?.downcast_ref()
}

/// A transport that hands at most `chunk` bytes per call and answers every
/// other call with `Pending` (waking at once), to drive every partial-I/O
/// path in the stream.
pub struct Choppy {
    inner: DuplexStream,
    chunk: usize,
    read_tick: bool,
    write_tick: bool,
}

impl Choppy {
    pub fn new(inner: DuplexStream, chunk: usize) -> Self {
        Self {
            inner,
            chunk,
            read_tick: false,
            write_tick: false,
        }
    }
}

impl AsyncRead for Choppy {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_tick = !self.read_tick;
        if self.read_tick {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let take = buf.remaining().min(self.chunk);
        let mut small = ReadBuf::new(buf.initialize_unfilled_to(take));
        let result = Pin::new(&mut self.inner).poll_read(cx, &mut small);
        let n = small.filled().len();
        buf.advance(n);
        result
    }
}

impl AsyncWrite for Choppy {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_tick = !self.write_tick;
        if self.write_tick {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let take = buf.len().min(self.chunk);
        Pin::new(&mut self.inner).poll_write(cx, &buf[..take])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Deterministic test data.
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + i / 251) as u8).collect()
}

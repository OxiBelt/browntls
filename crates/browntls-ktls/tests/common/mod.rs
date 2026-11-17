//! Shared helpers: run-time generated certificates, configurations for one
//! cipher suite, loopback sockets, and whether this kernel has kernel TLS.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use browntls::crypto::CryptoProvider;
use browntls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls::{ClientConfig, RootCertStore, ServerConfig, SupportedCipherSuite};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

/// The provider under test: the native one when built, else RustCrypto.
pub fn provider() -> CryptoProvider {
    #[cfg(feature = "native")]
    let provider = browntls::crypto::native::default_provider();
    #[cfg(not(feature = "native"))]
    let provider = browntls::crypto::rustcrypto::default_provider();
    provider
}

/// The provider's suites that kernel TLS takes and an ECDSA certificate
/// allows: AEAD suites other than TLS 1.3 AES-128-CCM-8.
pub fn offloadable_suites() -> Vec<SupportedCipherSuite> {
    provider()
        .cipher_suites
        .into_iter()
        .filter(|suite| {
            let name = format!("{:?}", suite.suite());
            !name.contains("CBC") && !name.contains("CCM_8") && !name.contains("ECDHE_RSA")
        })
        .collect()
}

/// Whether the kernel has the `tls` upper layer protocol loaded. Without
/// it the tests that need the kernel are skipped, unless
/// `BROWNTLS_KTLS_REQUIRED=1` makes that a failure.
pub fn kernel_tls() -> bool {
    let loaded = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp")
        .is_ok_and(|ulps| ulps.split_whitespace().any(|ulp| ulp == "tls"));
    if !loaded {
        assert!(
            std::env::var_os("BROWNTLS_KTLS_REQUIRED").is_none_or(|v| v != "1"),
            "BROWNTLS_KTLS_REQUIRED=1 but the kernel has no `tls` ULP (sudo modprobe tls)"
        );
        eprintln!("skipped: no kernel TLS (sudo modprobe tls)");
    }
    loaded
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
            .push(DnType::CommonName, "browntls-ktls test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let ee_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ee_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        ee_params.is_ca = IsCa::NoCa;
        ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        ee_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let ee_cert = ee_params.signed_by(&ee_key, &issuer).unwrap();

        let ca = CertificateDer::from(ca_cert.der().to_vec());
        Self {
            server_chain: vec![CertificateDer::from(ee_cert.der().to_vec()), ca.clone()],
            ca,
            server_key: ee_key.serialize_der(),
        }
    }

    fn single(suite: SupportedCipherSuite) -> Arc<CryptoProvider> {
        let mut provider = provider();
        provider.cipher_suites = vec![suite];
        Arc::new(provider)
    }

    /// A server configuration for `suite` only, secret extraction on.
    pub fn server_config(&self, suite: SupportedCipherSuite) -> ServerConfig {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key.clone()));
        let mut config = ServerConfig::builder_with_provider(Self::single(suite))
            .with_protocol_versions(&[suite.version()])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(self.server_chain.clone(), key)
            .unwrap();
        config.enable_secret_extraction = true;
        config
    }

    /// A client configuration for `suite` only, secret extraction on.
    pub fn client_config(&self, suite: SupportedCipherSuite) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        let mut config = ClientConfig::builder_with_provider(Self::single(suite))
            .with_protocol_versions(&[suite.version()])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.enable_secret_extraction = true;
        config
    }
}

pub fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

/// A connected loopback TCP pair: (client, server).
pub fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

/// The bytes a [`relay`] saw in each direction.
#[derive(Default)]
pub struct Wire {
    pub client_to_server: Vec<u8>,
    pub server_to_client: Vec<u8>,
}

/// A loopback pair joined through a relay that records what passes:
/// (client end, server end, the recording). The recording is complete once
/// both ends are closed.
pub fn relay() -> (TcpStream, TcpStream, Arc<Mutex<Wire>>, RelayDone) {
    let (client, relay_client) = tcp_pair();
    let (relay_server, server) = tcp_pair();
    let wire = Arc::new(Mutex::new(Wire::default()));
    let copy = |mut from: TcpStream, mut to: TcpStream, wire: Arc<Mutex<Wire>>, up: bool| {
        thread::spawn(move || {
            let mut buf = [0u8; 65536];
            loop {
                let n = match from.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                {
                    let mut wire = wire.lock().unwrap();
                    let log = if up {
                        &mut wire.client_to_server
                    } else {
                        &mut wire.server_to_client
                    };
                    log.extend_from_slice(&buf[..n]);
                }
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            let _ = to.shutdown(Shutdown::Write);
        })
    };
    let up = copy(
        relay_client.try_clone().unwrap(),
        relay_server.try_clone().unwrap(),
        wire.clone(),
        true,
    );
    let down = copy(relay_server, relay_client, wire.clone(), false);
    (client, server, wire, RelayDone(vec![up, down]))
}

/// The relay's copying threads.
pub struct RelayDone(Vec<thread::JoinHandle<()>>);

impl RelayDone {
    /// Waits until both directions ended.
    pub fn join(self) {
        for handle in self.0 {
            handle.join().unwrap();
        }
    }
}

/// The TLS 1.2 AES-GCM explicit nonces (the first 8 bytes of every
/// protected record) in `wire`, in order.
pub fn tls12_explicit_nonces(wire: &[u8]) -> Vec<[u8; 8]> {
    let mut nonces = Vec::new();
    let mut protected = false;
    let mut rest = wire;
    while rest.len() >= 5 {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        let Some(body) = rest.get(5..5 + len) else {
            break;
        };
        if rest[0] == 20 {
            protected = true;
        } else if protected {
            nonces.push(body[..8].try_into().unwrap());
        }
        rest = &rest[5 + len..];
    }
    nonces
}

/// `n` bytes of a pattern that shows where data was lost or reordered.
pub fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 8) as u8)
        .collect()
}

/// Reads exactly `n` bytes.
pub fn read_n(r: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

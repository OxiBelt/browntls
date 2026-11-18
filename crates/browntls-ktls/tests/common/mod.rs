//! Shared helpers: run-time generated certificates, configurations for one
//! cipher suite, loopback sockets, and whether this kernel has kernel TLS.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use browntls::crypto::CryptoProvider;
use browntls::crypto::cipher::{
    AeadKey, Iv, MessageDecrypter, MessageEncrypter, OutboundChunks, OutboundOpaqueMessage,
    OutboundPlainMessage, Tls13AeadAlgorithm, UnsupportedOperationError,
};
use browntls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls::{
    ClientConfig, ConnectionTrafficSecrets, ContentType, Error, RootCertStore, ServerConfig,
    SupportedCipherSuite, Tls13CipherSuite,
};
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

/// Whether the running kernel is one the streams promise unpadded records
/// to (`TLS_RX_EXPECT_NO_PAD`): Linux 7.2 or later and not a release
/// candidate of 7.2, since older kernels misplace a padded record in the
/// reader's buffer. On another kernel the tests of the promise are
/// skipped, unless `BROWNTLS_KTLS_NO_PAD_REQUIRED=1` makes that a failure.
pub fn no_pad_kernel() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let release = release.trim();
    let mut numbers = release
        .split(|c: char| !c.is_ascii_digit())
        .map(str::parse::<u32>);
    let bytes = release.as_bytes();
    // `rc` and a digit, not inside a word such as `arch1`.
    let candidate = bytes.windows(3).enumerate().any(|(at, window)| {
        window.starts_with(b"rc")
            && window[2].is_ascii_digit()
            && !(at > 0 && bytes[at - 1].is_ascii_alphabetic())
    });
    let fixed = match (numbers.next(), numbers.next()) {
        (Some(Ok(major)), Some(Ok(minor))) => {
            (major, minor) > (7, 2) || ((major, minor) == (7, 2) && !candidate)
        }
        _ => false,
    };
    if !fixed {
        assert!(
            std::env::var_os("BROWNTLS_KTLS_NO_PAD_REQUIRED").is_none_or(|v| v != "1"),
            "BROWNTLS_KTLS_NO_PAD_REQUIRED=1 but Linux {release} cannot be promised unpadded records"
        );
        eprintln!("Linux {release}: unpadded records cannot be promised");
    }
    fixed
}

/// The kernel's count `name` in `/proc/net/tls_stat` (all connections of
/// the network namespace; it only grows).
pub fn tls_stat(name: &str) -> u64 {
    let stat = std::fs::read_to_string("/proc/net/tls_stat").unwrap();
    stat.lines()
        .find_map(|line| {
            let (key, count) = line.split_once(char::is_whitespace)?;
            (key == name).then(|| count.trim().parse().unwrap())
        })
        .unwrap()
}

/// The most padding [`padding_suite`] adds to a record.
pub const MAX_PADDING: usize = 300;

/// The TLS 1.3 `suite` with an encrypter that pads what it sends (RFC 9846
/// §5.4): two records of three get 1 to [`MAX_PADDING`] zero bytes behind
/// their content type, where the record has room. browntls itself never
/// pads.
pub fn padding_suite(suite: SupportedCipherSuite) -> SupportedCipherSuite {
    let inner = tls13_suite(suite);
    let aead_alg = Box::leak(Box::new(PaddingAead(inner.aead_alg)));
    tls13_variant(inner, aead_alg, inner.common.confidentiality_limit)
}

/// The TLS 1.3 `suite` with keys that last for `limit` records only.
pub fn limited_suite(suite: SupportedCipherSuite, limit: u64) -> SupportedCipherSuite {
    let inner = tls13_suite(suite);
    tls13_variant(inner, inner.aead_alg, limit)
}

// Without `tls12` the suite can only be a TLS 1.3 one.
#[allow(clippy::infallible_destructuring_match)]
fn tls13_suite(suite: SupportedCipherSuite) -> &'static Tls13CipherSuite {
    match suite {
        SupportedCipherSuite::Tls13(inner) => inner,
        #[cfg(feature = "tls12")]
        SupportedCipherSuite::Tls12(_) => panic!("not a TLS 1.3 suite"),
    }
}

fn tls13_variant(
    suite: &'static Tls13CipherSuite,
    aead_alg: &'static dyn Tls13AeadAlgorithm,
    confidentiality_limit: u64,
) -> SupportedCipherSuite {
    SupportedCipherSuite::Tls13(Box::leak(Box::new(Tls13CipherSuite {
        common: browntls::CipherSuiteCommon {
            suite: suite.common.suite,
            hash_provider: suite.common.hash_provider,
            confidentiality_limit,
        },
        hkdf_provider: suite.hkdf_provider,
        aead_alg,
        quic: suite.quic,
    })))
}

struct PaddingAead(&'static dyn Tls13AeadAlgorithm);

impl Tls13AeadAlgorithm for PaddingAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Padder(self.0.encrypter(key, iv)))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        self.0.extract_keys(key, iv)
    }
}

struct Padder(Box<dyn MessageEncrypter>);

impl MessageEncrypter for Padder {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let padding = match seq % 3 {
            0 => 0,
            _ => 1 + (seq as usize * 37) % MAX_PADDING,
        };
        if padding == 0 || msg.payload.len() + padding > 16384 {
            return self.0.encrypt(msg, seq);
        }
        // The content, its type and all but one byte of the padding, as
        // the content of a record of type zero: the inner encrypter adds
        // that type as the last zero.
        let mut inner = msg.payload.to_vec();
        inner.push(msg.typ.into());
        inner.resize(inner.len() + padding - 1, 0);
        self.0.encrypt(
            OutboundPlainMessage {
                typ: ContentType::from(0),
                version: msg.version,
                payload: OutboundChunks::Single(&inner),
            },
            seq,
        )
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        self.0.encrypted_payload_len(payload_len + MAX_PADDING)
    }
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

/// A file holding `contents`, open for reading. Its name is removed from
/// the temporary directory before this returns, so nothing is left behind
/// however the test ends.
pub fn temp_file(contents: &[u8]) -> File {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "browntls-ktls-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    file.write_all(contents).unwrap();
    file
}

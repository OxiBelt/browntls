// Shared cases, included by `tests/cert_compression.rs` (RustCrypto provider)
// and `tests/cert_compression_native.rs` (native provider). Provider items
// are reached through the including target's `prov` module.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use browntls_core::compress::{
    self, CertCompressor, CertDecompressor, CompressionFailed, CompressionLevel,
    DecompressionFailed,
};
use browntls_core::server::PostHandshakeAuthStatus;
use browntls_core::{
    AlertDescription, CertificateCompressionAlgorithm, ClientConfig, ClientConnection, Error,
    PeerMisbehaved, ServerConfig, ServerConnection, version,
};
use common::*;

#[cfg(feature = "zstd")]
#[path = "cert_compression/zstd_transports.rs"]
mod zstd_transports;

type Builtin = (&'static dyn CertCompressor, &'static dyn CertDecompressor);

/// Every built-in algorithm this build has.
fn builtins() -> Vec<Builtin> {
    vec![
        #[cfg(feature = "brotli")]
        (&compress::BROTLI, &compress::BROTLI),
        #[cfg(feature = "zlib")]
        (&compress::ZLIB, &compress::ZLIB),
        #[cfg(feature = "zstd")]
        (&compress::ZSTD, &compress::ZSTD),
    ]
}

/// Wraps a decompressor and counts the messages it expanded.
#[derive(Debug)]
struct Counting {
    inner: &'static dyn CertDecompressor,
    calls: AtomicUsize,
}

impl Counting {
    fn new(inner: &'static dyn CertDecompressor) -> &'static Self {
        Box::leak(Box::new(Self {
            inner,
            calls: AtomicUsize::new(0),
        }))
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CertDecompressor for Counting {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        self.inner.decompress(input, output)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(feature = "zstd")]
    fn decompress_with_zstd_limits(
        &self,
        input: &[u8],
        output: &mut [u8],
        limits: compress::ZstdDecompressionLimits,
    ) -> Result<(), DecompressionFailed> {
        self.inner
            .decompress_with_zstd_limits(input, output, limits)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        self.inner.algorithm()
    }
}

/// What a misbehaving peer compresses instead of its Certificate message;
/// the `uncompressed_length` it declares stays that of the real message.
#[derive(Debug, Clone, Copy)]
enum Tamper {
    /// The real message: an honest peer, recording the message length.
    Nothing,
    /// One byte more than declared.
    OneMore,
    /// One byte less than declared.
    OneLess,
    /// Megabytes of zeros.
    Bomb,
}

#[derive(Debug)]
struct Tampering {
    inner: &'static dyn CertCompressor,
    tamper: Tamper,
    message_len: AtomicUsize,
}

impl Tampering {
    fn new(inner: &'static dyn CertCompressor, tamper: Tamper) -> &'static Self {
        Box::leak(Box::new(Self {
            inner,
            tamper,
            message_len: AtomicUsize::new(0),
        }))
    }
}

impl CertCompressor for Tampering {
    fn compress(
        &self,
        mut input: Vec<u8>,
        level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        self.message_len.store(input.len(), Ordering::SeqCst);
        match self.tamper {
            Tamper::Nothing => {}
            Tamper::OneMore => input.push(0),
            Tamper::OneLess => {
                input.pop();
            }
            Tamper::Bomb => input = vec![0; 4 << 20],
        }
        self.inner.compress(input, level)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        self.inner.algorithm()
    }
}

fn tls13_client(chain: &Chain, client_chain: Option<&Chain>) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain));
    let mut config = match client_chain {
        Some(client_chain) => builder
            .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config
}

fn tls13_server(chain: &Chain, client_chain: Option<&Chain>) -> ServerConfig {
    let builder = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap();
    let builder = match client_chain {
        Some(client_chain) => {
            builder.with_client_cert_verifier(PinnedClientVerifier::new(client_chain, true))
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

#[test]
fn new_configurations_start_with_the_built_ins() {
    let chain = server_chain(KeyType::EcdsaP256);
    let expected: Vec<_> = builtins().iter().map(|(c, _)| c.algorithm()).collect();
    assert!(!expected.is_empty());

    let client = client_config(&chain);
    let server = server_config(&chain);
    let algorithms =
        |c: &[&'static dyn CertCompressor]| -> Vec<_> { c.iter().map(|c| c.algorithm()).collect() };
    let algorithms_d = |d: &[&'static dyn CertDecompressor]| -> Vec<_> {
        d.iter().map(|d| d.algorithm()).collect()
    };
    assert_eq!(algorithms(&client.cert_compressors), expected);
    assert_eq!(algorithms(&server.cert_compressors), expected);
    assert_eq!(algorithms_d(&client.cert_decompressors), expected);
    assert_eq!(algorithms_d(&server.cert_decompressors), expected);
    assert_eq!(
        client.cert_decompression_limit,
        compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE
    );
    assert_eq!(
        server.cert_decompression_limit,
        compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE
    );

    // and a handshake between two default configurations works, with
    // client authentication so both directions are exercised
    let client_chain = client_chain(KeyType::EcdsaP256);
    let client = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap();
    let server = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client, server);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
}

#[test]
fn built_ins_compress_both_certificates() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);

    for (compressor, decompressor) in builtins() {
        let client_counter = Counting::new(decompressor);
        let server_counter = Counting::new(decompressor);

        let mut client_config = tls13_client(&chain, Some(&client_chain));
        client_config.cert_compressors = vec![compressor];
        client_config.cert_decompressors = vec![client_counter];
        let mut server_config = tls13_server(&chain, Some(&client_chain));
        server_config.cert_compressors = vec![compressor];
        server_config.cert_decompressors = vec![server_counter];

        let (mut client, mut server) = connect(client_config, server_config);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
        assert_eq!(
            server.peer_certificates().unwrap(),
            client_chain.cert_chain()
        );
        // each side received a CompressedCertificate and expanded it
        assert_eq!(client_counter.calls(), 1, "{:?}", compressor.algorithm());
        assert_eq!(server_counter.calls(), 1, "{:?}", compressor.algorithm());
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"compressed"),
            b"compressed"
        );
    }
}

#[test]
fn post_handshake_client_auth_compresses_the_client_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);

    for (compressor, decompressor) in builtins() {
        let server_counter = Counting::new(decompressor);

        let mut client_config = tls13_client(&chain, Some(&client_chain));
        client_config.cert_compressors = vec![compressor];
        client_config.enable_post_handshake_auth = true;
        let mut server_config = tls13_server(&chain, Some(&client_chain));
        server_config.cert_decompressors = vec![server_counter];
        server_config.request_client_auth_after_handshake = true;

        let (mut client, mut server) = connect(client_config, server_config);
        do_handshake(&mut client, &mut server).unwrap();
        assert!(server.peer_certificates().is_none());
        assert_eq!(server_counter.calls(), 0);

        // RFC 8879 §4: the post-handshake CertificateRequest offers the
        // same algorithms, and the answer is a CompressedCertificate.
        server.request_client_auth().unwrap();
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        assert_eq!(
            server.post_handshake_auth_status(),
            Some(PostHandshakeAuthStatus::Authenticated)
        );
        assert_eq!(
            server.peer_certificates().unwrap(),
            client_chain.cert_chain()
        );
        assert_eq!(server_counter.calls(), 1, "{:?}", compressor.algorithm());
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"after"),
            b"after"
        );
    }
}

#[test]
fn the_sender_picks_its_first_algorithm_the_peer_offered() {
    let chain = server_chain(KeyType::EcdsaP256);
    let all = builtins();
    for (i, (_, offered)) in all.iter().enumerate() {
        // the client offers one algorithm; the server has every compressor
        let counter = Counting::new(*offered);
        let mut client_config = tls13_client(&chain, None);
        client_config.cert_decompressors = vec![counter];
        let mut server_config = tls13_server(&chain, None);
        server_config.cert_compressors = all.iter().map(|(c, _)| *c).collect();
        let (mut client, mut server) = connect(client_config, server_config);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(counter.calls(), 1);

        // nothing in common: a plain Certificate
        let counter = Counting::new(*offered);
        let mut client_config = tls13_client(&chain, None);
        client_config.cert_decompressors = vec![counter];
        let mut server_config = tls13_server(&chain, None);
        server_config.cert_compressors = all
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, (c, _))| *c)
            .collect();
        let (mut client, mut server) = connect(client_config, server_config);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(counter.calls(), 0);
        assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
    }
}

#[test]
fn a_server_certificate_of_another_length_is_bad_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for (compressor, decompressor) in builtins() {
        for tamper in [Tamper::OneMore, Tamper::OneLess, Tamper::Bomb] {
            let mut client_config = tls13_client(&chain, None);
            client_config.cert_decompressors = vec![decompressor];
            let mut server_config = tls13_server(&chain, None);
            server_config.cert_compressors = vec![Tampering::new(compressor, tamper)];
            let (mut client, mut server) = connect(client_config, server_config);
            let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                client_res,
                Err(PeerMisbehaved::InvalidCertCompression.into()),
                "{:?} {tamper:?}",
                compressor.algorithm()
            );
            assert_eq!(
                server_res,
                Err(Error::AlertReceived(AlertDescription::BadCertificate))
            );
        }
    }
}

#[test]
fn a_client_certificate_of_another_length_is_bad_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    for (compressor, decompressor) in builtins() {
        for tamper in [Tamper::OneMore, Tamper::OneLess, Tamper::Bomb] {
            let mut client_config = tls13_client(&chain, Some(&client_chain));
            client_config.cert_compressors = vec![Tampering::new(compressor, tamper)];
            let mut server_config = tls13_server(&chain, Some(&client_chain));
            server_config.cert_decompressors = vec![decompressor];
            let (mut client, mut server) = connect(client_config, server_config);
            let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                server_res,
                Err(PeerMisbehaved::InvalidCertCompression.into()),
                "{:?} {tamper:?}",
                compressor.algorithm()
            );
            assert_eq!(
                client_res,
                Err(Error::AlertReceived(AlertDescription::BadCertificate))
            );
        }
    }
}

#[test]
fn a_certificate_over_the_configured_limit_is_bad_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    for (compressor, decompressor) in builtins() {
        // learn the length of each side's Certificate message
        let server_recorder = Tampering::new(compressor, Tamper::Nothing);
        let client_recorder = Tampering::new(compressor, Tamper::Nothing);
        let configs = |client_limit: Option<usize>, server_limit: Option<usize>| {
            let mut client_config = tls13_client(&chain, Some(&client_chain));
            client_config.cert_compressors = vec![client_recorder];
            client_config.cert_decompressors = vec![decompressor];
            if let Some(limit) = client_limit {
                client_config.cert_decompression_limit = limit;
            }
            let mut server_config = tls13_server(&chain, Some(&client_chain));
            server_config.cert_compressors = vec![server_recorder];
            server_config.cert_decompressors = vec![decompressor];
            if let Some(limit) = server_limit {
                server_config.cert_decompression_limit = limit;
            }
            connect(client_config, server_config)
        };
        let (mut client, mut server) = configs(None, None);
        do_handshake(&mut client, &mut server).unwrap();
        let server_message = server_recorder.message_len.load(Ordering::SeqCst);
        let client_message = client_recorder.message_len.load(Ordering::SeqCst);
        assert!(server_message > 100 && client_message > 100);

        // exactly at the limit: accepted
        let (mut client, mut server) = configs(Some(server_message), Some(client_message));
        do_handshake(&mut client, &mut server).unwrap();

        // one byte over the client's limit
        let (mut client, mut server) = configs(Some(server_message - 1), None);
        let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            client_res,
            Err(PeerMisbehaved::InvalidCertCompression.into())
        );
        assert_eq!(
            server_res,
            Err(Error::AlertReceived(AlertDescription::BadCertificate))
        );

        // one byte over the server's limit
        let (mut client, mut server) = configs(None, Some(client_message - 1));
        let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            server_res,
            Err(PeerMisbehaved::InvalidCertCompression.into())
        );
        assert_eq!(
            client_res,
            Err(Error::AlertReceived(AlertDescription::BadCertificate))
        );
    }
}

/// Passes for the algorithm the peer offered when it is selected, then
/// labels its output with a code point nobody offered.
#[derive(Debug)]
struct Relabelling {
    inner: &'static dyn CertCompressor,
    asked: AtomicUsize,
}

impl CertCompressor for Relabelling {
    fn compress(
        &self,
        input: Vec<u8>,
        level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        self.inner.compress(input, level)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        if self.asked.fetch_add(1, Ordering::SeqCst) == 0 {
            self.inner.algorithm()
        } else {
            CertificateCompressionAlgorithm::Unknown(0x7a7a)
        }
    }
}

#[test]
fn an_algorithm_that_was_not_offered_is_illegal_parameter() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let (compressor, decompressor) = builtins()[0];
    let relabelling = || -> &'static Relabelling {
        Box::leak(Box::new(Relabelling {
            inner: compressor,
            asked: AtomicUsize::new(0),
        }))
    };

    // from the server
    let mut client_config = tls13_client(&chain, None);
    client_config.cert_decompressors = vec![decompressor];
    let mut server_config = tls13_server(&chain, None);
    server_config.cert_compressors = vec![relabelling()];
    let (mut client, mut server) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res,
        Err(PeerMisbehaved::SelectedUnofferedCertCompression.into())
    );
    assert_eq!(
        server_res,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );

    // from the client
    let mut client_config = tls13_client(&chain, Some(&client_chain));
    client_config.cert_compressors = vec![relabelling()];
    let mut server_config = tls13_server(&chain, Some(&client_chain));
    server_config.cert_decompressors = vec![decompressor];
    let (mut client, mut server) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res,
        Err(PeerMisbehaved::SelectedUnofferedCertCompression.into())
    );
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );

    // a server that offers nothing gets a plain Certificate
    let mut client_config = tls13_client(&chain, Some(&client_chain));
    client_config.cert_compressors = vec![compressor];
    let server_config = tls13_server(&chain, Some(&client_chain));
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
}

/// The other provider serves; this target's provider connects, and back.
#[cfg(all(feature = "native", feature = "rustcrypto"))]
#[test]
fn compression_across_providers() {
    let other = || {
        Arc::new(if prov::NAME == "native" {
            browntls_core::crypto::rustcrypto::default_provider()
        } else {
            browntls_core::crypto::native::default_provider()
        })
    };
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);

    for (compressor, decompressor) in builtins() {
        for ours_is_client in [true, false] {
            let (client_provider, server_provider) = if ours_is_client {
                (provider(), other())
            } else {
                (other(), provider())
            };
            let client_counter = Counting::new(decompressor);
            let server_counter = Counting::new(decompressor);
            let mut client_config = ClientConfig::builder_with_provider(client_provider)
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
                .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
                .unwrap();
            client_config.cert_compressors = vec![compressor];
            client_config.cert_decompressors = vec![client_counter];
            let mut server_config = ServerConfig::builder_with_provider(server_provider)
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
                .with_single_cert(chain.cert_chain(), chain.private_key())
                .unwrap();
            server_config.cert_compressors = vec![compressor];
            server_config.cert_decompressors = vec![server_counter];

            let (mut client, mut server) = connect(client_config, server_config);
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
            assert_eq!(
                server.peer_certificates().unwrap(),
                client_chain.cert_chain()
            );
            assert_eq!(client_counter.calls(), 1);
            assert_eq!(server_counter.calls(), 1);
        }
    }
}

#[test]
fn a_limit_of_zero_does_not_offer_compression() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    for (compressor, decompressor) in builtins() {
        let client_counter = Counting::new(decompressor);
        let server_counter = Counting::new(decompressor);
        let configs = |client_limit: usize, server_limit: usize| {
            let mut client_config = tls13_client(&chain, Some(&client_chain));
            client_config.cert_compressors = vec![compressor];
            client_config.cert_decompressors = vec![client_counter];
            client_config.cert_decompression_limit = client_limit;
            let mut server_config = tls13_server(&chain, Some(&client_chain));
            server_config.cert_compressors = vec![compressor];
            server_config.cert_decompressors = vec![server_counter];
            server_config.cert_decompression_limit = server_limit;
            connect(client_config, server_config)
        };

        // the client offers nothing: the server's Certificate is plain,
        // the client's own is still compressed
        let (mut client, mut server) = configs(0, 4096);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!((client_counter.calls(), server_counter.calls()), (0, 1));
        assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());

        // the server's CertificateRequest offers nothing
        let (mut client, mut server) = configs(4096, 0);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!((client_counter.calls(), server_counter.calls()), (1, 1));
        assert_eq!(
            server.peer_certificates().unwrap(),
            client_chain.cert_chain()
        );
    }
}

// ------------------------------------------------------- rustls as the peer
//
// rustls 0.23 implements RFC 8879 with zlib (zlib-rs) and Brotli; it has no
// Zstandard. Its implementation is independent of the built-ins here, so
// these cases check the wire format of both, in both roles.

mod with_rustls {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustls_pki_types as rpki;

    use super::{Builtin, Counting, builtins, tls13_client, tls13_server};
    use crate::common::*;

    /// Wraps a rustls decompressor and counts the messages it expanded.
    #[derive(Debug)]
    struct RustlsCounting {
        inner: &'static dyn rustls::compress::CertDecompressor,
        calls: AtomicUsize,
    }

    impl rustls::compress::CertDecompressor for RustlsCounting {
        fn decompress(
            &self,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(), rustls::compress::DecompressionFailed> {
            self.inner.decompress(input, output)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
            self.inner.algorithm()
        }
    }

    /// The built-ins rustls also implements, with rustls's counterparts.
    #[allow(clippy::type_complexity)]
    fn shared() -> Vec<(
        Builtin,
        &'static dyn rustls::compress::CertCompressor,
        &'static RustlsCounting,
    )> {
        builtins()
            .into_iter()
            .filter_map(|ours| {
                let code = u16::from(ours.0.algorithm());
                let compressor = rustls::compress::default_cert_compressors()
                    .iter()
                    .find(|c| u16::from(c.algorithm()) == code)?;
                let decompressor = rustls::compress::default_cert_decompressors()
                    .iter()
                    .find(|d| u16::from(d.algorithm()) == code)?;
                let counting: &'static RustlsCounting = Box::leak(Box::new(RustlsCounting {
                    inner: *decompressor,
                    calls: AtomicUsize::new(0),
                }));
                Some((ours, *compressor, counting))
            })
            .collect()
    }

    fn r_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn r_certs(chain: &Chain) -> Vec<rpki::CertificateDer<'static>> {
        chain
            .cert_chain()
            .iter()
            .map(|c| rpki::CertificateDer::from(c.as_ref().to_vec()))
            .collect()
    }

    fn r_key(chain: &Chain) -> rpki::PrivateKeyDer<'static> {
        rpki::PrivateKeyDer::Pkcs8(rpki::PrivatePkcs8KeyDer::from(chain.end_entity_key.clone()))
    }

    fn r_roots(chain: &Chain) -> Arc<rustls::RootCertStore> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rpki::CertificateDer::from(chain.ca.as_ref().to_vec()))
            .unwrap();
        Arc::new(roots)
    }

    /// Runs the handshake between a browntls side and a rustls side.
    macro_rules! handshake {
        ($client:expr, $server:expr) => {{
            let (client, server) = (&mut $client, &mut $server);
            for _ in 0..16 {
                if !client.is_handshaking() && !server.is_handshaking() {
                    break;
                }
                let mut buf = Vec::new();
                while client.wants_write() {
                    client.write_tls(&mut buf).unwrap();
                }
                let mut input = &buf[..];
                while !input.is_empty() {
                    server.read_tls(&mut input).unwrap();
                    server.process_new_packets().unwrap();
                }
                let mut buf = Vec::new();
                while server.wants_write() {
                    server.write_tls(&mut buf).unwrap();
                }
                let mut input = &buf[..];
                while !input.is_empty() {
                    client.read_tls(&mut input).unwrap();
                    client.process_new_packets().unwrap();
                }
            }
            assert!(!client.is_handshaking() && !server.is_handshaking());
        }};
    }

    #[test]
    fn browntls_client_with_rustls_server() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let client_chain = client_chain(KeyType::EcdsaP256);
        let cases = shared();
        // the dev-dependency enables rustls's zlib and Brotli
        #[cfg(any(feature = "zlib", feature = "brotli"))]
        assert!(!cases.is_empty());

        for ((compressor, decompressor), r_compressor, r_counter) in cases {
            let counter = Counting::new(decompressor);
            let mut client_config = tls13_client(&chain, Some(&client_chain));
            client_config.cert_compressors = vec![compressor];
            client_config.cert_decompressors = vec![counter];

            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                r_roots(&client_chain),
                r_provider(),
            )
            .build()
            .unwrap();
            let mut server_config = rustls::ServerConfig::builder_with_provider(r_provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(r_certs(&chain), r_key(&chain))
                .unwrap();
            server_config.cert_compressors = vec![r_compressor];
            server_config.cert_decompressors = vec![r_counter];

            let mut client =
                browntls_core::ClientConnection::new(Arc::new(client_config), server_name())
                    .unwrap();
            let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
            handshake!(client, server);

            // browntls expanded what rustls compressed, and the reverse
            assert_eq!(counter.calls(), 1, "{:?}", compressor.algorithm());
            assert_eq!(r_counter.calls.load(Ordering::SeqCst), 1);
            assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
            assert_eq!(
                server.peer_certificates().unwrap(),
                r_certs(&client_chain).as_slice()
            );
        }
    }

    #[test]
    fn rustls_client_with_browntls_server() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let client_chain = client_chain(KeyType::EcdsaP256);

        for ((compressor, decompressor), r_compressor, r_counter) in shared() {
            let mut client_config = rustls::ClientConfig::builder_with_provider(r_provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(r_roots(&chain))
                .with_client_auth_cert(r_certs(&client_chain), r_key(&client_chain))
                .unwrap();
            client_config.cert_compressors = vec![r_compressor];
            client_config.cert_decompressors = vec![r_counter];

            let counter = Counting::new(decompressor);
            let mut server_config = tls13_server(&chain, Some(&client_chain));
            server_config.cert_compressors = vec![compressor];
            server_config.cert_decompressors = vec![counter];

            let mut client = rustls::ClientConnection::new(
                Arc::new(client_config),
                rpki::ServerName::try_from("localhost").unwrap(),
            )
            .unwrap();
            let mut server = browntls_core::ServerConnection::new(Arc::new(server_config)).unwrap();
            handshake!(client, server);

            assert_eq!(r_counter.calls.load(Ordering::SeqCst), 1);
            assert_eq!(counter.calls(), 1, "{:?}", compressor.algorithm());
            assert_eq!(
                client.peer_certificates().unwrap(),
                r_certs(&chain).as_slice()
            );
            assert_eq!(
                server.peer_certificates().unwrap(),
                client_chain.cert_chain()
            );
        }
    }
}

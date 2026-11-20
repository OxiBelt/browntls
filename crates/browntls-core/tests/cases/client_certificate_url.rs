// Shared cases, included by `tests/client_certificate_url.rs` (RustCrypto
// provider) and `tests/client_certificate_url_native.rs` (native provider):
// client certificate URLs (RFC 6066 §5) in TLS 1.2, client and server.
// Provider items are reached through the including target's `prov` module.
//
// The fetches are simulated: a map from URL to object stands in for the
// application's HTTP client. The library itself fetches nothing.

use std::collections::HashMap;
use std::sync::Arc;

use browntls_core::certificate_url::{
    CertChainType, CertificateUrl, CertificateUrlError, ClientCertificateUrlPolicy,
    ClientCertificateUrlQuery, ClientCertificateUrlResponse, UrlAndHash, encode_pki_path,
};
use browntls_core::pki_types::CertificateDer;
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, Error, HandshakeKind,
    HandshakeType, InvalidMessage, ServerConfig, ServerConnection, SupportedProtocolVersion,
    version,
};
use common::hello_wire::*;
use common::*;

const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
const ALERT_BAD_CERTIFICATE: u8 = 42;
const ALERT_ILLEGAL_PARAMETER: u8 = 47;
const ALERT_UNKNOWN_CA: u8 = 48;
const ALERT_DECODE_ERROR: u8 = 50;
const ALERT_CERTIFICATE_UNOBTAINABLE: u8 = 111;
const ALERT_BAD_CERTIFICATE_HASH_VALUE: u8 = 114;
/// The CertificateURL handshake message type (RFC 6066 §5).
const CERTIFICATE_URL: u8 = 21;

static TLS12: [&SupportedProtocolVersion; 1] = [&version::TLS12];
static TLS13: [&SupportedProtocolVersion; 1] = [&version::TLS13];
static BOTH: [&SupportedProtocolVersion; 2] = [&version::TLS13, &version::TLS12];

/// The server's certificate, the client's chain, and where the client's
/// chain is published.
struct Setup {
    server: Chain,
    client: Chain,
    web: HashMap<String, Vec<u8>>,
}

const EE_URL: &str = "http://certs.example/client.der";
const CA_URL: &str = "http://certs.example/ca.der";
const PATH_URL: &str = "http://certs.example/client.pkipath";

impl Setup {
    fn new() -> Self {
        let client = client_chain(KeyType::EcdsaP256);
        let mut web = HashMap::new();
        web.insert(EE_URL.to_string(), client.end_entity.to_vec());
        web.insert(CA_URL.to_string(), client.ca.to_vec());
        web.insert(
            PATH_URL.to_string(),
            encode_pki_path(&client.cert_chain()).unwrap(),
        );
        Self {
            server: server_chain(KeyType::EcdsaP256),
            client,
            web,
        }
    }

    fn entry(&self, url: &str) -> UrlAndHash {
        UrlAndHash::for_object(url, &self.web[url], prov::sha1).unwrap()
    }

    /// `url`, claiming the hash of the client's end-entity certificate.
    fn entry_for(&self, url: &str) -> UrlAndHash {
        UrlAndHash::for_object(url, &self.web[EE_URL], prov::sha1).unwrap()
    }

    fn individual(&self) -> CertificateUrl {
        CertificateUrl::individual_certs(vec![self.entry(EE_URL), self.entry(CA_URL)]).unwrap()
    }

    fn pkipath(&self) -> CertificateUrl {
        CertificateUrl::pkipath(self.entry(PATH_URL)).unwrap()
    }

    /// The client's key with `urls`, holding its chain or none.
    fn key(&self, urls: Option<CertificateUrl>, with_chain: bool) -> CertifiedKey {
        let key = provider()
            .key_provider
            .load_private_key(self.client.private_key())
            .unwrap();
        let chain = if with_chain {
            self.client.cert_chain()
        } else {
            Vec::new()
        };
        let mut key = CertifiedKey::new(chain, key);
        key.set_certificate_url(urls);
        key
    }

    fn client(
        &self,
        versions: &[&'static SupportedProtocolVersion],
        key: CertifiedKey,
        enable: bool,
    ) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&self.server))
            .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
        config.enable_client_certificate_url = enable;
        config
    }

    fn server(
        &self,
        versions: &[&'static SupportedProtocolVersion],
        mandatory: bool,
        policy: Option<ClientCertificateUrlPolicy>,
    ) -> ServerConfig {
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&self.client, mandatory))
            .with_single_cert(self.server.cert_chain(), self.server.private_key())
            .unwrap();
        config.client_certificate_url = policy;
        config
    }

    /// The application's fetch: what the simulated web serves.
    fn fetch(&self, query: &ClientCertificateUrlQuery) -> ClientCertificateUrlResponse {
        ClientCertificateUrlResponse::Fetched(
            query
                .entries()
                .iter()
                .map(|entry| self.web[entry.url()].clone())
                .collect(),
        )
    }
}

fn policy() -> Option<ClientCertificateUrlPolicy> {
    Some(ClientCertificateUrlPolicy::new(prov::sha1))
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

/// How a handshake driven by [`run`] ended.
#[derive(Debug)]
struct Outcome {
    client: Result<(), Error>,
    server: Result<(), Error>,
    /// The queries the server raised, in order.
    queries: Vec<ClientCertificateUrlQuery>,
    /// The alert the failing side sent, if any.
    alert: Option<u8>,
}

/// Drives a handshake, answering every client certificate URL query of the
/// server with `answer`.
fn run(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    mut answer: impl FnMut(&ClientCertificateUrlQuery) -> ClientCertificateUrlResponse,
) -> Outcome {
    let mut queries = Vec::new();
    let fail = |client: Result<(), Error>, server: Result<(), Error>, alert, queries| Outcome {
        client,
        server,
        queries,
        alert,
    };
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return fail(Ok(()), Ok(()), None, queries);
        }
        give(server, &take_flight(client));
        let mut result = server.process_new_packets().map(|_| ());
        while result.is_ok()
            && let Some(query) = server.pending_client_certificate_url()
        {
            let query = query.clone();
            assert!(!server.wants_read());
            result = server.resolve_client_certificate_url(query.id(), answer(&query));
            queries.push(query);
        }
        if let Err(err) = result {
            let flight = take_flight(server);
            let alert = fatal_alert(&flight);
            give(client, &flight);
            let client_result = client.process_new_packets().map(|_| ());
            return fail(client_result, Err(err), alert, queries);
        }
        give(client, &take_flight(server));
        if let Err(err) = client.process_new_packets() {
            let flight = take_flight(client);
            let alert = fatal_alert(&flight);
            give(server, &flight);
            let server_result = server.process_new_packets().map(|_| ());
            return fail(Err(err), server_result, alert, queries);
        }
    }
    panic!("handshake did not complete");
}

/// Runs the client's ClientHello to the server and returns the server's
/// first flight, both left unprocessed by the client.
fn hello_round(client: &mut ClientConnection, server: &mut ServerConnection) -> (Vec<u8>, Vec<u8>) {
    let hello = take_flight(client);
    give(server, &hello);
    server.process_new_packets().unwrap();
    (hello, take_flight(server))
}

#[test]
fn individual_certs_from_a_client_without_a_chain() {
    init_logging();
    let s = Setup::new();
    let (mut client, mut server) = connect(
        s.client(&TLS12, s.key(Some(s.individual()), false), true),
        s.server(&TLS12, true, policy()),
    );
    let (hello, flight) = hello_round(&mut client, &mut server);
    assert!(hello_extension_types(&hello, true).contains(&EXT_CLIENT_CERTIFICATE_URL));
    assert!(hello_extension_types(&flight, false).contains(&EXT_CLIENT_CERTIFICATE_URL));
    give(&mut client, &flight);
    client.process_new_packets().unwrap();
    // The client's flight starts with CertificateURL, in the clear.
    let reply = take_flight(&mut client);
    assert_eq!(first_record(&reply).unwrap().1[0], CERTIFICATE_URL);
    give(&mut server, &reply);
    server.process_new_packets().unwrap();

    let query = server.pending_client_certificate_url().unwrap().clone();
    assert_eq!(query.chain_type(), CertChainType::IndividualCerts);
    assert_eq!(query.entries(), s.individual().entries());
    assert_eq!(query.entries()[0].url(), EE_URL);
    // Nothing counts as authenticated while the chain is fetched.
    assert!(server.peer_certificates().is_none());
    assert!(server.is_handshaking());

    let outcome = run(&mut client, &mut server, |q| s.fetch(q));
    assert!(outcome.server.is_ok() && outcome.client.is_ok(), "{outcome:?}");
    assert_eq!(
        server.peer_certificates().unwrap(),
        s.client.cert_chain().as_slice()
    );
}

#[test]
fn pkipath_from_a_client_without_a_chain() {
    init_logging();
    let s = Setup::new();
    let (mut client, mut server) = connect(
        s.client(&TLS12, s.key(Some(s.pkipath()), false), true),
        s.server(&TLS12, true, policy()),
    );
    let outcome = run(&mut client, &mut server, |q| s.fetch(q));
    assert!(outcome.server.is_ok() && outcome.client.is_ok(), "{outcome:?}");
    assert_eq!(outcome.queries.len(), 1);
    assert_eq!(outcome.queries[0].chain_type(), CertChainType::PkiPath);
    assert_eq!(outcome.queries[0].entries()[0].url(), PATH_URL);
    assert_eq!(
        server.peer_certificates().unwrap(),
        s.client.cert_chain().as_slice()
    );
}

/// The hash a `pkipath` URL carries, for a PkiPath of two stand-in
/// certificates (`30 03 02 01 01` in TLS order before `30 03 02 01 02`).
/// The DER and its SHA-1 come from Python (`hashlib.sha1`) and agree with
/// `openssl asn1parse` and `openssl sha1`.
#[test]
fn pkipath_hash_vector() {
    let chain = [
        CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01]),
        CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x02]),
    ];
    let der = encode_pki_path(&chain).unwrap();
    assert_eq!(der, [0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x02, 0x30, 0x03, 0x02, 0x01, 0x01]);
    let entry = UrlAndHash::for_object("http://a/p", &der, prov::sha1).unwrap();
    assert_eq!(
        entry.sha1_hash(),
        &[
            0xf2, 0x40, 0x1d, 0x4f, 0x98, 0xcf, 0xba, 0x18, 0xc9, 0xc6, 0x44, 0x45, 0x8d, 0xf2, 0x39,
            0xa0, 0xfa, 0x17, 0x07, 0x43
        ]
    );
}

/// The PkiPath helper against an independent encoding: the chain in
/// reverse order inside one SEQUENCE.
#[test]
fn pkipath_object_is_the_reversed_chain() {
    let s = Setup::new();
    let der = &s.web[PATH_URL];
    let (ee, ca) = (s.client.end_entity.as_ref(), s.client.ca.as_ref());
    let contents = [ca, ee].concat();
    assert_eq!(der[0], 0x30);
    assert!(der.ends_with(&contents));
    assert_eq!(der.len() - contents.len(), if contents.len() < 256 { 3 } else { 4 });
}

#[test]
fn a_server_without_a_policy_gets_the_ordinary_certificate() {
    init_logging();
    let s = Setup::new();
    let (mut client, mut server) = connect(
        s.client(&TLS12, s.key(Some(s.individual()), true), true),
        s.server(&TLS12, true, None),
    );
    let (hello, flight) = hello_round(&mut client, &mut server);
    assert!(hello_extension_types(&hello, true).contains(&EXT_CLIENT_CERTIFICATE_URL));
    assert!(!hello_extension_types(&flight, false).contains(&EXT_CLIENT_CERTIFICATE_URL));
    give(&mut client, &flight);
    client.process_new_packets().unwrap();
    let outcome = run(&mut client, &mut server, |_| unreachable!());
    assert!(outcome.server.is_ok() && outcome.client.is_ok(), "{outcome:?}");
    assert_eq!(
        server.peer_certificates().unwrap(),
        s.client.cert_chain().as_slice()
    );
}

/// A key without a chain has nothing to send to a server that does not
/// take URLs: an empty Certificate and no CertificateVerify.
#[test]
fn a_key_without_a_chain_sends_no_certificate_to_other_servers() {
    init_logging();
    let s = Setup::new();
    for versions in [&TLS12[..], &TLS13[..]] {
        let (mut client, mut server) = connect(
            s.client(versions, s.key(Some(s.individual()), false), true),
            s.server(versions, false, None),
        );
        let outcome = run(&mut client, &mut server, |_| unreachable!());
        assert!(outcome.server.is_ok() && outcome.client.is_ok(), "{outcome:?}");
        assert!(server.peer_certificates().is_none());

        let (mut client, mut server) = connect(
            s.client(versions, s.key(Some(s.individual()), false), true),
            s.server(versions, true, None),
        );
        let outcome = run(&mut client, &mut server, |_| unreachable!());
        assert_eq!(outcome.server, Err(Error::NoCertificatesPresented));
    }
}

#[test]
fn a_disabled_client_sends_neither_extension_nor_urls() {
    init_logging();
    let s = Setup::new();
    let (mut client, mut server) = connect(
        s.client(&TLS12, s.key(Some(s.individual()), true), false),
        s.server(&TLS12, true, policy()),
    );
    let (hello, flight) = hello_round(&mut client, &mut server);
    assert!(!hello_extension_types(&hello, true).contains(&EXT_CLIENT_CERTIFICATE_URL));
    assert!(!hello_extension_types(&flight, false).contains(&EXT_CLIENT_CERTIFICATE_URL));
    give(&mut client, &flight);
    client.process_new_packets().unwrap();
    let outcome = run(&mut client, &mut server, |_| unreachable!());
    assert!(outcome.server.is_ok() && outcome.client.is_ok(), "{outcome:?}");
    assert!(outcome.queries.is_empty());
}

/// Offered alongside TLS 1.3, never acknowledged in it; not offered
/// without TLS 1.2, nor without client certificates.
#[test]
fn tls13_never_uses_certificate_urls() {
    init_logging();
    let s = Setup::new();
    let (mut client, mut server) = connect(
        s.client(&BOTH, s.key(Some(s.individual()), true), true),
        s.server(&BOTH, true, policy()),
    );
    let (hello, _) = hello_round(&mut client, &mut server);
    assert!(hello_extension_types(&hello, true).contains(&EXT_CLIENT_CERTIFICATE_URL));
    let (mut client, mut server) = connect(
        s.client(&BOTH, s.key(Some(s.individual()), true), true),
        s.server(&BOTH, true, policy()),
    );
    let outcome = run(&mut client, &mut server, |_| unreachable!());
    assert!(outcome.server.is_ok() && outcome.client.is_ok(), "{outcome:?}");
    assert_eq!(
        server.protocol_version(),
        Some(browntls_core::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        server.peer_certificates().unwrap(),
        s.client.cert_chain().as_slice()
    );

    let mut tls13 = ClientConnection::new(
        Arc::new(s.client(&TLS13, s.key(Some(s.individual()), true), true)),
        server_name(),
    )
    .unwrap();
    let hello = take_flight(&mut tls13);
    assert!(!hello_extension_types(&hello, true).contains(&EXT_CLIENT_CERTIFICATE_URL));

    let mut config = client_config(&s.server);
    config.enable_client_certificate_url = true;
    let mut no_certs = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    let hello = take_flight(&mut no_certs);
    assert!(!hello_extension_types(&hello, true).contains(&EXT_CLIENT_CERTIFICATE_URL));
}

/// A resumed session sends no certificate, so nothing is acknowledged.
#[test]
fn resumption_does_not_acknowledge() {
    init_logging();
    let s = Setup::new();
    let client_config = Arc::new(s.client(&TLS12, s.key(Some(s.individual()), false), true));
    let server_config = Arc::new(s.server(&TLS12, true, policy()));
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    let outcome = run(&mut client, &mut server, |q| s.fetch(q));
    assert!(outcome.server.is_ok() && outcome.client.is_ok(), "{outcome:?}");

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    let (hello, flight) = hello_round(&mut client, &mut server);
    assert!(hello_extension_types(&hello, true).contains(&EXT_CLIENT_CERTIFICATE_URL));
    assert!(!hello_extension_types(&flight, false).contains(&EXT_CLIENT_CERTIFICATE_URL));
    give(&mut client, &flight);
    client.process_new_packets().unwrap();
    let outcome = run(&mut client, &mut server, |_| unreachable!());
    assert!(outcome.server.is_ok() && outcome.client.is_ok(), "{outcome:?}");
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(
        server.peer_certificates().unwrap(),
        s.client.cert_chain().as_slice()
    );
}

/// RFC 7250 raw public keys have no URL form.
#[test]
fn raw_public_keys_are_not_named_by_url() {
    init_logging();
    let s = Setup::new();
    let mut client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&TLS12)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&s.server))
        .with_client_cert_resolver(RawKeyResolver::new(&s.client));
    client_config.enable_client_certificate_url = true;
    let mut server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&TLS12)
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::raw_public_key(&s.client))
        .with_single_cert(s.server.cert_chain(), s.server.private_key())
        .unwrap();
    server_config.client_certificate_url = policy();
    let (mut client, mut server) = connect(client_config, server_config);
    let (hello, flight) = hello_round(&mut client, &mut server);
    assert!(hello_extension_types(&hello, true).contains(&EXT_CLIENT_CERTIFICATE_URL));
    assert!(!hello_extension_types(&flight, false).contains(&EXT_CLIENT_CERTIFICATE_URL));
    give(&mut client, &flight);
    client.process_new_packets().unwrap();
    let outcome = run(&mut client, &mut server, |_| unreachable!());
    assert!(outcome.server.is_ok() && outcome.client.is_ok(), "{outcome:?}");
}

/// Invalid policies fail connection creation, like other invalid
/// configuration.
#[test]
fn invalid_policies_are_refused() {
    let s = Setup::new();
    let cases: [fn(&mut ClientCertificateUrlPolicy); 5] = [
        |p| p.max_urls = 0,
        |p| p.max_url_len = 0,
        |p| p.max_fetched_len = 0,
        |p| p.allowed_schemes.clear(),
        |p| p.allowed_schemes = vec!["not a scheme".into()],
    ];
    for change in cases {
        let mut p = ClientCertificateUrlPolicy::new(prov::sha1);
        change(&mut p);
        let config = Arc::new(s.server(&TLS12, true, Some(p)));
        assert!(matches!(
            ServerConnection::new(config),
            Err(Error::General(_))
        ));
    }
    let p = ClientCertificateUrlPolicy::new(prov::sha1);
    assert_eq!(p.allowed_schemes, ["http"]);
    assert_eq!((p.max_urls, p.max_url_len, p.max_fetched_len), (8, 2048, 65536));
}

include!("client_certificate_url/failures.rs");
include!("client_certificate_url/wire.rs");

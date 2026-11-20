//! The client certificate URL operation of the `tls_auth` target (RFC 6066
//! §5): every public function of `browntls_core::certificate_url`, the
//! pause API of the connections, and the fetcher hooks of `browntls-tokio`.
//!
//! * `decode_pki_path` over fuzzed bytes and `encode_pki_path` over
//!   fuzz-chosen elements (round trips);
//! * `UrlAndHash` and `CertificateUrl` from fuzzed URLs, hashes and list
//!   lengths, against a model of their rules, and the URLs of a
//!   `CertifiedKey`;
//! * TLS 1.2 handshakes whose client names its chain by URL, with a
//!   fuzz-chosen policy, URLs and answer (the objects, unobtainable,
//!   fuzzed bytes, swapped, an extra object, a wrong id first), on a
//!   buffered server (through `ConnectionCommon` or `Connection`), an
//!   unbuffered one, and the six Tokio acceptors with a fetcher.
//!
//! Checked properties: a query surfaces exactly when the policy model lets
//! every URL through; while it is pending the server reads nothing, has no
//! plaintext and refuses an answer with the wrong id, leaving the query as
//! it was; the outcome is the one the model predicts, and a successful
//! handshake reports the chain the URLs name.
//!
//! The library fetches nothing: the harness answers from a map of URLs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use browntls_core::certificate_url::{
    CertChainType, CertificateUrl, CertificateUrlError, ClientCertificateUrlPolicy,
    ClientCertificateUrlResponse, UrlAndHash, decode_pki_path, encode_pki_path,
};
use browntls_core::crypto::CryptoProvider;
use browntls_core::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use browntls_core::{
    ClientConfig, Error, RootCertStore, ServerConfig, SupportedProtocolVersion, version,
};
use sha1::{Digest, Sha1};

use super::{Issuer, leaf};
use crate::input::{Input, put_field, put_short_field};

mod asynchronous;
mod handshake;

pub(super) const EE_URL: &str = "http://certs.example/client.der";
pub(super) const CA_URL: &str = "http://certs.example/ca.der";
pub(super) const PATH_URL: &str = "http://certs.example/client.pkipath";

/// Handshakes per input (each kind of driver counts).
const MAX_HANDSHAKES: usize = 3;

/// The SHA-1 the policy and the entries use (RustCrypto, an independent
/// implementation).
pub(super) fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).as_slice().try_into().expect("20 bytes")
}

// ----------------------------------------------------------------- fixture

pub(super) struct Fixture {
    provider: Arc<CryptoProvider>,
    roots: Arc<RootCertStore>,
    server_chain: Vec<CertificateDer<'static>>,
    server_pkcs8: Vec<u8>,
    /// The client's chain: end entity, then the CA.
    pub(super) chain: Vec<CertificateDer<'static>>,
    client_key: Arc<dyn SigningKey>,
    /// The client's chain as a PkiPath.
    pub(super) path: Vec<u8>,
}

pub(super) fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let provider = Arc::new(browntls_core::crypto::native::default_provider());
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let issuer = Issuer {
            issuer: rcgen::Issuer::new(ca_params, ca_key),
            ca: CertificateDer::from(ca.der().to_vec()),
        };
        let mut roots = RootCertStore::empty();
        roots.add(issuer.ca.clone()).expect("root");

        let server_key = rcgen::KeyPair::generate().expect("key");
        let server = leaf(
            &issuer,
            &server_key,
            "localhost",
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            |_| {},
        );
        let client_key = rcgen::KeyPair::generate().expect("key");
        let client = leaf(
            &issuer,
            &client_key,
            "client.example",
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            |_| {},
        );
        let chain = vec![client, issuer.ca.clone()];
        let path = encode_pki_path(&chain).expect("PkiPath");
        let client_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                client_key.serialize_der(),
            )))
            .expect("key loads");
        Fixture {
            roots: Arc::new(roots),
            server_chain: vec![server],
            server_pkcs8: server_key.serialize_der(),
            chain,
            client_key,
            path,
            provider,
        }
    })
}

/// What the simulated web serves at `url`: any URL but the CA's and the
/// PkiPath's serves the end-entity certificate.
pub(super) fn served(url: &str) -> Vec<u8> {
    let fixture = fixture();
    match url {
        CA_URL => fixture.chain[1].to_vec(),
        PATH_URL => fixture.path.clone(),
        _ => fixture.chain[0].to_vec(),
    }
}

fn entry(url: &str) -> UrlAndHash {
    UrlAndHash::for_object(url, &served(url), sha1).expect("entry")
}

// ------------------------------------------------------------------- model

/// The URL rules of `UrlAndHash::new`.
fn url_ok(url: &str) -> bool {
    (1..=0xffff).contains(&url.len()) && url.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn is_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
}

/// A policy that connection creation accepts.
fn policy_ok(policy: &ClientCertificateUrlPolicy) -> bool {
    policy.max_urls != 0
        && policy.max_url_len != 0
        && policy.max_fetched_len != 0
        && !policy.allowed_schemes.is_empty()
        && policy.allowed_schemes.iter().all(|s| is_scheme(s))
}

/// Whether the server refuses `url` before the application sees it.
fn refused(policy: &ClientCertificateUrlPolicy, url: &str) -> bool {
    if url.len() > policy.max_url_len || !url_ok(url) || url.contains(['\\', '#']) {
        return true;
    }
    let Some((scheme, rest)) = url.split_once(':') else {
        return true;
    };
    if !is_scheme(scheme)
        || !policy
            .allowed_schemes
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(scheme))
    {
        return true;
    }
    let Some(after) = rest.strip_prefix("//") else {
        return true;
    };
    let authority = after.split(['/', '?']).next().unwrap_or("");
    authority.is_empty() || authority.contains('@')
}

// ------------------------------------------------------------------- plans

/// How the application answers the query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Answer {
    Fetched,
    Unobtainable,
    Fuzzed,
    Reversed,
    Extra,
    /// A wrong id first (refused), then the objects.
    WrongIdFirst,
}

/// One handshake: what each side is configured with and how the query is
/// answered.
pub(super) struct Plan {
    enable: bool,
    tls13: bool,
    mandatory: bool,
    with_chain: bool,
    urls: Option<CertificateUrl>,
    policy: Option<ClientCertificateUrlPolicy>,
    pub(super) answer: Answer,
    /// The objects of `Answer::Fuzzed`.
    pub(super) fuzzed: Vec<Vec<u8>>,
}

/// What the model expects of a handshake.
#[derive(Debug)]
pub(super) enum Expected {
    /// Success, with the client's chain reported (`None`: no certificate).
    Ok(Option<Vec<CertificateDer<'static>>>),
    /// The server fails with this error.
    Err(Error),
    /// The server fails, with an error the fuzzed bytes decide.
    Fails,
}

impl Plan {
    fn read(input: &mut Input) -> Self {
        let flags = input.byte();
        let urls = match input.choose(5) {
            0 => Some(
                CertificateUrl::individual_certs(vec![entry(EE_URL), entry(CA_URL)])
                    .expect("two URLs"),
            ),
            1 => Some(CertificateUrl::pkipath(entry(PATH_URL)).expect("one URL")),
            2 => {
                let url = String::from_utf8_lossy(input.short_field()).into_owned();
                let url = UrlAndHash::for_object(url, &served(EE_URL), sha1)
                    .unwrap_or_else(|_| entry(EE_URL));
                Some(CertificateUrl::individual_certs(vec![url]).expect("one URL"))
            }
            3 => None,
            _ => Some(CertificateUrl::individual_certs(vec![entry(EE_URL)]).expect("one URL")),
        };
        let policy = match input.choose(6) {
            0 => None,
            1 | 2 => Some(ClientCertificateUrlPolicy::new(sha1)),
            _ => {
                let mut policy = ClientCertificateUrlPolicy::new(sha1);
                policy.allowed_schemes = match input.choose(5) {
                    0 => vec!["HTTP".into(), "https".into()],
                    1 => vec!["ftp".into()],
                    2 => vec![],
                    3 => vec![String::from_utf8_lossy(input.short_field()).into_owned()],
                    _ => vec!["http".into()],
                };
                policy.max_urls = input.choose(4);
                policy.max_url_len = usize::from(input.u16());
                policy.max_fetched_len = match input.choose(4) {
                    0 => usize::from(input.u16()),
                    1 => 0,
                    _ => 0x10000,
                };
                Some(policy)
            }
        };
        let answer = match input.choose(8) {
            0 => Answer::Unobtainable,
            1 => Answer::Fuzzed,
            2 => Answer::Reversed,
            3 => Answer::Extra,
            4 => Answer::WrongIdFirst,
            _ => Answer::Fetched,
        };
        let fuzzed = (0..input.choose(3))
            .map(|_| input.field().to_vec())
            .collect();
        Self {
            enable: flags & 1 == 0,
            tls13: flags & 2 != 0,
            mandatory: flags & 4 != 0,
            with_chain: flags & 8 != 0,
            urls,
            policy,
            answer,
            fuzzed,
        }
    }

    pub(super) fn client_config(&self) -> Arc<ClientConfig> {
        let fixture = fixture();
        let versions: &[&SupportedProtocolVersion] = if self.tls13 {
            &[&version::TLS13, &version::TLS12]
        } else {
            &[&version::TLS12]
        };
        let chain = if self.with_chain {
            fixture.chain.clone()
        } else {
            Vec::new()
        };
        let mut key = CertifiedKey::new(chain, fixture.client_key.clone());
        key.set_certificate_url(self.urls.clone());
        assert_eq!(key.certificate_url(), self.urls.as_ref());
        let mut config = ClientConfig::builder_with_provider(fixture.provider.clone())
            .with_protocol_versions(versions)
            .expect("versions")
            .with_root_certificates(fixture.roots.clone())
            .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
        config.enable_client_certificate_url = self.enable;
        Arc::new(config)
    }

    pub(super) fn server_config(&self) -> Arc<ServerConfig> {
        let fixture = fixture();
        let builder = WebPkiClientVerifier::builder_with_provider(
            fixture.roots.clone(),
            fixture.provider.clone(),
        );
        let builder = if self.mandatory {
            builder
        } else {
            builder.allow_unauthenticated()
        };
        let mut config = ServerConfig::builder_with_provider(fixture.provider.clone())
            .with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .expect("versions")
            .with_client_cert_verifier(builder.build().expect("verifier"))
            .with_single_cert(
                fixture.server_chain.clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture.server_pkcs8.clone())),
            )
            .expect("server certificate");
        config.client_certificate_url = self.policy.clone();
        Arc::new(config)
    }

    /// Whether connection creation accepts the server's policy.
    pub(super) fn valid(&self) -> bool {
        self.policy.as_ref().is_none_or(policy_ok)
    }

    /// Whether the server pauses with a query.
    pub(super) fn surfaces(&self) -> bool {
        let (Some(urls), Some(policy)) = (&self.urls, &self.policy) else {
            return false;
        };
        self.sends_urls()
            && urls.entries().len() <= policy.max_urls
            && !urls.entries().iter().any(|e| refused(policy, e.url()))
    }

    /// Whether the client sends a CertificateURL message.
    fn sends_urls(&self) -> bool {
        self.enable && !self.tls13 && self.policy.is_some() && self.urls.is_some()
    }

    /// The objects the URLs name, in order.
    pub(super) fn objects(&self) -> Vec<Vec<u8>> {
        self.urls
            .iter()
            .flat_map(CertificateUrl::entries)
            .map(|e| served(e.url()))
            .collect()
    }

    /// The response for `Answer` (after any wrong id).
    pub(super) fn response(&self) -> ClientCertificateUrlResponse {
        let mut objects = self.objects();
        match self.answer {
            Answer::Unobtainable => return ClientCertificateUrlResponse::Unobtainable,
            Answer::Fuzzed => objects = self.fuzzed.clone(),
            Answer::Reversed => objects.reverse(),
            Answer::Extra => objects.push(Vec::new()),
            Answer::Fetched | Answer::WrongIdFirst => {}
        }
        ClientCertificateUrlResponse::Fetched(objects)
    }

    pub(super) fn expected(&self) -> Expected {
        let fixture = fixture();
        let url_error = |e: CertificateUrlError| Expected::Err(Error::CertificateUrl(e));
        if self.sends_urls() && !self.surfaces() {
            return url_error(CertificateUrlError::RefusedByPolicy);
        }
        if !self.surfaces() {
            return if self.with_chain {
                Expected::Ok(Some(fixture.chain.clone()))
            } else if self.mandatory {
                Expected::Fails
            } else {
                Expected::Ok(None)
            };
        }
        let objects = self.objects();
        let policy = self.policy.as_ref().expect("policy");
        let total: usize = objects.iter().map(Vec::len).sum();
        let chain = match self.urls.as_ref().expect("URLs").chain_type() {
            CertChainType::PkiPath => fixture.chain.clone(),
            _ => objects.iter().cloned().map(CertificateDer::from).collect(),
        };
        match self.answer {
            Answer::Unobtainable => url_error(CertificateUrlError::Unobtainable),
            Answer::Extra => url_error(CertificateUrlError::WrongObjectCount),
            Answer::Fuzzed if self.fuzzed != objects => Expected::Fails,
            _ if total > policy.max_fetched_len => url_error(CertificateUrlError::FetchedTooLarge),
            Answer::Reversed if objects.len() > 1 => url_error(CertificateUrlError::HashMismatch),
            _ => Expected::Ok(Some(chain)),
        }
    }
}

/// Handshakes that completed with a chain fetched by URL, for the seed
/// test.
static FETCHED: AtomicUsize = AtomicUsize::new(0);

/// Checks a finished handshake against the model.
pub(super) fn check(
    plan: &Plan,
    surfaced: usize,
    client: Result<(), Error>,
    server: Result<(), Error>,
    peer: Option<&[CertificateDer<'static>]>,
) {
    assert_eq!(surfaced, usize::from(plan.surfaces()), "queries");
    match plan.expected() {
        Expected::Ok(chain) => {
            assert!(client.is_ok() && server.is_ok(), "{client:?} {server:?}");
            assert_eq!(peer, chain.as_deref());
            if surfaced != 0 {
                FETCHED.fetch_add(1, Ordering::Relaxed);
            }
        }
        Expected::Err(error) => {
            assert_eq!(server, Err(error));
            assert!(peer.is_none());
        }
        Expected::Fails => {
            assert!(server.is_err(), "the server accepted");
            assert!(peer.is_none());
        }
    }
}

// --------------------------------------------------------------- operations

fn pki_path(input: &mut Input) {
    let fixture = fixture();
    if input.bool() {
        let der = input.field();
        if let Ok(chain) = decode_pki_path(der) {
            assert!((1..=16).contains(&chain.len()));
            assert_eq!(encode_pki_path(&chain).expect("re-encodes"), der);
        }
        return;
    }
    let chain: Vec<CertificateDer<'static>> = (0..input.choose(18))
        .map(|_| match input.choose(4) {
            0 => CertificateDer::from(input.short_field().to_vec()),
            n => fixture.chain[n % 2].clone(),
        })
        .collect();
    match encode_pki_path(&chain) {
        Ok(der) => assert_eq!(decode_pki_path(&der).expect("decodes"), chain),
        Err(_) => assert!(
            !(1..=16).contains(&chain.len()) || chain.iter().any(|c| !fixture.chain.contains(c)),
            "a chain of real certificates was refused"
        ),
    }
}

fn urls(input: &mut Input) {
    let mut entries = Vec::new();
    for _ in 0..input.choose(4) {
        let url = match input.choose(3) {
            0 => {
                let len = usize::from(input.u16()) + 1;
                format!("http://x/{}", "a".repeat(len))
            }
            _ => String::from_utf8_lossy(input.short_field()).into_owned(),
        };
        let object = input.short_field();
        let made = if input.bool() {
            UrlAndHash::new(url.clone(), input.array())
        } else {
            UrlAndHash::for_object(url.clone(), object, sha1)
        };
        assert_eq!(made.is_ok(), url_ok(&url), "{url:?}");
        if let Ok(made) = made {
            assert_eq!(made.url(), url);
            entries.push(made);
        }
    }
    let len: usize = entries.iter().map(|e| 23 + e.url().len()).sum();
    let fits = len <= 0xffff;
    if let Some(first) = entries.first().cloned() {
        let path = CertificateUrl::pkipath(first.clone());
        assert_eq!(path.is_ok(), 23 + first.url().len() <= 0xffff);
        if let Ok(path) = path {
            assert_eq!(path.chain_type(), CertChainType::PkiPath);
            assert_eq!(path.entries()[0].sha1_hash(), first.sha1_hash());
        }
    }
    let list = CertificateUrl::individual_certs(entries.clone());
    assert_eq!(list.is_ok(), fits && !entries.is_empty());
    if let Ok(list) = list {
        assert_eq!(list.chain_type(), CertChainType::IndividualCerts);
        assert_eq!(list.entries(), entries);
        let mut key = CertifiedKey::new(Vec::new(), fixture().client_key.clone());
        key.set_certificate_url(Some(list.clone()));
        assert_eq!(key.certificate_url(), Some(&list));
        key.set_certificate_url(None);
        assert!(key.certificate_url().is_none());
    }
}

/// The certificate URL operation: a sub-operation byte (modulo 5), then
/// its arguments: 0 PkiPath, 1 URLs, 2 buffered handshake (bit 0 of the
/// next byte: answer through `Connection`), 3 unbuffered handshake, 4 Tokio
/// handshake (the next byte picks the acceptor).
pub(super) fn certificate_url(input: &mut Input, handshakes: &mut usize) {
    let op = input.choose(5);
    if op >= 2 {
        if *handshakes >= MAX_HANDSHAKES {
            return;
        }
        *handshakes += 1;
    }
    match op {
        0 => pki_path(input),
        1 => urls(input),
        2 => {
            let via_enum = input.bool();
            handshake::buffered(&Plan::read(input), via_enum);
        }
        3 => handshake::unbuffered(&Plan::read(input)),
        _ => {
            let acceptor = input.choose(6);
            asynchronous::run(&Plan::read(input), acceptor);
        }
    }
}

// ------------------------------------------------------------------- seeds

/// A handshake plan: flags, URL choice (and fuzzed URL), policy choice
/// (and its settings), answer, fuzzed objects.
fn plan_seed(flags: u8, urls: u8, policy: &[u8], answer: u8) -> Vec<u8> {
    let mut seed = vec![flags, urls];
    if urls == 2 {
        put_short_field(&mut seed, b"HTTP://certs.example/x?y");
    }
    seed.extend_from_slice(policy);
    seed.push(answer);
    if answer == 1 {
        seed.push(2);
        put_field(&mut seed, &served(EE_URL));
        put_field(&mut seed, &served(CA_URL));
    } else {
        seed.push(0);
    }
    seed
}

/// Seeds of the certificate URL operation, each starting with `op`, the
/// operation byte of `tls_auth`.
pub(super) fn seeds(op: u8) -> Vec<Vec<u8>> {
    let fixture = fixture();
    let mut seeds = Vec::new();
    // PkiPath: decode the real one and broken ones; encode real elements,
    // too many, and garbage
    for der in [&fixture.path[..], &fixture.path[..10], &[0x30, 0x80, 0, 0]] {
        let mut seed = vec![op, 0, 1];
        put_field(&mut seed, der);
        seeds.push(seed);
    }
    seeds.push(vec![op, 0, 0, 2, 1, 2]);
    seeds.push(vec![op, 0, 0, 17]);
    seeds.push(vec![op, 0, 0, 1, 0, 2, 0x30, 0]);
    // URLs: printable, with a space, long, and a hash given directly
    let mut seed = vec![op, 1, 3, 1];
    put_short_field(&mut seed, b"http://a/b");
    seed.extend_from_slice(&[0, 0, 1]);
    put_short_field(&mut seed, b"http://a b");
    put_short_field(&mut seed, b"o");
    seed.extend_from_slice(&[0, 0, 0x7f, 0xf0, 0, 0]);
    seeds.push(seed);
    let mut seed = vec![op, 1, 3, 0, 0x80, 0, 0, 0, 0, 0x80, 0, 0, 0, 1, 2, 0, 0x7f];
    seed.extend_from_slice(&[0, 0]);
    seeds.push(seed);

    // Handshakes: each URL form with the default policy and each answer
    let default = [1u8];
    let mut plans = Vec::new();
    for urls in [0u8, 1, 2, 4] {
        for answer in [5u8, 0, 1, 2, 3, 4] {
            plans.push(plan_seed(0, urls, &default, answer));
        }
    }
    // no URLs, TLS 1.3, not enabled, no policy, without a chain
    plans.push(plan_seed(8, 3, &default, 5));
    plans.push(plan_seed(2 | 8, 0, &default, 5));
    plans.push(plan_seed(1 | 8, 0, &default, 5));
    plans.push(plan_seed(4 | 8, 0, &[0], 5));
    plans.push(plan_seed(4, 3, &default, 5));
    // no certificate at all, in TLS 1.2 and TLS 1.3 (an empty Certificate)
    plans.push(plan_seed(0, 3, &default, 5));
    plans.push(plan_seed(2, 0, &default, 5));
    // tuned policies: https allowed, too few URLs, short URLs, a small
    // fetch limit, an invalid scheme, zero limits
    plans.push(plan_seed(0, 0, &[3, 0, 3, 8, 0, 3], 5));
    plans.push(plan_seed(0, 0, &[3, 4, 1, 8, 0, 3], 5));
    plans.push(plan_seed(0, 0, &[3, 4, 3, 0, 4, 3], 5));
    plans.push(plan_seed(0, 0, &[3, 4, 3, 8, 0, 0, 1, 0], 5));
    plans.push(plan_seed(0, 0, &[3, 3, 2, b'1', b'x', 3, 8, 0, 3], 5));
    plans.push(plan_seed(0, 0, &[3, 4, 0, 8, 0, 3], 5));
    for (i, plan) in plans.iter().enumerate() {
        let driver = [2u8, 3, 4][i % 3];
        let mut seed = vec![op, driver];
        match driver {
            2 => seed.push(i as u8),
            4 => seed.push((i / 3) as u8),
            _ => {}
        }
        seed.extend_from_slice(plan);
        seeds.push(seed);
    }
    // every driver and acceptor with the objects fetched
    let fetched = plan_seed(0, 0, &default, 5);
    for driver in [[2u8, 0], [2, 1]] {
        seeds.push([&[op][..], &driver, &fetched].concat());
    }
    seeds.push([&[op, 3][..], &fetched].concat());
    for acceptor in 0..6u8 {
        seeds.push([&[op, 4, acceptor][..], &fetched].concat());
    }
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds complete handshakes with a fetched chain on every driver,
    /// not only refusals.
    #[test]
    fn seeds_fetch_chains() {
        crate::init();
        let before = FETCHED.load(Ordering::Relaxed);
        for seed in seeds(7) {
            super::super::run(&seed);
        }
        let fetched = FETCHED.load(Ordering::Relaxed) - before;
        assert!(fetched >= 20, "{fetched}");
    }
}

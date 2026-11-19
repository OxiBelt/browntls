//! The TLS server pod: one listener without a stapled response (clients
//! must look the status up themselves) and one whose certificate resolver
//! staples a response that the server fetched from the responder and
//! refreshes on request.
//!
//! Test protocol, one command per connection: `STATUS` reports the staple
//! in use, `ROTATE` (stapling listener only) first replaces it with a
//! newer response.

use std::sync::Arc;
use std::time::Duration;

use browntls::ServerConfig;
use browntls::pki_types::PrivateKeyDer;
use browntls::pki_types::pem::PemObject;
use browntls::revocation::{RevocationDigests, ServerStapleResolver, StapleInstall};
use browntls::sign::CertifiedKey;
use browntls::time_provider::DefaultTimeProvider;
use browntls_tokio::{TlsAcceptor, browntls};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::http::fetch_ocsp;
use crate::support::{
    Authority, Failure, Options, STEP_TIMEOUT, bounded, certificates, fingerprint, provider,
    read_line, write_line,
};

/// Longest OCSP response the server accepts for its own certificate.
const MAX_RESPONSE_LEN: usize = 16 * 1024;

/// How often a refresh is tried: at start-up while the network policy of a
/// new pod is still being programmed, and on `ROTATE` until the responder
/// produces a response newer than the one in use (its timestamps have a
/// resolution of one second).
const REFRESH_ATTEMPTS: usize = 30;
const REFRESH_PAUSE: Duration = Duration::from_secs(1);

/// The stapling resolver and the staple the test protocol reports.
struct Staples {
    resolver: Arc<ServerStapleResolver>,
    authority: Authority,
    /// The number of responses installed so far and the fingerprint of the
    /// one in use. The lock also serializes refreshes.
    current: Mutex<(u64, String)>,
}

impl Staples {
    /// One explicit refresh: asks the resolver for its query, sends it to
    /// the authorized responder and installs the answer, which the
    /// resolver verifies for the server's certificate first. Returns the
    /// fingerprint of a newly installed response.
    async fn refresh(&self) -> Result<Option<String>, Failure> {
        let query = self
            .resolver
            .refresh_query()?
            .ok_or("the certificate names no OCSP responder")?;
        let responder = self.authority.authorized_responder(query.query())?;
        let response = bounded(
            "certificate status fetch",
            fetch_ocsp(query.query(), &responder, MAX_RESPONSE_LEN),
        )
        .await?;
        let fingerprint = fingerprint(&response);
        match self.resolver.install(&query, response)? {
            StapleInstall::Installed { expires } => {
                let lifetime = self.resolver.remaining_lifetime(expires);
                println!("staple installed sha256={fingerprint} lifetime={lifetime:?}");
                Ok(Some(fingerprint))
            }
            StapleInstall::Obsolete => Ok(None),
            other => Err(format!("certificate status response not installed: {other:?}").into()),
        }
    }

    /// Refreshes until a response newer than the one in use is installed.
    async fn rotate(&self) -> Result<(u64, String), Failure> {
        let mut current = self.current.lock().await;
        let mut last_error: Failure = "no refresh attempted".into();
        for attempt in 1..=REFRESH_ATTEMPTS {
            match self.refresh().await {
                Ok(Some(fingerprint)) => {
                    *current = (current.0 + 1, fingerprint);
                    return Ok(current.clone());
                }
                Ok(None) => last_error = "the responder's answer is not newer".into(),
                Err(err) => {
                    println!("refresh attempt {attempt} failed: {err}");
                    last_error = err;
                }
            }
            tokio::time::sleep(REFRESH_PAUSE).await;
        }
        Err(format!("no newer staple after {REFRESH_ATTEMPTS} attempts: {last_error}").into())
    }
}

pub(crate) async fn run(options: &Options) -> Result<(), Failure> {
    let authority = Authority::load(options)?;
    let provider = provider();
    let chain = certificates(options.get("cert")?)?;
    let key_path = options.get("key")?;
    let key =
        PrivateKeyDer::from_pem_file(key_path).map_err(|err| format!("{key_path}: {err:?}"))?;

    let plain = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain.clone(), key.clone_key())?;

    let credential = CertifiedKey::from_der(chain, key, &provider)?;
    let resolver = Arc::new(ServerStapleResolver::new(
        credential,
        authority.roots.clone(),
        provider.clone(),
        RevocationDigests::native(),
        Arc::new(DefaultTimeProvider),
    )?);
    let stapling = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());

    let staples = Arc::new(Staples {
        resolver,
        authority,
        current: Mutex::new((0, String::from("none"))),
    });
    // The first staple, before any client is served.
    let (generation, fingerprint) = staples.rotate().await?;
    println!("first staple generation={generation} sha256={fingerprint}");

    let plain_listener = TcpListener::bind(options.get("plain-listen")?).await?;
    let staple_listener = TcpListener::bind(options.get("staple-listen")?).await?;
    println!("READY");
    let plain_task = tokio::spawn(serve(plain_listener, Arc::new(plain), None));
    let staple_task = tokio::spawn(serve(staple_listener, Arc::new(stapling), Some(staples)));
    let (plain_result, staple_result) = tokio::join!(plain_task, staple_task);
    plain_result??;
    staple_result??;
    Ok(())
}

async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    staples: Option<Arc<Staples>>,
) -> Result<(), Failure> {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let staples = staples.clone();
        tokio::spawn(async move {
            match connection(tcp, acceptor, staples).await {
                Ok(served) => println!("{peer}: {served}"),
                Err(err) => println!("{peer}: connection failed: {err}"),
            }
        });
    }
}

async fn connection(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    staples: Option<Arc<Staples>>,
) -> Result<String, Failure> {
    let mut tls = bounded("handshake", acceptor.accept(tcp)).await?;
    let command = bounded("command", read_line(&mut tls)).await?;
    let reply = match (command.as_str(), &staples) {
        ("STATUS", None) => String::from("OK staple=none generation=0"),
        ("STATUS", Some(staples)) => {
            let current = staples.current.lock().await;
            format!("OK staple={} generation={}", current.1, current.0)
        }
        ("ROTATE", Some(staples)) => {
            let rotation =
                REFRESH_PAUSE * u32::try_from(REFRESH_ATTEMPTS).unwrap_or(u32::MAX) + STEP_TIMEOUT;
            match tokio::time::timeout(rotation, staples.rotate()).await {
                Ok(Ok((generation, fingerprint))) => {
                    format!("OK staple={fingerprint} generation={generation}")
                }
                Ok(Err(err)) => format!("ERR {err}"),
                Err(_) => String::from("ERR rotation timed out"),
            }
        }
        _ => String::from("ERR unknown command"),
    };
    bounded("reply", write_line(&mut tls, &reply)).await?;
    // The peer closes first; a missing close_notify is not an error here.
    let _ = bounded("close", read_line(&mut tls)).await;
    Ok(format!("{command} -> {reply}"))
}

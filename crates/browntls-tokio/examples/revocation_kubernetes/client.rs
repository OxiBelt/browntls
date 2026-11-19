//! The TLS client pods: one scenario per run, each asserting its outcome.
//!
//! * `live`: no staple is offered, the verifier asks for the certificate's
//!   status and the fetcher gets it from the responder.
//! * `denied`: as `live`, from a pod whose egress to the responder is
//!   denied while the TLS server stays reachable: the handshake must fail
//!   for want of a revocation status.
//! * `staple`: no live lookup is configured and the responder is out of
//!   reach, so only the server's staple can satisfy the verifier, before
//!   and after the server rotates it.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use browntls::client::WebPkiServerVerifier;
use browntls::pki_types::ServerName;
use browntls::revocation::{
    RevocationDigests, RevocationPolicy, RevocationQuery, RevocationStatus,
};
use browntls::time_provider::DefaultTimeProvider;
use browntls::{CertificateError, ClientConfig};
use browntls_tokio::client::TlsStream;
use browntls_tokio::revocation::{FetchLimits, RevocationFetcher};
use browntls_tokio::{TlsConnector, browntls};
use tokio::net::TcpStream;

use crate::http::{fetch_ocsp, split_url};
use crate::support::{
    Authority, Failure, Options, STEP_TIMEOUT, bounded, provider, read_line, write_line,
};

/// How often a step that must succeed is tried while the network policy
/// of this new pod is still being programmed.
const ATTEMPTS: usize = 20;
const PAUSE: Duration = Duration::from_secs(2);

/// Bound on one certificate status fetch.
const FETCH_DEADLINE: Duration = Duration::from_secs(3);

/// How often, and for how long each time, the client tries to reach a
/// responder that must be out of reach.
const DENIAL_PROBES: usize = 3;
const DENIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the server may take to rotate its staple.
const ROTATION_TIMEOUT: Duration = Duration::from_secs(60);

struct Client {
    connector: TlsConnector,
    name: ServerName<'static>,
    /// How many fetches the connector's fetcher started.
    fetches: Arc<AtomicUsize>,
}

impl Client {
    /// A client that requires a revocation status for the server's
    /// certificate. With `live` the verifier may ask for one and a fetcher
    /// answers from the authorized responder; without, only evidence that
    /// comes with the handshake counts.
    fn new(options: &Options, authority: &Arc<Authority>, live: bool) -> Result<Self, Failure> {
        let provider = provider();
        let mut policy = RevocationPolicy::new(RevocationDigests::native());
        if live {
            policy = policy.with_live_ocsp(Arc::new(DefaultTimeProvider));
        }
        let verifier =
            WebPkiServerVerifier::builder_with_provider(authority.roots.clone(), provider.clone())
                .with_revocation_policy(policy)
                .build()
                .map_err(|err| format!("verifier: {err:?}"))?;
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_webpki_verifier(verifier)
            .with_no_client_auth();
        let mut connector = TlsConnector::from(Arc::new(config));
        let fetches = Arc::new(AtomicUsize::new(0));
        if live {
            let authority = authority.clone();
            let counter = fetches.clone();
            let fetch = move |query: RevocationQuery, limits: FetchLimits| {
                counter.fetch_add(1, Ordering::Relaxed);
                let responder = authority.authorized_responder(&query);
                async move { fetch_ocsp(&query, &responder?, limits.max_response_len).await }
            };
            // Nothing is remembered: every handshake of the test asks the
            // responder, and a failure is not answered from memory.
            let fetcher = RevocationFetcher::builder(fetch)
                .deadline(FETCH_DEADLINE)
                .cache_ttl(Duration::ZERO)
                .unavailable_ttl(Duration::ZERO)
                .build();
            connector = connector.revocation_fetcher(Arc::new(fetcher));
        }
        Ok(Self {
            connector,
            name: ServerName::try_from(options.get("name")?.to_owned())
                .map_err(|_| "invalid --name")?,
            fetches,
        })
    }

    async fn handshake(&self, address: &str) -> io::Result<TlsStream<TcpStream>> {
        let tcp = bounded("TCP connect", TcpStream::connect(address)).await?;
        bounded("handshake", self.connector.connect(self.name.clone(), tcp)).await
    }

    /// A handshake that must succeed with a certificate known to be good,
    /// followed by one command of the test protocol. Returns the staple
    /// fingerprint and generation the server reports.
    async fn command(
        &self,
        address: &str,
        command: &str,
        reply_timeout: Duration,
    ) -> Result<(String, String), Failure> {
        let mut tls = self.handshake(address).await?;
        let status = tls.get_ref().1.peer_revocation_status();
        if status != Some(RevocationStatus::Good) {
            return Err(format!("revocation status is {status:?}, not Good").into());
        }
        bounded("command", write_line(&mut tls, command)).await?;
        let reply = tokio::time::timeout(reply_timeout, read_line(&mut tls))
            .await
            .map_err(|_| "no reply in time")??;
        let fields = reply
            .strip_prefix("OK staple=")
            .and_then(|rest| rest.split_once(" generation="))
            .ok_or_else(|| format!("{command} answered {reply}"))?;
        Ok((fields.0.to_owned(), fields.1.to_owned()))
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::Relaxed)
    }
}

/// Whether a handshake failed because the verifier had no revocation
/// status for the server's certificate.
fn is_unknown_revocation_status(err: &io::Error) -> bool {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<browntls::Error>())
        .is_some_and(|tls| {
            matches!(
                tls,
                browntls::Error::InvalidCertificate(CertificateError::UnknownRevocationStatus)
            )
        })
}

/// Tries `step` until it succeeds, [`ATTEMPTS`] times at most.
async fn eventually<T, Fut>(what: &str, mut step: impl FnMut() -> Fut) -> Result<T, Failure>
where
    Fut: Future<Output = Result<T, Failure>>,
{
    let mut last = None;
    for attempt in 1..=ATTEMPTS {
        match step().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                println!("{what}: attempt {attempt} failed: {err}");
                last = Some(err);
            }
        }
        tokio::time::sleep(PAUSE).await;
    }
    Err(format!(
        "{what}: gave up: {}",
        last.map(|err| err.to_string()).unwrap_or_default()
    )
    .into())
}

/// Checks that TCP connections to the responder do not get through.
async fn responder_is_out_of_reach(authority: &Authority) -> Result<(), Failure> {
    let (address, _) = split_url(authority.responder())?;
    for probe in 1..=DENIAL_PROBES {
        match tokio::time::timeout(DENIAL_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(_)) => return Err(format!("responder {address} is reachable").into()),
            Ok(Err(err)) => println!("responder probe {probe}: {err}"),
            Err(_) => println!("responder probe {probe}: no answer in {DENIAL_TIMEOUT:?}"),
        }
    }
    Ok(())
}

/// Checks that the TLS server accepts TCP connections from this pod.
async fn server_is_reachable(address: &str) -> Result<(), Failure> {
    eventually("TLS server TCP connect", || async {
        bounded("TCP connect", TcpStream::connect(address)).await?;
        Ok(())
    })
    .await
}

/// A handshake that must fail for want of a revocation status.
async fn refused_for_unknown_status(client: &Client, address: &str) -> Result<(), Failure> {
    match client.handshake(address).await {
        Ok(_) => Err("handshake succeeded without a revocation status".into()),
        Err(err) if is_unknown_revocation_status(&err) => Ok(()),
        Err(err) => Err(format!("handshake failed for another reason: {err}").into()),
    }
}

pub(crate) async fn run(options: &Options) -> Result<(), Failure> {
    let authority = Arc::new(Authority::load(options)?);
    let plain = options.get("plain")?;
    let staple = options.get("staple")?;
    match options.get("scenario")? {
        "live" => live(&Client::new(options, &authority, true)?, plain).await,
        "denied" => denied(&Client::new(options, &authority, true)?, &authority, plain).await,
        "staple" => {
            let client = Client::new(options, &authority, false)?;
            stapled(&client, &authority, plain, staple).await
        }
        other => Err(format!("unknown scenario {other}").into()),
    }
}

async fn live(client: &Client, plain: &str) -> Result<(), Failure> {
    let (staple, _) = eventually("live lookup", || {
        client.command(plain, "STATUS", STEP_TIMEOUT)
    })
    .await?;
    if staple != "none" {
        return Err("the listener without staples reported one".into());
    }
    let fetches = client.fetches();
    if fetches == 0 {
        return Err("the certificate was accepted without a lookup".into());
    }
    println!("RESULT live ok status=Good fetches={fetches}");
    Ok(())
}

async fn denied(client: &Client, authority: &Authority, plain: &str) -> Result<(), Failure> {
    server_is_reachable(plain).await?;
    responder_is_out_of_reach(authority).await?;
    refused_for_unknown_status(client, plain).await?;
    let fetches = client.fetches();
    if fetches == 0 {
        return Err("the handshake failed before any lookup was attempted".into());
    }
    // The server is still there after the refusal.
    server_is_reachable(plain).await?;
    println!("RESULT denied ok error=UnknownRevocationStatus fetches={fetches}");
    Ok(())
}

async fn stapled(
    client: &Client,
    authority: &Authority,
    plain: &str,
    staple: &str,
) -> Result<(), Failure> {
    server_is_reachable(staple).await?;
    responder_is_out_of_reach(authority).await?;
    // Control: without a staple this client has no evidence at all.
    refused_for_unknown_status(client, plain).await?;

    let (first, first_generation) = client.command(staple, "STATUS", STEP_TIMEOUT).await?;
    let (rotated, _) = client.command(staple, "ROTATE", ROTATION_TIMEOUT).await?;
    let (second, second_generation) = client.command(staple, "STATUS", STEP_TIMEOUT).await?;
    if first == "none" || second == "none" {
        return Err("the stapling listener reported no staple".into());
    }
    if second != rotated || second == first || second_generation == first_generation {
        return Err(format!("the staple did not rotate: {first} then {second}").into());
    }
    println!("RESULT staple ok status=Good first={first} second={second}");
    Ok(())
}

//! Keeping a server's stapled certificate status (OCSP) responses fresh.
//!
//! A server staples the response of its certificate's responder to its
//! handshakes, and has to replace it before it expires.
//! [`ServerStapleResolver`] says what to ask the responder for and
//! verifies each new response before it staples it; [`StapleRefresh`] is
//! the loop around it, for the application to spawn, and decides when to
//! ask:
//!
//! ```no_run
//! use std::io;
//! use std::sync::Arc;
//!
//! use browntls_tokio::browntls::revocation::{RevocationQuery, ServerStapleResolver};
//! use browntls_tokio::revocation::FetchLimits;
//! use browntls_tokio::revocation::staple::StapleRefresh;
//!
//! async fn fetch(query: RevocationQuery, limits: FetchLimits) -> io::Result<Vec<u8>> {
//!     // The application's HTTP client, as for the queries about peers.
//! #   let _ = (query, limits);
//! #   Err(io::ErrorKind::Unsupported.into())
//! }
//!
//! # async fn run(resolver: Arc<ServerStapleResolver>) {
//! let mut refresh = StapleRefresh::new(resolver, fetch);
//! // Start with a stapled response, then keep it fresh.
//! let _ = refresh.refresh_once().await;
//! let task = tokio::spawn(refresh.run());
//! // ...
//! task.abort();
//! # }
//! ```
//!
//! The application makes the HTTP request, through the same
//! [`FetchRevocation`] callback as for the queries about peers; here the
//! query is about the server's own certificate. The response goes from the
//! callback straight to [`ServerStapleResolver::install`], which staples it
//! only after verifying it for that certificate: nothing here parses or
//! judges a response, and there is no way to staple one around that check.
//! A response that is refused leaves the one in use in place. The loop
//! needs the runtime's time driver.

use std::convert::Infallible;
use std::fmt;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::sync::Arc;
use std::time::Duration;

use browntls::revocation::{ServerStapleResolver, StapleInstall};

use super::{FetchFuture, FetchLimits, FetchRevocation};

/// What one round of refreshing did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StapleRefreshed {
    /// How many responses were verified and are stapled from now on.
    pub installed: usize,
    /// How many responses came too late: the certificate they were
    /// fetched for is not the one in use any more.
    pub obsolete: usize,
    /// How many responses say that the server's certificate is revoked.
    /// What the server staples then is the resolver's decision; the
    /// certificate needs replacing.
    pub revoked: usize,
    /// The shortest time left to any response installed in this round,
    /// zero for one that had expired already; when nothing was installed
    /// because the response was obsolete, the time left to the staple in
    /// use. The loop refreshes after half of it.
    pub shortest_lifetime: Option<Duration>,
}

/// Why a round of refreshing ended early. Responses it had installed
/// before stay installed.
#[derive(Debug)]
#[non_exhaustive]
pub enum StapleRefreshError {
    /// The resolver could not say what to fetch.
    Query(browntls::Error),
    /// The application's fetch failed.
    Fetch(std::io::Error),
    /// The fetch did not answer within the deadline.
    Deadline,
    /// The response was empty or longer than
    /// [`FetchLimits::max_response_len`].
    Length {
        /// The length of the response.
        len: usize,
    },
    /// The resolver refused the response; the one in use stays.
    Rejected(browntls::Error),
}

impl fmt::Display for StapleRefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query(err) => write!(f, "no certificate status request to send: {err}"),
            Self::Fetch(err) => write!(f, "fetching the certificate status response failed: {err}"),
            Self::Deadline => f.write_str("fetching the certificate status response timed out"),
            Self::Length { len } => {
                write!(
                    f,
                    "certificate status response of {len} bytes is out of bounds"
                )
            }
            Self::Rejected(err) => write!(f, "certificate status response refused: {err}"),
        }
    }
}

impl std::error::Error for StapleRefreshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fetch(err) => Some(err),
            Self::Query(err) | Self::Rejected(err) => Some(err),
            Self::Deadline | Self::Length { .. } => None,
        }
    }
}

/// One fetch under its bounds: the deadline, and the length of the answer.
async fn bounded(fetch: FetchFuture, limits: FetchLimits) -> Result<Vec<u8>, StapleRefreshError> {
    let response = match tokio::time::timeout(limits.deadline, fetch).await {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => return Err(StapleRefreshError::Fetch(err)),
        Err(_) => return Err(StapleRefreshError::Deadline),
    };
    let len = response.len();
    if len == 0 || len > limits.max_response_len {
        return Err(StapleRefreshError::Length { len });
    }
    Ok(response)
}

/// When the loop refreshes next.
#[derive(Clone, Copy, Debug)]
struct Schedule {
    /// The longest wait after a round that succeeded.
    interval: Duration,
    /// The shortest wait of all, and the first after a failure.
    retry_min: Duration,
    /// The longest wait after a failure.
    retry_max: Duration,
    /// The wait after the next failure.
    retry: Duration,
}

impl Schedule {
    /// The wait after a round: half of what is left to the response that
    /// expires first, within the interval, or the next step of the backoff.
    fn wait_after(&mut self, round: Result<&StapleRefreshed, &StapleRefreshError>) -> Duration {
        match round {
            Ok(done) => {
                self.retry = self.retry_min;
                done.shortest_lifetime
                    .map_or(self.interval, |left| (left / 2).min(self.interval))
                    .max(self.retry_min)
            }
            Err(_) => {
                let wait = self.retry.max(self.retry_min);
                self.retry = wait.saturating_mul(2).min(self.retry_max);
                wait
            }
        }
    }
}

type Observer = Box<dyn FnMut(Result<&StapleRefreshed, &StapleRefreshError>) + Send>;

/// The loop that keeps a server's stapled responses fresh; see the
/// [module documentation](self).
pub struct StapleRefresh {
    resolver: Arc<ServerStapleResolver>,
    fetch: Arc<dyn FetchRevocation>,
    observe: Option<Observer>,
    limits: FetchLimits,
    schedule: Schedule,
}

impl StapleRefresh {
    /// A loop that fetches what `resolver` asks for with `fetch` and
    /// installs it there: at least every hour, each fetch bounded to 10
    /// seconds and 64 KiB, a failed round tried again after 30 seconds and
    /// then at doubling waits of up to 15 minutes.
    pub fn new(resolver: Arc<ServerStapleResolver>, fetch: impl FetchRevocation + 'static) -> Self {
        let retry_min = Duration::from_secs(30);
        Self {
            resolver,
            fetch: Arc::new(fetch),
            observe: None,
            limits: FetchLimits {
                deadline: Duration::from_secs(10),
                max_response_len: 64 * 1024,
            },
            schedule: Schedule {
                interval: Duration::from_secs(60 * 60),
                retry_min,
                retry_max: Duration::from_secs(15 * 60),
                retry: retry_min,
            },
        }
    }

    /// The longest wait between a round that succeeded and the next. The
    /// wait is shorter when a response installed in the round has less
    /// than twice that left: half of what it has left.
    pub fn interval(mut self, interval: Duration) -> Self {
        self.schedule.interval = interval;
        self
    }

    /// The wait after a failed round (`first`), doubled after each further
    /// failure up to `longest`. `first` is also the shortest wait after a
    /// success, however soon a response expires: the responder is never
    /// asked more often.
    pub fn retry(mut self, first: Duration, longest: Duration) -> Self {
        let first = first.max(Duration::from_millis(1));
        self.schedule.retry_min = first;
        self.schedule.retry_max = longest.max(first);
        self.schedule.retry = first;
        self
    }

    /// How long one fetch may take.
    pub fn deadline(mut self, deadline: Duration) -> Self {
        self.limits.deadline = deadline;
        self
    }

    /// The longest response handed to the resolver.
    pub fn max_response_len(mut self, len: usize) -> Self {
        self.limits.max_response_len = len;
        self
    }

    /// Calls `observe` after every round of [`run`](Self::run), with what
    /// it did or why it ended early (to log it, to count failures, to
    /// raise the alarm over a revoked certificate).
    pub fn observe(
        mut self,
        observe: impl FnMut(Result<&StapleRefreshed, &StapleRefreshError>) + Send + 'static,
    ) -> Self {
        self.observe = Some(Box::new(observe));
        self
    }

    /// Fetches and validates a response for the resolver's current leaf.
    /// A server may call this before accepting connections.
    pub async fn refresh_once(&mut self) -> Result<StapleRefreshed, StapleRefreshError> {
        let mut done = StapleRefreshed::default();
        if let Some(staple) = self
            .resolver
            .refresh_query()
            .map_err(StapleRefreshError::Query)?
        {
            let fetch = self.fetch.fetch(staple.query().clone(), self.limits);
            let response = bounded(fetch, self.limits).await?;
            let installed = self
                .resolver
                .install(&staple, response)
                .map_err(StapleRefreshError::Rejected)?;
            match installed {
                StapleInstall::Installed { expires, .. } => {
                    done.installed = 1;
                    done.shortest_lifetime = self.resolver.remaining_lifetime(expires);
                }
                StapleInstall::Obsolete => {
                    done.obsolete = 1;
                    done.shortest_lifetime = self
                        .resolver
                        .staple_expiry()
                        .and_then(|expires| self.resolver.remaining_lifetime(expires));
                }
                StapleInstall::Revoked => done.revoked = 1,
                _ => {}
            }
        }
        Ok(done)
    }

    /// Refreshes now and then for ever: spawn the future, and abort or
    /// drop it to stop.
    pub async fn run(mut self) -> Infallible {
        loop {
            let round = self.refresh_once().await;
            if let Some(observe) = &mut self.observe {
                observe(round.as_ref());
            }
            let mut wait = self.schedule.wait_after(round.as_ref());
            if round.is_err()
                && let Some(left) = self
                    .resolver
                    .staple_expiry()
                    .and_then(|expires| self.resolver.remaining_lifetime(expires))
            {
                wait = wait.min(left / 2);
            }
            let jitter = RandomState::new().build_hasher().finish() % 11;
            let wait = (wait - (wait / 100) * jitter as u32).max(self.schedule.retry_min);
            tokio::time::sleep(wait).await;
        }
    }
}

impl fmt::Debug for StapleRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StapleRefresh")
            .field("limits", &self.limits)
            .field("schedule", &self.schedule)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule() -> Schedule {
        Schedule {
            interval: Duration::from_secs(3600),
            retry_min: Duration::from_secs(30),
            retry_max: Duration::from_secs(100),
            retry: Duration::from_secs(30),
        }
    }

    fn installed(left: Option<u64>) -> StapleRefreshed {
        StapleRefreshed {
            installed: 1,
            shortest_lifetime: left.map(Duration::from_secs),
            ..StapleRefreshed::default()
        }
    }

    #[test]
    fn a_round_that_succeeded_waits_half_the_shortest_lifetime_within_bounds() {
        let mut schedule = schedule();
        let mut secs = |round: StapleRefreshed| schedule.wait_after(Ok(&round)).as_secs();
        // Nothing was due: the interval.
        assert_eq!(secs(StapleRefreshed::default()), 3600);
        assert_eq!(secs(installed(Some(1000))), 500);
        // Never beyond the interval, never below the first retry wait.
        assert_eq!(secs(installed(Some(1_000_000))), 3600);
        assert_eq!(secs(installed(Some(10))), 30);
        assert_eq!(secs(installed(Some(0))), 30);
    }

    #[test]
    fn failures_back_off_to_the_longest_wait_and_a_success_starts_over() {
        let mut schedule = schedule();
        let failed = StapleRefreshError::Deadline;
        let waits: Vec<u64> = (0..4)
            .map(|_| schedule.wait_after(Err(&failed)).as_secs())
            .collect();
        assert_eq!(waits, [30, 60, 100, 100]);
        schedule.wait_after(Ok(&StapleRefreshed::default()));
        assert_eq!(schedule.wait_after(Err(&failed)).as_secs(), 30);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fetch_is_bounded_in_time_and_in_length() {
        let limits = FetchLimits {
            deadline: Duration::from_secs(2),
            max_response_len: 4,
        };
        let fetched = |response: Vec<u8>| -> FetchFuture { Box::pin(async move { Ok(response) }) };
        assert_eq!(
            bounded(fetched(vec![1; 4]), limits).await.ok(),
            Some(vec![1; 4])
        );
        assert!(matches!(
            bounded(fetched(vec![1; 5]), limits).await,
            Err(StapleRefreshError::Length { len: 5 })
        ));
        assert!(matches!(
            bounded(fetched(Vec::new()), limits).await,
            Err(StapleRefreshError::Length { len: 0 })
        ));
        assert!(matches!(
            bounded(Box::pin(std::future::pending()), limits).await,
            Err(StapleRefreshError::Deadline)
        ));
        let refused: FetchFuture =
            Box::pin(async { Err(std::io::ErrorKind::PermissionDenied.into()) });
        assert!(matches!(
            bounded(refused, limits).await,
            Err(StapleRefreshError::Fetch(_))
        ));
    }
}

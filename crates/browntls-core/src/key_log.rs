//! Logging of session secrets for debugging (NSS key log format).

use core::fmt::Debug;

/// A sink for session secrets in the NSS key log format.
///
/// Secrets written through this trait defeat the confidentiality of the
/// connection; enable it only in debugging builds.
pub trait KeyLog: Debug + Send + Sync {
    /// Logs `secret` for the connection identified by `client_random` under `label`.
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);

    /// Whether `log` would do anything for `label`; lets callers skip work.
    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

/// A [`KeyLog`] that discards everything.
#[derive(Debug)]
pub struct NoKeyLog;

impl KeyLog for NoKeyLog {
    fn log(&self, _: &str, _: &[u8], _: &[u8]) {}

    fn will_log(&self, _label: &str) -> bool {
        false
    }
}

//! Logging of session secrets for diagnostics (RFC 9850).

use core::fmt::Debug;

/// A sink for session secrets in the RFC 9850 key log format.
///
/// Connections invoke the sink only with the non-default `key-log` feature.
/// Use it with test traffic only. The application is responsible for access
/// control, retention, and disposal of any secrets its sink receives.
pub trait KeyLog: Debug + Send + Sync {
    /// Logs `secret` for the connection identified by `client_random` under
    /// `label`.
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);

    /// Whether `log` would do anything for `label`; lets callers skip work.
    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

#[cfg(feature = "key-log")]
pub(crate) fn emit(sink: &dyn KeyLog, label: &str, client_random: &[u8; 32], secret: &[u8]) {
    if sink.will_log(label) {
        sink.log(label, client_random, secret);
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

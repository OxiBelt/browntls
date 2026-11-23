//! A file sink for RFC 9850 diagnostic session secrets.

use core::fmt::{self, Debug, Formatter};
use std::io;
use std::path::Path;

use crate::key_log::KeyLog;

#[cfg(all(feature = "key-log", target_os = "linux"))]
mod unix;

/// An opt-in file sink for RFC 9850 session secrets.
///
/// Install it in a client or server configuration to record test traffic.
/// File logging requires the non-default `key-log` feature on Linux.
/// Use a private directory on a local filesystem with Unix
/// ownership, permission, and advisory-lock semantics.
pub struct KeyLogFile {
    #[cfg(all(feature = "key-log", target_os = "linux"))]
    sink: Option<unix::Sink>,
}

impl KeyLogFile {
    /// Opens the file selected by `SSLKEYLOGFILE`.
    ///
    /// An unset or empty variable, an unavailable sink, or an open error
    /// leaves the sink inactive. Open and write failures do not fail TLS.
    pub fn new() -> Self {
        Self {
            #[cfg(all(feature = "key-log", target_os = "linux"))]
            sink: unix::from_env(),
        }
    }

    /// Opens an explicitly authorized diagnostic path without reading the
    /// environment. Creates a private file or appends to an existing regular
    /// file with mode `0600` owned by the effective user.
    ///
    /// Returns [`io::ErrorKind::Unsupported`] when the sink is unavailable.
    /// Errors omit the path and any record data.
    pub fn try_from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        #[cfg(all(feature = "key-log", target_os = "linux"))]
        {
            Ok(Self {
                sink: Some(unix::Sink::open(path.as_ref())?),
            })
        }
        #[cfg(not(all(feature = "key-log", target_os = "linux")))]
        {
            let _ = path;
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}

impl Default for KeyLogFile {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyLog for KeyLogFile {
    fn log(&self, _label: &str, _client_random: &[u8], _secret: &[u8]) {
        #[cfg(all(feature = "key-log", target_os = "linux"))]
        if let Some(sink) = &self.sink {
            sink.log(_label, _client_random, _secret);
        }
    }

    fn will_log(&self, _label: &str) -> bool {
        #[cfg(all(feature = "key-log", target_os = "linux"))]
        {
            self.sink.as_ref().is_some_and(|sink| sink.will_log(_label))
        }
        #[cfg(not(all(feature = "key-log", target_os = "linux")))]
        false
    }
}

impl Debug for KeyLogFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyLogFile").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_key_log_discards_everything() {
        let sink = crate::NoKeyLog;
        assert!(!sink.will_log("CLIENT_RANDOM"));
        sink.log("CLIENT_RANDOM", &[0; 32], &[0; 48]);
    }

    #[cfg(not(all(feature = "key-log", target_os = "linux")))]
    #[test]
    fn unavailable_file_sink_is_inert() {
        let sink = KeyLogFile::new();
        assert!(!sink.will_log("CLIENT_RANDOM"));
        sink.log("CLIENT_RANDOM", &[0; 32], &[0; 48]);
        assert_eq!(
            KeyLogFile::try_from_path("not-opened").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}

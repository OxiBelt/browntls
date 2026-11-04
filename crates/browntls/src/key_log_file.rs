//! A [`KeyLog`] writing to the file named by `SSLKEYLOGFILE`.

use alloc::format;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use crate::key_log::KeyLog;
use crate::log::warning;

struct KeyLogFileInner {
    file: Option<File>,
    buf: Vec<u8>,
}

impl KeyLogFileInner {
    fn new(var: Option<OsString>) -> Self {
        let Some(path) = var else {
            return Self {
                file: None,
                buf: Vec::new(),
            };
        };

        let path = Path::new(&path);
        let file = match open_private(path) {
            Ok(f) => Some(f),
            Err(e) => {
                warning!("unable to create key log file {:?}: {}", path, e);
                None
            }
        };
        Self {
            file,
            buf: Vec::new(),
        }
    }

    fn try_write(
        &mut self,
        label: &str,
        client_random: &[u8],
        secret: &[u8],
    ) -> std::io::Result<()> {
        let Some(file) = &mut self.file else {
            return Ok(());
        };
        self.buf.clear();
        self.buf.extend_from_slice(label.as_bytes());
        self.buf.push(b' ');
        for b in client_random {
            self.buf.extend_from_slice(format!("{b:02x}").as_bytes());
        }
        self.buf.push(b' ');
        for b in secret {
            self.buf.extend_from_slice(format!("{b:02x}").as_bytes());
        }
        self.buf.push(b'\n');
        file.write_all(&self.buf)
    }
}

/// Opens (or creates) the log file readable only by its owner.
fn open_private(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

impl Debug for KeyLogFileInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyLogFileInner")
            .field("file", &self.file)
            .finish_non_exhaustive()
    }
}

/// Logs secrets to the file named by the `SSLKEYLOGFILE` environment variable.
///
/// If the variable is unset or the file cannot be opened, nothing is logged.
/// Writing is best-effort: I/O errors are logged and otherwise ignored.
pub struct KeyLogFile(Mutex<KeyLogFileInner>);

impl KeyLogFile {
    /// Reads `SSLKEYLOGFILE` and opens the file (with owner-only permissions on Unix).
    pub fn new() -> Self {
        let var = std::env::var_os("SSLKEYLOGFILE");
        Self(Mutex::new(KeyLogFileInner::new(var)))
    }
}

impl Default for KeyLogFile {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let Ok(mut inner) = self.0.lock() else {
            return;
        };
        if let Err(e) = inner.try_write(label, client_random, secret) {
            warning!("error writing to key log file: {}", e);
        }
    }

    fn will_log(&self, _label: &str) -> bool {
        self.0.lock().is_ok_and(|inner| inner.file.is_some())
    }
}

impl Debug for KeyLogFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0.lock() {
            Ok(inner) => inner.fmt(f),
            Err(_) => f.write_str("KeyLogFile(<poisoned>)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_variable_logs_nothing() {
        let inner = KeyLogFileInner::new(None);
        assert!(inner.file.is_none());
        let log = KeyLogFile(Mutex::new(inner));
        assert!(!log.will_log("CLIENT_RANDOM"));
        log.log("CLIENT_RANDOM", &[1], &[2]);
    }

    #[test]
    fn writes_nss_format() {
        let dir = std::env::temp_dir().join(format!("browntls-keylog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.log");
        let mut inner = KeyLogFileInner::new(Some(path.clone().into_os_string()));
        assert!(inner.file.is_some());
        inner.try_write("LABEL", &[0xab, 0xcd], &[0x01]).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "LABEL abcd 01\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unopenable_path_is_tolerated() {
        let inner = KeyLogFileInner::new(Some(OsString::from("/nonexistent-dir/keys.log")));
        assert!(inner.file.is_none());
    }
}

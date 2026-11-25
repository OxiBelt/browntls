use alloc::vec::Vec;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Component, Path};
use std::sync::Mutex;

use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::{getegid, geteuid, getgid, getuid};

use crate::crypto::zeroize_slice;
use crate::log::warning;

#[cfg(test)]
mod tests;

pub(super) struct Sink {
    file: Mutex<Option<File>>,
}

pub(super) fn from_env() -> Option<Sink> {
    // In a credential-changing program the launch environment may belong to
    // a different principal. Check before consulting it.
    check_credentials().ok()?;
    let path = std::env::var_os("SSLKEYLOGFILE").filter(|path| !path.is_empty())?;
    match Sink::open(Path::new(&path)) {
        Ok(sink) => Some(sink),
        Err(_) => {
            warning!("key log file unavailable");
            None
        }
    }
}

impl Sink {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let file = open_private(path)?;
        with_file_lock(&file, || check_record_boundary(&file))?.ok_or(io::ErrorKind::WouldBlock)?;
        Ok(Self {
            file: Mutex::new(Some(file)),
        })
    }

    pub(super) fn will_log(&self, label: &str) -> bool {
        secret_length_valid(label, None) && self.file.lock().is_ok_and(|file| file.is_some())
    }

    pub(super) fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if client_random.len() != 32 || !secret_length_valid(label, Some(secret.len())) {
            return;
        }
        // The one value that is not a secret, and the one that does not fit
        // the fixed line: built before the file is locked.
        let config_line = if label == ECH_CONFIG {
            if !ech_config_well_formed(secret) {
                return;
            }
            let mut line = Vec::with_capacity(record_len(label, secret.len()));
            push_record(
                &mut |bytes| line.extend_from_slice(bytes),
                label,
                client_random,
                secret,
            );
            Some(line)
        } else {
            None
        };
        let Ok(mut state) = self.file.lock() else {
            return;
        };
        let Some(file) = state.as_ref() else {
            return;
        };

        let result = with_file_lock(file, || {
            check_credentials()?;
            check_file(&fs::fstat(file).map_err(os_error)?)?;
            let len = check_record_boundary(file)?;

            if let Some(line) = &config_line {
                return append_record(file, len, line, |mut writer, bytes| writer.write(bytes));
            }
            let mut line = SecretLine::new();
            push_record(&mut |bytes| line.push(bytes), label, client_random, secret);
            append_record(file, len, line.as_bytes(), |mut writer, bytes| {
                writer.write(bytes)
            })
        });
        if result.is_err() {
            *state = None;
            drop(state);
            warning!("key log file disabled after a write failure");
        }
    }
}

fn check_credentials() -> io::Result<()> {
    if getuid() != geteuid() || getgid() != getegid() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn open_private(path: &Path) -> io::Result<File> {
    check_credentials()?;
    if path.as_os_str().is_empty()
        || path.as_os_str().as_encoded_bytes().ends_with(b"/")
        || path
            .as_os_str()
            .as_encoded_bytes()
            .rsplit(|byte| *byte == b'/')
            .next()
            == Some(b".")
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let absolute = std::path::absolute(path).map_err(io_kind)?;
    let mut components = absolute.components().peekable();
    if components.next() != Some(Component::RootDir) {
        return Err(io::ErrorKind::InvalidInput.into());
    }

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = fs::open("/", flags, Mode::empty()).map_err(os_error)?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let is_parent = components.peek().is_none();
        check_directory(&fs::fstat(&dir).map_err(os_error)?, is_parent)?;
        if is_parent {
            return open_leaf(&dir, name);
        }
        dir = fs::openat(&dir, name, flags, Mode::empty()).map_err(os_error)?;
    }

    Err(io::ErrorKind::InvalidInput.into())
}

fn check_directory(stat: &Stat, is_parent: bool) -> io::Result<()> {
    let root_owned = stat.st_uid == 0;
    let trusted_owner = root_owned || stat.st_uid == geteuid().as_raw();
    let shared = stat.st_mode & 0o022 != 0;
    let sticky_ancestor = !is_parent && root_owned && stat.st_mode & 0o1000 != 0;
    if !trusted_owner || (shared && !sticky_ancestor) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn open_leaf(dir: &rustix::fd::OwnedFd, name: &std::ffi::OsStr) -> io::Result<File> {
    let flags = OFlags::RDWR
        | OFlags::APPEND
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::NOCTTY
        | OFlags::CLOEXEC;
    let create = flags | OFlags::CREATE | OFlags::EXCL;
    let mode = Mode::RUSR | Mode::WUSR;
    let fd = match fs::openat(dir, name, create, mode) {
        Ok(fd) => fd,
        Err(Errno::EXIST) => {
            let before = fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(os_error)?;
            check_file(&before)?;
            let fd = fs::openat(dir, name, flags, Mode::empty()).map_err(os_error)?;
            let after = fs::fstat(&fd).map_err(os_error)?;
            if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            fd
        }
        Err(err) => return Err(os_error(err)),
    };
    check_file(&fs::fstat(&fd).map_err(os_error)?)?;
    Ok(File::from(fd))
}

fn check_file(stat: &Stat) -> io::Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_uid != geteuid().as_raw()
        || stat.st_nlink != 1
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn with_file_lock<T>(file: &File, action: impl FnOnce() -> io::Result<T>) -> io::Result<Option<T>> {
    if let Err(err) = fs::flock(file, FlockOperation::NonBlockingLockExclusive) {
        let err = os_error(err);
        return if err.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(err)
        };
    }
    let result = action();
    fs::flock(file, FlockOperation::Unlock).map_err(os_error)?;
    result.map(Some)
}

fn check_record_boundary(file: &File) -> io::Result<u64> {
    let len = file.metadata().map_err(io_kind)?.len();
    if len >= 3 {
        let mut prefix = [0; 3];
        let result = file.read_exact_at(&mut prefix, 0).map_err(io_kind);
        let has_bom = prefix == [0xef, 0xbb, 0xbf];
        zeroize_slice(&mut prefix);
        result?;
        if has_bom {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    if let Some(end) = len.checked_sub(1) {
        let mut byte = [0];
        let result = file.read_exact_at(&mut byte, end).map_err(io_kind);
        let ends_with_newline = matches!(byte[0], b'\r' | b'\n');
        zeroize_slice(&mut byte);
        result?;
        if !ends_with_newline {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(len)
}

fn append_record(
    file: &File,
    len: u64,
    bytes: &[u8],
    write: impl FnOnce(&File, &[u8]) -> io::Result<usize>,
) -> io::Result<()> {
    let written = write(file, bytes).map_err(io_kind)?;
    if written == bytes.len() {
        return Ok(());
    }
    // Roll back only the bytes written by this call. A writer that ignores
    // the lock can have changed the file, in which case leave it alone.
    if written != 0 && file.metadata().map_err(io_kind)?.len() == len + written as u64 {
        file.set_len(len).map_err(io_kind)?;
    }
    Err(io::ErrorKind::WriteZero.into())
}

fn io_kind(err: io::Error) -> io::Error {
    err.kind().into()
}

fn os_error(err: Errno) -> io::Error {
    io_kind(err.into())
}

/// The label of an offer's `ECHConfig` (RFC 9850 §2.3): public data of a
/// variable length, unlike every other value this sink writes.
const ECH_CONFIG: &str = "ECH_CONFIG";

/// The longest `ECHConfig` the format allows: a version, a length, and
/// `2^16 - 1` bytes of contents (RFC 9849 §4).
const MAX_ECH_CONFIG_LEN: usize = 4 + 0xffff;

fn secret_length_valid(label: &str, length: Option<usize>) -> bool {
    match label {
        "CLIENT_RANDOM" => length.is_none_or(|len| len == 48),
        "CLIENT_EARLY_TRAFFIC_SECRET"
        | "EARLY_EXPORTER_SECRET"
        | "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
        | "SERVER_HANDSHAKE_TRAFFIC_SECRET"
        | "CLIENT_TRAFFIC_SECRET_0"
        | "SERVER_TRAFFIC_SECRET_0"
        | "EXPORTER_SECRET" => length.is_none_or(|len| matches!(len, 32 | 48 | 64)),
        // The KEM shared secret of an ECH offer: `Nsecret` of a KEM of
        // RFC 9180 §7.1, the output length of its HKDF.
        "ECH_SECRET" => length.is_none_or(|len| matches!(len, 32 | 48 | 64)),
        ECH_CONFIG => length.is_none_or(|len| (4..=MAX_ECH_CONFIG_LEN).contains(&len)),
        _ => false,
    }
}

/// Whether `config` has the framing of one `ECHConfig`: a version, then a
/// length that accounts for every byte after it.
fn ech_config_well_formed(config: &[u8]) -> bool {
    match config {
        [_, _, hi, lo, contents @ ..] => {
            usize::from(u16::from_be_bytes([*hi, *lo])) == contents.len()
        }
        _ => false,
    }
}

/// The length of the record of a `value_len`-byte value under `label`.
fn record_len(label: &str, value_len: usize) -> usize {
    label.len() + 1 + 64 + 1 + 2 * value_len + 1
}

/// Hands `push` one record, piece by piece: the label, the random and the
/// value in lowercase hexadecimal, separated by single spaces, and a
/// newline (RFC 9850 §2).
fn push_record(push: &mut dyn FnMut(&[u8]), label: &str, client_random: &[u8], value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let push_hex = |push: &mut dyn FnMut(&[u8]), data: &[u8]| {
        for &byte in data {
            push(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]]);
        }
    };
    push(label.as_bytes());
    push(b" ");
    push_hex(push, client_random);
    push(b" ");
    push_hex(push, value);
    push(b"\n");
}

struct SecretLine {
    // The longest label of a secret, two spaces, 32-byte random, up to a
    // 64-byte secret (both hex-encoded), and newline fit in this buffer.
    bytes: [u8; 256],
    used: usize,
}

impl SecretLine {
    fn new() -> Self {
        Self {
            bytes: [0; 256],
            used: 0,
        }
    }

    fn push(&mut self, data: &[u8]) {
        let end = self.used + data.len();
        self.bytes[self.used..end].copy_from_slice(data);
        self.used = end;
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
}

impl Drop for SecretLine {
    fn drop(&mut self) {
        zeroize_slice(&mut self.bytes);
    }
}

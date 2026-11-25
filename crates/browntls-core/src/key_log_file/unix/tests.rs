use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;

use std::fs::{self as disk, OpenOptions, Permissions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustix::fs::CWD;

use super::*;
use crate::{KeyLog, KeyLogFile};

const LABEL: &str = "CLIENT_RANDOM";
const RANDOM: [u8; 32] = [0xab; 32];
const SECRET: [u8; 48] = [0xcd; 48];
static DIRECTORY_ID: AtomicUsize = AtomicUsize::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        loop {
            let id = DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("browntls-key-log-{}-{id}", std::process::id()));
            match disk::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("fixture directory creation failed: {err}"),
            }
        }
    }

    fn path(&self) -> PathBuf {
        self.0.join("key-log")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = disk::remove_dir_all(&self.0);
    }
}

fn private_fixture(path: &Path, contents: &[u8]) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(contents)
        .unwrap();
}

fn expected_line() -> String {
    format!("{LABEL} {} {}\n", "ab".repeat(32), "cd".repeat(48))
}

#[test]
fn creates_and_appends_private_records() {
    let dir = TestDir::new();
    let path = dir.path();
    let first = KeyLogFile::try_from_path(&path).unwrap();
    assert!(first.will_log(LABEL));
    first.log(LABEL, &RANDOM, &SECRET);
    let second = KeyLogFile::try_from_path(&path).unwrap();
    second.log(LABEL, &RANDOM, &SECRET);
    let metadata = disk::metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), geteuid().as_raw());
    assert_eq!(
        disk::read_to_string(&path).unwrap(),
        expected_line().repeat(2)
    );
    assert_eq!(format!("{first:?}"), "KeyLogFile { .. }");
}

#[test]
fn rejects_untrusted_paths_and_existing_files() {
    let dir = TestDir::new();
    let path = dir.path();
    assert!(KeyLogFile::try_from_path(dir.0.join("missing").join("log")).is_err());
    assert!(KeyLogFile::try_from_path(dir.0.join("../key-log")).is_err());
    assert!(KeyLogFile::try_from_path(&dir.0).is_err());

    let permissive = dir.0.join("permissive");
    disk::create_dir(&permissive).unwrap();
    disk::set_permissions(&permissive, Permissions::from_mode(0o777)).unwrap();
    assert!(KeyLogFile::try_from_path(permissive.join("log")).is_err());
    assert!(!permissive.join("log").exists());

    private_fixture(&path, b"");
    let alias = dir.0.join("alias");
    symlink(&path, &alias).unwrap();
    assert!(KeyLogFile::try_from_path(&alias).is_err());
    disk::remove_file(&alias).unwrap();
    symlink(&dir.0, &alias).unwrap();
    assert!(KeyLogFile::try_from_path(alias.join("key-log")).is_err());
    assert!(KeyLogFile::try_from_path(alias.join("permissive/log")).is_err());
    disk::remove_file(&alias).unwrap();
    disk::hard_link(&path, &alias).unwrap();
    assert!(KeyLogFile::try_from_path(&path).is_err());
    disk::remove_file(&alias).unwrap();
    disk::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    let err = KeyLogFile::try_from_path(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(!format!("{err:?} {err}").contains(&path.display().to_string()));
    assert_eq!(disk::metadata(&path).unwrap().mode() & 0o7777, 0o644);
    assert_eq!(disk::metadata(&path).unwrap().len(), 0);
}

#[test]
fn rejects_special_files_and_foreign_owner() {
    let dir = TestDir::new();
    let path = dir.path();
    fs::mkfifoat(CWD, &path, Mode::RUSR | Mode::WUSR).unwrap();
    assert!(KeyLogFile::try_from_path(&path).is_err());
    disk::remove_file(&path).unwrap();
    let socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
    assert!(KeyLogFile::try_from_path(&path).is_err());
    drop(socket);
    disk::remove_file(&path).unwrap();
    private_fixture(&path, b"");
    let mut stat = fs::statat(CWD, &path, AtFlags::SYMLINK_NOFOLLOW).unwrap();
    stat.st_uid = if geteuid().is_root() { 1 } else { 0 };
    assert_eq!(
        check_file(&stat).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn rejects_invalid_records_and_stops_after_file_policy_changes() {
    let dir = TestDir::new();
    let path = dir.path();
    let sink = KeyLogFile::try_from_path(&path).unwrap();
    for label in ["CLIENT_RANDOM\nINJECTED", "UNKNOWN", "EXPORTER_SECRET 00"] {
        assert!(!sink.will_log(label));
        sink.log(label, &RANDOM, &SECRET);
    }
    sink.log(LABEL, &RANDOM[1..], &SECRET);
    sink.log(LABEL, &RANDOM, &SECRET[1..]);
    sink.log("EXPORTER_SECRET", &RANDOM, &[0; 65]);
    assert_eq!(disk::metadata(&path).unwrap().len(), 0);
    disk::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    sink.log(LABEL, &RANDOM, &SECRET);
    assert!(!sink.will_log(LABEL));
    assert_eq!(disk::metadata(&path).unwrap().len(), 0);
}

/// A well-formed `ECHConfig` with `contents_len` bytes of contents.
fn ech_config(contents_len: usize) -> Vec<u8> {
    let mut config = vec![0xfe, 0x0d];
    config.extend_from_slice(&u16::try_from(contents_len).unwrap().to_be_bytes());
    config.extend((0..contents_len).map(|i| i as u8));
    config
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn writes_the_ech_records_in_the_rfc_9850_format() {
    let dir = TestDir::new();
    let path = dir.path();
    let sink = KeyLogFile::try_from_path(&path).unwrap();
    assert!(sink.will_log("ECH_SECRET"));
    assert!(sink.will_log("ECH_CONFIG"));
    // Each `Nsecret` of RFC 9180, then configurations from an empty body
    // (which only a version this library does not know could have) to the
    // longest the length field allows, far longer than the line buffer of
    // a secret.
    let mut expected = String::new();
    for len in [32, 48, 64] {
        let secret = vec![0xcd; len];
        sink.log("ECH_SECRET", &RANDOM, &secret);
        expected += &format!("ECH_SECRET {} {}\n", "ab".repeat(32), "cd".repeat(len));
    }
    for contents_len in [0, 1, 60, 300, 0xffff] {
        let config = ech_config(contents_len);
        sink.log("ECH_CONFIG", &RANDOM, &config);
        expected += &format!("ECH_CONFIG {} {}\n", "ab".repeat(32), hex(&config));
    }
    assert_eq!(disk::read_to_string(&path).unwrap(), expected);
    // Still appending whole records after the long ones.
    sink.log(LABEL, &RANDOM, &SECRET);
    expected += &expected_line();
    assert_eq!(disk::read_to_string(&path).unwrap(), expected);
}

#[test]
fn rejects_ech_values_that_are_not_a_kem_secret_or_one_config() {
    let dir = TestDir::new();
    let path = dir.path();
    let sink = KeyLogFile::try_from_path(&path).unwrap();
    // No KEM has a secret of these lengths (66 is a P-521 scalar).
    for len in [0, 16, 31, 33, 56, 65, 66, 128] {
        sink.log("ECH_SECRET", &RANDOM, &vec![0xcd; len]);
    }
    sink.log("ECH_SECRET", &RANDOM[1..], &[0xcd; 32]);
    // Too short for a version and a length; a length that leaves bytes
    // over, or promises more than there are; two configurations in a row
    // (a list entry pair); a whole ECHConfigList, with its length prefix;
    // and one byte past the longest configuration.
    let good = ech_config(60);
    let mut list = u16::try_from(good.len()).unwrap().to_be_bytes().to_vec();
    list.extend_from_slice(&good);
    let mut too_long = ech_config(0xffff);
    too_long.push(0);
    for bad in [
        &[][..],
        &[0xfe, 0x0d, 0x00][..],
        &good[..good.len() - 1],
        &[&good[..], &[0]].concat(),
        &[&good[..], &good[..]].concat(),
        &list,
        &too_long,
    ] {
        sink.log("ECH_CONFIG", &RANDOM, bad);
    }
    sink.log("ECH_CONFIG", &RANDOM[1..], &good);
    // Near misses of the labels are unknown labels.
    for label in ["ECH_SECRETS", "ECH", "ech_secret", "ECH_CONFIG ", "ECH_KEY"] {
        assert!(!sink.will_log(label));
        sink.log(label, &RANDOM, &[0xcd; 32]);
        sink.log(label, &RANDOM, &good);
    }
    assert_eq!(disk::metadata(&path).unwrap().len(), 0);
    // None of that disabled the sink.
    sink.log("ECH_CONFIG", &RANDOM, &good);
    assert_eq!(
        disk::read_to_string(&path).unwrap(),
        format!("ECH_CONFIG {} {}\n", "ab".repeat(32), hex(&good))
    );
}

#[test]
fn refuses_bom_or_incomplete_record_boundary() {
    let dir = TestDir::new();
    let path = dir.path();
    for contents in [b"\xef\xbb\xbf# comment\n".as_slice(), b"partial-record"] {
        private_fixture(&path, contents);
        assert_eq!(
            KeyLogFile::try_from_path(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(disk::read(&path).unwrap(), contents);
        disk::remove_file(&path).unwrap();
    }
}

#[test]
fn shared_sink_writes_complete_records_and_external_contention_skips() {
    let dir = TestDir::new();
    let path = dir.path();
    let sink = KeyLogFile::try_from_path(&path).unwrap();
    let other = open_private(&path).unwrap();
    with_file_lock(&other, || {
        sink.log(LABEL, &RANDOM, &SECRET);
        assert_eq!(other.metadata().unwrap().len(), 0);
        assert!(sink.will_log(LABEL));
        assert_eq!(
            KeyLogFile::try_from_path(&path).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        Ok(())
    })
    .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..8 {
                    sink.log(LABEL, &RANDOM, &SECRET);
                }
            });
        }
    });
    assert_eq!(
        disk::read_to_string(&path).unwrap(),
        expected_line().repeat(32)
    );
}

#[test]
fn environment_is_consulted_only_for_a_new_sink() {
    const TEST: &str = "key_log_file::unix::tests::environment_is_consulted_only_for_a_new_sink";
    const CHILD: &str = "BROWNTLS_TEST_KEY_LOG_CHILD";
    if let Some(case) = std::env::var_os(CHILD) {
        let sink = KeyLogFile::new();
        assert_eq!(sink.will_log(LABEL), case == "set");
        sink.log(LABEL, &RANDOM, &SECRET);
        return;
    }
    let dir = TestDir::new();
    let path = dir.path();
    for case in ["unset", "empty", "set"] {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", TEST]).env(CHILD, case);
        match case {
            "unset" => {
                cmd.env_remove("SSLKEYLOGFILE");
            }
            "empty" => {
                cmd.env("SSLKEYLOGFILE", "");
            }
            _ => {
                cmd.env("SSLKEYLOGFILE", &path);
            }
        }
        assert!(cmd.status().unwrap().success());
        assert_eq!(path.exists(), case == "set");
    }
    assert_eq!(disk::read_to_string(path).unwrap(), expected_line());
}

#[test]
fn short_write_rolls_back_the_partial_record() {
    let dir = TestDir::new();
    let path = dir.path();
    let previous = b"# previous record\n";
    private_fixture(&path, previous);
    let file = open_private(&path).unwrap();
    let result = with_file_lock(&file, || {
        let len = check_record_boundary(&file)?;
        append_record(
            &file,
            len,
            expected_line().as_bytes(),
            |mut writer, bytes| writer.write(&bytes[..5]),
        )
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WriteZero);
    assert_eq!(disk::read(&path).unwrap(), previous);
    assert!(KeyLogFile::try_from_path(&path).is_ok());
}

#[test]
fn rollback_failure_is_reported_to_the_sink() {
    let dir = TestDir::new();
    let path = dir.path();
    private_fixture(&path, b"x");
    let read_only = File::open(&path).unwrap();
    let result = append_record(&read_only, 0, b"test", |_, _| Ok(1));
    assert_ne!(result.unwrap_err().kind(), io::ErrorKind::WriteZero);
    assert_eq!(disk::read(&path).unwrap(), b"x");
}

#[cfg(feature = "logging")]
#[test]
fn file_warnings_omit_path_and_record_data() {
    const CHILD: &str = "BROWNTLS_TEST_KEY_LOG_WARNINGS";
    const PATH_MARKER: &str = "private-diagnostic-path-marker";
    if let Some(raw_path) = std::env::var_os(CHILD) {
        // Use a subprocess to own the global logger.
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Warn)
            .init();
        let path = PathBuf::from(raw_path);
        let sink = KeyLogFile::try_from_path(&path).unwrap();
        disk::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        sink.log(LABEL, &RANDOM, &SECRET);
        let disabled = KeyLogFile::new();
        assert!(!disabled.will_log(LABEL));
        return;
    }
    let dir = TestDir::new();
    let path = dir.0.join(PATH_MARKER);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "key_log_file::unix::tests::file_warnings_omit_path_and_record_data",
            "--nocapture",
        ])
        .env(CHILD, &path)
        .env("SSLKEYLOGFILE", &path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("key log file disabled after a write failure"));
    assert!(stderr.contains("key log file unavailable"));
    for marker in [PATH_MARKER, LABEL, &"ab".repeat(32), &"cd".repeat(48)] {
        assert!(!stderr.contains(marker), "warning contains diagnostic data");
    }
}

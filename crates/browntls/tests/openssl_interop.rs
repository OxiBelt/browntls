//! Interoperability with the OpenSSL command-line tool over loopback TCP.
//!
//! Every case runs in both directions (browntls client against
//! `openssl s_server`, `openssl s_client` against a browntls server), with and
//! without client authentication, and checks the negotiated protocol version,
//! cipher suite and key exchange group on the browntls side plus application
//! data in both directions. Keys and certificates are generated with OpenSSL
//! at run time in a temporary directory that is removed afterwards.
//!
//! The tests are skipped, with a message, when no OpenSSL 3 (or later) binary
//! is found.
//! Set `BROWNTLS_OPENSSL_INTEROP=require` to make that a failure, and
//! `BROWNTLS_OPENSSL` to choose the binary.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "openssl_interop/matrix.rs"]
mod matrix;
#[path = "openssl_interop/psk.rs"]
mod psk;
#[path = "openssl_interop/tls13_optional.rs"]
mod tls13_optional;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use browntls::crypto::{CryptoProvider, SupportedKxGroup, native};
use browntls::pki_types::pem::PemObject;
use browntls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use browntls::server::WebPkiClientVerifier;
use browntls::{
    ClientConfig, ClientConnection, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    StreamOwned, SupportedCipherSuite, SupportedProtocolVersion, version,
};

/// Time allowed for any single step (process start-up, handshake, I/O).
const STEP: Duration = Duration::from_secs(20);

/// The line the client sends; the server answers with a transformed copy.
const PING: &str = "hello from the client";

// ------------------------------------------------------------ OpenSSL binary

fn openssl() -> Option<&'static Path> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        let bin =
            std::env::var_os("BROWNTLS_OPENSSL").map_or_else(|| "openssl".into(), PathBuf::from);
        let out = Command::new(&bin).arg("version").output().ok()?;
        let version = String::from_utf8_lossy(&out.stdout).into_owned();
        // OpenSSL 3 or later (the options used here exist since 3.0).
        let major = version
            .strip_prefix("OpenSSL ")
            .and_then(|v| v.split('.').next())
            .and_then(|m| m.parse::<u32>().ok());
        (out.status.success() && major.is_some_and(|m| m >= 3)).then(|| {
            eprintln!("OpenSSL interop with {}: {}", bin.display(), version.trim());
            bin
        })
    })
    .as_deref()
}

/// The OpenSSL binary, or `None` after reporting the skip (or failing when
/// `BROWNTLS_OPENSSL_INTEROP=require`).
fn openssl_or_skip() -> Option<&'static Path> {
    let bin = openssl();
    if bin.is_none() {
        let required = std::env::var("BROWNTLS_OPENSSL_INTEROP").is_ok_and(|v| v == "require");
        assert!(!required, "no OpenSSL 3 or later binary found");
        eprintln!("skipping OpenSSL interop: no OpenSSL 3 or later binary found");
    }
    bin
}

fn run(openssl: &Path, dir: &Path, args: &[&str]) {
    let out = Command::new(openssl)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --------------------------------------------------------- keys and chains

/// Certificate key types; the CA and both end entities use the same type, so
/// path validation exercises it too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyType {
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Ed25519,
    Ed448,
    /// RSASSA-PSS key without parameters (`rsa_pss_pss_*`).
    RsaPss,
    /// RSASSA-PSS key restricted to SHA-384 (MGF1-SHA-384, 48-byte salt).
    RsaPssSha384,
    /// RSASSA-PSS key restricted to SHA-256 (MGF1-SHA-256) whose
    /// `saltLength` OpenSSL omits: a minimum of 20 bytes (RFC 4055 §3.3),
    /// which TLS signatures (32-byte salts) meet.
    RsaPssSha256DefaultSalt,
}

impl KeyType {
    fn genpkey(self) -> &'static [&'static str] {
        match self {
            Self::EcdsaP256 => &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
            Self::EcdsaP384 => &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
            Self::Rsa2048 => &["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
            Self::Ed25519 => &["-algorithm", "ED25519"],
            Self::Ed448 => &["-algorithm", "ED448"],
            Self::RsaPss => &["-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048"],
            Self::RsaPssSha384 => &[
                "-algorithm",
                "RSA-PSS",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-pkeyopt",
                "rsa_pss_keygen_md:sha384",
                "-pkeyopt",
                "rsa_pss_keygen_mgf1_md:sha384",
                "-pkeyopt",
                "rsa_pss_keygen_saltlen:48",
            ],
            Self::RsaPssSha256DefaultSalt => &[
                "-algorithm",
                "RSA-PSS",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-pkeyopt",
                "rsa_pss_keygen_md:sha256",
                "-pkeyopt",
                "rsa_pss_keygen_mgf1_md:sha256",
            ],
        }
    }

    /// Extra arguments for signing certificates with this key type: PSS
    /// signatures use MGF1 with the same hash and a salt as long as the
    /// digest, the only form RFC 9846 signature schemes describe.
    fn sign_args(self) -> &'static [&'static str] {
        match self {
            Self::RsaPss | Self::RsaPssSha256DefaultSalt => &[
                "-sha256",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:digest",
                "-sigopt",
                "rsa_mgf1_md:sha256",
            ],
            Self::RsaPssSha384 => &[
                "-sha384",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:digest",
                "-sigopt",
                "rsa_mgf1_md:sha384",
            ],
            _ => &[],
        }
    }
}

/// A temporary directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!(
            "browntls-openssl-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A CA and server and client end entities, as files and as DER.
struct Pki {
    dir: TempDir,
    ca: CertificateDer<'static>,
}

impl Pki {
    fn path(&self, name: &str) -> String {
        self.dir.0.join(name).to_str().unwrap().to_owned()
    }

    fn chain(&self, who: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let cert = CertificateDer::from_pem_file(self.path(&format!("{who}.pem"))).unwrap();
        let key = PrivateKeyDer::from_pem_file(self.path(&format!("{who}.key"))).unwrap();
        (vec![cert], key)
    }

    fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        Arc::new(roots)
    }
}

fn make_pki(openssl: &Path, key: KeyType) -> Pki {
    let dir = TempDir::new();
    let d = dir.0.as_path();
    let genpkey = |out: &str| {
        let mut args = vec!["genpkey"];
        args.extend_from_slice(key.genpkey());
        args.extend_from_slice(&["-out", out]);
        run(openssl, d, &args);
    };
    genpkey("ca.key");
    let with_sign_args = |args: &[&'static str]| -> Vec<&'static str> {
        args.iter().chain(key.sign_args()).copied().collect()
    };
    run(
        openssl,
        d,
        &with_sign_args(&[
            "req",
            "-x509",
            "-new",
            "-key",
            "ca.key",
            "-subj",
            "/CN=browntls interop CA",
            "-days",
            "2",
            "-out",
            "ca.pem",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]),
    );
    std::fs::write(
        d.join("ee.ext"),
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
         extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost\n",
    )
    .unwrap();
    for (who, serial) in [("server", "2"), ("client", "3")] {
        let (key_file, csr, pem) = (
            format!("{who}.key"),
            format!("{who}.csr"),
            format!("{who}.pem"),
        );
        genpkey(&key_file);
        run(
            openssl,
            d,
            &[
                "req",
                "-new",
                "-key",
                &key_file,
                "-subj",
                "/CN=localhost",
                "-out",
                &csr,
            ],
        );
        let mut args = vec![
            "x509",
            "-req",
            "-in",
            &csr,
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-set_serial",
            serial,
            "-days",
            "2",
            "-extfile",
            "ee.ext",
            "-out",
            &pem,
        ];
        args.extend_from_slice(key.sign_args());
        run(openssl, d, &args);
    }
    let ca = CertificateDer::from_pem_file(d.join("ca.pem")).unwrap();
    if key == KeyType::RsaPssSha256DefaultSalt {
        // The case is about the omitted saltLength: OpenSSL writes the CA
        // key's SPKI algorithm as SHA-256 and MGF1-SHA-256 alone.
        let alg = "303c06092a864886f70d01010a302fa00f300d06096086480165030402010500a11c301a\
                   06092a864886f70d010108300d06096086480165030402010500";
        let alg = hex::decode(alg).unwrap();
        assert!(ca.as_ref().windows(alg.len()).any(|w| w == alg));
    }
    Pki { dir, ca }
}

/// One PKI per key type, shared by every case in the process.
fn pki(openssl: &Path, key: KeyType) -> Arc<Pki> {
    static CACHE: Mutex<Vec<(KeyType, Arc<Pki>)>> = Mutex::new(Vec::new());
    let mut cache = CACHE.lock().unwrap();
    if let Some((_, p)) = cache.iter().find(|(k, _)| *k == key) {
        return p.clone();
    }
    let p = Arc::new(make_pki(openssl, key));
    cache.push((key, p.clone()));
    p
}

// ---------------------------------------------------------------- plumbing

/// Waits for `child` to exit, killing it after [`STEP`]; returns its stdout
/// and stderr.
fn finish(mut child: Child, stdout_rx: Option<mpsc::Receiver<String>>) -> (bool, String, String) {
    let deadline = Instant::now() + STEP;
    let ok = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.success();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = String::new();
    if let Some(rx) = stdout_rx {
        while let Ok(line) = rx.try_recv() {
            stdout.push_str(&line);
            stdout.push('\n');
        }
    } else if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    let mut stderr = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }
    (ok, stdout, stderr)
}

/// Reads one line (including the newline) from `r`.
fn read_line(r: &mut impl Read) -> std::io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.last() != Some(&b'\n') {
        if r.read(&mut byte)? == 0 {
            break;
        }
        line.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Bind attempts of [`start_s_server`].
const BIND_ATTEMPTS: usize = 8;

/// Starts `openssl s_server` with `args(port)` on a free port and waits until
/// it listens; returns the child, its stdout lines and the port.
///
/// Finding a free port and binding it are separate steps, so a test running
/// in parallel can take the port in between: a server that fails with
/// `Address already in use` is retried on another port.
fn start_s_server(
    openssl: &Path,
    args: &dyn Fn(&str) -> Vec<String>,
    envs: &[(&'static str, String)],
) -> Result<(Child, mpsc::Receiver<String>, String), String> {
    let mut last = String::new();
    for _ in 0..BIND_ATTEMPTS {
        let port = free_port().to_string();
        let mut child = Command::new(openssl)
            .args(args(&port))
            .envs(envs.iter().map(|(k, v)| (*k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        // `s_server` prints ACCEPT once it listens.
        let (tx, rx) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + STEP;
        let started = loop {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line) if line.trim() == "ACCEPT" => break true,
                Ok(_) => {}
                Err(_) => break false,
            }
        };
        if started {
            return Ok((child, rx, port));
        }
        let (_, out, err) = finish(child, Some(rx));
        last = format!("s_server did not start\n{out}\n{err}");
        if !err.contains("Address already in use") {
            break;
        }
    }
    Err(last)
}

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

// -------------------------------------------------------------------- cases

struct Case {
    version: &'static SupportedProtocolVersion,
    suite: SupportedCipherSuite,
    /// `-ciphersuites` (TLS 1.3) or `-cipher` (TLS 1.2) value.
    openssl_suite: &'static str,
    /// The group that must be negotiated (browntls offers it first).
    group: &'static dyn SupportedKxGroup,
    /// Further groups browntls offers after `group`.
    extra_groups: Vec<&'static dyn SupportedKxGroup>,
    /// `-groups` value.
    openssl_group: &'static str,
    key: KeyType,
}

impl Case {
    fn name(&self) -> String {
        format!(
            "{:?} {:?} {:?} {:?}",
            self.version.version,
            self.suite.suite(),
            self.group.name(),
            self.key
        )
    }

    fn openssl_args(&self) -> Vec<&'static str> {
        let mut args = if self.version.version == ProtocolVersion::TLSv1_3 {
            vec!["-tls1_3", "-ciphersuites", self.openssl_suite]
        } else {
            vec!["-tls1_2", "-cipher", self.openssl_suite]
        };
        args.extend_from_slice(&["-groups", self.openssl_group]);
        args
    }

    fn provider(&self) -> Arc<CryptoProvider> {
        Arc::new(CryptoProvider {
            cipher_suites: vec![self.suite],
            kx_groups: [self.group]
                .into_iter()
                .chain(self.extra_groups.iter().copied())
                .collect(),
            ..native::default_provider()
        })
    }

    /// Checks what the browntls side negotiated.
    fn check(&self, common: &browntls::CommonState) -> Result<(), String> {
        let got = (
            common.protocol_version(),
            common.negotiated_cipher_suite().map(|s| s.suite()),
            common.negotiated_key_exchange_group().map(|g| g.name()),
        );
        let want = (
            Some(self.version.version),
            Some(self.suite.suite()),
            Some(self.group.name()),
        );
        if got == want {
            Ok(())
        } else {
            Err(format!("negotiated {got:?}, expected {want:?}"))
        }
    }
}

fn cases() -> Vec<Case> {
    use native::cipher_suite as cs;
    use native::kx_group as kx;
    let tls13 = |suite, openssl_suite, group, openssl_group, key| Case {
        version: &version::TLS13,
        suite,
        openssl_suite,
        group,
        extra_groups: Vec::new(),
        openssl_group,
        key,
    };
    let mut cases = vec![
        tls13(
            cs::TLS13_AES_128_GCM_SHA256,
            "TLS_AES_128_GCM_SHA256",
            kx::X25519,
            "X25519",
            KeyType::EcdsaP256,
        ),
        tls13(
            cs::TLS13_AES_256_GCM_SHA384,
            "TLS_AES_256_GCM_SHA384",
            kx::SECP384R1,
            "P-384",
            KeyType::Rsa2048,
        ),
        tls13(
            cs::TLS13_CHACHA20_POLY1305_SHA256,
            "TLS_CHACHA20_POLY1305_SHA256",
            kx::SECP256R1,
            "P-256",
            KeyType::Ed25519,
        ),
        tls13(
            cs::TLS13_AES_128_GCM_SHA256,
            "TLS_AES_128_GCM_SHA256",
            kx::SECP521R1,
            "P-521",
            KeyType::EcdsaP384,
        ),
        // Non-preferred tier (RFC 9846 optional algorithms). OpenSSL's
        // default TLS 1.3 list omits CCM, hence the explicit suites.
        tls13(
            cs::TLS13_AES_128_CCM_SHA256,
            "TLS_AES_128_CCM_SHA256",
            kx::X25519,
            "X25519",
            KeyType::EcdsaP256,
        ),
        tls13(
            cs::TLS13_AES_128_CCM_8_SHA256,
            "TLS_AES_128_CCM_8_SHA256",
            kx::SECP256R1,
            "P-256",
            KeyType::Rsa2048,
        ),
        tls13(
            cs::TLS13_AES_256_GCM_SHA384,
            "TLS_AES_256_GCM_SHA384",
            kx::X448,
            "X448",
            KeyType::Ed448,
        ),
        tls13(
            cs::TLS13_AES_128_GCM_SHA256,
            "TLS_AES_128_GCM_SHA256",
            kx::X25519,
            "X25519",
            KeyType::RsaPss,
        ),
        tls13(
            cs::TLS13_AES_256_GCM_SHA384,
            "TLS_AES_256_GCM_SHA384",
            kx::SECP256R1,
            "P-256",
            KeyType::RsaPssSha384,
        ),
        tls13(
            cs::TLS13_CHACHA20_POLY1305_SHA256,
            "TLS_CHACHA20_POLY1305_SHA256",
            kx::X25519,
            "X25519",
            KeyType::RsaPssSha256DefaultSalt,
        ),
    ];
    // RFC 7919 finite-field groups (TLS 1.3 only).
    for (group, name) in [
        (kx::FFDHE2048, "ffdhe2048"),
        (kx::FFDHE3072, "ffdhe3072"),
        (kx::FFDHE4096, "ffdhe4096"),
        (kx::FFDHE6144, "ffdhe6144"),
        (kx::FFDHE8192, "ffdhe8192"),
    ] {
        cases.push(tls13(
            cs::TLS13_AES_128_GCM_SHA256,
            "TLS_AES_128_GCM_SHA256",
            group,
            name,
            KeyType::EcdsaP256,
        ));
    }
    #[cfg(feature = "tls12")]
    {
        let tls12 = |suite, openssl_suite, group, openssl_group, key| Case {
            version: &version::TLS12,
            suite,
            openssl_suite,
            group,
            extra_groups: Vec::new(),
            openssl_group,
            key,
        };
        cases.extend([
            // In TLS 1.2 OpenSSL also requires the certificate's curve to be
            // among the supported groups (RFC 8422 §5.1.1).
            Case {
                extra_groups: vec![kx::SECP256R1],
                ..tls12(
                    cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    "ECDHE-ECDSA-AES128-GCM-SHA256",
                    kx::X25519,
                    "X25519:P-256",
                    KeyType::EcdsaP256,
                )
            },
            tls12(
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                "ECDHE-ECDSA-AES256-GCM-SHA384",
                kx::SECP384R1,
                "P-384",
                KeyType::EcdsaP384,
            ),
            tls12(
                cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                "ECDHE-RSA-CHACHA20-POLY1305",
                kx::SECP256R1,
                "P-256",
                KeyType::Rsa2048,
            ),
            tls12(
                cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                "ECDHE-RSA-AES256-GCM-SHA384",
                kx::X25519,
                "X25519",
                KeyType::Rsa2048,
            ),
            // X448 and Ed448 in TLS 1.2 ECDHE (RFC 8422).
            tls12(
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                "ECDHE-ECDSA-AES256-GCM-SHA384",
                kx::X448,
                "X448",
                KeyType::Ed448,
            ),
            tls12(
                cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                "ECDHE-RSA-AES128-GCM-SHA256",
                kx::X448,
                "X448",
                KeyType::Rsa2048,
            ),
            // rsa_pss_pss_* also apply to TLS 1.2 (RFC 9846 §4.3.3).
            tls12(
                cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                "ECDHE-RSA-AES128-GCM-SHA256",
                kx::SECP256R1,
                "P-256",
                KeyType::RsaPss,
            ),
            tls12(
                cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                "ECDHE-RSA-AES256-GCM-SHA384",
                kx::X25519,
                "X25519",
                KeyType::RsaPssSha256DefaultSalt,
            ),
        ]);
    }
    cases
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

// --------------------------------------------------------------- directions

/// browntls client against `openssl s_server -rev` (which echoes each line
/// reversed).
fn browntls_client(openssl: &Path, case: &Case, client_auth: bool) -> Result<(), String> {
    let pki = pki(openssl, case.key);
    let port = free_port().to_string();
    let (cert, key) = (pki.path("server.pem"), pki.path("server.key"));
    let ca = pki.path("ca.pem");
    let mut args = vec![
        "s_server", "-accept", &port, "-naccept", "1", "-rev", "-cert", &cert, "-key", &key,
    ];
    args.extend(case.openssl_args());
    if client_auth {
        args.extend_from_slice(&["-Verify", "1", "-verify_return_error", "-CAfile", &ca]);
    }
    let mut child = Command::new(openssl)
        .args(&args)
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
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) if line.trim() == "ACCEPT" => break,
            Ok(_) => {}
            Err(_) => {
                let (_, out, err) = finish(child, Some(rx));
                return Err(format!("s_server did not start\n{out}\n{err}"));
            }
        }
    }

    let result = (|| -> Result<(), String> {
        let builder = ClientConfig::builder_with_provider(case.provider())
            .with_protocol_versions(&[case.version])
            .map_err(|e| e.to_string())?
            .with_root_certificates(pki.roots());
        let config = if client_auth {
            let (chain, key) = pki.chain("client");
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| e.to_string())?
        } else {
            builder.with_no_client_auth()
        };
        let conn =
            ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
                .map_err(|e| e.to_string())?;
        let sock = TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(STEP)).unwrap();
        sock.set_write_timeout(Some(STEP)).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        tls.write_all(format!("{PING}\n").as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        let reply = read_line(&mut tls).map_err(|e| format!("read: {e}"))?;
        let expected: String = PING.chars().rev().collect();
        if reply.trim_end() != expected {
            return Err(format!("reply {reply:?}, expected {expected:?}"));
        }
        case.check(&tls.conn)?;
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(())
    })();
    let (_, out, err) = finish(child, Some(rx));
    result.map_err(|e| format!("{e}\ns_server stdout:\n{out}\ns_server stderr:\n{err}"))
}

/// `openssl s_client` against a browntls server that answers each line with
/// a prefixed copy.
fn openssl_client(openssl: &Path, case: &Case, client_auth: bool) -> Result<(), String> {
    let pki = pki(openssl, case.key);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (cert, key) = (pki.path("client.pem"), pki.path("client.key"));
    let ca = pki.path("ca.pem");
    let mut args = vec![
        "s_client",
        "-connect",
        &addr,
        "-servername",
        "localhost",
        "-CAfile",
        &ca,
        "-verify_return_error",
        "-quiet",
    ];
    args.extend(case.openssl_args());
    if client_auth {
        args.extend_from_slice(&["-cert", &cert, "-key", &key]);
    }
    let mut child = Command::new(openssl)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // `-quiet` implies `-ign_eof`: s_client keeps the connection until the
    // server closes it, so stdin can stay open.
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(format!("{PING}\n").as_bytes()).unwrap();

    let result = (|| -> Result<(), String> {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + STEP;
        let sock = loop {
            match listener.accept() {
                Ok((sock, _)) => break sock,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(format!("accept: {e}")),
            }
        };
        sock.set_nonblocking(false).unwrap();
        sock.set_read_timeout(Some(STEP)).unwrap();
        sock.set_write_timeout(Some(STEP)).unwrap();

        let builder = ServerConfig::builder_with_provider(case.provider())
            .with_protocol_versions(&[case.version])
            .map_err(|e| e.to_string())?;
        let builder = if client_auth {
            let verifier =
                WebPkiClientVerifier::builder_with_provider(pki.roots(), case.provider())
                    .build()
                    .map_err(|e| e.to_string())?;
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let (chain, key) = pki.chain("server");
        let config = builder
            .with_single_cert(chain, key)
            .map_err(|e| e.to_string())?;
        let conn = ServerConnection::new(Arc::new(config)).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, sock);
        let line = read_line(&mut tls).map_err(|e| format!("read: {e}"))?;
        if line.trim_end() != PING {
            return Err(format!("received {line:?}"));
        }
        tls.write_all(format!("browntls:{line}").as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        case.check(&tls.conn)?;
        if client_auth && tls.conn.peer_certificates().is_none_or(<[_]>::is_empty) {
            return Err("no client certificate".into());
        }
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(())
    })();
    drop(stdin);
    let (_, out, err) = finish(child, None);
    result?;
    if out.contains(&format!("browntls:{PING}")) {
        Ok(())
    } else {
        Err(format!("s_client stdout:\n{out}\ns_client stderr:\n{err}"))
    }
}

/// Runs `f` for every case with and without client authentication and
/// reports all failures together.
fn for_all(f: fn(&Path, &Case, bool) -> Result<(), String>) {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    let mut failures = Vec::new();
    let mut runs = 0;
    for case in cases() {
        for client_auth in [false, true] {
            runs += 1;
            let start = Instant::now();
            let result = f(openssl, &case, client_auth);
            eprintln!(
                "{} client_auth={client_auth}: {:?} in {:.2?}",
                case.name(),
                result.as_ref().map(|()| "ok"),
                start.elapsed()
            );
            if let Err(e) = result {
                failures.push(format!("{} client_auth={client_auth}: {e}", case.name()));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {runs} runs failed:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn browntls_client_with_openssl_server() {
    for_all(browntls_client);
}

#[test]
fn openssl_client_with_browntls_server() {
    for_all(openssl_client);
}

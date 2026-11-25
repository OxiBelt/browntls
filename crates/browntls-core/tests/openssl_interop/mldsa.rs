//! TLS 1.3 authentication with ML-DSA (`draft-ietf-tls-mldsa-06`, schemes
//! `mldsa44`, `mldsa65` and `mldsa87`, code points 0x0904 to 0x0906) against
//! OpenSSL 3.5 or later, through the native provider's opt-in
//! (`SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13`, `KEY_PROVIDER_WITH_ML_DSA`).
//!
//! The CA and both end entities use one parameter set, and OpenSSL
//! generates every key and certificate, so browntls loads the PKCS #8
//! private keys (RFC 9881 §6) OpenSSL writes. OpenSSL is restricted to the
//! scheme under test with `-sigalgs` and reports the scheme of the
//! `CertificateVerify` it received ("Peer signature type" in `s_client`,
//! "Signature type" for the client's in `s_server`), which the cases check;
//! browntls has no accessor for the negotiated signature scheme. Negative
//! cases show that nothing is negotiated without the opt-in, with classical
//! schemes only, or in TLS 1.2 (§3 of the draft: TLS 1.3 only).
//!
//! The cases need an OpenSSL that lists the three schemes in
//! `openssl list -tls-signature-algorithms` (OpenSSL 3.5 or later; 3.0 has
//! no such option). Otherwise they are skipped with a message, except that
//! with `BROWNTLS_OPENSSL_INTEROP=require` a binary that reports version 3.5
//! or later without the schemes is a failure.

use browntls_core::{AlertDescription, Error};

use super::*;

/// The parameter sets and their TLS signature scheme names.
const SETS: [(KeyType, &str); 3] = [
    (KeyType::MlDsa44, "mldsa44"),
    (KeyType::MlDsa65, "mldsa65"),
    (KeyType::MlDsa87, "mldsa87"),
];

/// Classical TLS 1.3 schemes only, for an OpenSSL peer that must not
/// negotiate ML-DSA.
const CLASSICAL_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:ed25519";

// ------------------------------------------------------------- capability

/// Writes `line` to the process's standard error directly: the test harness
/// captures `eprintln!` of passing tests, and CI logs must show whether these
/// cases ran.
fn report(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// `(major, minor)` from an `openssl version` line.
fn major_minor(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.strip_prefix("OpenSSL ")?.split(['.', ' ']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// The OpenSSL binary when it implements the ML-DSA TLS 1.3 signature
/// schemes, or `None` after reporting the skip (see the module
/// documentation for when that is a failure instead).
fn openssl_with_ml_dsa_or_skip() -> Option<&'static Path> {
    let openssl = openssl_or_skip()?;
    // `Ok(version)` when the schemes are listed, `Err(version)` otherwise.
    static PROBE: OnceLock<Result<String, String>> = OnceLock::new();
    let probe = PROBE.get_or_init(|| {
        let version = Command::new(openssl)
            .arg("version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        let listed = Command::new(openssl)
            .args(["list", "-tls-signature-algorithms"])
            .output()
            .is_ok_and(|o| {
                let names = String::from_utf8_lossy(&o.stdout).into_owned();
                let names: Vec<&str> = names.trim().split(':').collect();
                o.status.success() && SETS.iter().all(|(_, s)| names.contains(s))
            });
        if listed {
            report(&format!(
                "OpenSSL ML-DSA interop cases run with {}: {version}",
                openssl.display()
            ));
            Ok(version)
        } else {
            report(&format!(
                "skipping OpenSSL ML-DSA interop: {version:?} does not list the \
                 mldsa44/65/87 TLS signature schemes (OpenSSL 3.5 or later)"
            ));
            Err(version)
        }
    });
    match probe {
        Ok(_) => Some(openssl),
        Err(version) => {
            let required = std::env::var("BROWNTLS_OPENSSL_INTEROP").is_ok_and(|v| v == "require");
            assert!(
                !(required && major_minor(version).is_some_and(|v| v >= (3, 5))),
                "{version} does not list the ML-DSA TLS signature schemes"
            );
            None
        }
    }
}

// ---------------------------------------------------------------- helpers

/// The native provider with both halves of the ML-DSA opt-in.
fn ml_dsa_provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        signature_verification_algorithms: native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13,
        key_provider: native::KEY_PROVIDER_WITH_ML_DSA,
        ..native::default_provider()
    })
}

/// Reads a DER header: tag, header length and content length.
fn der_header(der: &[u8]) -> (u8, usize, usize) {
    let (tag, first) = (der[0], der[1]);
    if first < 0x80 {
        return (tag, 2, usize::from(first));
    }
    let n = usize::from(first & 0x7f);
    let len = der[2..2 + n]
        .iter()
        .fold(0, |acc, b| (acc << 8) | usize::from(*b));
    (tag, 2 + n, len)
}

/// The RFC 9881 §6 `ML-DSA-PrivateKey` choice inside a PKCS #8
/// `OneAsymmetricKey`: `seed`, `expandedKey` or `both`.
fn private_key_form(pkcs8: &[u8]) -> &'static str {
    let (_, header, _) = der_header(pkcs8);
    let mut rest = &pkcs8[header..];
    // Skip `version` and `privateKeyAlgorithm`.
    for _ in 0..2 {
        let (_, header, len) = der_header(rest);
        rest = &rest[header + len..];
    }
    let (tag, header, _) = der_header(rest);
    assert_eq!(tag, 0x04, "privateKey is not an OCTET STRING");
    match rest[header] {
        0x80 => "seed",
        0x04 => "expandedKey",
        0x30 => "both",
        tag => panic!("unknown ML-DSA-PrivateKey choice {tag:#04x}"),
    }
}

/// Whether a line of OpenSSL output that starts with `label` names `scheme`
/// (`mldsa65`; OpenSSL 3.5 prints `id-ml-dsa-65` in algorithm lists).
fn line_names(out: &str, label: &str, scheme: &str) -> bool {
    let alt = scheme.replace("mldsa", "ml-dsa-");
    out.lines()
        .filter(|l| l.trim_start().starts_with(label))
        .any(|l| {
            let l = l.to_ascii_lowercase();
            l.contains(scheme) || l.contains(&alt)
        })
}

/// What the browntls side of a run uses.
struct Side<'a> {
    provider: Arc<CryptoProvider>,
    versions: &'a [&'static SupportedProtocolVersion],
    /// Client authentication: the browntls client presents `client.pem`,
    /// the browntls server requires a client certificate.
    client_auth: bool,
}

impl Side<'_> {
    /// The opt-in provider with every protocol version browntls enables by
    /// default.
    fn opt_in(client_auth: bool) -> Self {
        Self {
            provider: ml_dsa_provider(),
            versions: browntls_core::DEFAULT_VERSIONS,
            client_auth,
        }
    }
}

/// Checks that a browntls connection negotiated TLS 1.3.
fn check_tls13(common: &browntls_core::CommonState) -> Result<(), String> {
    match common.protocol_version() {
        Some(ProtocolVersion::TLSv1_3) => Ok(()),
        v => Err(format!("negotiated {v:?}, expected TLS 1.3")),
    }
}

/// The browntls error inside an I/O error of a `StreamOwned`, if any.
fn browntls_error(e: &std::io::Error) -> Option<Error> {
    e.get_ref()?.downcast_ref::<Error>().cloned()
}

/// browntls client against `openssl s_server -rev` with the server
/// certificate of `pki` and `extra` arguments; returns the outcome, the
/// server's output (stdout and stderr) and the browntls error the
/// connection failed with, if it did.
fn browntls_client(
    openssl: &Path,
    pki: &Pki,
    extra: &[&str],
    side: &Side<'_>,
) -> (Result<(), String>, String, Option<Error>) {
    let mut tls_error = None;
    let (cert, key) = (pki.path("server.pem"), pki.path("server.key"));
    let args = |port: &str| {
        let mut args = vec![
            "s_server", "-accept", port, "-naccept", "1", "-rev", "-cert", &cert, "-key", &key,
        ];
        args.extend_from_slice(extra);
        args.into_iter().map(String::from).collect()
    };
    let (child, rx, port) = match start_s_server(openssl, &args, &[]) {
        Ok(started) => started,
        Err(e) => return (Err(e), String::new(), None),
    };

    let result = (|| -> Result<(), String> {
        let builder = ClientConfig::builder_with_provider(side.provider.clone())
            .with_protocol_versions(side.versions)
            .map_err(|e| e.to_string())?
            .with_root_certificates(pki.roots());
        let config = if side.client_auth {
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
        tls.write_all(format!("{PING}\n").as_bytes()).map_err(|e| {
            tls_error = browntls_error(&e);
            format!("write: {e}")
        })?;
        let reply = read_line(&mut tls).map_err(|e| {
            tls_error = browntls_error(&e);
            format!("read: {e}")
        })?;
        let expected: String = PING.chars().rev().collect();
        if reply.trim_end() != expected {
            return Err(format!("reply {reply:?}, expected {expected:?}"));
        }
        check_tls13(&tls.conn)?;
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(())
    })();
    let (_, out, err) = finish(child, Some(rx));
    let result =
        result.map_err(|e| format!("{e}\ns_server stdout:\n{out}\ns_server stderr:\n{err}"));
    // With `-rev`, s_server prints the connection details to stderr.
    (result, format!("{out}{err}"), tls_error)
}

/// `openssl s_client` (with `extra` arguments) against a browntls server
/// holding `key` and the server certificate of `pki`; returns the outcome
/// and the client's standard output. s_client runs without `-quiet` so that
/// it prints the session summary.
fn openssl_client(
    openssl: &Path,
    pki: &Pki,
    key: PrivateKeyDer<'static>,
    extra: &[&str],
    side: &Side<'_>,
) -> (Result<(), String>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
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
        "-ign_eof",
    ];
    args.extend_from_slice(extra);
    let mut child = Command::new(openssl)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
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

        let builder = ServerConfig::builder_with_provider(side.provider.clone())
            .with_protocol_versions(side.versions)
            .map_err(|e| e.to_string())?;
        let builder = if side.client_auth {
            let verifier =
                WebPkiClientVerifier::builder_with_provider(pki.roots(), side.provider.clone())
                    .build()
                    .map_err(|e| e.to_string())?;
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let (chain, _) = pki.chain("server");
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
        check_tls13(&tls.conn)?;
        if side.client_auth && tls.conn.peer_certificates().is_none_or(<[_]>::is_empty) {
            return Err("no client certificate".into());
        }
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(())
    })();
    drop(stdin);
    let (_, out, err) = finish(child, None);
    let result = result.and_then(|()| {
        if out.contains(&format!("browntls:{PING}")) {
            Ok(())
        } else {
            Err("s_client did not print the reply".into())
        }
    });
    let result =
        result.map_err(|e| format!("{e}\ns_client stdout:\n{out}\ns_client stderr:\n{err}"));
    (result, out)
}

/// The server's private key as OpenSSL wrote it.
fn server_key(pki: &Pki) -> PrivateKeyDer<'static> {
    pki.chain("server").1
}

/// One named run of a test.
type Case<'a> = (String, Box<dyn FnOnce() -> Result<(), String> + 'a>);

/// Runs every case and reports all failures together.
fn run_all(cases: Vec<Case<'_>>) {
    let mut failures = Vec::new();
    let runs = cases.len();
    for (name, run) in cases {
        let start = Instant::now();
        let result = run();
        eprintln!(
            "{name}: {:?} in {:.2?}",
            result.as_ref().map(|()| "ok"),
            start.elapsed()
        );
        if let Err(e) = result {
            failures.push(format!("{name}: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {runs} runs failed:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// Checks that a run failed with an error that mentions `reason`.
fn refused(result: Result<(), String>, reason: &str) {
    match result {
        Ok(()) => panic!("handshake succeeded"),
        Err(e) => {
            let first = e.lines().next().unwrap_or("");
            assert!(first.contains(reason), "expected {reason}: {e}");
            eprintln!("refused as expected: {first}");
        }
    }
}

// ------------------------------------------------------------ positive cases

/// browntls client (opt-in) against `s_server -sigalgs <scheme>` with an
/// ML-DSA certificate, with and without client authentication. s_server
/// lists the schemes the ClientHello offered and, with client
/// authentication, the scheme of the client's `CertificateVerify`.
#[test]
fn browntls_client_with_openssl_server_ml_dsa() {
    let Some(openssl) = openssl_with_ml_dsa_or_skip() else {
        return;
    };
    let mut cases: Vec<Case<'_>> = Vec::new();
    for (key, scheme) in SETS {
        for client_auth in [false, true] {
            cases.push((
                format!("{scheme} client_auth={client_auth}"),
                Box::new(move || {
                    let pki = pki(openssl, key);
                    let ca = pki.path("ca.pem");
                    let mut extra = vec!["-sigalgs", scheme];
                    if client_auth {
                        extra.extend_from_slice(&[
                            "-Verify",
                            "1",
                            "-verify_return_error",
                            "-CAfile",
                            &ca,
                        ]);
                    }
                    let (result, out, _) =
                        browntls_client(openssl, &pki, &extra, &Side::opt_in(client_auth));
                    result?;
                    if !line_names(&out, "Signature Algorithms:", scheme) {
                        return Err(format!("no {scheme} in the ClientHello:\n{out}"));
                    }
                    let seen = format!("Signature type: {scheme}");
                    if client_auth && !out.lines().any(|l| l.trim() == seen) {
                        return Err(format!("s_server did not report {seen:?}:\n{out}"));
                    }
                    Ok(())
                }),
            ));
        }
    }
    run_all(cases);
}

/// `s_client -sigalgs <scheme>` against a browntls server (opt-in) holding
/// the ML-DSA key OpenSSL generated, with and without client
/// authentication. s_client reports the scheme of the server's
/// `CertificateVerify` and, with client authentication, the schemes of the
/// browntls `CertificateRequest`.
#[test]
fn openssl_client_with_browntls_server_ml_dsa() {
    let Some(openssl) = openssl_with_ml_dsa_or_skip() else {
        return;
    };
    let mut cases: Vec<Case<'_>> = Vec::new();
    for (key, scheme) in SETS {
        for client_auth in [false, true] {
            cases.push((
                format!("{scheme} client_auth={client_auth}"),
                Box::new(move || {
                    let pki = pki(openssl, key);
                    let (cert, client_key) = (pki.path("client.pem"), pki.path("client.key"));
                    let mut extra = vec!["-sigalgs", scheme];
                    if client_auth {
                        extra.extend_from_slice(&["-cert", &cert, "-key", &client_key]);
                    }
                    let side = Side::opt_in(client_auth);
                    let (result, out) =
                        openssl_client(openssl, &pki, server_key(&pki), &extra, &side);
                    result?;
                    let seen = format!("Peer signature type: {scheme}");
                    if !out.lines().any(|l| l.trim() == seen) {
                        return Err(format!("s_client did not report {seen:?}:\n{out}"));
                    }
                    if client_auth && !line_names(&out, "Requested Signature Algorithms:", scheme) {
                        return Err(format!("CertificateRequest did not offer {scheme}:\n{out}"));
                    }
                    Ok(())
                }),
            ));
        }
    }
    run_all(cases);
}

/// The browntls server loads an OpenSSL ML-DSA-65 private key in each
/// RFC 9881 §6 form: the one `genpkey` writes by default and each form
/// `openssl pkey -provparam ml-dsa.output_formats=...` writes on request.
#[test]
fn openssl_client_with_browntls_server_ml_dsa_key_forms() {
    let Some(openssl) = openssl_with_ml_dsa_or_skip() else {
        return;
    };
    let pki = pki(openssl, KeyType::MlDsa65);
    let default = server_key(&pki);
    let form = private_key_form(default.secret_der());
    report(&format!(
        "OpenSSL writes ML-DSA private keys in the `{form}` form by default"
    ));
    let mut keys = vec![(format!("default ({form})"), default)];
    for (format, expected) in [
        ("seed-only", "seed"),
        ("priv-only", "expandedKey"),
        ("seed-priv", "both"),
    ] {
        let out = format!("server-{format}.key");
        run(
            openssl,
            &pki.dir.0,
            &[
                "pkey",
                "-provparam",
                &format!("ml-dsa.output_formats={format}"),
                "-in",
                "server.key",
                "-out",
                &out,
            ],
        );
        let key = PrivateKeyDer::from_pem_file(pki.path(&out)).unwrap();
        assert_eq!(private_key_form(key.secret_der()), expected, "{format}");
        keys.push((format!("{format} ({expected})"), key));
    }
    let pki = &pki;
    run_all(
        keys.into_iter()
            .map(|(name, key)| {
                let run: Box<dyn FnOnce() -> Result<(), String>> = Box::new(move || {
                    let extra = ["-sigalgs", "mldsa65"];
                    let side = Side::opt_in(false);
                    let (result, out) = openssl_client(openssl, pki, key, &extra, &side);
                    result?;
                    if !out
                        .lines()
                        .any(|l| l.trim() == "Peer signature type: mldsa65")
                    {
                        return Err(format!("s_client did not report mldsa65:\n{out}"));
                    }
                    Ok(())
                });
                (name, run)
            })
            .collect(),
    );
}

// ------------------------------------------------------------ negative cases

/// Without the opt-in, a browntls client offers no ML-DSA scheme, so an
/// ML-DSA-only `s_server` has nothing to sign with, and the default key
/// provider does not load the ML-DSA key OpenSSL wrote.
#[test]
fn ml_dsa_needs_the_opt_in() {
    let Some(openssl) = openssl_with_ml_dsa_or_skip() else {
        return;
    };
    let pki = pki(openssl, KeyType::MlDsa65);
    let side = Side {
        provider: Arc::new(native::default_provider()),
        ..Side::opt_in(false)
    };
    let (result, _, tls_error) = browntls_client(openssl, &pki, &[], &side);
    // s_server finds no scheme to sign with and sends handshake_failure.
    refused(result, "HandshakeFailure");
    assert_eq!(
        tls_error,
        Some(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );

    let (chain, key) = pki.chain("server");
    let err = ServerConfig::builder_with_provider(Arc::new(native::default_provider()))
        .with_protocol_versions(browntls_core::DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect_err("the default key provider loaded an ML-DSA key");
    eprintln!("default key provider: {err}");
}

/// `s_client` offering classical schemes only cannot complete a handshake
/// with a browntls server whose only key is ML-DSA.
#[test]
fn openssl_client_with_classical_sigalgs_and_ml_dsa_browntls_server() {
    let Some(openssl) = openssl_with_ml_dsa_or_skip() else {
        return;
    };
    let pki = pki(openssl, KeyType::MlDsa65);
    let extra = ["-sigalgs", CLASSICAL_SIGALGS];
    let (result, _) = openssl_client(
        openssl,
        &pki,
        server_key(&pki),
        &extra,
        &Side::opt_in(false),
    );
    refused(result, "NoSignatureSchemesInCommon");
}

/// A browntls server whose only key is ML-DSA completes no TLS 1.2
/// handshake (`s_client -tls1_2`), even with TLS 1.2 enabled.
#[cfg(feature = "tls12")]
#[test]
fn openssl_tls12_client_and_ml_dsa_browntls_server() {
    let Some(openssl) = openssl_with_ml_dsa_or_skip() else {
        return;
    };
    let pki = pki(openssl, KeyType::MlDsa65);
    let side = Side {
        versions: &[&version::TLS12, &version::TLS13],
        ..Side::opt_in(false)
    };
    let (result, _) = openssl_client(openssl, &pki, server_key(&pki), &["-tls1_2"], &side);
    // No TLS 1.2 cipher suite matches a key that signs in TLS 1.3 only.
    refused(result, "NoCipherSuitesInCommon");
}

/// A browntls client (opt-in) offering TLS 1.2 only cannot use an ML-DSA-only
/// `s_server -tls1_2`: OpenSSL uses no ML-DSA certificate in TLS 1.2 (it
/// reports no shared cipher suite) and sends handshake_failure. (That a
/// ClientHello without TLS 1.3 lists no ML-DSA scheme is checked without
/// OpenSSL, in `mldsa_tls13_only_rules`.)
#[cfg(feature = "tls12")]
#[test]
fn browntls_tls12_client_and_ml_dsa_openssl_server() {
    let Some(openssl) = openssl_with_ml_dsa_or_skip() else {
        return;
    };
    let pki = pki(openssl, KeyType::MlDsa65);
    let side = Side {
        versions: &[&version::TLS12],
        ..Side::opt_in(false)
    };
    let (result, _, tls_error) = browntls_client(openssl, &pki, &["-tls1_2"], &side);
    refused(result, "HandshakeFailure");
    assert_eq!(
        tls_error,
        Some(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );
}

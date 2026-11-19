//! The case matrix (versions, suites, groups, key types) and the two
//! directions every case runs in.

use super::*;

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
    /// How Encrypt-then-MAC (RFC 7366) is handled for a CBC suite.
    etm: Etm,
}

/// The Encrypt-then-MAC variants of a CBC case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Etm {
    /// Both sides offer the extension (the default); AEAD suites too.
    Negotiated,
    /// OpenSSL has the extension disabled and browntls allows
    /// MAC-then-encrypt: the handshake uses the RFC 5246 construction.
    #[cfg_attr(not(feature = "tls12"), allow(dead_code))]
    DisabledAllowed,
    /// OpenSSL has the extension disabled and browntls keeps its default:
    /// the handshake must fail.
    #[cfg_attr(not(feature = "tls12"), allow(dead_code))]
    DisabledRefused,
}

/// An OpenSSL configuration file that disables Encrypt-then-MAC for every
/// `SSL_CTX` of the process (`OPENSSL_CONF`), next to the PKI files.
fn no_etm_conf(pki: &Pki) -> String {
    // Tests run in parallel and share the cached `Pki`, so an OpenSSL
    // process may read this file while another test writes it. Writing in
    // place truncates it first, and a process that read the empty file kept
    // encrypt_then_mac on; write a private file and rename it into place,
    // which replaces the file atomically.
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let path = pki.path("no-etm.cnf");
    let tmp = pki.path(&format!(
        "no-etm.cnf.{}.tmp",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(
        &tmp,
        "openssl_conf = openssl_init\n\n[openssl_init]\nssl_conf = ssl_sect\n\n\
         [ssl_sect]\nsystem_default = system_default_sect\n\n[system_default_sect]\n\
         Options = -EncryptThenMac\n",
    )
    .unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    path
}

impl Case {
    fn name(&self) -> String {
        format!(
            "{:?} {:?} {:?} {:?} {:?}",
            self.version.version,
            self.suite.suite(),
            self.group.name(),
            self.key,
            self.etm
        )
    }

    /// The environment for the OpenSSL process.
    fn openssl_env(&self, pki: &Pki) -> Vec<(&'static str, String)> {
        match self.etm {
            Etm::Negotiated => Vec::new(),
            Etm::DisabledAllowed | Etm::DisabledRefused => {
                vec![("OPENSSL_CONF", no_etm_conf(pki))]
            }
        }
    }

    /// Whether browntls may use MAC-then-encrypt.
    fn allow_mac_then_encrypt(&self) -> bool {
        self.etm == Etm::DisabledAllowed
    }

    /// Turns the outcome of a run into the verdict for this case: a case
    /// that must fail passes when the handshake failed.
    fn verdict(&self, result: Result<(), String>) -> Result<(), String> {
        match (self.etm, result) {
            (Etm::DisabledRefused, Ok(())) => {
                Err("handshake succeeded without encrypt_then_mac".into())
            }
            (Etm::DisabledRefused, Err(e)) => {
                eprintln!("  refused as expected: {}", e.lines().next().unwrap_or(""));
                Ok(())
            }
            (_, result) => result,
        }
    }

    fn openssl_args(&self) -> Vec<&'static str> {
        let mut args = if self.version.version == ProtocolVersion::TLSv1_3 {
            vec!["-tls1_3", "-ciphersuites", self.openssl_suite]
        } else {
            vec!["-tls1_2", "-cipher", self.openssl_suite]
        };
        args.extend_from_slice(&["-groups", self.openssl_group]);
        if self.openssl_suite == "TLS_AES_128_CCM_8_SHA256" {
            // OpenSSL 3.2 moved the CCM-8 suites to security level 0 for
            // their 8-byte tag; the default level (2 on most distributions)
            // would otherwise refuse to negotiate the suite at all.
            args.extend_from_slice(&["-cipher", "DEFAULT:@SECLEVEL=0"]);
        }
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
    fn check(&self, common: &browntls_core::CommonState) -> Result<(), String> {
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
        etm: Etm::Negotiated,
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
            etm: Etm::Negotiated,
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
        // The CBC suites (RFC 5246 §6.2.3.2, RFC 5289, RFC 8422) with
        // Encrypt-then-MAC (RFC 7366), which OpenSSL negotiates by default.
        cases.extend([
            Case {
                extra_groups: vec![kx::SECP256R1],
                ..tls12(
                    cs::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                    "ECDHE-ECDSA-AES128-SHA256",
                    kx::X25519,
                    "X25519:P-256",
                    KeyType::EcdsaP256,
                )
            },
            tls12(
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                "ECDHE-ECDSA-AES256-SHA384",
                kx::SECP384R1,
                "P-384",
                KeyType::EcdsaP384,
            ),
            tls12(
                cs::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                "ECDHE-RSA-AES128-SHA256",
                kx::SECP256R1,
                "P-256",
                KeyType::Rsa2048,
            ),
            tls12(
                cs::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                "ECDHE-RSA-AES256-SHA384",
                kx::X25519,
                "X25519",
                KeyType::Rsa2048,
            ),
            Case {
                extra_groups: vec![kx::SECP256R1],
                ..tls12(
                    cs::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                    "ECDHE-ECDSA-AES128-SHA",
                    kx::X25519,
                    "X25519:P-256",
                    KeyType::EcdsaP256,
                )
            },
            tls12(
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                "ECDHE-ECDSA-AES256-SHA",
                kx::SECP384R1,
                "P-384",
                KeyType::EcdsaP384,
            ),
            tls12(
                cs::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                "ECDHE-RSA-AES128-SHA",
                kx::X25519,
                "X25519",
                KeyType::Rsa2048,
            ),
            tls12(
                cs::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                "ECDHE-RSA-AES256-SHA",
                kx::SECP256R1,
                "P-256",
                KeyType::Rsa2048,
            ),
        ]);
        // Without Encrypt-then-MAC on the OpenSSL side (RFC 5246
        // MAC-then-encrypt): refused by default, used when allowed.
        for etm in [Etm::DisabledRefused, Etm::DisabledAllowed] {
            cases.push(Case {
                etm,
                ..tls12(
                    cs::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                    "ECDHE-RSA-AES128-SHA256",
                    kx::X25519,
                    "X25519",
                    KeyType::Rsa2048,
                )
            });
            cases.push(Case {
                etm,
                ..tls12(
                    cs::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    "ECDHE-RSA-AES256-SHA",
                    kx::SECP256R1,
                    "P-256",
                    KeyType::Rsa2048,
                )
            });
        }
    }
    cases
}

// --------------------------------------------------------------- directions

/// browntls client against `openssl s_server -rev` (which echoes each line
/// reversed).
fn browntls_client(openssl: &Path, case: &Case, client_auth: bool) -> Result<(), String> {
    browntls_client_with(openssl, case, client_auth, |_| {})
}

/// [`browntls_client`] with every optional ClientHello extension on: GREASE
/// (RFC 8701), a small `record_size_limit` (RFC 8449, which OpenSSL 3 does
/// not implement and must ignore), `ticket_request` (RFC 9149) and padding
/// to a fixed size (RFC 7685).
fn browntls_client_with_extensions(
    openssl: &Path,
    case: &Case,
    client_auth: bool,
) -> Result<(), String> {
    browntls_client_with(openssl, case, client_auth, |config| {
        config.enable_grease = true;
        config.record_size_limit = Some(512);
        config.tls13_ticket_request = Some(browntls_core::client::TicketRequest {
            new_session_count: 1,
            resumption_count: 1,
        });
        config.client_hello_padding = browntls_core::client::ClientHelloPadding::AtLeast(1024);
    })
}

fn browntls_client_with(
    openssl: &Path,
    case: &Case,
    client_auth: bool,
    tweak: fn(&mut ClientConfig),
) -> Result<(), String> {
    let pki = pki(openssl, case.key);
    let (cert, key) = (pki.path("server.pem"), pki.path("server.key"));
    let ca = pki.path("ca.pem");
    let args = |port: &str| {
        let mut args = vec![
            "s_server", "-accept", port, "-naccept", "1", "-rev", "-cert", &cert, "-key", &key,
        ];
        args.extend(case.openssl_args());
        if client_auth {
            args.extend_from_slice(&["-Verify", "1", "-verify_return_error", "-CAfile", &ca]);
        }
        args.into_iter().map(String::from).collect()
    };
    let (child, rx, port) = start_s_server(openssl, &args, &case.openssl_env(&pki))?;

    let result = (|| -> Result<(), String> {
        let builder = ClientConfig::builder_with_provider(case.provider())
            .with_protocol_versions(&[case.version])
            .map_err(|e| e.to_string())?
            .with_root_certificates(pki.roots());
        let mut config = if client_auth {
            let (chain, key) = pki.chain("client");
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| e.to_string())?
        } else {
            builder.with_no_client_auth()
        };
        config.allow_mac_then_encrypt = case.allow_mac_then_encrypt();
        tweak(&mut config);
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
    case.verdict(
        result.map_err(|e| format!("{e}\ns_server stdout:\n{out}\ns_server stderr:\n{err}")),
    )
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
        .envs(case.openssl_env(&pki))
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
        let mut config = builder
            .with_single_cert(chain, key)
            .map_err(|e| e.to_string())?;
        config.allow_mac_then_encrypt = case.allow_mac_then_encrypt();
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
    case.verdict(result.and_then(|()| {
        if out.contains(&format!("browntls:{PING}")) {
            Ok(())
        } else {
            Err(format!("s_client stdout:\n{out}\ns_client stderr:\n{err}"))
        }
    }))
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
fn browntls_client_with_grease_and_optional_extensions_with_openssl_server() {
    for_all(browntls_client_with_extensions);
}

#[test]
fn openssl_client_with_browntls_server() {
    for_all(openssl_client);
}

//! External PSK handshakes in both directions.

use super::*;

// ------------------------------------------------------ external PSKs

/// The external PSK both sides use: OpenSSL's `-psk` takes it in hex and,
/// for TLS 1.3, associates it with SHA-256 (TLS_AES_128_GCM_SHA256).
const PSK_IDENTITY: &str = "browntls-interop";
const PSK_KEY: [u8; 32] = [
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

fn psk_hex() -> String {
    PSK_KEY.iter().map(|b| format!("{b:02x}")).collect()
}

fn external_psk() -> Arc<browntls_core::psk::ExternalPsk> {
    Arc::new(
        browntls_core::psk::ExternalPsk::new(
            PSK_IDENTITY.as_bytes().to_vec(),
            PSK_KEY.to_vec(),
            browntls_core::crypto::hash::HashAlgorithm::SHA256,
        )
        .unwrap(),
    )
}

/// browntls client offering an external PSK to `openssl s_server -psk
/// -nocert`, which can only authenticate with the PSK. `server_suites` is
/// the s_server TLS 1.3 suite list (`None`: its default).
fn browntls_psk_client(openssl: &Path, server_suites: Option<&str>) -> Result<(), String> {
    let hex = psk_hex();
    let args = |port: &str| {
        let mut args = vec![
            "s_server",
            "-accept",
            port,
            "-naccept",
            "1",
            "-rev",
            "-nocert",
            "-tls1_3",
            "-psk",
            &hex,
            "-psk_identity",
            PSK_IDENTITY,
        ];
        if let Some(suites) = server_suites {
            args.extend_from_slice(&["-ciphersuites", suites]);
        }
        args.into_iter().map(String::from).collect()
    };
    let (child, rx, port) = start_s_server(openssl, &args, &[])?;

    let result = (|| -> Result<(), String> {
        // No trust anchors: the server has no certificate, and any it might
        // send would be refused.
        let mut config = ClientConfig::builder_with_provider(Arc::new(native::default_provider()))
            .with_protocol_versions(&[&version::TLS13])
            .map_err(|e| e.to_string())?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config.external_psks = vec![external_psk()];
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
        if tls.conn.external_psk_identity() != Some(PSK_IDENTITY.as_bytes()) {
            return Err("external PSK not used".into());
        }
        if tls.conn.peer_certificates().is_some() {
            return Err("unexpected server certificate".into());
        }
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(())
    })();
    let (_, out, err) = finish(child, Some(rx));
    result.map_err(|e| format!("{e}\ns_server stdout:\n{out}\ns_server stderr:\n{err}"))
}

/// `openssl s_client -psk` against a browntls server without a certificate.
fn openssl_psk_client(openssl: &Path, client_suites: Option<&str>) -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let hex = psk_hex();
    let mut args = vec![
        "s_client",
        "-connect",
        &addr,
        "-servername",
        "localhost",
        "-tls1_3",
        "-psk",
        &hex,
        "-psk_identity",
        PSK_IDENTITY,
        "-quiet",
    ];
    if let Some(suites) = client_suites {
        args.extend_from_slice(&["-ciphersuites", suites]);
    }
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

        let resolver: Vec<Arc<browntls_core::psk::ExternalPsk>> = vec![external_psk()];
        let config = ServerConfig::builder_with_provider(Arc::new(native::default_provider()))
            .with_protocol_versions(&[&version::TLS13])
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_external_psks_only(Arc::new(resolver));
        let conn = ServerConnection::new(Arc::new(config)).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, sock);
        let line = read_line(&mut tls).map_err(|e| format!("read: {e}"))?;
        if line.trim_end() != PING {
            return Err(format!("received {line:?}"));
        }
        tls.write_all(format!("browntls:{line}").as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        if tls.conn.external_psk_identity() != Some(PSK_IDENTITY.as_bytes()) {
            return Err("external PSK not used".into());
        }
        let suite = tls.conn.negotiated_cipher_suite().map(|s| s.suite());
        eprintln!("  negotiated {suite:?}");
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(())
    })();
    drop(stdin);
    let (_, out, err) = finish(child, None);
    result.and_then(|()| {
        if out.contains(&format!("browntls:{PING}")) {
            Ok(())
        } else {
            Err(format!("s_client stdout:\n{out}\ns_client stderr:\n{err}"))
        }
    })
}

/// Runs `f` with each OpenSSL suite list and reports all failures together.
fn for_psk_suites(f: fn(&Path, Option<&str>) -> Result<(), String>) {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    let mut failures = Vec::new();
    for suites in [
        None,
        Some("TLS_AES_128_GCM_SHA256"),
        Some("TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"),
    ] {
        let result = f(openssl, suites);
        eprintln!("external PSK, OpenSSL suites {suites:?}: {result:?}");
        if let Err(e) = result {
            failures.push(format!("{suites:?}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn browntls_external_psk_client_with_openssl_server() {
    for_psk_suites(browntls_psk_client);
}

#[test]
fn openssl_external_psk_client_with_browntls_server() {
    for_psk_suites(openssl_psk_client);
}

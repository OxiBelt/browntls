//! A TLS 1.3-only policy against OpenSSL (RFC 9852 §4): a browntls endpoint
//! whose version list holds TLS 1.3 alone negotiates TLS 1.3 with an OpenSSL
//! peer left at its defaults, and refuses one held to TLS 1.2, in both
//! roles. The OpenSSL side confirms the alert it received or sent.

use super::*;

use browntls_core::{AlertDescription, Error, PeerIncompatible};

/// The browntls error that a `StreamOwned` wrapped in `err`.
fn tls_error(err: &std::io::Error) -> Option<&Error> {
    err.get_ref()?.downcast_ref()
}

/// A browntls client for `versions` exchanges one line with
/// `openssl s_server` started with `server_args`. Returns the version it
/// negotiated, or its error, and what the server printed.
fn browntls_client(
    openssl: &Path,
    server_args: &[&str],
    versions: &[&'static SupportedProtocolVersion],
) -> (std::io::Result<Option<ProtocolVersion>>, String) {
    let pki = pki(openssl, KeyType::EcdsaP256);
    let (cert, key) = (pki.path("server.pem"), pki.path("server.key"));
    let args = |port: &str| {
        let mut args = vec![
            "s_server", "-accept", port, "-naccept", "1", "-rev", "-cert", &cert, "-key", &key,
        ];
        args.extend_from_slice(server_args);
        args.into_iter().map(String::from).collect()
    };
    let (child, rx, port) = start_s_server(openssl, &args, &[]).unwrap();

    let config = ClientConfig::builder_with_provider(Arc::new(native::default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(pki.roots())
        .with_no_client_auth();
    let conn = ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
        .unwrap();
    let sock = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    sock.set_read_timeout(Some(STEP)).unwrap();
    sock.set_write_timeout(Some(STEP)).unwrap();
    let mut tls = StreamOwned::new(conn, sock);
    let result = (|| {
        tls.write_all(format!("{PING}\n").as_bytes())?;
        let reply = read_line(&mut tls)?;
        assert_eq!(reply.trim_end(), PING.chars().rev().collect::<String>());
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(tls.conn.protocol_version())
    })();
    drop(tls);
    let (_, out, err) = finish(child, Some(rx));
    (result, format!("{out}\n{err}"))
}

/// `openssl s_client` started with `client_args` sends one line to a
/// browntls server for `versions`. Returns the version the server
/// negotiated, or its error, and what the client printed.
fn browntls_server(
    openssl: &Path,
    client_args: &[&str],
    versions: &[&'static SupportedProtocolVersion],
) -> (std::io::Result<Option<ProtocolVersion>>, String) {
    let pki = pki(openssl, KeyType::EcdsaP256);
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
        "-quiet",
    ];
    args.extend_from_slice(client_args);
    let mut child = Command::new(openssl)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // `-quiet` implies `-ign_eof`, so stdin can stay open until the end.
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(format!("{PING}\n").as_bytes()).unwrap();

    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + STEP;
    let sock = loop {
        match listener.accept() {
            Ok((sock, _)) => break sock,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("accept: {e}"),
        }
    };
    sock.set_nonblocking(false).unwrap();
    sock.set_read_timeout(Some(STEP)).unwrap();
    sock.set_write_timeout(Some(STEP)).unwrap();

    let (chain, key) = pki.chain("server");
    let config = ServerConfig::builder_with_provider(Arc::new(native::default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let conn = ServerConnection::new(Arc::new(config)).unwrap();
    let mut tls = StreamOwned::new(conn, sock);
    let result = (|| {
        let line = read_line(&mut tls)?;
        assert_eq!(line.trim_end(), PING);
        tls.write_all(format!("browntls:{line}").as_bytes())?;
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(tls.conn.protocol_version())
    })();
    drop(tls);
    drop(stdin);
    let (_, out, err) = finish(child, None);
    (result, format!("{out}\n{err}"))
}

#[test]
fn a_tls13_only_browntls_client_and_openssl_servers() {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    // An OpenSSL server with its defaults has both versions: TLS 1.3.
    let (result, printed) = browntls_client(openssl, &[], &[&version::TLS13]);
    assert_eq!(
        result.map_err(|e| format!("{e}\n{printed}")),
        Ok(Some(ProtocolVersion::TLSv1_3))
    );

    // One held to TLS 1.2 answers the TLS 1.3-only hello with
    // `protocol_version`, and the client does not try anything else.
    let (result, printed) = browntls_client(openssl, &["-tls1_2"], &[&version::TLS13]);
    let err = result.expect_err("a TLS 1.2 server served a TLS 1.3-only client");
    assert_eq!(
        tls_error(&err),
        Some(&Error::AlertReceived(AlertDescription::ProtocolVersion)),
        "{err:?}\n{printed}"
    );
}

#[test]
fn a_tls13_only_browntls_server_and_openssl_clients() {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    // An OpenSSL client with its defaults offers both versions: TLS 1.3.
    let (result, printed) = browntls_server(openssl, &[], &[&version::TLS13]);
    assert_eq!(
        result.map_err(|e| format!("{e}\n{printed}")),
        Ok(Some(ProtocolVersion::TLSv1_3))
    );
    assert!(printed.contains(&format!("browntls:{PING}")), "{printed}");

    // One held to TLS 1.2 is refused, and reports the alert it was sent.
    // Its hello has no `supported_versions` extension at all (OpenSSL
    // sends it only when it offers TLS 1.3), which is the cause named.
    let (result, printed) = browntls_server(openssl, &["-tls1_2"], &[&version::TLS13]);
    let err = result.expect_err("a TLS 1.3-only server served a TLS 1.2 client");
    assert_eq!(
        tls_error(&err),
        Some(&Error::PeerIncompatible(
            PeerIncompatible::SupportedVersionsExtensionRequired
        )),
        "{err:?}\n{printed}"
    );
    assert!(printed.contains("alert protocol version"), "{printed}");
    assert!(!printed.contains(&format!("browntls:{PING}")), "{printed}");
}

/// The default version list keeps serving a TLS 1.2 peer, and takes
/// TLS 1.3 with a peer that has it.
#[cfg(feature = "tls12")]
#[test]
fn the_default_browntls_versions_and_openssl_peers() {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    let versions = browntls_core::DEFAULT_VERSIONS;
    for (openssl_args, expected) in [
        (&["-tls1_2"][..], ProtocolVersion::TLSv1_2),
        (&[][..], ProtocolVersion::TLSv1_3),
    ] {
        let (result, printed) = browntls_client(openssl, openssl_args, versions);
        assert_eq!(
            result.map_err(|e| format!("{e}\n{printed}")),
            Ok(Some(expected))
        );
        let (result, printed) = browntls_server(openssl, openssl_args, versions);
        assert_eq!(
            result.map_err(|e| format!("{e}\n{printed}")),
            Ok(Some(expected))
        );
    }
}

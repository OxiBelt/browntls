//! `openssl s_client` with the optional TLS 1.3 features of RFC 9846:
//! post-handshake authentication and a stateless HelloRetryRequest.

use super::*;

// ------------------------------------- RFC 9846 optional features (TLS 1.3)

/// Spawns `openssl s_client` (TLS 1.3, `-quiet`) with `extra` arguments
/// against `addr`, sends [`PING`] and accepts the TCP connection.
fn spawn_tls13_client(
    openssl: &Path,
    pki: &Pki,
    listener: &TcpListener,
    extra: &[&str],
) -> (Child, std::process::ChildStdin, Result<TcpStream, String>) {
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
        "-tls1_3",
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
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + STEP;
    let sock = loop {
        match listener.accept() {
            Ok((sock, _)) => break Ok(sock),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => break Err(format!("accept: {e}")),
        }
    };
    let sock = sock.inspect(|sock| {
        sock.set_nonblocking(false).unwrap();
        sock.set_read_timeout(Some(STEP)).unwrap();
        sock.set_write_timeout(Some(STEP)).unwrap();
    });
    (child, stdin, sock)
}

/// Checks that s_client printed the browntls reply.
fn reply_seen(child: Child, stdin: std::process::ChildStdin, result: Result<(), String>) {
    drop(stdin);
    let (_, out, err) = finish(child, None);
    result.unwrap_or_else(|e| panic!("{e}\ns_client stdout:\n{out}\ns_client stderr:\n{err}"));
    assert!(
        out.contains(&format!("browntls:{PING}")),
        "s_client stdout:\n{out}\ns_client stderr:\n{err}"
    );
}

/// `openssl s_client -enable_pha` against a browntls server that defers
/// client authentication and requests it after reading the first line
/// (RFC 9846 §4.7.2).
#[test]
fn openssl_client_answers_post_handshake_auth() {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    let pki = pki(openssl, KeyType::EcdsaP256);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (cert, key) = (pki.path("client.pem"), pki.path("client.key"));
    let (child, stdin, sock) = spawn_tls13_client(
        openssl,
        &pki,
        &listener,
        &["-enable_pha", "-cert", &cert, "-key", &key],
    );

    let result = (|| -> Result<(), String> {
        let provider = Arc::new(native::default_provider());
        let verifier = WebPkiClientVerifier::builder_with_provider(pki.roots(), provider.clone())
            .build()
            .map_err(|e| e.to_string())?;
        let (chain, server_key) = pki.chain("server");
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&version::TLS13])
            .map_err(|e| e.to_string())?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, server_key)
            .map_err(|e| e.to_string())?;
        config.request_client_auth_after_handshake = true;
        let conn = ServerConnection::new(Arc::new(config)).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, sock?);
        let line = read_line(&mut tls).map_err(|e| format!("read: {e}"))?;
        if line.trim_end() != PING {
            return Err(format!("received {line:?}"));
        }
        if !tls.conn.post_handshake_auth_offered() || tls.conn.peer_certificates().is_some() {
            return Err("expected a deferred client authentication".into());
        }
        tls.conn
            .request_client_auth()
            .map_err(|e| format!("request: {e}"))?;
        while tls.conn.post_handshake_auth_status()
            == Some(browntls_core::server::PostHandshakeAuthStatus::Requested)
        {
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|e| format!("io: {e}"))?;
        }
        if tls.conn.post_handshake_auth_status()
            != Some(browntls_core::server::PostHandshakeAuthStatus::Authenticated)
            || tls.conn.peer_certificates().is_none_or(<[_]>::is_empty)
        {
            return Err("client certificate not received".into());
        }
        tls.write_all(format!("browntls:{line}").as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(())
    })();
    reply_seen(child, stdin, result);
}

/// `openssl s_client` against a browntls server whose HelloRetryRequest
/// carries a stateless cookie (RFC 9846 §4.3.2): the connection object that
/// sent it is dropped and a fresh one completes the handshake from OpenSSL's
/// second ClientHello on the same socket.
#[test]
fn openssl_client_follows_stateless_hello_retry_request() {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    let pki = pki(openssl, KeyType::EcdsaP256);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // OpenSSL sends a key share for X25519 only; the server wants P-256.
    let (child, stdin, sock) =
        spawn_tls13_client(openssl, &pki, &listener, &["-groups", "X25519:P-256"]);

    let result = (|| -> Result<(), String> {
        let mut provider = native::default_provider();
        provider.kx_groups = vec![native::kx_group::SECP256R1];
        let (chain, server_key) = pki.chain("server");
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&version::TLS13])
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(chain, server_key)
            .map_err(|e| e.to_string())?;
        config.hello_retry_cookies = Some(Arc::new(
            browntls_core::ticketer::TicketRotator::new(3600, || {
                Ok(Box::new(native::ticketer::AeadTicketProducer::new()?))
            })
            .map_err(|e| e.to_string())?,
        ));
        let config = Arc::new(config);
        let mut sock = sock?;

        // First connection object: reads the first ClientHello, sends the
        // HelloRetryRequest, and is dropped.
        let mut first = ServerConnection::new(config.clone()).map_err(|e| e.to_string())?;
        while first.wants_read() && !first.wants_write() {
            first
                .read_tls(&mut sock)
                .map_err(|e| format!("read: {e}"))?;
            first.process_new_packets().map_err(|e| e.to_string())?;
        }
        while first.wants_write() {
            first
                .write_tls(&mut sock)
                .map_err(|e| format!("write: {e}"))?;
        }
        if first.handshake_kind() != Some(browntls_core::HandshakeKind::FullWithHelloRetryRequest) {
            return Err("no HelloRetryRequest was sent".into());
        }
        drop(first);

        let conn = ServerConnection::new(config).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, sock);
        let line = read_line(&mut tls).map_err(|e| format!("read: {e}"))?;
        if line.trim_end() != PING {
            return Err(format!("received {line:?}"));
        }
        if tls.conn.handshake_kind()
            != Some(browntls_core::HandshakeKind::FullWithHelloRetryRequest)
            || tls.conn.negotiated_key_exchange_group().map(|g| g.name())
                != Some(browntls_core::NamedGroup::secp256r1)
        {
            return Err("the fresh connection did not continue the retry".into());
        }
        tls.write_all(format!("browntls:{line}").as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(())
    })();
    reply_seen(child, stdin, result);
}

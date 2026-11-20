//! `openssl s_client` against a browntls server with `enable_grease` on
//! (RFC 8701 §4.1): GREASE in the TLS 1.3 CertificateRequest, during the
//! handshake and after it, and in every NewSessionTicket.

use super::*;

use browntls_core::server::{NoServerSessionStorage, PostHandshakeAuthStatus};

/// Spawns `openssl s_client` (TLS 1.3, `-quiet`) with `extra` arguments
/// against `listener`, sends [`PING`] and accepts the TCP connection.
fn spawn_client(
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
    // `-quiet` implies `-ign_eof`: s_client keeps the connection until the
    // server closes it, so stdin can stay open.
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

/// Waits for s_client and checks that it printed the browntls reply.
fn reply_seen(child: Child, stdin: std::process::ChildStdin, result: Result<(), String>) {
    drop(stdin);
    let (_, out, err) = finish(child, None);
    result.unwrap_or_else(|e| panic!("{e}\ns_client stdout:\n{out}\ns_client stderr:\n{err}"));
    assert!(
        out.contains(&format!("browntls:{PING}")),
        "s_client stdout:\n{out}\ns_client stderr:\n{err}"
    );
}

/// A TLS 1.3 server configuration with GREASE on that verifies client
/// certificates against the PKI's CA.
fn grease_server(pki: &Pki) -> Result<ServerConfig, String> {
    let provider = Arc::new(native::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(pki.roots(), provider.clone())
        .build()
        .map_err(|e| e.to_string())?;
    let (chain, key) = pki.chain("server");
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    config.enable_grease = true;
    Ok(config)
}

/// Serves one line on `sock`: reads [`PING`], runs `check` on the
/// connection, answers with a prefixed copy and closes.
fn serve(
    config: Arc<ServerConfig>,
    sock: TcpStream,
    check: impl FnOnce(&mut StreamOwned<ServerConnection, TcpStream>) -> Result<(), String>,
) -> Result<(), String> {
    let conn = ServerConnection::new(config).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, sock);
    let line = read_line(&mut tls).map_err(|e| format!("read: {e}"))?;
    if line.trim_end() != PING {
        return Err(format!("received {line:?}"));
    }
    check(&mut tls)?;
    tls.write_all(format!("browntls:{line}").as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}

fn has_client_certificate(conn: &ServerConnection) -> Result<(), String> {
    if conn.peer_certificates().is_none_or(<[_]>::is_empty) {
        return Err("no client certificate".into());
    }
    Ok(())
}

/// `openssl s_client` with a certificate against a browntls server that
/// requires client authentication with GREASE on.
#[test]
fn openssl_client_auth_with_browntls_grease_server() {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    for key in [KeyType::EcdsaP256, KeyType::Rsa2048, KeyType::Ed25519] {
        let pki = pki(openssl, key);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (cert, client_key) = (pki.path("client.pem"), pki.path("client.key"));
        let (child, stdin, sock) = spawn_client(
            openssl,
            &pki,
            &listener,
            &["-cert", &cert, "-key", &client_key],
        );
        let result = grease_server(&pki).and_then(|config| {
            serve(Arc::new(config), sock?, |tls| {
                if tls.conn.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
                    return Err("not TLS 1.3".into());
                }
                has_client_certificate(&tls.conn)
            })
        });
        eprintln!("{key:?}: {:?}", result.as_ref().map(|()| "ok"));
        reply_seen(child, stdin, result);
    }
}

/// `openssl s_client -enable_pha` against a browntls server with GREASE on
/// that requests client authentication after the handshake (RFC 9846
/// §4.7.2): the post-handshake CertificateRequest carries GREASE.
#[test]
fn openssl_client_answers_post_handshake_auth_with_grease() {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    let pki = pki(openssl, KeyType::EcdsaP256);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (cert, key) = (pki.path("client.pem"), pki.path("client.key"));
    let (child, stdin, sock) = spawn_client(
        openssl,
        &pki,
        &listener,
        &["-enable_pha", "-cert", &cert, "-key", &key],
    );
    let result = grease_server(&pki).and_then(|mut config| {
        config.request_client_auth_after_handshake = true;
        serve(Arc::new(config), sock?, |tls| {
            if !tls.conn.post_handshake_auth_offered() || tls.conn.peer_certificates().is_some() {
                return Err("expected a deferred client authentication".into());
            }
            tls.conn
                .request_client_auth()
                .map_err(|e| format!("request: {e}"))?;
            while tls.conn.post_handshake_auth_status() == Some(PostHandshakeAuthStatus::Requested)
            {
                tls.conn
                    .complete_io(&mut tls.sock)
                    .map_err(|e| format!("io: {e}"))?;
            }
            if tls.conn.post_handshake_auth_status() != Some(PostHandshakeAuthStatus::Authenticated)
            {
                return Err("post-handshake authentication did not complete".into());
            }
            has_client_certificate(&tls.conn)
        })
    });
    reply_seen(child, stdin, result);
}

/// A first `s_client` run stores a ticket from a browntls server with GREASE
/// on (`-sess_out`); a second run resumes with it (`-sess_in`). Runs with
/// stateful and with stateless tickets.
#[test]
fn openssl_client_resumes_with_browntls_grease_server_ticket() {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    let pki = pki(openssl, KeyType::EcdsaP256);
    let (cert, key) = (pki.path("client.pem"), pki.path("client.key"));
    for stateless in [false, true] {
        let mut config = grease_server(&pki).unwrap();
        if stateless {
            config.ticketer = Arc::new(
                browntls_core::ticketer::TicketRotator::new(3600, || {
                    Ok(Box::new(native::ticketer::AeadTicketProducer::new()?))
                })
                .unwrap(),
            );
            config.session_storage = Arc::new(NoServerSessionStorage {});
        }
        let config = Arc::new(config);
        let session = pki.path(&format!("grease-session-{stateless}.pem"));
        let _ = std::fs::remove_file(&session);

        for (resumed, session_arg) in [(false, "-sess_out"), (true, "-sess_in")] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let (child, stdin, sock) = spawn_client(
                openssl,
                &pki,
                &listener,
                &["-cert", &cert, "-key", &key, session_arg, &session],
            );
            let result = sock.and_then(|sock| {
                serve(config.clone(), sock, |tls| {
                    let kind = tls.conn.handshake_kind();
                    let want = if resumed {
                        browntls_core::HandshakeKind::Resumed
                    } else {
                        browntls_core::HandshakeKind::Full
                    };
                    if kind != Some(want) {
                        return Err(format!("handshake {kind:?}, expected {want:?}"));
                    }
                    has_client_certificate(&tls.conn)
                })
            });
            eprintln!(
                "stateless={stateless} resumed={resumed}: {:?}",
                result.as_ref().map(|()| "ok")
            );
            reply_seen(child, stdin, result);
            if !resumed {
                let stored = std::fs::read_to_string(&session).unwrap_or_default();
                assert!(
                    stored.contains("BEGIN SSL SESSION PARAMETERS"),
                    "stateless={stateless}: s_client stored no session"
                );
            }
        }
    }
}

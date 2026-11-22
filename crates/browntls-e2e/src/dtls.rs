use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use browntls::client::{Resumption, Tls12Resumption};
use browntls::crypto::native::ticketer::AeadTicketProducer;
use browntls::dtls::{self, ServerEvent, UdpClient, UdpServer};
use browntls::server::{NoServerSessionStorage, ServerSessionMemoryCache};
use browntls::ticketer::TicketRotator;
use browntls::{ClientConfig, ClientServerIdentity, CommonState, HandshakeKind, ServiceIdentity};

use super::{IO_TIMEOUT, Options, Result, ServerName, emit, negotiated, required, roots};

const MESSAGE: &str = "hello from browntls";

pub(super) fn client(options: &Options) -> Result<()> {
    #[cfg(feature = "zstd")]
    super::observed_zstd::reset();
    if options.unbuffered_io {
        return Err("--unbuffered currently selects the TCP unbuffered stream adapter".into());
    }
    if options.async_io && options.dtls_rebind.is_some() {
        return Err("--async does not support --dtls-rebind".into());
    }
    let count = exchange_count(options, options.connections)?;
    let address = required(options.connect.as_ref(), "--connect")?;
    let name = required(options.server_name.as_ref(), "--server-name")?;
    let ca = required(options.ca.as_ref(), "--ca")?;
    let builder = ClientConfig::builder_with_provider(options.provider())
        .with_protocol_versions(options.versions())
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots(ca)?);
    let mut config = match options.chain()? {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|error| error.to_string())?,
        None => builder.with_no_client_auth(),
    };
    if options.zstd_cert_compression {
        #[cfg(feature = "zstd")]
        {
            config.cert_compressors = vec![&browntls::compress::ZSTD];
            config.cert_decompressors = vec![&super::observed_zstd::OBSERVED_ZSTD];
        }
    }
    if let Some(psk) = options.external_psk()? {
        config.external_psks.push(psk);
        config.cert_with_extern_psk = true;
        config.require_cert_with_extern_psk = true;
        config.require_external_psk = true;
    }
    if let Some(mechanism) = options.dtls12_resumption.as_deref() {
        config.resumption =
            Resumption::in_memory_sessions(4).tls12_resumption(if mechanism == "session-id" {
                Tls12Resumption::SessionIdOnly
            } else {
                Tls12Resumption::SessionIdOrTickets
            });
    }
    let config = Arc::new(config);
    let peer = address
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or("no UDP peer address")?;
    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let name = ServerName::try_from(name.to_owned()).map_err(|error| error.to_string())?;
    let identity = super::service_identity(&options.reference_ids)?;
    if options.dtls_rebind.is_none() && (options.async_io || identity.is_some()) {
        return tokio_client(options, config, name, identity, peer, bind, count);
    }
    let socket = UdpSocket::bind(bind).map_err(|error| error.to_string())?;
    socket.connect(peer).map_err(|error| error.to_string())?;

    // Retain the UDP endpoint and authentication objects across connections.
    for index in 0..count {
        let settings = settings(options)?;
        let conn = match &identity {
            Some(policy) => dtls::ClientConnection::new_with_identity_and_settings(
                config.clone(),
                ClientServerIdentity::new(name.clone(), policy.clone()),
                settings,
            ),
            None => {
                dtls::ClientConnection::new_with_settings(config.clone(), name.clone(), settings)
            }
        }
        .map_err(|error| error.to_string())?;
        let mut client = UdpClient::from_connection(
            conn,
            socket.try_clone().map_err(|error| error.to_string())?,
        );
        client.set_read_timeout(Some(IO_TIMEOUT));
        client
            .complete_handshake()
            .map_err(|error| format!("handshake: {error}"))?;

        if let Some(mode) = &options.dtls_rebind {
            return rebind_client(client, bind, peer, mode);
        }

        let message = options.message.as_deref().unwrap_or(MESSAGE);
        let expected = options
            .expect_reply
            .clone()
            .unwrap_or_else(|| reverse(message));
        client
            .send(message.as_bytes())
            .map_err(|error| format!("send: {error}"))?;
        let mut reply = [0u8; 1200];
        let len = client
            .recv(&mut reply)
            .map_err(|error| format!("reply: {error}"))?;
        if &reply[..len] != expected.as_bytes() {
            return Err("unexpected DTLS reply".into());
        }
        if client
            .recv(&mut reply)
            .map_err(|error| format!("close: {error}"))?
            != 0
        {
            return Err("expected the server's close_notify".into());
        }
        client.close().map_err(|error| format!("close: {error}"))?;
        check_handshake(client.connection(), index, options)?;
        emit(&exchange_fields(
            client.connection(),
            "client",
            &expected,
            message,
            index,
            options,
        ));
    }
    Ok(())
}

fn tokio_client(
    options: &Options,
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
    identity: Option<ServiceIdentity>,
    peer: std::net::SocketAddr,
    bind: &str,
    count: usize,
) -> Result<()> {
    use browntls::tokio::dtls::{Recv, UdpClient as TokioUdpClient};

    use super::async_io::bounded;

    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("runtime: {error}"))?
        .block_on(async {
            for index in 0..count {
                let socket = tokio::net::UdpSocket::bind(bind)
                    .await
                    .map_err(|error| error.to_string())?;
                socket
                    .connect(peer)
                    .await
                    .map_err(|error| error.to_string())?;
                let mut client = match &identity {
                    Some(identity) => TokioUdpClient::new_with_identity_and_settings(
                        config.clone(),
                        ClientServerIdentity::new(name.clone(), identity.clone()),
                        socket,
                        settings(options)?,
                    ),
                    None => TokioUdpClient::new_with_settings(
                        config.clone(),
                        name.clone(),
                        socket,
                        settings(options)?,
                    ),
                }
                .map_err(|error| error.to_string())?;
                bounded("handshake", client.complete_handshake()).await?;
                let message = options.message.as_deref().unwrap_or(MESSAGE);
                let expected = options
                    .expect_reply
                    .clone()
                    .unwrap_or_else(|| reverse(message));
                bounded("send", client.send(message.as_bytes())).await?;
                let mut reply = [0u8; 1200];
                let len = match bounded("reply", client.recv(&mut reply)).await? {
                    Recv::Data(len) => len,
                    Recv::Closed => return Err("peer closed before replying".into()),
                };
                if &reply[..len] != expected.as_bytes() {
                    return Err("unexpected DTLS reply".into());
                }
                let closed = bounded("close", client.recv(&mut reply)).await?;
                if closed != Recv::Closed {
                    return Err("expected the server's close_notify".into());
                }
                let common = client.connection();
                check_handshake(common, index, options)?;
                let mut fields =
                    connection_fields(common, "client", &expected, message, Some(options));
                fields.extend([
                    ("index", super::Value::Num(index)),
                    ("io", "tokio-dtls".into()),
                    ("record_size_limit_configured", limit_value(options)),
                    (
                        "max_application_data",
                        super::Value::Num(common.max_application_data().ok_or("no DTLS send cap")?),
                    ),
                ]);
                emit(&fields);
                bounded("close", client.close()).await?;
            }
            Ok(())
        })
}

pub(super) fn server(options: &Options) -> Result<()> {
    #[cfg(feature = "zstd")]
    super::observed_zstd::reset();
    if options.unbuffered_io {
        return Err("--unbuffered currently selects the TCP unbuffered stream adapter".into());
    }
    if options.async_io && options.dtls_rebind.is_some() {
        return Err("--async does not support --dtls-rebind".into());
    }
    let count = exchange_count(options, options.accept)?;
    let mut config = super::server_config(options, None)?;
    let cookies = TicketRotator::new(6 * 60 * 60, || Ok(Box::new(AeadTicketProducer::new()?)))
        .map_err(|error| error.to_string())?;
    let owned = Arc::get_mut(&mut config).ok_or("expected an owned DTLS server configuration")?;
    if options.zstd_cert_compression {
        #[cfg(feature = "zstd")]
        {
            owned.cert_compressors = vec![&browntls::compress::ZSTD];
            owned.cert_decompressors = vec![&super::observed_zstd::OBSERVED_ZSTD];
        }
    }
    owned.hello_retry_cookies = Some(Arc::new(cookies));
    if let Some(mechanism) = options.dtls12_resumption.as_deref() {
        if mechanism == "ticket" {
            // Give tickets separate keys from TLS tickets and DTLS cookies;
            // forbid ID fallback.
            owned.dtls12_ticketer = Arc::new(
                TicketRotator::new(6 * 60 * 60, || Ok(Box::new(AeadTicketProducer::new()?)))
                    .map_err(|error| error.to_string())?,
            );
            owned.session_storage = Arc::new(NoServerSessionStorage {});
        } else {
            // The builder leaves DTLS tickets disabled.
            owned.session_storage = ServerSessionMemoryCache::new(4);
        }
        owned
            .enable_dtls12_resumption()
            .map_err(|error| error.to_string())?;
    }
    if options.async_io {
        return tokio_server(options, config);
    }
    let listen = required(options.listen.as_ref(), "--listen")?;
    let socket = UdpSocket::bind(listen).map_err(|error| format!("bind {listen}: {error}"))?;
    let mut server = UdpServer::new_with_settings(config, socket, settings(options)?)
        .map_err(|error| error.to_string())?;
    if let Some(mode) = &options.dtls_rebind {
        server.set_path_selection(match mode.as_str() {
            "basic" => dtls::rrc::Selection::Basic,
            "enhanced" => dtls::rrc::Selection::Enhanced,
            _ => return Err("unknown DTLS rebind mode".into()),
        });
        return rebind_server(server, mode);
    }
    server.set_read_timeout(Some(IO_TIMEOUT));
    emit(&[("event", "listening".into())]);

    let mut exchange = None;
    let mut index = 0;
    loop {
        match server
            .next_event()
            .map_err(|error| format!("DTLS event: {error}"))?
        {
            ServerEvent::Received(peer, data) if exchange.is_none() => {
                let message = std::str::from_utf8(&data).map_err(|error| error.to_string())?;
                let reply = reverse(message);
                server
                    .send_to(reply.as_bytes(), peer)
                    .map_err(|error| format!("send: {error}"))?;
                let connection = server
                    .connection_mut(peer)
                    .ok_or("missing DTLS connection")?;
                check_handshake(connection, index, options)?;
                connection.send_close_notify();
                exchange = Some((
                    peer,
                    exchange_fields(connection, "server", message, &reply, index, options),
                ));
            }
            ServerEvent::Closed(peer) => {
                let (expected, fields) = exchange
                    .take()
                    .ok_or("peer closed before application data")?;
                if peer != expected {
                    return Err("unexpected peer closed".into());
                }
                emit(&fields);
                index += 1;
                if index == count {
                    return Ok(());
                }
            }
            ServerEvent::Failed(_, error) => return Err(error.to_string()),
            _ => {}
        }
    }
}

fn tokio_server(options: &Options, config: Arc<browntls::ServerConfig>) -> Result<()> {
    use browntls::tokio::dtls::{ServerEvent as TokioServerEvent, UdpServer as TokioUdpServer};

    let count = exchange_count(options, options.accept)?;
    let listen = required(options.listen.as_ref(), "--listen")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("runtime: {error}"))?
        .block_on(async {
            let socket = tokio::net::UdpSocket::bind(listen)
                .await
                .map_err(|error| format!("bind {listen}: {error}"))?;
            let mut server = TokioUdpServer::new_with_settings(config, socket, settings(options)?)
                .map_err(|error| error.to_string())?;
            server.set_read_timeout(Some(IO_TIMEOUT));
            emit(&[("event", "listening".into()), ("io", "tokio-dtls".into())]);

            let mut index = 0;
            while index < count {
                match server
                    .next_event()
                    .await
                    .map_err(|error| format!("DTLS event: {error}"))?
                {
                    TokioServerEvent::Received(peer, data) => {
                        let message =
                            std::str::from_utf8(&data).map_err(|error| error.to_string())?;
                        let reply = reverse(message);
                        server
                            .send_to(reply.as_bytes(), peer)
                            .await
                            .map_err(|error| format!("send: {error}"))?;
                        let connection =
                            server.connection(peer).ok_or("missing DTLS connection")?;
                        check_handshake(connection, index, options)?;
                        let mut fields =
                            exchange_fields(connection, "server", message, &reply, index, options);
                        fields.extend([
                            ("io", "tokio-dtls".into()),
                            (
                                "max_application_data",
                                super::Value::Num(
                                    connection
                                        .max_application_data()
                                        .ok_or("no DTLS send cap")?,
                                ),
                            ),
                        ]);
                        server
                            .close(peer)
                            .await
                            .map_err(|error| format!("close: {error}"))?;
                        emit(&fields);
                        index += 1;
                    }
                    TokioServerEvent::Closed(_) => {}
                    TokioServerEvent::Failed(_, error) => return Err(error.to_string()),
                    _ => {}
                }
            }
            Ok(())
        })
}

fn reverse(message: &str) -> String {
    message.chars().rev().collect()
}

fn exchange_count(options: &Options, count: usize) -> Result<usize> {
    match options.dtls12_resumption.as_deref() {
        None => Ok(1),
        Some("session-id" | "ticket")
            if count == 2
                && options.versions.len() == 1
                && options.versions[0].version == browntls::version::TLS12.version =>
        {
            Ok(2)
        }
        _ => Err("DTLS resumption needs session-id|ticket, --tls 1.2 and count 2".into()),
    }
}

fn check_handshake(common: &CommonState, index: usize, options: &Options) -> Result<()> {
    if options.dtls12_resumption.is_some() {
        let expected = if index == 0 {
            HandshakeKind::Full
        } else {
            HandshakeKind::Resumed
        };
        if common.handshake_kind() != Some(expected)
            || common
                .peer_certificates()
                .is_none_or(|chain| chain.is_empty())
        {
            return Err(format!(
                "DTLS connection {index}: expected {expected:?} with peer certificates"
            ));
        }
    }
    Ok(())
}

fn exchange_fields(
    common: &CommonState,
    role: &str,
    received: &str,
    sent: &str,
    index: usize,
    options: &Options,
) -> Vec<(&'static str, super::Value)> {
    let mut fields = connection_fields(common, role, received, sent, Some(options));
    fields.push(("record_size_limit_configured", limit_value(options)));
    if let Some(mechanism) = options.dtls12_resumption.as_deref() {
        fields.extend([
            ("index", super::Value::Num(index)),
            ("mechanism", mechanism.into()),
        ]);
    }
    fields
}

fn connection_fields(
    common: &CommonState,
    role: &str,
    received: &str,
    sent: &str,
    options: Option<&Options>,
) -> Vec<(&'static str, super::Value)> {
    let mut fields = negotiated(common);
    if let Some(options) = options
        && let Some(field) = super::zstd_compression_diagnostic(options)
    {
        fields.push(field);
    }
    fields.extend([
        ("event", "connection".into()),
        ("role", role.into()),
        ("received", received.into()),
        ("sent", sent.into()),
        ("closed", super::Value::Bool(true)),
        (
            "service_identity_matched",
            super::Value::Bool(common.matched_service_identity().is_some()),
        ),
    ]);
    fields
}

fn limit_value(options: &Options) -> super::Value {
    options
        .record_size_limit
        .flatten()
        .map_or_else(|| "none".into(), |limit| limit.to_string().into())
}

const REBIND_MESSAGE: &str = "hello after rebind";

fn settings(options: &Options) -> Result<dtls::Settings> {
    let mut settings = dtls::Settings::default().with_versions(options.dtls_versions());
    if let Some(limit) = options.record_size_limit {
        settings = settings
            .with_record_size_limit(limit)
            .map_err(|error| error.to_string())?;
    }
    if options.dtls_rebind.is_some() || options.dtls_cid {
        let policy = dtls::ConnectionIdPolicy::new(8, true).map_err(|e| e.to_string())?;
        Ok(if options.dtls_rebind.is_some() {
            settings.with_return_routability_checks(policy)
        } else {
            settings.with_connection_ids(policy)
        })
    } else {
        Ok(settings)
    }
}

fn check_migration_negotiation<D: browntls::SideData>(
    conn: &dtls::ConnectionCommon<D>,
) -> Result<()> {
    if !conn.return_routability_checks_negotiated()
        || conn.outbound_connection_id().is_none()
        || conn.local_connection_ids().next().is_none()
    {
        return Err("RRC and bidirectional DTLS CIDs are required for migration".into());
    }
    Ok(())
}

fn rebind_client(
    mut client: UdpClient,
    bind: &str,
    peer: std::net::SocketAddr,
    mode: &str,
) -> Result<()> {
    check_migration_negotiation(client.connection())?;
    client.send(MESSAGE.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = [0; 1200];
    let len = client.recv(&mut buf).map_err(|e| e.to_string())?;
    if &buf[..len] != reverse(MESSAGE).as_bytes() {
        return Err("unexpected initial reply".into());
    }
    let original = client.socket().local_addr().map_err(|e| e.to_string())?;
    let replacement = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    replacement.connect(peer).map_err(|e| e.to_string())?;
    let changed = replacement.local_addr().map_err(|e| e.to_string())?;
    if original.port() == changed.port() {
        return Err("replacement socket has the original source port".into());
    }
    let old = client
        .replace_socket(replacement)
        .map_err(|e| e.to_string())?;
    drop(old);
    client.set_read_timeout(Some(Duration::from_millis(250)));
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if Instant::now() >= deadline {
            return Err("rebind exchange timed out".into());
        }
        client
            .send(REBIND_MESSAGE.as_bytes())
            .map_err(|e| e.to_string())?;
        match client.recv(&mut buf) {
            Ok(len) if &buf[..len] == reverse(REBIND_MESSAGE).as_bytes() => break,
            Ok(_) => return Err("unexpected rebind reply or close".into()),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("rebind reply: {e}")),
        }
    }
    client.set_read_timeout(Some(IO_TIMEOUT));
    // Retries can have produced additional replies before the close alert.
    loop {
        let len = client.recv(&mut buf).map_err(|e| format!("close: {e}"))?;
        if len == 0 {
            break;
        }
        if &buf[..len] != reverse(REBIND_MESSAGE).as_bytes() {
            return Err("unexpected data while closing".into());
        }
    }
    client.close().map_err(|e| e.to_string())?;
    let mut fields = connection_fields(
        client.connection(),
        "client",
        &reverse(MESSAGE),
        MESSAGE,
        None,
    );
    fields.extend([
        ("mode", mode.into()),
        ("initial_local", original.to_string().into()),
        ("rebound_local", changed.to_string().into()),
        ("old_socket_dropped", super::Value::Bool(true)),
        ("rebind_sent", REBIND_MESSAGE.into()),
        ("rebind_received", reverse(REBIND_MESSAGE).into()),
        ("rrc", super::Value::Bool(true)),
        ("bidirectional_cid", super::Value::Bool(true)),
    ]);
    emit(&fields);
    Ok(())
}

fn rebind_server(mut server: UdpServer, mode: &str) -> Result<()> {
    server.set_read_timeout(Some(Duration::from_millis(250)));
    emit(&[("event", "listening".into())]);
    let deadline = Instant::now() + Duration::from_secs(75);
    let mut handle = None;
    let mut original = None;
    let mut fields = None;
    let mut rebound = false;
    loop {
        if Instant::now() >= deadline {
            return Err("server rebind timed out".into());
        }
        match server.next_event() {
            Ok(ServerEvent::Connected(peer)) => {
                if handle.replace(peer).is_some() {
                    return Err("more than one association".into());
                }
                let conn = server.connection(peer).ok_or("missing connection")?;
                check_migration_negotiation(conn)?;
                original = Some(server.peer_addr(peer).ok_or("missing original path")?);
            }
            Ok(ServerEvent::Received(peer, data)) => {
                if Some(peer) != handle || server.peers().count() != 1 {
                    return Err("unexpected DTLS association handle".into());
                }
                let path = server.peer_addr(peer).ok_or("missing validated path")?;
                if fields.is_none() && data == MESSAGE.as_bytes() {
                    if Some(path) != original {
                        return Err("initial path changed".into());
                    }
                    server
                        .send_to(reverse(MESSAGE).as_bytes(), peer)
                        .map_err(|e| e.to_string())?;
                    fields = Some(connection_fields(
                        server.connection(peer).ok_or("missing connection")?,
                        "server",
                        MESSAGE,
                        &reverse(MESSAGE),
                        None,
                    ));
                } else if data == REBIND_MESSAGE.as_bytes() && rebound {
                    continue;
                } else if data == REBIND_MESSAGE.as_bytes() && fields.is_some() {
                    let before = original.ok_or("missing original path")?;
                    if path == before {
                        return Err("rebind path was not validated".into());
                    }
                    let mut result = fields.take().ok_or("missing initial exchange")?;
                    result.extend([
                        ("mode", mode.into()),
                        ("handle", peer.to_string().into()),
                        ("initial_peer", before.to_string().into()),
                        ("rebound_peer", path.to_string().into()),
                        ("rebind_received", REBIND_MESSAGE.into()),
                        ("rebind_sent", reverse(REBIND_MESSAGE).into()),
                        ("rrc", super::Value::Bool(true)),
                        ("bidirectional_cid", super::Value::Bool(true)),
                    ]);
                    server
                        .send_to(reverse(REBIND_MESSAGE).as_bytes(), peer)
                        .map_err(|e| e.to_string())?;
                    server
                        .connection_mut(peer)
                        .ok_or("missing connection")?
                        .send_close_notify();
                    fields = Some(result);
                    rebound = true;
                } else {
                    return Err("unexpected application datagram".into());
                }
            }
            Ok(ServerEvent::Closed(peer)) => {
                if Some(peer) != handle {
                    return Err("unexpected closed association".into());
                }
                let result = fields.take().ok_or("closed before exchanges")?;
                if !result.iter().any(|(key, _)| *key == "rebound_peer") {
                    return Err("closed before rebind".into());
                }
                emit(&result);
                return Ok(());
            }
            Ok(ServerEvent::Failed(_, error)) => return Err(error.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Ok(_) => return Err("unexpected DTLS server event".into()),
            Err(e) => return Err(format!("DTLS event: {e}")),
        }
    }
}

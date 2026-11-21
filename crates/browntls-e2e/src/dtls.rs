use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use browntls::crypto::native::ticketer::AeadTicketProducer;
use browntls::dtls::{self, ServerEvent, UdpClient, UdpServer};
use browntls::ticketer::TicketRotator;
use browntls::{ClientConfig, CommonState};

use super::{IO_TIMEOUT, Options, Result, ServerName, emit, negotiated, required, roots};

const MESSAGE: &str = "hello from browntls";

pub(super) fn client(options: &Options) -> Result<()> {
    let address = required(options.connect.as_ref(), "--connect")?;
    let name = required(options.server_name.as_ref(), "--server-name")?;
    let ca = required(options.ca.as_ref(), "--ca")?;
    let builder = ClientConfig::builder_with_provider(options.provider())
        .with_protocol_versions(options.versions())
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots(ca)?);
    let config = match options.chain()? {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|error| error.to_string())?,
        None => builder.with_no_client_auth(),
    };
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
    let socket = UdpSocket::bind(bind).map_err(|error| error.to_string())?;
    socket.connect(peer).map_err(|error| error.to_string())?;
    let name = ServerName::try_from(name.to_owned()).map_err(|error| error.to_string())?;
    let conn =
        dtls::ClientConnection::new_with_settings(Arc::new(config), name, settings(options)?)
            .map_err(|error| error.to_string())?;
    let mut client = UdpClient::from_connection(conn, socket);
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
    report(client.connection(), "client", &expected, message);
    Ok(())
}

pub(super) fn server(options: &Options) -> Result<()> {
    let mut config = super::server_config(options, None)?;
    let cookies = TicketRotator::new(6 * 60 * 60, || Ok(Box::new(AeadTicketProducer::new()?)))
        .map_err(|error| error.to_string())?;
    Arc::get_mut(&mut config)
        .ok_or("expected an owned DTLS server configuration")?
        .hello_retry_cookies = Some(Arc::new(cookies));
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
                connection.send_close_notify();
                exchange = Some((
                    peer,
                    connection_fields(connection, "server", message, &reply),
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
                return Ok(());
            }
            ServerEvent::Failed(_, error) => return Err(error.to_string()),
            _ => {}
        }
    }
}

fn reverse(message: &str) -> String {
    message.chars().rev().collect()
}

fn report(common: &CommonState, role: &str, received: &str, sent: &str) {
    emit(&connection_fields(common, role, received, sent));
}

fn connection_fields(
    common: &CommonState,
    role: &str,
    received: &str,
    sent: &str,
) -> Vec<(&'static str, super::Value)> {
    let mut fields = negotiated(common);
    fields.extend([
        ("event", "connection".into()),
        ("role", role.into()),
        ("received", received.into()),
        ("sent", sent.into()),
        ("closed", super::Value::Bool(true)),
    ]);
    fields
}

const REBIND_MESSAGE: &str = "hello after rebind";

fn settings(options: &Options) -> Result<dtls::Settings> {
    let settings = dtls::Settings::default().with_versions(options.dtls_versions());
    if options.dtls_rebind.is_some() {
        let policy = dtls::ConnectionIdPolicy::new(8, true).map_err(|e| e.to_string())?;
        Ok(settings.with_return_routability_checks(policy))
    } else {
        Ok(settings)
    }
}

fn rebind_client(
    mut client: UdpClient,
    bind: &str,
    peer: std::net::SocketAddr,
    mode: &str,
) -> Result<()> {
    if !client.connection().return_routability_checks_negotiated()
        || client.connection().outbound_connection_id().is_none()
    {
        return Err("DTLS CID/RRC was not negotiated".into());
    }
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
    let mut fields = connection_fields(client.connection(), "client", &reverse(MESSAGE), MESSAGE);
    fields.extend([
        ("mode", mode.into()),
        ("initial_local", original.to_string().into()),
        ("rebound_local", changed.to_string().into()),
        ("old_socket_dropped", super::Value::Bool(true)),
        ("rebind_sent", REBIND_MESSAGE.into()),
        ("rebind_received", reverse(REBIND_MESSAGE).into()),
        ("rrc", super::Value::Bool(true)),
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
                if !conn.return_routability_checks_negotiated()
                    || conn.outbound_connection_id().is_none()
                {
                    return Err("DTLS CID/RRC was not negotiated".into());
                }
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

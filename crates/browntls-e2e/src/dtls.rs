use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;

use browntls::client::{Resumption, Tls12Resumption};
use browntls::crypto::native::ticketer::AeadTicketProducer;
use browntls::dtls::{ServerEvent, UdpClient, UdpServer};
use browntls::server::{NoServerSessionStorage, ServerSessionMemoryCache};
use browntls::ticketer::TicketRotator;
use browntls::{ClientConfig, CommonState, HandshakeKind};

use super::{IO_TIMEOUT, Options, Result, ServerName, emit, negotiated, required, roots};

const MESSAGE: &str = "hello from browntls";

pub(super) fn client(options: &Options) -> Result<()> {
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
    let socket = UdpSocket::bind(bind).map_err(|error| error.to_string())?;
    socket.connect(peer).map_err(|error| error.to_string())?;
    let name = ServerName::try_from(name.to_owned()).map_err(|error| error.to_string())?;
    // Retain the UDP endpoint and authentication objects across connections.
    for index in 0..count {
        let conn = browntls::dtls::ClientConnection::new_with_versions(
            config.clone(),
            name.clone(),
            options.dtls_versions(),
        )
        .map_err(|error| error.to_string())?;
        let mut client = UdpClient::from_connection(
            conn,
            socket.try_clone().map_err(|error| error.to_string())?,
        );
        client.set_read_timeout(Some(IO_TIMEOUT));
        client
            .complete_handshake()
            .map_err(|error| format!("handshake: {error}"))?;

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
        emit(&connection_fields(
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

pub(super) fn server(options: &Options) -> Result<()> {
    let count = exchange_count(options, options.accept)?;
    let mut config = super::server_config(options, None)?;
    let cookies = TicketRotator::new(6 * 60 * 60, || Ok(Box::new(AeadTicketProducer::new()?)))
        .map_err(|error| error.to_string())?;
    let owned = Arc::get_mut(&mut config).ok_or("expected an owned DTLS server configuration")?;
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
    let listen = required(options.listen.as_ref(), "--listen")?;
    let socket = UdpSocket::bind(listen).map_err(|error| format!("bind {listen}: {error}"))?;
    let mut server = UdpServer::new_with_versions(config, socket, options.dtls_versions())
        .map_err(|error| error.to_string())?;
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
                    connection_fields(connection, "server", message, &reply, index, options),
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

fn connection_fields(
    common: &CommonState,
    role: &str,
    received: &str,
    sent: &str,
    index: usize,
    options: &Options,
) -> Vec<(&'static str, super::Value)> {
    let mut fields = negotiated(common);
    fields.extend([
        ("event", "connection".into()),
        ("role", role.into()),
        ("received", received.into()),
        ("sent", sent.into()),
        ("closed", super::Value::Bool(true)),
    ]);
    if let Some(mechanism) = options.dtls12_resumption.as_deref() {
        fields.extend([
            ("index", super::Value::Num(index)),
            ("mechanism", mechanism.into()),
        ]);
    }
    fields
}

use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;

use browntls::crypto::native::ticketer::AeadTicketProducer;
use browntls::dtls::{ConnectionIdPolicy, ServerEvent, Settings, UdpClient, UdpServer};
use browntls::ticketer::TicketRotator;
use browntls::{ClientConfig, CommonState};

use super::{IO_TIMEOUT, Options, Result, ServerName, emit, negotiated, required, roots};

const MESSAGE: &str = "hello from browntls";

fn settings(options: &Options) -> Result<Settings> {
    let mut settings = Settings::default().with_versions(options.dtls_versions());
    if options.dtls_cid {
        settings = settings.with_connection_ids(
            ConnectionIdPolicy::new(8, true).map_err(|error| error.to_string())?,
        );
    }
    Ok(settings)
}

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
    let conn = browntls::dtls::ClientConnection::new_with_settings(
        Arc::new(config),
        name,
        settings(options)?,
    )
    .map_err(|error| error.to_string())?;
    let mut client = UdpClient::from_connection(conn, socket);
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

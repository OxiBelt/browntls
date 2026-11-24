//! `--unbuffered`: the same bounded line exchange through Tokio's
//! `UnbufferedTlsConnector` and `UnbufferedTlsAcceptor` adapters.

use std::sync::Arc;
use std::time::{Duration, Instant};

use browntls::pki_types::ServerName;
use browntls::tokio::unbuffered::{TlsAcceptor, TlsConnector};
use browntls::{ClientConfig, ClientServerIdentity, ServerConfig, ServiceIdentity};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::output::{Value, emit, negotiated};
use crate::{IO_TIMEOUT, MAX_LINE, Options, Result, required};

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("runtime: {error}"))
}

async fn bounded<T>(what: &str, fut: impl Future<Output = std::io::Result<T>>) -> Result<T> {
    match timeout(IO_TIMEOUT, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("{what}: {error}")),
        Err(_) => Err(format!("{what}: timed out")),
    }
}

async fn read_line<R: AsyncRead + Unpin>(reader: R) -> Result<String> {
    let mut line = Vec::new();
    let mut limited = BufReader::new(reader.take(MAX_LINE as u64 + 1));
    bounded("read", limited.read_until(b'\n', &mut line)).await?;
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if line.len() > MAX_LINE {
        return Err("line too long".into());
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| "line is not UTF-8".into())
}

async fn close<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    let _ = timeout(IO_TIMEOUT, stream.shutdown()).await;
    let mut sink = [0u8; 4096];
    let drain = async { while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {} };
    let _ = timeout(Duration::from_secs(2), drain).await;
}

pub(super) fn server(options: &Options, config: Arc<ServerConfig>) -> Result<()> {
    runtime()?.block_on(async {
        let address = required(options.listen.as_ref(), "--listen")?;
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("bind {address}: {error}"))?;
        let local = listener.local_addr().map_err(|error| error.to_string())?;
        emit(&[
            ("event", "listening".into()),
            ("addr", local.to_string().into()),
            ("io", "tokio-unbuffered".into()),
        ]);
        let acceptor = TlsAcceptor::from(config);
        let mut failed = None;
        for index in 0..options.accept {
            let (socket, peer) = listener
                .accept()
                .await
                .map_err(|error| format!("accept: {error}"))?;
            if let Err(error) = serve(&acceptor, socket, index, options).await {
                emit(&[
                    ("event", "error".into()),
                    ("index", Value::Num(index)),
                    ("peer", peer.to_string().into()),
                    ("message", error.clone().into()),
                ]);
                failed = Some(error);
            }
        }
        failed.map_or(Ok(()), |error| {
            Err(format!("at least one connection failed: {error}"))
        })
    })
}

async fn serve(
    acceptor: &TlsAcceptor,
    socket: TcpStream,
    index: usize,
    options: &Options,
) -> Result<()> {
    #[cfg(feature = "zstd")]
    super::observed_zstd::reset();
    let mut tls = bounded("handshake", acceptor.accept(socket)).await?;
    let request = read_line(&mut tls).await?;
    let reply: String = request.chars().rev().collect();
    bounded("write", tls.write_all(format!("{reply}\n").as_bytes())).await?;
    bounded("write", tls.flush()).await?;
    let connection = tls.get_ref().1;
    let mut fields = vec![
        ("event", "connection".into()),
        ("role", "server".into()),
        ("index", Value::Num(index)),
        ("io", "tokio-unbuffered".into()),
    ];
    fields.extend(negotiated(connection));
    if let Some(field) = super::zstd_compression_diagnostic(options) {
        fields.push(field);
    }
    fields.extend([
        (
            "delegated_credential",
            Value::Bool(connection.client_delegated_credential().is_some()),
        ),
        (
            "record_size_limit_configured",
            super::configured_record_size_limit(options),
        ),
        (
            "server_name",
            connection.server_name().unwrap_or("none").to_owned().into(),
        ),
        ("received", request.into()),
        ("sent", reply.into()),
    ]);
    emit(&fields);
    close(&mut tls).await;
    Ok(())
}

pub(super) fn client(
    options: &Options,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    identity: Option<ServiceIdentity>,
    message: &str,
) -> Result<()> {
    let address = required(options.connect.as_ref(), "--connect")?;
    runtime()?.block_on(async {
        let connector = TlsConnector::from(config);
        for index in 0..options.connections {
            #[cfg(feature = "zstd")]
            super::observed_zstd::reset();
            let socket = connect_with_retry(address, options.wait).await?;
            let handshake = match &identity {
                Some(identity) => connector.connect_with_identity(
                    ClientServerIdentity::new(server_name.clone(), identity.clone()),
                    socket,
                ),
                None => connector.connect(server_name.clone(), socket),
            };
            let mut tls = bounded("handshake", handshake).await?;
            bounded("write", tls.write_all(format!("{message}\n").as_bytes())).await?;
            bounded("write", tls.flush()).await?;
            let reply = read_line(&mut tls)
                .await
                .map_err(|error| format!("connection {index}: {error}"))?;
            let connection = tls.get_ref().1;
            let mut fields = vec![
                ("event", "connection".into()),
                ("role", "client".into()),
                ("index", Value::Num(index)),
                ("io", "tokio-unbuffered".into()),
            ];
            fields.extend(negotiated(connection));
            if let Some(field) = super::zstd_compression_diagnostic(options) {
                fields.push(field);
            }
            fields.extend([
                (
                    "delegated_credential",
                    Value::Bool(connection.delegated_credential().is_some()),
                ),
                (
                    "record_size_limit_configured",
                    super::configured_record_size_limit(options),
                ),
                ("ech", format!("{:?}", connection.ech_status()).into()),
                ("sent", message.into()),
                ("received", reply.clone().into()),
                (
                    "service_identity_matched",
                    Value::Bool(connection.matched_service_identity().is_some()),
                ),
            ]);
            emit(&fields);
            close(&mut tls).await;
            if let Some(expected) = options
                .expect_reply
                .as_ref()
                .filter(|expected| **expected != reply)
            {
                return Err(format!(
                    "connection {index}: reply {reply:?}, expected {expected:?}"
                ));
            }
        }
        Ok(())
    })
}

async fn connect_with_retry(address: &str, wait: Duration) -> Result<TcpStream> {
    let deadline = Instant::now() + wait;
    loop {
        match TcpStream::connect(address).await {
            Ok(socket) => return Ok(socket),
            Err(error) if Instant::now() >= deadline => {
                return Err(format!("connect {address}: {error}"));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

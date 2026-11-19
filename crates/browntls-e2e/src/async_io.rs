//! `--async`: the same line exchange as the blocking client and server, over
//! `browntls-tokio` streams on a single-threaded Tokio runtime.

use std::sync::Arc;
use std::time::{Duration, Instant};

use browntls::pki_types::ServerName;
use browntls::{ClientConfig, ServerConfig};
use browntls_tokio::{TlsAcceptor, TlsConnector};
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
        .map_err(|e| format!("runtime: {e}"))
}

/// Bounds `fut` by [`IO_TIMEOUT`], naming `what` on expiry.
async fn bounded<T>(what: &str, fut: impl Future<Output = std::io::Result<T>>) -> Result<T> {
    match timeout(IO_TIMEOUT, fut).await {
        Ok(Ok(value)) => Ok(value),
        // A TLS failure carries the `browntls::Error` (already in `e`'s
        // message); other failures are transport errors.
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: timed out")),
    }
}

/// Reads one line, without its line ending, of at most [`MAX_LINE`] bytes.
async fn read_line<R: AsyncRead + Unpin>(r: R) -> Result<String> {
    let mut line = Vec::new();
    let mut limited = BufReader::new(r.take(MAX_LINE as u64 + 1));
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

/// Sends `close_notify` and half-closes, then drains what the peer still
/// sends (its own `close_notify`) for up to two seconds.
async fn close<S: AsyncRead + AsyncWrite + Unpin>(tls: &mut S) {
    let _ = timeout(IO_TIMEOUT, tls.shutdown()).await;
    let mut sink = [0u8; 4096];
    let drain = async { while matches!(tls.read(&mut sink).await, Ok(n) if n > 0) {} };
    let _ = timeout(Duration::from_secs(2), drain).await;
}

pub(super) fn server(o: &Options, config: Arc<ServerConfig>) -> Result<()> {
    runtime()?.block_on(async {
        let listen = required(o.listen.as_ref(), "--listen")?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| format!("bind {listen}: {e}"))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        emit(&[
            ("event", "listening".into()),
            ("addr", addr.to_string().into()),
            ("io", "async".into()),
        ]);
        let acceptor = TlsAcceptor::from(config);
        let mut failed = None;
        for index in 0..o.accept {
            let (sock, peer) = listener
                .accept()
                .await
                .map_err(|e| format!("accept: {e}"))?;
            if let Err(e) = serve(&acceptor, sock, index).await {
                emit(&[
                    ("event", "error".into()),
                    ("index", Value::Num(index)),
                    ("peer", peer.to_string().into()),
                    ("message", e.clone().into()),
                ]);
                failed = Some(e);
            }
        }
        failed.map_or(Ok(()), |e| {
            Err(format!("at least one connection failed: {e}"))
        })
    })
}

async fn serve(acceptor: &TlsAcceptor, sock: TcpStream, index: usize) -> Result<()> {
    let mut tls = bounded("handshake", acceptor.accept(sock)).await?;
    let line = read_line(&mut tls).await?;
    let reply: String = line.chars().rev().collect();
    bounded("write", tls.write_all(format!("{reply}\n").as_bytes())).await?;
    bounded("write", tls.flush()).await?;
    let conn = tls.get_ref().1;
    let mut fields = vec![
        ("event", "connection".into()),
        ("role", "server".into()),
        ("index", Value::Num(index)),
        ("io", "async".into()),
    ];
    fields.extend(negotiated(conn));
    fields.push(("ech", format!("{:?}", conn.ech_status()).into()));
    fields.push((
        "server_name",
        conn.server_name().unwrap_or("none").to_owned().into(),
    ));
    fields.push(("received", line.into()));
    fields.push(("sent", reply.into()));
    emit(&fields);
    close(&mut tls).await;
    Ok(())
}

pub(super) fn client(
    o: &Options,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    message: &str,
) -> Result<()> {
    let connect = required(o.connect.as_ref(), "--connect")?;
    runtime()?.block_on(async {
        let connector = TlsConnector::from(config);
        for index in 0..o.connections {
            let sock = connect_with_retry(connect, o.wait).await?;
            let mut tls =
                bounded("handshake", connector.connect(server_name.clone(), sock)).await?;
            bounded("write", tls.write_all(format!("{message}\n").as_bytes())).await?;
            bounded("write", tls.flush()).await?;
            let reply = read_line(&mut tls)
                .await
                .map_err(|e| format!("connection {index}: {e}"))?;
            let conn = tls.get_ref().1;
            let mut fields = vec![
                ("event", "connection".into()),
                ("role", "client".into()),
                ("index", Value::Num(index)),
                ("io", "async".into()),
            ];
            fields.extend(negotiated(conn));
            fields.push(("ech", format!("{:?}", conn.ech_status()).into()));
            fields.push(("sent", message.into()));
            fields.push(("received", reply.clone().into()));
            emit(&fields);
            close(&mut tls).await;
            if let Some(expected) = o.expect_reply.as_ref().filter(|e| **e != reply) {
                return Err(format!(
                    "connection {index}: reply {reply:?}, expected {expected:?}"
                ));
            }
        }
        Ok(())
    })
}

/// Connects to `addr`, retrying while the server is starting up.
async fn connect_with_retry(addr: &str, wait: Duration) -> Result<TcpStream> {
    let deadline = Instant::now() + wait;
    loop {
        match TcpStream::connect(addr).await {
            Ok(sock) => return Ok(sock),
            Err(e) if Instant::now() >= deadline => return Err(format!("connect {addr}: {e}")),
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

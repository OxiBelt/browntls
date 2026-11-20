//! The client-facing server of ECH split mode (`browntls-e2e client-facing`).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;

use browntls_core::ech::EchServerConfig;
use browntls_core::ech::split::{ClientFacing, ClientFacingDecision};
use browntls_core::{ServerConfig, StreamOwned};

use super::output::{Value, emit};
use super::{Options, Result, connect_with_retry, listen, serve, server_config, set_timeouts};

/// The client-facing server of ECH split mode: decides each connection,
/// then relays it to a back-end server or completes it locally.
pub(super) fn client_facing(o: &Options) -> Result<()> {
    let ech = o
        .ech_server()?
        .ok_or("--ech-config and --ech-key are required")?;
    if o.backends.is_empty() {
        return Err("--backend is required".into());
    }
    // The local server: the public name's certificate, the same keys (for
    // the retry configurations).
    let local = server_config(o, Some(ech.clone()))?;
    let listener = listen(o)?;
    let mut failed = None;
    for index in 0..o.accept {
        let (sock, peer) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        if let Err(e) = set_timeouts(&sock).and_then(|()| front(o, &ech, &local, sock, index)) {
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
}

fn front(
    o: &Options,
    ech: &Arc<EchServerConfig>,
    local: &Arc<ServerConfig>,
    mut client: TcpStream,
    index: usize,
) -> Result<()> {
    let mut front = ClientFacing::new(ech.clone());
    let mut buf = vec![0u8; 16 * 1024];
    while front.decision().is_none() {
        let n = client.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("client closed before its ClientHello".into());
        }
        if let Err(e) = front.read_client(&buf[..n]) {
            let _ = client.write_all(&front.take_for_client());
            return Err(format!("client-facing: {e}"));
        }
    }
    let decision = front.decision();
    emit(&[
        ("event", "client-facing".into()),
        ("index", Value::Num(index)),
        (
            "decision",
            decision
                .map_or_else(|| "none".to_owned(), |d| format!("{d:?}"))
                .into(),
        ),
        ("ech", format!("{:?}", front.ech_status()).into()),
        (
            "server_name",
            front.server_name().unwrap_or("none").to_owned().into(),
        ),
    ]);
    if decision == Some(ClientFacingDecision::Local) {
        let conn = front
            .into_server_connection(local.clone())
            .map_err(|e| e.to_string())?;
        return serve(StreamOwned::new(conn, client), index);
    }

    let name = front.server_name().unwrap_or_default().to_owned();
    let addr = o
        .backends
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, addr)| addr.as_str())
        .ok_or_else(|| format!("no back-end server for {name:?}"))?;
    let mut backend = connect_with_retry(addr, o.wait)?;
    set_timeouts(&backend)?;
    backend
        .write_all(&front.take_for_backend())
        .map_err(|e| format!("write to {addr}: {e}"))?;
    relay(front, client, backend)
}

/// Relays a forwarded connection: the client-facing server inspects the
/// handshake until it relays both directions unmodified, then the bytes
/// are copied directly. Returns when both directions have ended.
fn relay(front: ClientFacing, client: TcpStream, backend: TcpStream) -> Result<()> {
    let front = Arc::new(std::sync::Mutex::new(front));
    let clone = |s: &TcpStream| s.try_clone().map_err(|e| format!("socket: {e}"));
    let (client_r, backend_w) = (clone(&client)?, clone(&backend)?);
    let to_backend = {
        let front = front.clone();
        std::thread::spawn(move || pump(&front, client_r, backend_w, true))
    };
    let from_backend = pump(&front, backend, client, false);
    let to_backend = to_backend
        .join()
        .unwrap_or_else(|_| Err("relay thread panicked".into()));
    from_backend.and(to_backend)
}

/// Copies `from` to `to` through the client-facing server (`from_client`
/// says which direction this is). Each read may also release bytes for the
/// other direction (a fatal alert for the client), which are written too.
fn pump(
    front: &std::sync::Mutex<ClientFacing>,
    mut from: TcpStream,
    mut to: TcpStream,
    from_client: bool,
) -> Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut other = clone_peer(&from)?;
    loop {
        let n = match from.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => 0,
            Err(e) => return Err(format!("relay read: {e}")),
        };
        if n == 0 {
            let _ = to.shutdown(Shutdown::Write);
            return Ok(());
        }
        let (forward, back, result) = {
            let mut front = front.lock().map_err(|_| "relay lock poisoned")?;
            let result = if from_client {
                front.read_client(&buf[..n])
            } else {
                front.read_backend(&buf[..n])
            };
            let (forward, back) = if from_client {
                (front.take_for_backend(), front.take_for_client())
            } else {
                (front.take_for_client(), front.take_for_backend())
            };
            (forward, back, result)
        };
        to.write_all(&forward)
            .map_err(|e| format!("relay write: {e}"))?;
        if !back.is_empty() {
            other
                .write_all(&back)
                .map_err(|e| format!("relay write: {e}"))?;
        }
        if let Err(e) = result {
            let _ = from.shutdown(Shutdown::Both);
            let _ = to.shutdown(Shutdown::Both);
            return Err(format!("client-facing: {e}"));
        }
    }
}

/// A second handle on the socket `s` reads from, to write back on it.
fn clone_peer(s: &TcpStream) -> Result<TcpStream> {
    s.try_clone().map_err(|e| format!("socket: {e}"))
}

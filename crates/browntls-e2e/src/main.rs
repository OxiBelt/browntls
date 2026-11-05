//! A command-line TLS peer for the Docker end-to-end test matrix
//! (`tests/e2e/`).
//!
//! ```text
//! browntls-e2e info
//! browntls-e2e server --listen ADDR --cert FILE --key FILE [--client-ca FILE]
//!                     [--accept N] [COMMON...]
//! browntls-e2e client --connect HOST:PORT --server-name NAME --ca FILE
//!                     [--cert FILE --key FILE] [--message TEXT]
//!                     [--expect-reply TEXT] [--connections N] [--wait SECS]
//!                     [COMMON...]
//!
//! COMMON: --tls 1.2|1.3 (repeatable), --suite NAME (repeatable),
//!         --group NAME (repeatable), --allow-mac-then-encrypt
//! ```
//!
//! The server answers the first line of each connection with the line
//! reversed (as `openssl s_server -rev` does), then closes the connection
//! with `close_notify`. The client sends one line per connection and checks
//! the reply; with `--connections 2` the second connection may resume the
//! first session. Suite and group names are those of the browntls `Debug`
//! output (`TLS13_AES_128_GCM_SHA256`, `X25519MLKEM768`, `secp256r1`).
//!
//! Results are written to standard output as one JSON object per line, for
//! the harness to check: `listening`, `connection` (negotiated protocol
//! version, cipher suite, key exchange group, handshake kind and the data
//! exchanged) and `error`. The exit status is non-zero after any error.
//!
//! This is test tooling: it loads keys from files given on the command line
//! and has no hardening beyond the library defaults it configures.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, Instant};

use browntls::crypto::{CryptoProvider, SupportedKxGroup, native};
use browntls::pki_types::pem::PemObject;
use browntls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use browntls::server::WebPkiClientVerifier;
use browntls::{
    ClientConfig, ClientConnection, CommonState, ConnectionCommon, RootCertStore, ServerConfig,
    ServerConnection, SideData, StreamOwned, SupportedCipherSuite, SupportedProtocolVersion,
    version,
};

/// Time allowed for a single read or write on an established connection.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest line either side accepts.
const MAX_LINE: usize = 16 * 1024;

type Result<T, E = String> = std::result::Result<T, E>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((cmd, rest)) if cmd == "server" => Options::parse(rest).and_then(|o| server(&o)),
        Some((cmd, rest)) if cmd == "client" => Options::parse(rest).and_then(|o| client(&o)),
        Some((cmd, rest)) if cmd == "info" && rest.is_empty() => {
            info();
            Ok(())
        }
        _ => Err("usage: browntls-e2e info | server [OPTIONS] | client [OPTIONS]".into()),
    };
    if let Err(e) = result {
        emit(&[("event", "error".into()), ("message", e.into())]);
        std::process::exit(1);
    }
}

// ------------------------------------------------------------------ options

#[derive(Debug, Default)]
struct Options {
    listen: Option<String>,
    connect: Option<String>,
    server_name: Option<String>,
    ca: Option<String>,
    client_ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    message: Option<String>,
    expect_reply: Option<String>,
    accept: usize,
    connections: usize,
    wait: Duration,
    versions: Vec<&'static SupportedProtocolVersion>,
    suites: Vec<SupportedCipherSuite>,
    groups: Vec<&'static dyn SupportedKxGroup>,
    allow_mac_then_encrypt: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut o = Self {
            accept: 1,
            connections: 1,
            wait: Duration::from_secs(30),
            ..Self::default()
        };
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            if flag == "--allow-mac-then-encrypt" {
                o.allow_mac_then_encrypt = true;
                continue;
            }
            let value = it
                .next()
                .ok_or_else(|| format!("{flag} needs a value"))?
                .clone();
            match flag.as_str() {
                "--listen" => o.listen = Some(value),
                "--connect" => o.connect = Some(value),
                "--server-name" => o.server_name = Some(value),
                "--ca" => o.ca = Some(value),
                "--client-ca" => o.client_ca = Some(value),
                "--cert" => o.cert = Some(value),
                "--key" => o.key = Some(value),
                "--message" => o.message = Some(value),
                "--expect-reply" => o.expect_reply = Some(value),
                "--accept" => o.accept = parse_count(flag, &value)?,
                "--connections" => o.connections = parse_count(flag, &value)?,
                "--wait" => o.wait = Duration::from_secs(parse_count(flag, &value)? as u64),
                "--tls" => o.versions.push(match value.as_str() {
                    "1.2" => &version::TLS12,
                    "1.3" => &version::TLS13,
                    _ => return Err(format!("unknown TLS version {value:?}")),
                }),
                "--suite" => o.suites.push(
                    *native::ALL_CIPHER_SUITES
                        .iter()
                        .find(|s| format!("{:?}", s.suite()) == value)
                        .ok_or_else(|| format!("unknown cipher suite {value:?}"))?,
                ),
                "--group" => o.groups.push(
                    *native::ALL_KX_GROUPS
                        .iter()
                        .find(|g| format!("{:?}", g.name()) == value)
                        .ok_or_else(|| format!("unknown key exchange group {value:?}"))?,
                ),
                _ => return Err(format!("unknown option {flag}")),
            }
        }
        Ok(o)
    }

    /// The native provider restricted to the requested suites and groups.
    fn provider(&self) -> Arc<CryptoProvider> {
        let mut provider = native::default_provider();
        if !self.suites.is_empty() {
            provider.cipher_suites.clone_from(&self.suites);
        }
        if !self.groups.is_empty() {
            provider.kx_groups.clone_from(&self.groups);
        }
        Arc::new(provider)
    }

    fn versions(&self) -> &[&'static SupportedProtocolVersion] {
        if self.versions.is_empty() {
            browntls::DEFAULT_VERSIONS
        } else {
            &self.versions
        }
    }

    fn chain(&self) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
        match (&self.cert, &self.key) {
            (Some(cert), Some(key)) => {
                let chain = certs(cert)?;
                let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{key}: {e:?}"))?;
                Ok(Some((chain, key)))
            }
            (None, None) => Ok(None),
            _ => Err("--cert and --key go together".into()),
        }
    }
}

fn parse_count(flag: &str, value: &str) -> Result<usize> {
    match value.parse::<usize>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(format!("{flag} needs a positive integer, not {value:?}")),
    }
}

fn required<'a>(value: Option<&'a String>, flag: &str) -> Result<&'a str> {
    value
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} is required"))
}

/// Every certificate in a PEM file.
fn certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{path}: {e:?}"))?;
    if certs.is_empty() {
        return Err(format!("{path}: no certificate"));
    }
    Ok(certs)
}

fn roots(path: &str) -> Result<Arc<RootCertStore>> {
    let mut roots = RootCertStore::empty();
    for cert in certs(path)? {
        roots.add(cert).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(Arc::new(roots))
}

// ------------------------------------------------------------------- output

/// A JSON value for [`emit`].
#[derive(Debug)]
enum Value {
    Str(String),
    Num(usize),
    Bool(bool),
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::Str(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::Str(s)
    }
}

/// Writes one JSON object on its own line to standard output.
fn emit(fields: &[(&str, Value)]) {
    let mut line = String::from("{");
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            line.push(',');
        }
        push_json_str(&mut line, key);
        line.push(':');
        match value {
            Value::Str(s) => push_json_str(&mut line, s),
            Value::Num(n) => {
                let _ = write!(line, "{n}");
            }
            Value::Bool(b) => {
                let _ = write!(line, "{b}");
            }
        }
    }
    line.push('}');
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The negotiated parameters of an established connection.
fn negotiated(common: &CommonState) -> Vec<(&'static str, Value)> {
    let show = |v: Option<String>| Value::Str(v.unwrap_or_else(|| "none".into()));
    vec![
        (
            "version",
            show(common.protocol_version().map(|v| format!("{v:?}"))),
        ),
        (
            "suite",
            show(
                common
                    .negotiated_cipher_suite()
                    .map(|s| format!("{:?}", s.suite())),
            ),
        ),
        (
            "group",
            show(
                common
                    .negotiated_key_exchange_group()
                    .map(|g| format!("{:?}", g.name())),
            ),
        ),
        (
            "handshake",
            show(common.handshake_kind().map(|k| format!("{k:?}"))),
        ),
        (
            "peer_certificates",
            Value::Num(common.peer_certificates().map_or(0, <[_]>::len)),
        ),
    ]
}

/// Prints the acceleration backend selected for each algorithm family.
fn info() {
    emit(&[
        ("event", "info".into()),
        ("arch", std::env::consts::ARCH.into()),
        ("package_version", env!("CARGO_PKG_VERSION").into()),
    ]);
    for status in native::accel::status_all() {
        emit(&[
            ("event", "accel".into()),
            ("algorithm", status.algorithm.to_string().into()),
            ("backend", status.backend.to_string().into()),
            ("accelerated", Value::Bool(status.accelerated())),
        ]);
    }
}

// ---------------------------------------------------------------- transport

fn set_timeouts(sock: &TcpStream) -> Result<()> {
    sock.set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| sock.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|e| format!("socket timeouts: {e}"))
}

/// Reads one line, without its line ending.
fn read_line(r: &mut impl Read) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if line.len() >= MAX_LINE => return Err("line too long".into()),
            Ok(_) => line.push(byte[0]),
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| "line is not UTF-8".into())
}

/// Sends `close_notify`, half-closes the socket and drains what the peer
/// still sends, so that closing does not reset a connection whose last
/// records the peer has not read yet.
fn close<C, S>(tls: &mut StreamOwned<C, TcpStream>)
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    tls.conn.send_close_notify();
    let _ = tls.flush();
    let _ = tls.sock.shutdown(Shutdown::Write);
    let _ = tls.sock.set_read_timeout(Some(Duration::from_secs(2)));
    let mut sink = [0u8; 4096];
    while matches!(tls.sock.read(&mut sink), Ok(n) if n > 0) {}
}

// ------------------------------------------------------------------- server

fn server(o: &Options) -> Result<()> {
    let listen = required(o.listen.as_ref(), "--listen")?;
    let (chain, key) = o.chain()?.ok_or("--cert and --key are required")?;
    let provider = o.provider();
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(o.versions())
        .map_err(|e| e.to_string())?;
    let builder = match &o.client_ca {
        Some(ca) => builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(roots(ca)?, provider)
                .build()
                .map_err(|e| e.to_string())?,
        ),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    config.allow_mac_then_encrypt = o.allow_mac_then_encrypt;
    let config = Arc::new(config);

    let listener = TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    emit(&[
        ("event", "listening".into()),
        ("addr", addr.to_string().into()),
    ]);

    let mut failed = None;
    for index in 0..o.accept {
        let (sock, peer) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        if let Err(e) = serve(&config, sock, index) {
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

fn serve(config: &Arc<ServerConfig>, sock: TcpStream, index: usize) -> Result<()> {
    set_timeouts(&sock)?;
    let conn = ServerConnection::new(config.clone()).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, sock);
    let line = read_line(&mut tls)?;
    let reply: String = line.chars().rev().collect();
    tls.write_all(format!("{reply}\n").as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    tls.flush().map_err(|e| format!("write: {e}"))?;
    let mut fields = vec![
        ("event", "connection".into()),
        ("role", "server".into()),
        ("index", Value::Num(index)),
    ];
    fields.extend(negotiated(&tls.conn));
    fields.push(("received", line.into()));
    fields.push(("sent", reply.into()));
    emit(&fields);
    close(&mut tls);
    Ok(())
}

// ------------------------------------------------------------------- client

fn client(o: &Options) -> Result<()> {
    let connect = required(o.connect.as_ref(), "--connect")?;
    let name = required(o.server_name.as_ref(), "--server-name")?;
    let ca = required(o.ca.as_ref(), "--ca")?;
    let message = o.message.as_deref().unwrap_or("hello from browntls");
    let builder = ClientConfig::builder_with_provider(o.provider())
        .with_protocol_versions(o.versions())
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots(ca)?);
    let mut config = match o.chain()? {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|e| e.to_string())?,
        None => builder.with_no_client_auth(),
    };
    config.allow_mac_then_encrypt = o.allow_mac_then_encrypt;
    let config = Arc::new(config);
    let server_name = ServerName::try_from(name.to_owned()).map_err(|e| e.to_string())?;

    for index in 0..o.connections {
        let sock = connect_with_retry(connect, o.wait)?;
        set_timeouts(&sock)?;
        let conn = ClientConnection::new(config.clone(), server_name.clone())
            .map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, sock);
        tls.write_all(format!("{message}\n").as_bytes())
            .map_err(|e| format!("connection {index}: write: {e}"))?;
        tls.flush()
            .map_err(|e| format!("connection {index}: write: {e}"))?;
        let reply = read_line(&mut tls).map_err(|e| format!("connection {index}: {e}"))?;
        let mut fields = vec![
            ("event", "connection".into()),
            ("role", "client".into()),
            ("index", Value::Num(index)),
        ];
        fields.extend(negotiated(&tls.conn));
        fields.push(("sent", message.into()));
        fields.push(("received", reply.clone().into()));
        emit(&fields);
        close(&mut tls);
        if let Some(expected) = o.expect_reply.as_ref().filter(|e| **e != reply) {
            return Err(format!(
                "connection {index}: reply {reply:?}, expected {expected:?}"
            ));
        }
    }
    Ok(())
}

/// Connects to `addr`, retrying while the server is starting up.
fn connect_with_retry(addr: &str, wait: Duration) -> Result<TcpStream> {
    let deadline = Instant::now() + wait;
    loop {
        match TcpStream::connect(addr) {
            Ok(sock) => return Ok(sock),
            Err(e) if Instant::now() >= deadline => return Err(format!("connect {addr}: {e}")),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

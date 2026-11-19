//! A command-line TLS peer for the Docker end-to-end test matrix
//! (`tests/e2e/`).
//!
//! ```text
//! browntls-e2e info
//! browntls-e2e ech-keygen --out DIR --public-name NAME [--config-id N]
//! browntls-e2e server --listen ADDR --cert FILE --key FILE [--client-ca FILE]
//!                     [--accept N] [--sni-cert NAME,CERT,KEY]...
//!                     [ECH-SERVER...] [COMMON...]
//! browntls-e2e client-facing --listen ADDR --cert FILE --key FILE
//!                     --ech-config FILE --ech-key FILE
//!                     --backend NAME=HOST:PORT... [--accept N]
//!                     [ECH-SERVER...] [COMMON...]
//! browntls-e2e client --connect HOST:PORT --server-name NAME --ca FILE
//!                     [--cert FILE --key FILE] [--message TEXT]
//!                     [--expect-reply TEXT] [--connections N] [--wait SECS]
//!                     [ECH-CLIENT...] [COMMON...]
//!
//! COMMON: --tls 1.2|1.3 (repeatable), --suite NAME (repeatable),
//!         --group NAME (repeatable), --allow-mac-then-encrypt,
//!         --record-size-limit N|none, --async
//! CLIENT: --grease, --ticket-request NEW,RESUMPTION, --padding N
//! ECH-SERVER: --ech-config FILE --ech-key FILE (shared mode), --ech-backend,
//!         --ech-trial-decryption, --ech-public-name-check
//! ECH-CLIENT: --ech-config-list FILE, --ech-grease, --ech-random-config-id,
//!         --ech-retry
//! ```
//!
//! `--record-size-limit` sets the RFC 8449 limit to announce (`none`: no
//! extension); `--grease` sends RFC 8701 GREASE values; `--ticket-request`
//! sends the RFC 9149 extension; `--padding` pads the ClientHello to at
//! least N bytes (RFC 7685). `--async` runs the client's or server's
//! connections through `browntls-tokio` on a single-threaded Tokio runtime
//! instead of the blocking `StreamOwned` (same exchange and output, with
//! `"io":"async"`; a client then does not retry after an ECH rejection).
//!
//! Encrypted Client Hello (RFC 9849): `ech-keygen` writes an X25519 key for
//! every native HPKE suite with that KEM to `DIR/ech-config` (one
//! `ECHConfig`), `DIR/ech-config-list` (an `ECHConfigList`) and
//! `DIR/ech-key` (the raw private key). `--ech-config`/`--ech-key` make a
//! server decrypt itself (shared mode); `--ech-backend` makes it the
//! back-end server of split mode. `client-facing` is the client-facing
//! server of split mode: it decrypts each connection's ClientHello and
//! relays the connection to the back-end server named by the inner server
//! name, or completes the handshake itself (with the public name's
//! certificate and the retry configurations) when ECH is not accepted.
//! `--sni-cert` adds a certificate for one server name, such as the public
//! name. A client with `--ech-config-list` offers ECH (`--ech-grease` sends
//! GREASE instead); with `--ech-retry` it retries once with the server's
//! retry configurations after a rejection.
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
//! version, cipher suite, key exchange group, handshake kind, ECH status,
//! the server name a server saw, and the data exchanged), `client-facing`
//! (the client-facing server's decision), `ech-rejected` (a client's
//! rejection), `ech-required` (a server whose client refused the rejection,
//! as expected before a retry) and `error`. The exit status is non-zero
//! after any error.
//!
//! This is test tooling: it loads keys from files given on the command line
//! and has no hardening beyond the library defaults it configures.

mod async_io;
mod client_facing;
mod output;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, Instant};

use browntls::client::{ClientHelloPadding, TicketRequest};
use browntls::crypto::hpke::{HpkeKem, HpkePrivateKey};
use browntls::crypto::{CryptoProvider, SupportedKxGroup, native};
use browntls::ech::{EchConfig, EchGreaseConfig, EchMode, EchServerConfig, EchServerKey};
use browntls::pki_types::pem::PemObject;
use browntls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use browntls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use browntls::sign::CertifiedKey;
use browntls::{
    ClientConfig, ClientConnection, ConnectionCommon, Error, RootCertStore, ServerConfig,
    ServerConnection, SideData, StreamOwned, SupportedCipherSuite, SupportedProtocolVersion,
    version,
};

use client_facing::client_facing;
use output::{Value, emit, info, is_ech_required, negotiated, tls_error};

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
        Some((cmd, rest)) if cmd == "client-facing" => {
            Options::parse(rest).and_then(|o| client_facing(&o))
        }
        Some((cmd, rest)) if cmd == "ech-keygen" => {
            Options::parse(rest).and_then(|o| ech_keygen(&o))
        }
        Some((cmd, rest)) if cmd == "info" && rest.is_empty() => {
            info();
            Ok(())
        }
        _ => Err(
            "usage: browntls-e2e info | ech-keygen | server | client-facing | client [OPTIONS]"
                .into(),
        ),
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
    /// `None`: the library default; `Some(None)`: no extension.
    record_size_limit: Option<Option<u16>>,
    grease: bool,
    ticket_request: Option<TicketRequest>,
    padding: Option<u16>,
    /// Certificates for particular server names: (name, chain, key).
    sni_certs: Vec<(String, String, String)>,
    out: Option<String>,
    public_name: Option<String>,
    config_id: u8,
    ech_config: Option<String>,
    ech_key: Option<String>,
    ech_config_list: Option<String>,
    ech_backend: bool,
    ech_grease: bool,
    ech_random_config_id: bool,
    ech_retry: bool,
    ech_trial_decryption: bool,
    ech_public_name_check: bool,
    /// Back-end servers of the client-facing server: (inner server name,
    /// address).
    backends: Vec<(String, String)>,
    /// Client and server I/O through `browntls-tokio` (`--async`).
    async_io: bool,
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
            let switch = match flag.as_str() {
                "--grease" => Some(&mut o.grease),
                "--ech-backend" => Some(&mut o.ech_backend),
                "--ech-grease" => Some(&mut o.ech_grease),
                "--ech-random-config-id" => Some(&mut o.ech_random_config_id),
                "--ech-retry" => Some(&mut o.ech_retry),
                "--ech-trial-decryption" => Some(&mut o.ech_trial_decryption),
                "--ech-public-name-check" => Some(&mut o.ech_public_name_check),
                "--async" => Some(&mut o.async_io),
                _ => None,
            };
            if let Some(switch) = switch {
                *switch = true;
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
                "--record-size-limit" => {
                    o.record_size_limit = Some(match value.as_str() {
                        "none" => None,
                        n => Some(n.parse().map_err(|_| format!("{flag}: {value:?}"))?),
                    });
                }
                "--ticket-request" => {
                    let (new, resumption) = value
                        .split_once(',')
                        .ok_or_else(|| format!("{flag} needs NEW,RESUMPTION"))?;
                    let count = |v: &str| v.parse::<u8>().map_err(|_| format!("{flag}: {value:?}"));
                    o.ticket_request = Some(TicketRequest {
                        new_session_count: count(new)?,
                        resumption_count: count(resumption)?,
                    });
                }
                "--padding" => {
                    o.padding = Some(value.parse().map_err(|_| format!("{flag}: {value:?}"))?);
                }
                "--sni-cert" => {
                    let mut parts = value.splitn(3, ',');
                    match (parts.next(), parts.next(), parts.next()) {
                        (Some(name), Some(cert), Some(key)) => {
                            o.sni_certs.push((name.into(), cert.into(), key.into()));
                        }
                        _ => return Err(format!("{flag} needs NAME,CERT,KEY")),
                    }
                }
                "--out" => o.out = Some(value),
                "--public-name" => o.public_name = Some(value),
                "--config-id" => {
                    o.config_id = value.parse().map_err(|_| format!("{flag}: {value:?}"))?;
                }
                "--ech-config" => o.ech_config = Some(value),
                "--ech-key" => o.ech_key = Some(value),
                "--ech-config-list" => o.ech_config_list = Some(value),
                "--backend" => {
                    let (name, addr) = value
                        .split_once('=')
                        .ok_or_else(|| format!("{flag} needs NAME=HOST:PORT"))?;
                    o.backends.push((name.into(), addr.into()));
                }
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

fn read_file(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

/// The native HPKE suites with the X25519 KEM (the one every ECH
/// implementation supports).
fn x25519_hpke_suites() -> Vec<&'static dyn browntls::crypto::hpke::Hpke> {
    native::hpke::ALL_SUPPORTED_SUITES
        .iter()
        .copied()
        .filter(|s| s.suite().kem == HpkeKem::DHKEM_X25519_HKDF_SHA256)
        .collect()
}

impl Options {
    /// The ECH keys of `--ech-config` and `--ech-key`, if given.
    fn ech_server(&self) -> Result<Option<Arc<EchServerConfig>>> {
        let (config, key) = match (&self.ech_config, &self.ech_key) {
            (Some(config), Some(key)) => (read_file(config)?, read_file(key)?),
            (None, None) => return Ok(None),
            _ => return Err("--ech-config and --ech-key go together".into()),
        };
        let suites = x25519_hpke_suites();
        let key = EchServerKey::new(&config, HpkePrivateKey::from(key), &suites)
            .map_err(|e| format!("ECH key: {e}"))?;
        let mut ech = EchServerConfig::new(vec![key]).map_err(|e| e.to_string())?;
        if self.ech_trial_decryption {
            ech = ech.with_trial_decryption();
        }
        if self.ech_public_name_check {
            ech = ech.with_public_name_check();
        }
        Ok(Some(Arc::new(ech)))
    }

    /// The client's ECH mode, if any; `list` replaces `--ech-config-list`
    /// on a retry.
    fn ech_client(&self, list: Option<&[u8]>) -> Result<Option<EchMode>> {
        let suites = native::hpke::ALL_SUPPORTED_SUITES;
        if self.ech_grease {
            let grease =
                EchGreaseConfig::generate(x25519_hpke_suites()[0]).map_err(|e| e.to_string())?;
            return Ok(Some(EchMode::Grease(grease)));
        }
        let list = match (list, &self.ech_config_list) {
            (Some(list), _) => list.to_vec(),
            (None, Some(path)) => read_file(path)?,
            (None, None) => return Ok(None),
        };
        let mut config = EchConfig::new(&list, suites).map_err(|e| format!("ECH: {e}"))?;
        if self.ech_random_config_id {
            config = config.with_random_config_id();
        }
        Ok(Some(EchMode::Enable(config)))
    }
}

/// Picks the certificate for the ClientHello's server name, falling back to
/// the default one.
#[derive(Debug)]
struct SniResolver {
    default: Arc<CertifiedKey>,
    by_name: Vec<(String, Arc<CertifiedKey>)>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name();
        Some(
            self.by_name
                .iter()
                .find(|(n, _)| Some(n.as_str()) == name)
                .map_or_else(|| self.default.clone(), |(_, k)| k.clone()),
        )
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

/// The server configuration of `--cert`/`--key` (and `--sni-cert`), with
/// the common options and the ECH keys of `ech`.
fn server_config(o: &Options, ech: Option<Arc<EchServerConfig>>) -> Result<Arc<ServerConfig>> {
    let (chain, key) = o.chain()?.ok_or("--cert and --key are required")?;
    let provider = o.provider();
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(o.versions())
        .map_err(|e| e.to_string())?;
    let builder = match &o.client_ca {
        Some(ca) => builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(roots(ca)?, provider.clone())
                .build()
                .map_err(|e| e.to_string())?,
        ),
        None => builder.with_no_client_auth(),
    };
    let mut config = if o.sni_certs.is_empty() {
        builder
            .with_single_cert(chain, key)
            .map_err(|e| e.to_string())?
    } else {
        let certified = |chain, key: PrivateKeyDer<'static>| {
            CertifiedKey::from_der(chain, key, &provider)
                .map(Arc::new)
                .map_err(|e| e.to_string())
        };
        let mut by_name = Vec::new();
        for (name, cert, key) in &o.sni_certs {
            let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{key}: {e:?}"))?;
            by_name.push((name.clone(), certified(certs(cert)?, key)?));
        }
        builder.with_cert_resolver(Arc::new(SniResolver {
            default: certified(chain, key)?,
            by_name,
        }))
    };
    config.allow_mac_then_encrypt = o.allow_mac_then_encrypt;
    if let Some(limit) = o.record_size_limit {
        config.record_size_limit = limit;
    }
    config.ech = ech;
    config.ech_backend = o.ech_backend;
    Ok(Arc::new(config))
}

fn listen(o: &Options) -> Result<TcpListener> {
    let listen = required(o.listen.as_ref(), "--listen")?;
    let listener = TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    emit(&[
        ("event", "listening".into()),
        ("addr", addr.to_string().into()),
    ]);
    Ok(listener)
}

fn server(o: &Options) -> Result<()> {
    let config = server_config(o, o.ech_server()?)?;
    if o.async_io {
        return async_io::server(o, config);
    }
    let listener = listen(o)?;
    let mut failed = None;
    for index in 0..o.accept {
        let (sock, peer) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let result = set_timeouts(&sock).and_then(|()| {
            let conn = ServerConnection::new(config.clone()).map_err(|e| e.to_string())?;
            serve(StreamOwned::new(conn, sock), index)
        });
        if let Err(e) = result {
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

/// Answers one line on `tls`. A client refusing our ECH rejection
/// (`ech_required`) is reported as such, not as an error.
fn serve(mut tls: StreamOwned<ServerConnection, TcpStream>, index: usize) -> Result<()> {
    let line = match read_line(&mut tls) {
        Ok(line) => line,
        Err(e) => {
            return match tls_error(&mut tls.conn) {
                Some(err) if is_ech_required(&err) => {
                    emit(&[
                        ("event", "ech-required".into()),
                        ("role", "server".into()),
                        ("index", Value::Num(index)),
                        ("ech", format!("{:?}", tls.conn.ech_status()).into()),
                    ]);
                    Ok(())
                }
                Some(err) => Err(format!("{e}: {err}")),
                None => Err(e),
            };
        }
    };
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
    fields.push(("ech", format!("{:?}", tls.conn.ech_status()).into()));
    fields.push((
        "server_name",
        tls.conn.server_name().unwrap_or("none").to_owned().into(),
    ));
    fields.push(("received", line.into()));
    fields.push(("sent", reply.into()));
    emit(&fields);
    close(&mut tls);
    Ok(())
}

// ------------------------------------------------------------------ ech-keygen

fn ech_keygen(o: &Options) -> Result<()> {
    let out = std::path::PathBuf::from(required(o.out.as_ref(), "--out")?);
    let public_name = required(o.public_name.as_ref(), "--public-name")?;
    let key = EchServerKey::generate(o.config_id, public_name, 0, &x25519_hpke_suites())
        .map_err(|e| e.to_string())?;
    let list = EchServerConfig::new(vec![key.clone()]).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    for (name, bytes) in [
        ("ech-config", key.ech_config()),
        ("ech-config-list", list.ech_config_list()),
        ("ech-key", key.private_key().secret_bytes()),
    ] {
        let path = out.join(name);
        std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    emit(&[
        ("event", "ech-key".into()),
        ("config_id", Value::Num(usize::from(o.config_id))),
        ("public_name", public_name.into()),
    ]);
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
    if let Some(limit) = o.record_size_limit {
        config.record_size_limit = limit;
    }
    config.enable_grease = o.grease;
    config.tls13_ticket_request = o.ticket_request;
    if let Some(n) = o.padding {
        config.client_hello_padding = ClientHelloPadding::AtLeast(n);
    }
    config.ech_mode = o.ech_client(None)?;
    let mut config = Arc::new(config);
    let server_name = ServerName::try_from(name.to_owned()).map_err(|e| e.to_string())?;
    if o.async_io {
        return async_io::client(o, config, server_name, message);
    }

    let mut retried = false;
    let mut index = 0;
    while index < o.connections {
        let sock = connect_with_retry(connect, o.wait)?;
        set_timeouts(&sock)?;
        let conn = ClientConnection::new(config.clone(), server_name.clone())
            .map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, sock);
        let reply = tls
            .write_all(format!("{message}\n").as_bytes())
            .and_then(|()| tls.flush())
            .map_err(|e| format!("write: {e}"))
            .and_then(|()| read_line(&mut tls));
        let reply = match reply {
            Ok(reply) => reply,
            Err(e) => match tls_error(&mut tls.conn) {
                Some(Error::RejectedEch(rejected)) => {
                    emit(&[
                        ("event", "ech-rejected".into()),
                        ("index", Value::Num(index)),
                        ("retry_configs", Value::Bool(rejected.can_retry())),
                    ]);
                    // RFC 9849 §6.1.6: one retry with the new configurations.
                    let retry_configs = rejected.retry_configs().filter(|_| rejected.can_retry());
                    match retry_configs {
                        Some(list) if o.ech_retry && !retried => {
                            retried = true;
                            let mut next = (*config).clone();
                            next.ech_mode = o.ech_client(Some(list))?;
                            config = Arc::new(next);
                            continue;
                        }
                        _ => return Err(format!("connection {index}: ECH rejected")),
                    }
                }
                Some(err) => return Err(format!("connection {index}: {e}: {err}")),
                None => return Err(format!("connection {index}: {e}")),
            },
        };
        let mut fields = vec![
            ("event", "connection".into()),
            ("role", "client".into()),
            ("index", Value::Num(index)),
        ];
        fields.extend(negotiated(&tls.conn));
        fields.push(("ech", format!("{:?}", tls.conn.ech_status()).into()));
        fields.push(("sent", message.into()));
        fields.push(("received", reply.clone().into()));
        emit(&fields);
        close(&mut tls);
        if let Some(expected) = o.expect_reply.as_ref().filter(|e| **e != reply) {
            return Err(format!(
                "connection {index}: reply {reply:?}, expected {expected:?}"
            ));
        }
        index += 1;
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

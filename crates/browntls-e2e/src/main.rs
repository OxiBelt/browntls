//! A command-line TLS peer for the Docker end-to-end test matrix
//! (`tests/e2e/`).
//!
//! ```text
//! browntls-e2e info
//! browntls-e2e ech-keygen --out DIR --public-name NAME [--config-id N]
//!                        [--ech-pem [--ech-kem KEM]]
//! browntls-e2e server --listen ADDR --cert FILE --key FILE [--client-ca FILE]
//!                     [--accept N] [--sni-cert NAME,CERT,KEY]...
//!                     [ECH-SERVER...] [COMMON...]
//! browntls-e2e client-facing --listen ADDR --cert FILE --key FILE
//!                     --ech-config FILE --ech-key FILE
//!                     --backend NAME=HOST:PORT... [--accept N]
//!                     [ECH-SERVER...] [COMMON...]
//! browntls-e2e client --connect HOST:PORT --server-name NAME --ca FILE
//!                     [--reference-id dns:NAME|ip:ADDR|uri:URI|srv:ID]...
//!                     [--cert FILE --key FILE] [--message TEXT]
//!                     [--expect-reply TEXT] [--connections N] [--wait SECS]
//!                     [ECH-CLIENT...] [COMMON...]
//!
//! COMMON: --tls 1.2|1.3 (repeatable), --suite NAME (repeatable),
//!         --group NAME (repeatable), --allow-mac-then-encrypt,
//!         --record-size-limit N|none, --delegated-credentials, --grease,
//!         --async (buffered Tokio), --unbuffered (unbuffered Tokio),
//!         --key-log (logs only in diagnostic builds with SSLKEYLOGFILE),
//!         --zstd-cert-compression (only when built with browntls/zstd)
//! CLIENT: --ticket-request NEW,RESUMPTION, --padding N
//!         --reference-id dns:NAME|ip:ADDR|uri:URI|srv:ID (repeatable)
//! ECH-SERVER: --ech-config FILE --ech-key FILE (shared mode), --ech-backend,
//!         --ech-trial-decryption, --ech-public-name-check
//! ECH-CLIENT: --ech-config-list FILE, --ech-grease, --ech-random-config-id,
//!         --ech-retry
//! ```
//!
//! `dtls-client` and `dtls-server` use UDP with the same credentials and
//! `--tls` options: `1.2` selects DTLS 1.2, `1.3` selects DTLS 1.3, and
//! repeating both permits either. With no `--tls`, DTLS remains 1.3 only.
//! By default DTLS performs one full certificate handshake and a
//! request/reversed reply exchange, then checks both close alerts.
//! `--dtls-cid` opts into nonempty bidirectional connection IDs.
//! `--dtls12-resumption session-id|ticket` with `--tls 1.2` performs a full
//! then a resumed exchange; use `--connections 2` or `--accept 2`.
//! `--dtls-rebind basic|enhanced` selects the Kubernetes rebind scenario,
//! with two exchanges on one CID/RRC association.
//!
//! `--record-size-limit` sets the RFC 8449 limit to announce (`none`: no
//! extension); `--grease` sends RFC 8701 GREASE values (a client in its
//! ClientHello, a server in its TLS 1.3 CertificateRequest and
//! NewSessionTicket messages); `--ticket-request` sends the RFC 9149
//! extension; `--padding` pads the ClientHello to at least N bytes (RFC
//! 7685). `--async` runs TLS connections through the buffered `browntls-tokio`
//! adapters and `--unbuffered` through its unbuffered adapters, both on a
//! single-threaded Tokio runtime. For DTLS, `--async` selects the Tokio
//! UDP client and server and reports `"io":"tokio-dtls"`. It cannot be
//! combined with `--dtls-rebind`.
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
//! name. For RFC 9934, `ech-keygen --ech-pem` writes `ech.pem` and
//! `ech-public.pem`. Shared and client-facing servers take repeatable
//! `--ech-pem FILE` decryption bundles and ordered `--ech-retry-pem FILE`
//! retry lists. Clients can use one public-only `--ech-pem FILE`.
//! A client with `--ech-config-list` offers ECH (`--ech-grease` sends
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
//! The peer depends on the `browntls` facade crate alone, as an application
//! does: the protocol through its root and the Tokio streams through
//! `browntls::tokio`.
//!
//! This is test tooling: it loads keys from files given on the command line
//! and has no hardening beyond the library defaults it configures.
//! The `--key-log` flag installs the diagnostic sink. The sink can emit
//! traffic secrets only in builds that enable the `key-log` feature.

mod async_io;
mod client_facing;
mod dtls;
mod early_data;
mod ech_options;
#[cfg(feature = "zstd")]
mod observed_zstd;
mod output;
mod unbuffered_io;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, Instant};

use browntls::client::{ClientHelloPadding, TicketRequest};
use browntls::crypto::hash::HashAlgorithm;
use browntls::crypto::hpke::HpkeKem;
use browntls::crypto::native::delegated_credential;
use browntls::crypto::{CryptoProvider, SupportedKxGroup, native};
use browntls::ech::EchServerConfig;
use browntls::pki_types::pem::PemObject;
use browntls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use browntls::psk::ExternalPsk;
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

fn certified_key_with_credential(
    side: browntls::Side,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    provider: &CryptoProvider,
) -> Result<CertifiedKey> {
    let mut certified =
        CertifiedKey::from_der(chain, key, provider).map_err(|error| error.to_string())?;
    let cert = certified
        .end_entity_cert()
        .map_err(|error| error.to_string())?;
    let issued = delegated_credential::generate(
        side,
        cert,
        certified.key.as_ref(),
        &[browntls::SignatureScheme::ECDSA_NISTP256_SHA256],
        browntls::SignatureScheme::ECDSA_NISTP256_SHA256,
        24 * 60 * 60,
    )
    .map_err(|error| error.to_string())?;
    certified = match side {
        browntls::Side::Server => {
            certified.with_delegated_credential(issued.credential, issued.signing_key, provider)
        }
        browntls::Side::Client => certified.with_client_delegated_credential(
            issued.credential,
            issued.signing_key,
            provider,
        ),
    }
    .map_err(|error| error.to_string())?;
    Ok(certified)
}

fn configured_record_size_limit(options: &Options) -> Value {
    match options.record_size_limit {
        None => "default".into(),
        Some(None) => "none".into(),
        Some(Some(limit)) => limit.to_string().into(),
    }
}

fn zstd_compression_diagnostic(options: &Options) -> Option<(&'static str, Value)> {
    if !options.zstd_cert_compression {
        return None;
    }
    #[cfg(feature = "zstd")]
    {
        Some((
            "zstd_certificate_messages_received",
            Value::Num(observed_zstd::received()),
        ))
    }
    #[cfg(not(feature = "zstd"))]
    None
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((cmd, rest)) if cmd == "server" => Options::parse(rest, cmd).and_then(|o| server(&o)),
        Some((cmd, rest)) if cmd == "client" => Options::parse(rest, cmd).and_then(|o| client(&o)),
        Some((cmd, rest)) if cmd == "dtls-server" => {
            Options::parse(rest, cmd).and_then(|o| dtls::server(&o))
        }
        Some((cmd, rest)) if cmd == "dtls-client" => {
            Options::parse(rest, cmd).and_then(|o| dtls::client(&o))
        }
        Some((cmd, rest)) if cmd == "client-facing" => {
            Options::parse(rest, cmd).and_then(|o| client_facing(&o))
        }
        Some((cmd, rest)) if cmd == "ech-keygen" => {
            Options::parse(rest, cmd).and_then(|o| ech_options::keygen(&o))
        }
        Some((cmd, rest)) if matches!(cmd.as_str(), "early-data-server" | "early-data-client") => {
            early_data::run(cmd, rest)
        }
        Some((cmd, rest)) if cmd == "info" && rest.is_empty() => {
            info();
            Ok(())
        }
        _ => Err(concat!(
            "usage: browntls-e2e info | ech-keygen | server | client-facing | client",
            " | dtls-server | dtls-client | early-data-server | early-data-client [OPTIONS]"
        )
        .into()),
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
    reference_ids: Vec<String>,
    ca: Option<String>,
    client_ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    message: Option<String>,
    dtls_rebind: Option<String>,
    expect_reply: Option<String>,
    accept: usize,
    connections: usize,
    dtls12_resumption: Option<String>,
    wait: Duration,
    versions: Vec<&'static SupportedProtocolVersion>,
    suites: Vec<SupportedCipherSuite>,
    groups: Vec<&'static dyn SupportedKxGroup>,
    allow_mac_then_encrypt: bool,
    /// `None`: the library default; `Some(None)`: no extension.
    record_size_limit: Option<Option<u16>>,
    grease: bool,
    delegated_credentials: bool,
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
    ech_pems: Vec<String>,
    ech_retry_pems: Vec<String>,
    ech_keygen_pem: bool,
    ech_kem: Option<HpkeKem>,
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
    /// Client and server I/O through `browntls-tokio::unbuffered`.
    unbuffered_io: bool,
    dtls_cid: bool,
    external_psk_file: Option<String>,
    external_psk_identity: Option<String>,
    zstd_cert_compression: bool,
    key_log: bool,
}

impl Options {
    fn parse(args: &[String], command: &str) -> Result<Self> {
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
                "--delegated-credentials" => Some(&mut o.delegated_credentials),
                "--ech-backend" => Some(&mut o.ech_backend),
                "--ech-grease" => Some(&mut o.ech_grease),
                "--ech-random-config-id" => Some(&mut o.ech_random_config_id),
                "--ech-retry" => Some(&mut o.ech_retry),
                "--ech-pem" if command == "ech-keygen" => Some(&mut o.ech_keygen_pem),
                "--ech-trial-decryption" => Some(&mut o.ech_trial_decryption),
                "--ech-public-name-check" => Some(&mut o.ech_public_name_check),
                "--async" => Some(&mut o.async_io),
                "--unbuffered" => Some(&mut o.unbuffered_io),
                "--dtls-cid" => Some(&mut o.dtls_cid),
                "--zstd-cert-compression" => Some(&mut o.zstd_cert_compression),
                "--key-log" => Some(&mut o.key_log),
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
                "--reference-id" => o.reference_ids.push(value),
                "--ca" => o.ca = Some(value),
                "--client-ca" => o.client_ca = Some(value),
                "--cert" => o.cert = Some(value),
                "--key" => o.key = Some(value),
                "--external-psk-file" => o.external_psk_file = Some(value),
                "--external-psk-identity" => o.external_psk_identity = Some(value),
                "--message" => o.message = Some(value),
                "--dtls-rebind" => {
                    if !matches!(value.as_str(), "basic" | "enhanced") {
                        return Err(format!("unknown DTLS rebind mode {value:?}"));
                    }
                    o.dtls_rebind = Some(value);
                }
                "--expect-reply" => o.expect_reply = Some(value),
                "--accept" => o.accept = parse_count(flag, &value)?,
                "--connections" => o.connections = parse_count(flag, &value)?,
                "--dtls12-resumption" => o.dtls12_resumption = Some(value),
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
                "--ech-pem" => o.ech_pems.push(value),
                "--ech-retry-pem" => o.ech_retry_pems.push(value),
                "--ech-kem" => o.ech_kem = Some(ech_options::parse_kem(&value)?),
                "--backend" => {
                    let (name, addr) = value
                        .split_once('=')
                        .ok_or_else(|| format!("{flag} needs NAME=HOST:PORT"))?;
                    o.backends.push((name.into(), addr.into()));
                }
                _ => return Err(format!("unknown option {flag}")),
            }
        }
        o.validate_ech_options(command)?;
        if o.zstd_cert_compression && !cfg!(feature = "zstd") {
            return Err("--zstd-cert-compression requires a build with the zstd feature".into());
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

    fn dtls_versions(&self) -> browntls::dtls::Versions {
        use browntls::dtls::Versions;

        let tls12 = self
            .versions
            .iter()
            .any(|v| v.version == version::TLS12.version);
        let tls13 = self
            .versions
            .iter()
            .any(|v| v.version == version::TLS13.version);
        match (tls12, tls13) {
            (true, true) => Versions::V1_2And1_3,
            (true, false) => Versions::V1_2,
            _ => Versions::V1_3,
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

    /// Loads the per-run PSK from a file. Its bytes are never accepted on the
    /// command line or included in peer output.
    fn external_psk(&self) -> Result<Option<Arc<ExternalPsk>>> {
        match (&self.external_psk_file, &self.external_psk_identity) {
            (Some(path), Some(identity)) => ExternalPsk::new(
                identity.as_bytes().to_vec(),
                read_file(path)?,
                HashAlgorithm::SHA256,
            )
            .map(Arc::new)
            .map(Some)
            .map_err(|error| error.to_string()),
            (None, None) => Ok(None),
            _ => Err("--external-psk-file and --external-psk-identity go together".into()),
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
        if o.delegated_credentials {
            let certified =
                certified_key_with_credential(browntls::Side::Server, chain, key, &provider)?;
            builder.with_cert_resolver(Arc::new(browntls::sign::SingleCertAndKey::from(certified)))
        } else {
            builder
                .with_single_cert(chain, key)
                .map_err(|e| e.to_string())?
        }
    } else {
        let certified = |chain, key: PrivateKeyDer<'static>| {
            let certified = if o.delegated_credentials {
                certified_key_with_credential(browntls::Side::Server, chain, key, &provider)?
            } else {
                CertifiedKey::from_der(chain, key, &provider).map_err(|e| e.to_string())?
            };
            Ok::<Arc<CertifiedKey>, String>(Arc::new(certified))
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
    config.enable_grease = o.grease;
    config.enable_delegated_credentials = o.delegated_credentials;
    if o.key_log {
        config.key_log = Arc::new(browntls::KeyLogFile::new());
    }
    if o.zstd_cert_compression {
        #[cfg(feature = "zstd")]
        {
            config.cert_compressors = vec![&browntls::compress::ZSTD];
            config.cert_decompressors = vec![&observed_zstd::OBSERVED_ZSTD];
        }
    }
    if let Some(psk) = o.external_psk()? {
        config.external_psks = Some(Arc::new(vec![psk]));
        config.cert_with_extern_psk = true;
        config.require_cert_with_extern_psk = true;
        config.require_external_psk = true;
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
    if o.async_io && o.unbuffered_io {
        return Err("--async and --unbuffered are mutually exclusive".into());
    }
    if o.unbuffered_io {
        return unbuffered_io::server(o, config);
    }
    if o.async_io {
        return async_io::server(o, config);
    }
    let listener = listen(o)?;
    let mut failed = None;
    for index in 0..o.accept {
        let (sock, peer) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let result = set_timeouts(&sock).and_then(|()| {
            let conn = ServerConnection::new(config.clone()).map_err(|e| e.to_string())?;
            serve(StreamOwned::new(conn, sock), index, o)
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
fn serve(
    mut tls: StreamOwned<ServerConnection, TcpStream>,
    index: usize,
    o: &Options,
) -> Result<()> {
    #[cfg(feature = "zstd")]
    observed_zstd::reset();
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
    if let Some(field) = zstd_compression_diagnostic(o) {
        fields.push(field);
    }
    fields.push(("ech", format!("{:?}", tls.conn.ech_status()).into()));
    fields.push((
        "delegated_credential",
        Value::Bool(tls.conn.client_delegated_credential().is_some()),
    ));
    fields.push((
        "record_size_limit_configured",
        configured_record_size_limit(o),
    ));
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
        Some((chain, key)) if o.delegated_credentials => {
            let provider = o.provider();
            let certified = certified_key_with_credential(
                browntls::Side::Client,
                chain,
                key,
                provider.as_ref(),
            )?;
            builder.with_client_cert_resolver(Arc::new(browntls::sign::SingleCertAndKey::from(
                certified,
            )))
        }
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
    config.enable_delegated_credentials = o.delegated_credentials;
    if o.key_log {
        config.key_log = Arc::new(browntls::KeyLogFile::new());
    }
    if o.zstd_cert_compression {
        #[cfg(feature = "zstd")]
        {
            config.cert_compressors = vec![&browntls::compress::ZSTD];
            config.cert_decompressors = vec![&observed_zstd::OBSERVED_ZSTD];
        }
    }
    if let Some(psk) = o.external_psk()? {
        config.external_psks.push(psk);
        config.cert_with_extern_psk = true;
        config.require_cert_with_extern_psk = true;
        config.require_external_psk = true;
    }
    config.tls13_ticket_request = o.ticket_request;
    if let Some(n) = o.padding {
        config.client_hello_padding = ClientHelloPadding::AtLeast(n);
    }
    config.ech_mode = o.ech_client(None)?;
    let mut config = Arc::new(config);
    let server_name = ServerName::try_from(name.to_owned()).map_err(|e| e.to_string())?;
    let identity = service_identity(&o.reference_ids)?;
    if o.async_io && o.unbuffered_io {
        return Err("--async and --unbuffered are mutually exclusive".into());
    }
    if o.unbuffered_io {
        return unbuffered_io::client(o, config, server_name, identity, message);
    }
    if o.async_io {
        return async_io::client(o, config, server_name, identity, message);
    }

    let mut retried = false;
    let mut index = 0;
    while index < o.connections {
        #[cfg(feature = "zstd")]
        observed_zstd::reset();
        let sock = connect_with_retry(connect, o.wait)?;
        set_timeouts(&sock)?;
        let conn = match &identity {
            Some(identity) => ClientConnection::new_with_identity(
                config.clone(),
                browntls::ClientServerIdentity::new(server_name.clone(), identity.clone()),
            ),
            None => ClientConnection::new(config.clone(), server_name.clone()),
        }
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
        if let Some(field) = zstd_compression_diagnostic(o) {
            fields.push(field);
        }
        fields.push((
            "delegated_credential",
            Value::Bool(tls.conn.delegated_credential().is_some()),
        ));
        fields.push((
            "record_size_limit_configured",
            configured_record_size_limit(o),
        ));
        fields.push(("ech", format!("{:?}", tls.conn.ech_status()).into()));
        fields.push(("sent", message.into()));
        fields.push(("received", reply.clone().into()));
        fields.push((
            "service_identity_matched",
            Value::Bool(tls.conn.matched_service_identity().is_some()),
        ));
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

fn service_identity(references: &[String]) -> Result<Option<browntls::ServiceIdentity>> {
    use browntls::{ReferenceIdentifier as RefId, SrvId, UriId};
    if references.is_empty() {
        return Ok(None);
    }
    let mut parsed = Vec::with_capacity(references.len());
    for reference in references {
        let (kind, value) = reference
            .split_once(':')
            .ok_or_else(|| format!("invalid --reference-id {reference:?}; expected TYPE:VALUE"))?;
        parsed.push(match kind {
            "dns" => RefId::Dns(
                browntls::pki_types::DnsName::try_from(value.to_owned())
                    .map_err(|e| format!("invalid DNS reference {value:?}: {e}"))?,
            ),
            "ip" => RefId::Ip(
                browntls::pki_types::IpAddr::try_from(value)
                    .map_err(|e| format!("invalid IP reference {value:?}: {e:?}"))?,
            ),
            "uri" => RefId::Uri(
                UriId::try_from(value)
                    .map_err(|e| format!("invalid URI reference {value:?}: {e}"))?,
            ),
            "srv" => RefId::Srv(
                SrvId::try_from(value)
                    .map_err(|e| format!("invalid SRV reference {value:?}: {e}"))?,
            ),
            _ => return Err(format!("unknown --reference-id type {kind:?}")),
        });
    }
    browntls::ServiceIdentity::new(parsed)
        .map(Some)
        .map_err(|e| e.to_string())
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

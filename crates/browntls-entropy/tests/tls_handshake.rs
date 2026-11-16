//! Full in-memory TLS 1.3 and TLS 1.2 handshakes between a native client
//! and a native server, with the default configuration apart from the
//! protocol version.
//!
//! Examined from the handshake messages: both `random` values, the client's
//! `legacy_session_id`, the TLS 1.2 server's session ID, and the random
//! parts of the key shares. Examined from the client's key log (the same
//! interface as `SSLKEYLOGFILE`): every TLS 1.3 traffic and exporter secret
//! and the TLS 1.2 master secret, which are uniform only if the key
//! exchange produced a high-entropy shared secret.
//!
//! The client accepts the server certificate without validating it:
//! certificate validation does not affect any value examined here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use browntls::client::Resumption;
use browntls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use browntls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use browntls::{
    ClientConfig, ClientConnection, ConnectionCommon, DigitallySignedStruct, Error, KeyLog,
    ServerConfig, ServerConnection, SideData, SignatureScheme, SupportedProtocolVersion, version,
};
use browntls_entropy::{Stream, check, err, sample_count};

const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const SERVER_KEY_EXCHANGE: u8 = 12;
const KEY_SHARE: u16 = 0x0033;
const X25519: u16 = 0x001d;
const X25519MLKEM768: u16 = 0x11ec;
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;

const TLS13_SECRETS: [&str; 5] = [
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
];

/// Accepts any certificate; signatures are not checked either.
#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// Logged `(label, secret)` pairs of one connection.
type Logged = Vec<(String, Vec<u8>)>;

/// Collects logged secrets per client random.
#[derive(Debug, Default)]
struct Secrets(Mutex<HashMap<Vec<u8>, Logged>>);

impl KeyLog for Secrets {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Ok(mut map) = self.0.lock() {
            map.entry(client_random.to_vec())
                .or_default()
                .push((label.to_owned(), secret.to_vec()));
        }
    }
}

impl Secrets {
    fn take(&self, client_random: &[u8]) -> Result<Logged, String> {
        let mut map = self.0.lock().map_err(err)?;
        Ok(map.remove(client_random).unwrap_or_default())
    }
}

struct Setup {
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    secrets: Arc<Secrets>,
}

fn setup(server_versions: &[&'static SupportedProtocolVersion]) -> Setup {
    let provider = Arc::new(browntls::crypto::native::default_provider());
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let chain = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(server_versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    // Tickets travel encrypted and are not examined; skip their cost.
    server.send_tls13_tickets = 0;

    let secrets = Arc::new(Secrets::default());
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    client.key_log = secrets.clone();
    // Every handshake must be a full one: a resumed TLS 1.2 session would
    // repeat the session ID and master secret by design.
    client.resumption = Resumption::disabled();
    Setup {
        client: Arc::new(client),
        server: Arc::new(server),
        secrets,
    }
}

/// Everything `from` has queued.
fn drain<S: SideData>(from: &mut ConnectionCommon<S>) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).map_err(err)?;
    }
    Ok(buf)
}

/// Delivers `data` to `to` and processes it.
fn deliver<S: SideData>(to: &mut ConnectionCommon<S>, mut data: &[u8]) -> Result<(), String> {
    while !data.is_empty() {
        to.read_tls(&mut data).map_err(err)?;
        to.process_new_packets().map_err(err)?;
    }
    Ok(())
}

/// The handshake messages `(type, body)` at the start of a flight, up to
/// the first record that is not a plaintext handshake record.
fn handshake_messages(flight: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, String> {
    let mut stream = Vec::new();
    let mut rest = flight;
    while rest.len() >= 5 && rest[0] == HANDSHAKE {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        let record = rest.get(5..5 + len).ok_or("truncated record")?;
        stream.extend_from_slice(record);
        rest = &rest[5 + len..];
    }
    let mut msgs = Vec::new();
    let mut r = &stream[..];
    while r.len() >= 4 {
        let len = usize::from(r[1]) << 16 | usize::from(r[2]) << 8 | usize::from(r[3]);
        let body = r.get(4..4 + len).ok_or("truncated handshake message")?;
        msgs.push((r[0], body.to_vec()));
        r = &r[4 + len..];
    }
    Ok(msgs)
}

fn message(msgs: &[(u8, Vec<u8>)], typ: u8) -> Result<&[u8], String> {
    msgs.iter()
        .find(|(t, _)| *t == typ)
        .map(|(_, b)| &b[..])
        .ok_or_else(|| format!("no handshake message of type {typ}"))
}

/// A cursor over a message body.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("truncated message".into());
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<usize, String> {
        Ok(usize::from(self.take(1)?[0]))
    }

    fn u16(&mut self) -> Result<usize, String> {
        let b = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn vec8(&mut self) -> Result<&'a [u8], String> {
        let n = self.u8()?;
        self.take(n)
    }

    fn vec16(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()?;
        self.take(n)
    }
}

/// The parts of a hello examined here.
struct Hello<'a> {
    random: &'a [u8],
    session_id: &'a [u8],
    key_share: Option<&'a [u8]>,
}

fn parse_hello(body: &[u8], client: bool) -> Result<Hello<'_>, String> {
    let mut r = Reader(body);
    r.take(2)?; // legacy_version
    let random = r.take(32)?;
    let session_id = r.vec8()?;
    if client {
        r.vec16()?; // cipher_suites
        r.vec8()?; // legacy_compression_methods
    } else {
        r.take(3)?; // cipher_suite, legacy_compression_method
    }
    let mut key_share = None;
    if !r.0.is_empty() {
        let mut exts = Reader(r.vec16()?);
        while !exts.0.is_empty() {
            let typ = exts.u16()?;
            let data = exts.vec16()?;
            if typ == KEY_SHARE as usize {
                key_share = Some(data);
            }
        }
    }
    Ok(Hello {
        random,
        session_id,
        key_share,
    })
}

/// The client's key share for `group`.
fn client_share(key_share: &[u8], group: u16) -> Result<&[u8], String> {
    let mut shares = Reader(Reader(key_share).vec16()?);
    while !shares.0.is_empty() {
        let g = shares.u16()?;
        let key = shares.vec16()?;
        if g == usize::from(group) {
            return Ok(key);
        }
    }
    Err(format!("no client key share for group {group:#06x}"))
}

/// The server's key share and its group.
fn server_share(key_share: &[u8]) -> Result<(u16, &[u8]), String> {
    let mut r = Reader(key_share);
    let group = r.u16()? as u16;
    Ok((group, r.vec16()?))
}

fn copy(out: &mut [u8], value: &[u8], what: &str) -> Result<(), String> {
    if out.len() != value.len() {
        return Err(format!(
            "{what}: {} bytes, expected {}",
            value.len(),
            out.len()
        ));
    }
    out.copy_from_slice(value);
    Ok(())
}

/// Runs one handshake; returns the client's and the server's first flights
/// and the client's logged secrets.
type Flights = (Vec<u8>, Vec<u8>, Logged);

fn handshake(s: &Setup) -> Result<Flights, String> {
    let name = ServerName::try_from("localhost").map_err(err)?;
    let mut client = ClientConnection::new(s.client.clone(), name).map_err(err)?;
    let mut server = ServerConnection::new(s.server.clone()).map_err(err)?;
    let client_flight = drain(&mut client)?;
    deliver(&mut server, &client_flight)?;
    let server_flight = drain(&mut server)?;
    deliver(&mut client, &server_flight)?;
    for _ in 0..8 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        let data = drain(&mut client)?;
        deliver(&mut server, &data)?;
        let data = drain(&mut server)?;
        deliver(&mut client, &data)?;
    }
    if client.is_handshaking() || server.is_handshaking() {
        return Err("handshake did not complete".into());
    }
    let msgs = handshake_messages(&client_flight)?;
    let ch = parse_hello(message(&msgs, CLIENT_HELLO)?, true)?;
    let secrets = s.secrets.take(ch.random)?;
    Ok((client_flight, server_flight, secrets))
}

fn secret<'a>(secrets: &'a [(String, Vec<u8>)], label: &str) -> Result<&'a [u8], String> {
    let found: Vec<_> = secrets.iter().filter(|(l, _)| l == label).collect();
    match found.as_slice() {
        [(_, v)] => Ok(v),
        _ => Err(format!("{} {label} entries logged", found.len())),
    }
}

#[test]
fn tls13_handshakes() {
    let setup = setup(&[&version::TLS13]);
    // The secrets are as long as the hash of the negotiated suite:
    // TLS_AES_256_GCM_SHA384, the default first preference.
    let mut streams = vec![
        Stream::new("TLS 1.3 client random", 32),
        Stream::new("TLS 1.3 client legacy_session_id", 32),
        // rho of the ML-KEM-768 encapsulation key, then the X25519 share.
        Stream::new("TLS 1.3 client X25519MLKEM768 share (rho || X25519)", 64).fixed(63, 0x80),
        Stream::new("TLS 1.3 server random", 32),
        Stream::new("TLS 1.3 server X25519MLKEM768 share (X25519 part)", 32).fixed(31, 0x80),
    ];
    for label in TLS13_SECRETS {
        streams.push(Stream::new(format!("TLS 1.3 {label}"), 48));
    }
    check(
        "TLS 1.3 handshakes (native client and server)",
        sample_count(4, 1 << 10),
        &streams,
        |out| {
            let (cf, sf, secrets) = handshake(&setup)?;
            let msgs = handshake_messages(&cf)?;
            let ch = parse_hello(message(&msgs, CLIENT_HELLO)?, true)?;
            copy(out[0], ch.random, "client random")?;
            copy(out[1], ch.session_id, "client session id")?;
            let share = client_share(ch.key_share.ok_or("no key_share")?, X25519MLKEM768)?;
            if share.len() != MLKEM768_EK_LEN + 32 {
                return Err(format!("client hybrid share of {} bytes", share.len()));
            }
            out[2][..32].copy_from_slice(&share[MLKEM768_EK_LEN - 32..MLKEM768_EK_LEN]);
            out[2][32..].copy_from_slice(&share[MLKEM768_EK_LEN..]);

            let msgs = handshake_messages(&sf)?;
            let sh = parse_hello(message(&msgs, SERVER_HELLO)?, false)?;
            copy(out[3], sh.random, "server random")?;
            let (group, share) = server_share(sh.key_share.ok_or("no server key_share")?)?;
            if group != X25519MLKEM768 || share.len() != MLKEM768_CT_LEN + 32 {
                return Err(format!(
                    "server share {group:#06x} of {} bytes",
                    share.len()
                ));
            }
            copy(out[4], &share[MLKEM768_CT_LEN..], "server X25519 share")?;

            for (k, label) in TLS13_SECRETS.iter().enumerate() {
                copy(out[5 + k], secret(&secrets, label)?, label)?;
            }
            Ok(())
        },
    );
}

#[test]
fn tls12_handshakes() {
    // The client offers TLS 1.3 too, as by default, so it sends a random
    // legacy_session_id; the server only speaks TLS 1.2.
    let setup = setup(&[&version::TLS12]);
    check(
        "TLS 1.2 handshakes (native client and server)",
        sample_count(4, 1 << 10),
        &[
            Stream::new("TLS 1.2 client random", 32),
            Stream::new("TLS 1.2 client session_id", 32),
            Stream::new("TLS 1.2 server random", 32),
            Stream::new("TLS 1.2 server session_id", 32),
            Stream::new("TLS 1.2 ServerKeyExchange X25519 share", 32).fixed(31, 0x80),
            Stream::new("TLS 1.2 master secret", 48),
        ],
        |out| {
            let (cf, sf, secrets) = handshake(&setup)?;
            let msgs = handshake_messages(&cf)?;
            let ch = parse_hello(message(&msgs, CLIENT_HELLO)?, true)?;
            copy(out[0], ch.random, "client random")?;
            copy(out[1], ch.session_id, "client session id")?;

            let msgs = handshake_messages(&sf)?;
            let sh = parse_hello(message(&msgs, SERVER_HELLO)?, false)?;
            copy(out[2], sh.random, "server random")?;
            copy(out[3], sh.session_id, "server session id")?;
            let mut ske = Reader(message(&msgs, SERVER_KEY_EXCHANGE)?);
            let curve_type = ske.u8()?;
            let group = ske.u16()?;
            if curve_type != 3 || group != usize::from(X25519) {
                return Err(format!(
                    "ServerKeyExchange for curve {curve_type}/{group:#06x}"
                ));
            }
            copy(out[4], ske.vec8()?, "ServerKeyExchange share")?;
            copy(out[5], secret(&secrets, "CLIENT_RANDOM")?, "master secret")
        },
    );
}

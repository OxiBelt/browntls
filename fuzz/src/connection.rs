//! Client and server connections fed arbitrary bytes.
//!
//! A fuzzer cannot produce valid key exchange, signatures or record
//! protection by mutation, so raw bytes alone only reach the first handshake
//! message of either side. Two devices take the targets further:
//!
//! * A genuine peer, running in the same process with a matching
//!   configuration, can supply the first flights of a real handshake. The
//!   input says how many flights to deliver and how many records to drop
//!   from the end of the last one; the fuzzed bytes follow at that point.
//! * A provider variant whose TLS 1.3 record protection is the identity
//!   (`plain`): once both sides hold handshake keys, fuzzed records are
//!   accepted as "decrypted" plaintext, which exposes EncryptedExtensions,
//!   CertificateRequest, Certificate, CompressedCertificate and every
//!   post-handshake message to the fuzzer. Finished and CertificateVerify
//!   still need the real key schedule and signatures, so states behind them
//!   are reached through the genuine peer only.
//!
//! Certificates and keys are generated when the process starts; nothing in
//! a corpus depends on them except the genuine peer's own flights.

use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};

use browntls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use browntls::crypto::{CryptoProvider, native};
use browntls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls::server::WebPkiClientVerifier;
use browntls::{
    ClientConfig, ClientConnection, ConnectionCommon, ConnectionTrafficSecrets, ContentType, Error,
    ProtocolVersion, RootCertStore, ServerConfig, ServerConnection, SideData, SupportedCipherSuite,
    SupportedProtocolVersion, Tls13CipherSuite, version,
};

use crate::{take_byte, take_field};

// ------------------------------------------------------------- the provider

/// TLS 1.3 record protection that protects nothing: the "ciphertext" is the
/// inner plaintext (content, then content type), with no tag.
struct PlainAead;

struct Plain;

impl Tls13AeadAlgorithm for PlainAead {
    fn encrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Plain)
    }

    fn decrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Plain)
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

impl MessageEncrypter for Plain {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        _seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let mut payload = PrefixedPayload::with_capacity(msg.payload.len() + 1);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&[u8::from(msg.typ)]);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1
    }
}

impl MessageDecrypter for Plain {
    fn decrypt<'a>(
        &mut self,
        msg: InboundOpaqueMessage<'a>,
        _seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        msg.into_tls13_unpadded_message()
    }
}

/// The native provider, optionally with the identity transform in place of
/// every TLS 1.3 AEAD. Key exchange, key schedule, signatures and the TLS
/// 1.2 suites stay real.
fn provider(plain: bool) -> Arc<CryptoProvider> {
    let mut provider = native::default_provider();
    if plain {
        for suite in &mut provider.cipher_suites {
            if let SupportedCipherSuite::Tls13(real) = *suite {
                let fake: &'static Tls13CipherSuite = Box::leak(Box::new(Tls13CipherSuite {
                    common: browntls::crypto::CipherSuiteCommon {
                        suite: real.common.suite,
                        hash_provider: real.common.hash_provider,
                        confidentiality_limit: real.common.confidentiality_limit,
                    },
                    hkdf_provider: real.hkdf_provider,
                    aead_alg: &PlainAead,
                }));
                *suite = SupportedCipherSuite::Tls13(fake);
            }
        }
    }
    Arc::new(provider)
}

// ------------------------------------------------------------ configurations

/// A certificate chain and key generated for this process.
pub(crate) struct Identity {
    pub(crate) ca: CertificateDer<'static>,
    pub(crate) chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
    /// A CRL from the CA revoking one serial number.
    pub(crate) crl: Vec<u8>,
}

impl Identity {
    pub(crate) fn generate(name: &str, purpose: rcgen::ExtendedKeyUsagePurpose) -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "browntls fuzz CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let key = rcgen::KeyPair::generate().expect("end-entity key");
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("params");
        params.is_ca = rcgen::IsCa::NoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![purpose];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let cert = params.signed_by(&key, &issuer).expect("certificate");

        let now = rcgen::date_time_ymd(2026, 11, 1);
        let crl = rcgen::CertificateRevocationListParams {
            this_update: now,
            next_update: rcgen::date_time_ymd(2027, 11, 1),
            crl_number: rcgen::SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![rcgen::RevokedCertParams {
                serial_number: rcgen::SerialNumber::from_slice(&[0x7b, 4, 5, 6]),
                revocation_time: now,
                reason_code: Some(rcgen::RevocationReason::Superseded),
                invalidity_date: None,
            }],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .expect("CRL")
        .der()
        .to_vec();

        Self {
            ca: CertificateDer::from(ca_cert.der().to_vec()),
            chain: vec![CertificateDer::from(cert.der().to_vec())],
            key: key.serialize_der(),
            crl,
        }
    }

    fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).expect("root");
        Arc::new(roots)
    }

    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()))
    }
}

/// What the first input byte selects.
#[derive(Clone, Copy)]
struct Mode {
    /// Identity record protection for TLS 1.3.
    plain: bool,
    /// The server requires a client certificate and the client has one.
    client_auth: bool,
    /// TLS 1.2 only; otherwise both versions (two browntls peers pick 1.3).
    tls12_only: bool,
}

impl Mode {
    fn from_bits(bits: u8) -> Self {
        Self {
            plain: bits & 1 != 0,
            client_auth: bits & 2 != 0,
            tls12_only: bits & 4 != 0,
        }
    }

    fn index(self) -> usize {
        usize::from(self.plain)
            | usize::from(self.client_auth) << 1
            | usize::from(self.tls12_only) << 2
    }

    fn versions(self) -> &'static [&'static SupportedProtocolVersion] {
        static TLS12_ONLY: [&SupportedProtocolVersion; 1] = [&version::TLS12];
        if self.tls12_only {
            &TLS12_ONLY
        } else {
            browntls::ALL_VERSIONS
        }
    }
}

struct Configs {
    client: Vec<Arc<ClientConfig>>,
    server: Vec<Arc<ServerConfig>>,
}

fn configs() -> &'static Configs {
    static CONFIGS: OnceLock<Configs> = OnceLock::new();
    CONFIGS.get_or_init(|| {
        let server_identity =
            Identity::generate("localhost", rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let client_identity =
            Identity::generate("client.example", rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        let providers = [provider(false), provider(true)];

        let mut client = Vec::new();
        let mut server = Vec::new();
        for bits in 0..8 {
            let mode = Mode::from_bits(bits);
            let provider = &providers[usize::from(mode.plain)];

            let builder = ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(mode.versions())
                .expect("client versions")
                .with_root_certificates(server_identity.roots());
            let mut config = if mode.client_auth {
                builder
                    .with_client_auth_cert(client_identity.chain.clone(), client_identity.key())
                    .expect("client certificate")
            } else {
                builder.with_no_client_auth()
            };
            config.alpn_protocols = vec![b"fuzz".to_vec()];
            config.enable_early_data = true;
            client.push(Arc::new(config));

            let builder = ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(mode.versions())
                .expect("server versions");
            let builder = if mode.client_auth {
                builder.with_client_cert_verifier(
                    WebPkiClientVerifier::builder_with_provider(
                        client_identity.roots(),
                        provider.clone(),
                    )
                    .build()
                    .expect("client verifier"),
                )
            } else {
                builder.with_no_client_auth()
            };
            let mut config = builder
                .with_single_cert(server_identity.chain.clone(), server_identity.key())
                .expect("server certificate");
            config.alpn_protocols = vec![b"fuzz".to_vec()];
            config.max_early_data_size = 1024;
            server.push(Arc::new(config));
        }
        Configs { client, server }
    })
}

// ----------------------------------------------------------------- driving

/// Splits `stream` into TLS records (header included); a trailing partial
/// record is returned as the last element.
fn records(mut stream: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !stream.is_empty() {
        let len = match stream {
            [_, _, _, hi, lo, ..] => 5 + usize::from(u16::from_be_bytes([*hi, *lo])),
            _ => stream.len(),
        }
        .min(stream.len());
        let (record, rest) = stream.split_at(len);
        out.push(record);
        stream = rest;
    }
    out
}

/// Everything `conn` has to send.
fn drain<S: SideData>(conn: &mut ConnectionCommon<S>) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).is_err() {
            break;
        }
    }
    out
}

/// Delivers `bytes` to `conn`, processing as it goes. Stops at the first
/// error, which it returns.
fn deliver<S: SideData>(conn: &mut ConnectionCommon<S>, mut bytes: &[u8]) -> Result<(), Error> {
    let mut plaintext = [0u8; 512];
    while !bytes.is_empty() {
        // A full receive buffer is not an error: processing empties it.
        let _ = conn.read_tls(&mut bytes);
        conn.process_new_packets()?;
        while matches!(conn.reader().read(&mut plaintext), Ok(n) if n > 0) {}
    }
    Ok(())
}

/// Frames fuzzed fields as records. The first byte of each field picks the
/// content type and whether the record is written the way TLS 1.3 protects
/// it under the `plain` provider (outer type application_data, the real type
/// appended) or as an unprotected record.
fn wrap(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let mut field = take_field(&mut data);
        let selector = take_byte(&mut field);
        let typ = match selector & 3 {
            0 => 0x16, // handshake
            1 => 0x15, // alert
            2 => 0x17, // application data
            _ => 0x14, // change_cipher_spec
        };
        let protected = selector & 0x80 != 0;
        let field = &field[..field.len().min(16_384)];
        let len = field.len() + usize::from(protected);
        out.push(if protected { 0x17 } else { typ });
        out.extend_from_slice(&[0x03, 0x03]);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(field);
        if protected {
            out.push(typ);
        }
    }
    out
}

/// What the input header selects besides the [`Mode`].
struct Script<'a> {
    /// Genuine flights exchanged before the fuzzed bytes.
    flights: u8,
    /// Records dropped from the end of the last genuine flight delivered to
    /// the target.
    cut: u8,
    /// Whether `fuzz` is a sequence of fields to frame as records.
    wrap: bool,
    fuzz: &'a [u8],
}

fn parse(mut data: &[u8]) -> (Mode, Script<'_>) {
    let bits = take_byte(&mut data);
    let cut = take_byte(&mut data);
    (
        Mode::from_bits(bits),
        Script {
            wrap: bits & 8 != 0,
            flights: (bits >> 4) & 3,
            cut,
            fuzz: data,
        },
    )
}

/// The peer's pending output, with `cut` records dropped from its end.
fn flight<S: SideData>(peer: &mut ConnectionCommon<S>, cut: u8) -> Vec<u8> {
    let bytes = drain(peer);
    let records = records(&bytes);
    let keep = records.len() - usize::from(cut) % (records.len() + 1);
    records[..keep].concat()
}

/// After the scripted input: use the connection the way an application
/// would, then send whatever is pending (alerts included).
fn finish<S: SideData>(conn: &mut ConnectionCommon<S>, failed: bool) {
    if !failed && !conn.is_handshaking() {
        let _ = conn.writer().write(b"fuzz");
        let mut secret = [0u8; 16];
        let _ = conn.export_keying_material(&mut secret, b"fuzz", None);
        let _ = conn.refresh_traffic_keys();
        conn.send_close_notify();
    }
    let _ = drain(conn);
}

/// A client connection (`fuzz_targets/client.rs`).
///
/// Input: a mode byte (bit 0 identity record protection, bit 1 client
/// authentication, bit 2 TLS 1.2 only, bit 3 framed input, bits 4-5 genuine
/// server flights first), a byte giving the records to drop from the last
/// such flight, then the bytes the client receives.
pub fn client(data: &[u8]) {
    crate::init();
    let (mode, script) = parse(data);
    let configs = configs();
    let name = ServerName::try_from("localhost").expect("name");
    let Ok(mut client) = ClientConnection::new(configs.client[mode.index()].clone(), name) else {
        return;
    };
    let mut server = (script.flights > 0)
        .then(|| ServerConnection::new(configs.server[mode.index()].clone()).ok())
        .flatten();

    let mut failed = false;
    if let Some(server) = &mut server {
        for i in 1..=script.flights {
            let hello = drain(&mut client);
            // The genuine peer's own failures are not findings.
            let _ = deliver(server, &hello);
            let cut = if i == script.flights { script.cut } else { 0 };
            let reply = flight(server, cut);
            if deliver(&mut client, &reply).is_err() {
                failed = true;
                break;
            }
        }
    }
    if !failed {
        let _ = drain(&mut client);
        let wrapped;
        let fuzz = if script.wrap {
            wrapped = wrap(script.fuzz);
            &wrapped[..]
        } else {
            script.fuzz
        };
        failed = deliver(&mut client, fuzz).is_err();
    }
    finish(&mut client, failed);
}

/// A server connection (`fuzz_targets/server.rs`).
///
/// Input: as for [`client`], with genuine client flights first and the
/// bytes the server receives after them.
pub fn server(data: &[u8]) {
    crate::init();
    let (mode, script) = parse(data);
    let configs = configs();
    let Ok(mut server) = ServerConnection::new(configs.server[mode.index()].clone()) else {
        return;
    };
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = (script.flights > 0)
        .then(|| ClientConnection::new(configs.client[mode.index()].clone(), name).ok())
        .flatten();

    let mut failed = false;
    if let Some(client) = &mut client {
        for i in 1..=script.flights {
            let cut = if i == script.flights { script.cut } else { 0 };
            let request = flight(client, cut);
            if deliver(&mut server, &request).is_err() {
                failed = true;
                break;
            }
            if i < script.flights {
                let reply = drain(&mut server);
                let _ = deliver(client, &reply);
            }
        }
    }
    if !failed {
        let _ = drain(&mut server);
        let wrapped;
        let fuzz = if script.wrap {
            wrapped = wrap(script.fuzz);
            &wrapped[..]
        } else {
            script.fuzz
        };
        failed = deliver(&mut server, fuzz).is_err();
    }
    finish(&mut server, failed);
}

/// Runs a complete genuine handshake in every mode; returns how many
/// completed. Guards the harness itself: if the configurations stopped
/// interoperating, the fuzzers would silently lose their depth.
#[cfg(test)]
pub(crate) fn self_test() -> usize {
    let configs = configs();
    let mut completed = 0;
    for bits in 0..8 {
        let mode = Mode::from_bits(bits);
        let name = ServerName::try_from("localhost").expect("name");
        let mut client =
            ClientConnection::new(configs.client[mode.index()].clone(), name).expect("client");
        let mut server =
            ServerConnection::new(configs.server[mode.index()].clone()).expect("server");
        for _ in 0..4 {
            let bytes = drain(&mut client);
            deliver(&mut server, &bytes).expect("server");
            let bytes = drain(&mut server);
            deliver(&mut client, &bytes).expect("client");
        }
        assert_eq!(
            client.protocol_version() == Some(ProtocolVersion::TLSv1_2),
            mode.tls12_only
        );
        if !client.is_handshaking() && !server.is_handshaking() {
            completed += 1;
        }
    }
    completed
}

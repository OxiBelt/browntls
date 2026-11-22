//! Wire-format helpers and record containers (`fuzz_targets/tls_codec.rs`).
//!
//! Reaches the public functions of `browntls_core::msgs` that the
//! `handshake_message`, `deframer` and `cert_decompress` targets do not: the
//! codec [`Reader`], [`HandshakeMessagePayload`] and [`ClientHelloPayload`]
//! through `browntls_core::internal::msgs`, [`NamedGroup`] and
//! [`DistinguishedName`], the record containers of
//! `browntls_core::crypto::cipher` ([`OutboundChunks`], [`PrefixedPayload`],
//! [`OutboundOpaqueMessage`], [`InboundOpaqueMessage`] and its
//! `BorrowedPayload`, [`OutboundPlainMessage`]), the stored client session
//! values (`Tls12ClientSessionValue`, `Tls13ClientSessionValue`, taken from
//! and put back into a client session store between two real handshakes),
//! and the `browntls_core::fuzzing` entry points.
//!
//! Every container is checked against a plain `Vec<u8>` model, decoders
//! against re-encoding (encode, decode, encode must be stable), the enums
//! against their definitions, and the session values against the
//! handshake that made them and the resumption that follows.
//!
//! Input: up to 64 operations, each an operation byte followed by its
//! arguments (see [`run`]). The session operation runs at most twice per
//! input.

use std::sync::{Arc, OnceLock};

use browntls_core::client::{ClientSessionMemoryCache, ClientSessionStore, Resumption};
use browntls_core::crypto::KeyExchangeAlgorithm;
use browntls_core::crypto::cipher::{
    InboundOpaqueMessage, InboundPlainMessage, OutboundChunks, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload,
};
use browntls_core::crypto::hash::HashAlgorithm;
use browntls_core::fuzzing;
use browntls_core::internal::msgs::codec::{Codec, Reader};
use browntls_core::internal::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload};
use browntls_core::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::psk::ExternalPsk;
use browntls_core::{
    ClientConfig, ClientConnection, ContentType, DistinguishedName, Error, HandshakeKind,
    NamedGroup, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection, version,
};

use crate::input::{Input, put_field, put_short_field};

/// Operations per input.
const MAX_OPS: usize = 64;

/// Session round trips per input (each is two handshakes).
const MAX_SESSIONS: usize = 2;

/// The lifetime a server without a ticketer announces for TLS 1.3 tickets
/// (one day).
const STATEFUL_TICKET_LIFETIME: u32 = 24 * 60 * 60;

/// The `tls_codec` fuzz target.
///
/// Operations (first byte modulo 10):
///
/// 0. reader: a 16-bit-prefixed buffer, then up to 16 cursor calls
///    (`take`, `sub`, `rest`, `expect_empty`, a typed read) checked against
///    a model;
/// 1. handshake message: version selector, then a 16-bit-prefixed message
///    for `HandshakeMessagePayload::read_version`; a decoded TLS 1.2 or 1.3
///    message must re-encode stably;
/// 2. ClientHello body (16-bit-prefixed) through `Codec`; likewise;
/// 3. named group: a 16-bit code point;
/// 4. distinguished name: a DER field, a contents field and a 32-bit
///    length to repeat the contents to (`in_sequence`, long DER lengths);
/// 5. outbound chunks: a field split into chunks at fuzzed points, then
///    nested splits and copies;
/// 6. prefixed payload and outbound opaque record: content type, version,
///    capacity, initial bytes, then up to 16 edits;
/// 7. inbound opaque record: content type, version, a body field, padding,
///    up to 16 edits of its `BorrowedPayload`, then plain, TLS 1.3
///    unpadding or `into_inner`;
/// 8. outbound plain record: content type, version, chunked body;
/// 9. sessions: version, PSK, early data limit and the age to add to the
///    stored session between two handshakes;
///
/// and, with the high bit of the operation byte set, a `browntls_core::fuzzing`
/// entry point (bit 6: TLS 1.3) with a selector byte and a 16-bit-prefixed
/// field.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let mut sessions_run = 0;
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        let op = input.byte();
        if op & 0x80 != 0 {
            fuzzing_entry(op, &mut input);
            continue;
        }
        match op % 10 {
            0 => reader(&mut input),
            1 => handshake_message(&mut input),
            2 => client_hello(&mut input),
            3 => named_group(&mut input),
            4 => distinguished_name(&mut input),
            5 => outbound_chunks(&mut input),
            6 => prefixed_payload(&mut input),
            7 => inbound_opaque(&mut input),
            8 => outbound_plain(&mut input),
            _ => {
                if sessions_run < MAX_SESSIONS {
                    sessions_run += 1;
                    sessions(&mut input);
                }
            }
        }
    }
}

// ------------------------------------------------------------------ reader

fn reader(input: &mut Input) {
    let data = input.field();
    let mut r = Reader::init(data);
    let mut pos = 0usize;
    for _ in 0..16 {
        if input.is_empty() {
            break;
        }
        match input.choose(5) {
            0 => {
                let n = usize::from(input.byte());
                let got = r.take(n);
                if pos + n <= data.len() {
                    assert_eq!(got, Some(&data[pos..pos + n]));
                    pos += n;
                } else {
                    assert!(got.is_none());
                }
            }
            1 => {
                let n = usize::from(input.byte());
                match r.sub(n) {
                    Ok(mut sub) => {
                        assert!(pos + n <= data.len());
                        assert_eq!(sub.left(), n);
                        assert_eq!(sub.used(), 0);
                        assert_eq!(sub.rest(), &data[pos..pos + n]);
                        assert!(!sub.any_left());
                        pos += n;
                    }
                    Err(_) => assert!(pos + n > data.len()),
                }
            }
            2 => {
                assert_eq!(r.rest(), &data[pos..]);
                pos = data.len();
            }
            3 => assert_eq!(r.expect_empty("fuzz").is_ok(), pos == data.len()),
            _ => {
                // A typed read through `Codec` advances by its size, or not
                // at all when too little is left.
                match u16::read(&mut r) {
                    Ok(value) => {
                        assert_eq!(value.to_be_bytes(), data[pos..pos + 2]);
                        pos += 2;
                    }
                    Err(_) => assert!(data.len() - pos < 2),
                }
            }
        }
        assert_eq!(r.used(), pos);
        assert_eq!(r.left(), data.len() - pos);
        assert_eq!(r.any_left(), pos < data.len());
    }
}

// -------------------------------------------------------- message decoders

fn pick_version(input: &mut Input) -> ProtocolVersion {
    match input.choose(4) {
        0 => ProtocolVersion::TLSv1_2,
        1 => ProtocolVersion::TLSv1_3,
        2 => ProtocolVersion::TLSv1_0,
        _ => ProtocolVersion::from(input.u16()),
    }
}

fn handshake_message(input: &mut Input) {
    let vers = pick_version(input);
    let data = input.field();
    let mut r = Reader::init(data);
    let Ok(message) = HandshakeMessagePayload::read_version(&mut r, vers) else {
        return;
    };
    assert!(r.used() >= 4, "a handshake message has a 4-byte header");
    let mut first = Vec::new();
    message.encode(&mut first);
    let mut r = Reader::init(&first);
    let again = HandshakeMessagePayload::read_version(&mut r, vers);
    if matches!(vers, ProtocolVersion::TLSv1_2 | ProtocolVersion::TLSv1_3) {
        let again = again.expect("a decoded handshake message decodes after encoding");
        assert!(!r.any_left(), "re-encoding has trailing bytes");
        let mut second = Vec::new();
        again.encode(&mut second);
        assert_eq!(first, second, "handshake message encoding is not stable");
    }
}

fn client_hello(input: &mut Input) {
    let data = input.field();
    let Ok(hello) = ClientHelloPayload::read_bytes(data) else {
        return;
    };
    let first = hello.get_encoding();
    let again =
        ClientHelloPayload::read_bytes(&first).expect("an encoded ClientHello decodes again");
    assert_eq!(
        again.get_encoding(),
        first,
        "ClientHello encoding is not stable"
    );
}

fn fuzzing_entry(op: u8, input: &mut Input) {
    let selector = input.byte();
    let tls13 = op & 0x40 != 0;
    let data = input.field();
    match (op & 0x3f) % 5 {
        0 => fuzzing::deframer(data),
        1 => fuzzing::handshake_message(tls13, data),
        2 => fuzzing::handshake_body(selector, tls13, data),
        3 => fuzzing::record_payload(selector, tls13, data),
        _ => {
            let limits = [
                64,
                4096,
                browntls_core::compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE,
            ];
            fuzzing::compressed_certificate(limits[usize::from(selector % 3)], data);
        }
    }
}

// ------------------------------------------------------------------- enums

fn named_group(input: &mut Input) {
    let value = input.u16();
    let group = NamedGroup::from(value);
    assert_eq!(u16::from(group), value);
    // X448 and the RFC 7919 groups.
    assert_eq!(
        group.is_non_preferred(),
        matches!(value, 0x001e | 0x0100..=0x0104),
        "{group:?}"
    );
    let expected = if (0x0100..0x0200).contains(&value) {
        KeyExchangeAlgorithm::DHE
    } else {
        KeyExchangeAlgorithm::ECDHE
    };
    assert_eq!(group.key_exchange_algorithm(), expected, "{group:?}");
    let decoded = NamedGroup::read_bytes(&value.to_be_bytes()).expect("two bytes decode");
    assert_eq!(decoded, group);
}

// ------------------------------------------------------- distinguished name

fn der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(0);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
}

fn distinguished_name(input: &mut Input) {
    let der = input.field().to_vec();
    let name = DistinguishedName::new(der.clone());
    assert_eq!(name.as_ref(), &der[..]);
    let encoded = name.get_encoding();
    let mut expected = Vec::new();
    put_field(&mut expected, &der);
    assert_eq!(encoded, expected);
    // An empty name is refused on the wire.
    match DistinguishedName::read_bytes(&encoded) {
        Ok(decoded) => assert_eq!(decoded, name),
        Err(_) => assert!(der.is_empty(), "a non-empty name does not decode"),
    }

    let seed = input.field();
    // Repeating the contents reaches the two- and three-byte DER lengths.
    let target = (input.u32() & 0x01_ffff) as usize;
    let contents: Vec<u8> = if seed.is_empty() || target <= seed.len() {
        seed.to_vec()
    } else {
        seed.iter().copied().cycle().take(target).collect()
    };
    let wrapped = DistinguishedName::in_sequence(&contents);
    let mut expected = vec![0x30];
    der_length(contents.len(), &mut expected);
    expected.extend_from_slice(&contents);
    assert_eq!(wrapped.as_ref(), &expected[..]);
}

// ------------------------------------------------------- record containers

fn pick_type(input: &mut Input) -> ContentType {
    match input.choose(6) {
        0 => ContentType::Handshake,
        1 => ContentType::Alert,
        2 => ContentType::ApplicationData,
        3 => ContentType::ChangeCipherSpec,
        4 => ContentType::Heartbeat,
        _ => ContentType::from(input.byte()),
    }
}

/// Splits `data` at up to 8 fuzzed points (empty chunks included).
fn split<'a>(input: &mut Input, data: &'a [u8]) -> Vec<&'a [u8]> {
    let pieces = input.choose(9);
    let mut chunks = Vec::new();
    let mut rest = data;
    for _ in 0..pieces {
        let at = usize::from(input.byte()).min(rest.len());
        let (head, tail) = rest.split_at(at);
        chunks.push(head);
        rest = tail;
    }
    if !rest.is_empty() || input.bool() {
        chunks.push(rest);
    }
    chunks
}

/// Checks `chunks` against the bytes it should hold, then splits it at a
/// fuzzed point and recurses into both halves (to depth `depth`).
fn check_chunks(input: &mut Input, chunks: &OutboundChunks<'_>, model: &[u8], depth: u8) {
    assert_eq!(chunks.len(), model.len());
    assert_eq!(chunks.is_empty(), model.is_empty());
    assert_eq!(chunks.to_vec(), model);
    let mut appended = vec![0xa5];
    chunks.copy_to_vec(&mut appended);
    assert_eq!(&appended[1..], model);
    if depth == 0 || input.is_empty() {
        return;
    }
    // Points past the end are clamped.
    let mid = usize::from(input.u16()) % (model.len() + 8);
    let (left, right) = chunks.split_at(mid);
    let mid = mid.min(model.len());
    check_chunks(input, &left, &model[..mid], depth - 1);
    check_chunks(input, &right, &model[mid..], depth - 1);
}

fn outbound_chunks(input: &mut Input) {
    let data = input.field();
    let pieces = split(input, data);
    let chunks = OutboundChunks::new(&pieces);
    check_chunks(input, &chunks, data, 3);
    let single = OutboundChunks::from(data);
    check_chunks(input, &single, data, 2);
}

/// Up to 16 edits of a [`PrefixedPayload`], mirrored on `model`.
fn edit_prefixed(input: &mut Input, payload: &mut PrefixedPayload, model: &mut Vec<u8>) {
    for _ in 0..16 {
        if input.is_empty() {
            break;
        }
        match input.choose(5) {
            0 => {
                let bytes = input.short_field();
                payload.extend_from_slice(bytes);
                model.extend_from_slice(bytes);
            }
            1 => {
                let bytes = input.short_field();
                let pieces = split(input, bytes);
                payload.extend_from_chunks(&OutboundChunks::new(&pieces));
                model.extend_from_slice(bytes);
            }
            2 => {
                let len = usize::from(input.u16()) % (model.len() + 16);
                payload.truncate(len);
                model.truncate(len);
            }
            3 => {
                let len = usize::from(input.u16()) % 2048;
                payload.resize(len);
                model.resize(len, 0);
            }
            _ => {
                if !model.is_empty() {
                    let at = usize::from(input.u16()) % model.len();
                    let x = input.byte();
                    payload.as_mut()[at] ^= x;
                    model[at] ^= x;
                }
            }
        }
        assert_eq!(payload.len(), model.len());
        assert_eq!(payload.is_empty(), model.is_empty());
        assert_eq!(payload.as_ref(), &model[..]);
    }
}

fn record(typ: ContentType, vers: ProtocolVersion, body: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::from(typ)];
    out.extend_from_slice(&u16::from(vers).to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn prefixed_payload(input: &mut Input) {
    let typ = pick_type(input);
    let vers = pick_version(input);
    let capacity = usize::from(input.u16()) % 4096;
    let mut model = Vec::new();
    let mut payload = if input.bool() {
        PrefixedPayload::with_capacity(capacity)
    } else {
        let initial = input.short_field();
        model.extend_from_slice(initial);
        PrefixedPayload::from(initial)
    };
    assert_eq!(payload.len(), model.len());
    assert_eq!(payload.is_empty(), model.is_empty());
    edit_prefixed(input, &mut payload, &mut model);
    let message = OutboundOpaqueMessage::new(typ, vers, payload);
    assert_eq!(message.payload.len(), model.len());
    assert_eq!(message.encode(), record(typ, vers, &model));
}

/// The TLS 1.3 inner plaintext rules (RFC 8446 §5.2): the content type is
/// the last non-zero byte, the zero padding after it is dropped, and only
/// application data may be empty.
fn unpadded(model: &[u8]) -> Option<(ContentType, &[u8])> {
    let at = model.iter().rposition(|b| *b != 0)?;
    let typ = ContentType::from(model[at]);
    if matches!(typ, ContentType::Unknown(_)) {
        return None;
    }
    if at == 0 && typ != ContentType::ApplicationData {
        return None;
    }
    Some((typ, &model[..at]))
}

fn inbound_opaque(input: &mut Input) {
    let typ = pick_type(input);
    let vers = pick_version(input);
    let mut buf = input.field().to_vec();
    let zeros = usize::from(input.byte() % 64);
    buf.resize(buf.len() + zeros, 0);
    let mut model = buf.clone();
    let mut message = InboundOpaqueMessage::new(typ, vers, &mut buf);
    assert_eq!(message.typ, typ);
    assert_eq!(message.version, vers);
    for _ in 0..16 {
        if input.is_empty() {
            break;
        }
        let payload = &mut message.payload;
        match input.choose(4) {
            0 => {
                let len = usize::from(input.u16()) % (model.len() + 8);
                payload.truncate(len);
                model.truncate(len);
            }
            1 => {
                let n = usize::from(input.byte() % 32);
                payload.consume_prefix(n);
                model.drain(..n.min(model.len()));
            }
            2 => {
                if !model.is_empty() {
                    let at = usize::from(input.u16()) % model.len();
                    let x = input.byte();
                    payload[at] ^= x;
                    model[at] ^= x;
                }
            }
            _ => break,
        }
        assert_eq!(message.payload.len(), model.len());
        assert_eq!(message.payload.is_empty(), model.is_empty());
        assert_eq!(&message.payload[..], &model[..]);
    }
    match input.choose(3) {
        0 => {
            let plain = message.into_plain_message();
            assert_eq!(plain.typ, typ);
            assert_eq!(plain.version, vers);
            assert_eq!(plain.payload, &model[..]);
            let direct = InboundPlainMessage::new(typ, vers, &model);
            assert_eq!(plain.record_plaintext_len(), direct.record_plaintext_len());
            assert_eq!(direct.record_plaintext_len(), model.len());
        }
        1 => match (unpadded(&model), message.into_tls13_unpadded_message()) {
            (Some((typ, body)), Ok(plain)) => {
                assert_eq!(plain.typ, typ);
                assert_eq!(plain.version, ProtocolVersion::TLSv1_3);
                assert_eq!(plain.record_plaintext_len(), model.len());
                let direct = InboundPlainMessage::with_record_plaintext_len(
                    plain.typ,
                    plain.version,
                    body,
                    model.len(),
                );
                assert_eq!(direct.record_plaintext_len(), plain.record_plaintext_len());
                assert_eq!(plain.payload, body);
            }
            (None, Err(_)) => {}
            (expected, got) => panic!("unpadding {model:?}: {expected:?} vs {got:?}"),
        },
        _ => assert_eq!(message.payload.into_inner(), &model[..]),
    }
}

fn outbound_plain(input: &mut Input) {
    let typ = pick_type(input);
    let vers = pick_version(input);
    let data = input.field();
    let pieces = split(input, data);
    let message = OutboundPlainMessage {
        typ,
        version: vers,
        payload: OutboundChunks::new(&pieces),
    };
    assert_eq!(message.encoded_len(), 5 + data.len());
    let opaque = message.to_unencrypted_opaque();
    assert_eq!(opaque.typ, typ);
    assert_eq!(opaque.version, vers);
    assert_eq!(opaque.payload.as_ref(), data);
    assert_eq!(opaque.encode(), record(typ, vers, data));
}

// ---------------------------------------------------------------- sessions

/// A CA and a `localhost` certificate, made once per process.
struct Pki {
    roots: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &issuer).expect("certificate");
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .expect("root");
        Pki {
            roots: Arc::new(roots),
            chain: vec![CertificateDer::from(cert.der().to_vec())],
            key: key.serialize_der(),
        }
    })
}

/// Moves everything `from` has to send into `to`. Errors stay with the
/// connections and show up in `process_new_packets`.
fn send<A: browntls_core::SideData, B: browntls_core::SideData>(
    from: &mut browntls_core::ConnectionCommon<A>,
    to: &mut browntls_core::ConnectionCommon<B>,
) {
    let mut buf = Vec::new();
    while from.wants_write() {
        if from.write_tls(&mut buf).is_err() {
            break;
        }
    }
    let mut rest = &buf[..];
    while !rest.is_empty() {
        match to.read_tls(&mut rest) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Runs the handshake, then delivers what the server sends after it (TLS
/// 1.3 tickets); returns each side's first error.
fn handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> (Result<(), Error>, Result<(), Error>) {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        send(client, server);
        if let Err(e) = server.process_new_packets() {
            send(server, client);
            let client_res = client.process_new_packets().map(|_| ());
            return (client_res, Err(e));
        }
        send(server, client);
        if let Err(e) = client.process_new_packets() {
            send(client, server);
            let server_res = server.process_new_packets().map(|_| ());
            return (Err(e), server_res);
        }
    }
    send(server, client);
    let client_res = client.process_new_packets().map(|_| ());
    (client_res, Ok(()))
}

fn sessions(input: &mut Input) {
    let tls12 = input.bool();
    let psk = !tls12 && input.bool();
    let early = if input.bool() { input.u16().into() } else { 0 };
    let delta = match input.choose(4) {
        0 => 0,
        1 => input.u32() % STATEFUL_TICKET_LIFETIME,
        2 => STATEFUL_TICKET_LIFETIME + 2 + u32::from(input.u16()),
        _ => input.u32(),
    };
    let identity = b"fuzz session psk".to_vec();
    let pki = pki();
    let versions: &[&browntls_core::SupportedProtocolVersion] = if tls12 {
        &[&version::TLS12]
    } else {
        &[&version::TLS13]
    };
    let provider = Arc::new(browntls_core::crypto::native::default_provider());
    let new_psk = || {
        Arc::new(
            ExternalPsk::new(identity.clone(), vec![0x42; 32], HashAlgorithm::SHA256).expect("PSK"),
        )
    };

    let mut server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(
            pki.chain.clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.clone())),
        )
        .expect("server certificate");
    server_config.max_early_data_size = early;
    if psk {
        server_config.external_psks = Some(Arc::new(vec![new_psk()]));
    }
    let server_config = Arc::new(server_config);

    let store = Arc::new(ClientSessionMemoryCache::new(8));
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("client versions")
        .with_root_certificates(pki.roots.clone())
        .with_no_client_auth();
    client_config.resumption = Resumption::store(store.clone());
    if psk {
        client_config.external_psks = vec![new_psk()];
    }
    let client_config = Arc::new(client_config);
    let name = ServerName::try_from("localhost").expect("name");

    let connect = || {
        let mut client =
            ClientConnection::new(client_config.clone(), name.clone()).expect("client");
        let mut server = ServerConnection::new(server_config.clone()).expect("server");
        let (client_res, server_res) = handshake(&mut client, &mut server);
        assert!(
            client_res.is_ok() && server_res.is_ok(),
            "{client_res:?} {server_res:?}"
        );
        assert!(!client.is_handshaking() && !server.is_handshaking());
        client
    };

    let first = connect();
    let suite = first.negotiated_cipher_suite().expect("suite").suite();
    if tls12 {
        let mut value = store
            .tls12_session(&name)
            .expect("a stored TLS 1.2 session");
        value.rewind_epoch(delta);
        store.set_tls12_session(name.clone(), value);
    } else {
        let mut value = store.take_tls13_ticket(&name).expect("a TLS 1.3 ticket");
        assert_eq!(value.suite().common.suite, suite);
        assert_eq!(
            value.external_psk_identity(),
            psk.then_some(&identity[..]),
            "ticket of a PSK session"
        );
        if !psk {
            assert_eq!(value.max_early_data_size(), early);
        }
        value.rewind_epoch(delta);
        store.insert_tls13_ticket(name.clone(), value);
    }

    let second = connect();
    let kind = second.handshake_kind();
    if delta == 0 {
        assert_eq!(kind, Some(HandshakeKind::Resumed), "fresh session");
    } else if !tls12 && delta > STATEFUL_TICKET_LIFETIME + 1 {
        assert_eq!(kind, Some(HandshakeKind::Full), "expired ticket offered");
    }
}

/// Starting inputs for `tls_codec`: one or more per operation.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let mut seeds = Vec::new();

    // A real ClientHello for the decoders.
    let pki = pki();
    let config = ClientConfig::builder_with_provider(Arc::new(
        browntls_core::crypto::native::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(pki.roots.clone())
    .with_no_client_auth();
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(Arc::new(config), name).expect("client");
    let mut flight = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut flight).expect("write");
    }
    let message = flight[5..].to_vec();
    let body = message[4..].to_vec();

    // 0: reader, every call
    let mut seed = vec![0];
    put_field(&mut seed, b"0123456789abcdef");
    seed.extend_from_slice(&[0, 3, 1, 4, 4, 3, 0, 200, 1, 200, 2, 3]);
    seeds.push(seed);
    // 1: handshake messages, both versions and an odd one
    for vers in [0u8, 1, 2] {
        let mut seed = vec![1, vers];
        put_field(&mut seed, &message);
        seeds.push(seed);
    }
    // 2: ClientHello body
    let mut seed = vec![2];
    put_field(&mut seed, &body);
    seeds.push(seed);
    // 3: named groups
    seeds.push(vec![
        3, 0x00, 0x1d, 3, 0x01, 0x00, 3, 0x00, 0x1e, 3, 0x11, 0xec, 3, 0x01, 0xff,
    ]);
    // 4: distinguished names, short and long DER lengths
    for len in [0u32, 200, 300, 70_000] {
        let mut seed = vec![4];
        put_field(&mut seed, &[0x30, 0x03, 0x02, 0x01, 0x05]);
        put_field(&mut seed, b"\x31\x0b\x30\x09\x06\x03\x55\x04\x03\x0c\x02ab");
        seed.extend_from_slice(&len.to_be_bytes());
        seeds.push(seed);
    }
    // 5: chunks split three times, then split again
    let mut seed = vec![5];
    put_field(&mut seed, b"the quick brown fox jumps over the lazy dog");
    seed.extend_from_slice(&[3, 5, 0, 9, 1, 0, 7, 0, 3, 0, 1, 0, 2, 0, 50, 0, 4]);
    seeds.push(seed);
    // 6: prefixed payload, every edit
    let mut seed = vec![6, 0, 1, 0, 64, 0];
    put_short_field(&mut seed, b"init");
    seed.push(0);
    put_short_field(&mut seed, b"abc");
    seed.push(1);
    put_short_field(&mut seed, b"wxyz");
    seed.extend_from_slice(&[2, 1, 1, 2, 0, 5, 3, 0, 9, 4, 0, 1, 0xff]);
    seeds.push(seed);
    let mut seed = vec![6, 2, 0, 0, 0, 1, 0];
    put_short_field(&mut seed, b"hi");
    seeds.push(seed);
    // 7: inbound records: edits then plain, unpadded and inner
    for finish in 0..3u8 {
        let mut seed = vec![7, 0, 1];
        put_field(&mut seed, b"payload\x16");
        seed.push(5);
        seed.extend_from_slice(&[1, 1, 2, 0, 2, 0x01, 0, 0, 50, 3, finish]);
        seeds.push(seed);
    }
    for body in [&b"\x17\x00\x00"[..], b"\x00\x00", b"x\x63\x00", b"\x16"] {
        let mut seed = vec![7, 0, 1];
        put_field(&mut seed, body);
        seed.extend_from_slice(&[0, 3, 1]);
        seeds.push(seed);
    }
    // 8: outbound plain record
    let mut seed = vec![8, 2, 0];
    put_field(&mut seed, b"application data");
    seed.extend_from_slice(&[2, 4, 4]);
    seeds.push(seed);
    // 9: sessions: TLS 1.3 fresh with an early data limit, TLS 1.3 with a
    // PSK, TLS 1.3 expired, TLS 1.2 fresh and rewound
    seeds.push(vec![9, 0, 0, 1, 0x10, 0x00, 0]);
    seeds.push(vec![9, 0, 1, 0, 0]);
    seeds.push(vec![9, 0, 0, 0, 2, 0, 5]);
    seeds.push(vec![9, 1, 0, 0]);
    seeds.push(vec![9, 1, 0, 1, 0, 0, 0, 10]);
    // the fuzzing entry points
    for (op, selector, data) in [
        (0x80u8, 0u8, &flight[..]),
        (0x81, 0, &message[..]),
        (0xc2, 1, &body[..]),
        (0x83, 2, &message[..]),
        (0x84, 1, &[0, 1, 0, 0, 4, 0, 0, 1, 0][..]),
    ] {
        let mut seed = vec![op, selector];
        put_field(&mut seed, data);
        seeds.push(seed);
    }
    seeds
}

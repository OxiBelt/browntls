//! `MessageEncrypter::encrypt_into`, which the unbuffered API uses to build
//! application data records in place in the caller's buffer.
//!
//! For every cipher suite of every enabled built-in provider:
//!
//! * `encrypt_into` writes exactly the record `encrypt(..).encode()` returns
//!   for the same key, IV, sequence number and plaintext (the CBC suites draw
//!   a random IV per record, so for them only the length and the round trip
//!   are compared), for contiguous and chunked plaintext of 0, 1, a few
//!   hundred and 16 384 bytes, and the peer's decrypter opens it;
//! * an output buffer of exactly the record's length suffices, and one byte
//!   less fails with `Error::EncryptError` and leaves the buffer untouched.
//!
//! The provided method, which an encrypter that implements only `encrypt`
//! gets, is checked the same way.
//!
//! Both methods are also held to records that `encrypt` returned before
//! `encrypt_into` existed (`KNOWN_RECORDS`), so that a change to both at
//! once does not pass for agreement.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter, OutboundChunks,
    OutboundOpaqueMessage, OutboundPlainMessage,
};
use browntls::{ContentType, Error, ProtocolVersion, SupportedCipherSuite};

/// Plaintext lengths: empty, one byte, the lengths around which a CBC
/// record gains a block (the plaintext alone, and with a MAC of 20, 32 or 48
/// bytes and the padding length byte), a partial block and the largest
/// fragments (RFC 8446 §5.1).
const LENGTHS: &[usize] = &[0, 1, 11, 12, 15, 16, 17, 31, 32, 300, 16_383, 16_384];

/// Sequence numbers, including ones that carry into the explicit nonce.
const SEQS: &[u64] = &[0, 1, 0x0102_0304_0506_0708, u64::MAX - 1];

/// Filler around the plaintext and in output buffers; the plaintext never
/// contains it.
const FILL: u8 = 0xa5;

/// A record protection under test: an encrypter, the matching decrypter,
/// and whether its records are deterministic.
struct Case {
    name: String,
    enc: Box<dyn MessageEncrypter>,
    dec: Box<dyn MessageDecrypter>,
    deterministic: bool,
}

fn suites() -> Vec<(&'static str, SupportedCipherSuite)> {
    let mut suites = Vec::new();
    #[cfg(feature = "native")]
    suites.extend(
        browntls::crypto::native::ALL_CIPHER_SUITES
            .iter()
            .map(|s| ("native", *s)),
    );
    #[cfg(feature = "rustcrypto")]
    suites.extend(
        browntls::crypto::rustcrypto::ALL_CIPHER_SUITES
            .iter()
            .map(|s| ("rustcrypto", *s)),
    );
    assert!(!suites.is_empty());
    suites
}

/// Key material that differs per byte, so a misplaced byte shows.
fn material(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i as u8).wrapping_mul(29)))
        .collect()
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (provider, suite) in suites() {
        match suite {
            SupportedCipherSuite::Tls13(s) => {
                let alg = s.aead_alg;
                let key = || AeadKey::new(&material(alg.key_len(), 1));
                let iv = || Iv::copy(&material(12, 2));
                cases.push(Case {
                    name: format!("{provider} {:?}", s.common.suite),
                    enc: alg.encrypter(key(), iv()),
                    dec: alg.decrypter(key(), iv()),
                    deterministic: true,
                });
            }
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(s) => {
                use browntls::crypto::cipher::{Tls12MacOrder, Tls12RecordProtection};
                let shape = s.record.key_block_shape();
                let key = || AeadKey::new(&material(shape.enc_key_len, 3));
                match s.record {
                    Tls12RecordProtection::Aead(alg) => {
                        let iv = material(shape.fixed_iv_len, 4);
                        // An explicit nonce seed near the top, so that large
                        // sequence numbers wrap it.
                        let extra = vec![0xff; shape.explicit_nonce_len];
                        cases.push(Case {
                            name: format!("{provider} {:?}", s.common.suite),
                            enc: alg.encrypter(key(), &iv, &extra),
                            dec: alg.decrypter(key(), &iv),
                            deterministic: true,
                        });
                    }
                    Tls12RecordProtection::BlockCipher(alg) => {
                        let mac_key = material(shape.mac_key_len, 5);
                        for order in [Tls12MacOrder::EncryptThenMac, Tls12MacOrder::MacThenEncrypt]
                        {
                            cases.push(Case {
                                name: format!("{provider} {:?} {order:?}", s.common.suite),
                                enc: alg.encrypter(&mac_key, key(), order),
                                dec: alg.decrypter(&mac_key, key(), order),
                                deterministic: false,
                            });
                        }
                    }
                }
            }
        }
    }
    cases
}

/// The plaintext of `len` bytes, never containing `FILL`.
fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 0x5b) as u8).collect()
}

/// Calls `f` with `data` as a single slice and as a window over several
/// chunks (with filler before and after it, and an empty chunk).
fn with_chunks(data: &[u8], mut f: impl FnMut(&str, OutboundChunks<'_>)) {
    f("single", OutboundChunks::Single(data));
    let before = [FILL; 3];
    let after = [FILL; 4];
    let (a, rest) = data.split_at(data.len() / 3);
    let (b, c) = rest.split_at(rest.len() / 2);
    let chunks: [&[u8]; 6] = [&before, a, &[], b, c, &after];
    f(
        "multiple",
        OutboundChunks::Multiple {
            chunks: &chunks,
            start: before.len(),
            end: before.len() + data.len(),
        },
    );
}

fn message(typ: ContentType, payload: OutboundChunks<'_>) -> OutboundPlainMessage<'_> {
    OutboundPlainMessage {
        typ,
        version: ProtocolVersion::TLSv1_2,
        payload,
    }
}

/// Opens the whole `record` (header included) and returns its content type
/// and plaintext.
fn open(dec: &mut dyn MessageDecrypter, record: &[u8], seq: u64) -> (ContentType, Vec<u8>) {
    let mut buf = record.to_vec();
    let typ = ContentType::from(buf[0]);
    let version = ProtocolVersion::from(u16::from_be_bytes([buf[1], buf[2]]));
    assert_eq!(
        usize::from(u16::from_be_bytes([buf[3], buf[4]])),
        buf.len() - 5
    );
    let plain = dec
        .decrypt(InboundOpaqueMessage::new(typ, version, &mut buf[5..]), seq)
        .unwrap();
    (plain.typ, plain.payload.to_vec())
}

/// Checks `enc.encrypt_into` against `enc.encrypt` for every length,
/// sequence number, content type and chunking, and the exact output size.
fn check(name: &str, enc: &mut dyn MessageEncrypter, dec: &mut dyn MessageDecrypter, det: bool) {
    for (i, &len) in LENGTHS.iter().enumerate() {
        let data = plaintext(len);
        let record_len = 5 + enc.encrypted_payload_len(len);
        for (j, &seq) in SEQS.iter().enumerate() {
            let typ = [ContentType::ApplicationData, ContentType::Handshake][(i + j) % 2];
            with_chunks(&data, |how, chunks| {
                let ctx = format!("{name}: {how} len {len} seq {seq}");
                let expected = enc.encrypt(message(typ, chunks), seq).unwrap().encode();
                assert_eq!(expected.len(), record_len, "{ctx}");

                // Exactly the record's length, then more room than needed:
                // only the record is written.
                for spare in [0, 7] {
                    let mut out = vec![FILL; record_len + spare];
                    let n = enc
                        .encrypt_into(message(typ, chunks), seq, &mut out)
                        .unwrap();
                    assert_eq!(n, record_len, "{ctx}");
                    assert!(out[n..].iter().all(|b| *b == FILL), "{ctx}");
                    let record = &out[..n];
                    if det {
                        assert_eq!(record, expected, "{ctx}");
                    } else {
                        assert_eq!(record[..5], expected[..5], "{ctx}");
                    }
                    if typ == ContentType::ApplicationData || len > 0 {
                        assert_eq!(open(dec, record, seq), (typ, data.clone()), "{ctx}");
                    }
                }

                // One byte short: an error, and the buffer is untouched.
                let mut out = vec![FILL; record_len - 1];
                assert_eq!(
                    enc.encrypt_into(message(typ, chunks), seq, &mut out),
                    Err(Error::EncryptError),
                    "{ctx}"
                );
                assert!(out.iter().all(|b| *b == FILL), "{ctx}");
            });
        }
    }
}

#[test]
fn encrypt_into_matches_encrypt_for_every_suite() {
    let cases = cases();
    // Native: five TLS 1.3 suites, six TLS 1.2 AEAD suites and eight CBC
    // suites in two MAC orders; RustCrypto: three and six.
    let tls12 = cfg!(feature = "tls12");
    let expected = usize::from(cfg!(feature = "native")) * if tls12 { 27 } else { 5 }
        + usize::from(cfg!(feature = "rustcrypto")) * if tls12 { 9 } else { 3 };
    assert_eq!(cases.len(), expected);
    for mut case in cases {
        check(
            &case.name,
            &mut *case.enc,
            &mut *case.dec,
            case.deterministic,
        );
    }
}

/// An encrypter that implements only `encrypt`, so it gets the provided
/// `encrypt_into`.
struct EncryptOnly(Box<dyn MessageEncrypter>);

impl MessageEncrypter for EncryptOnly {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        self.0.encrypt(msg, seq)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        self.0.encrypted_payload_len(payload_len)
    }
}

#[test]
fn provided_encrypt_into_copies_the_encrypted_record() {
    for mut case in cases() {
        let mut enc = EncryptOnly(case.enc);
        let name = format!("{} (provided method)", case.name);
        check(&name, &mut enc, &mut *case.dec, case.deterministic);
    }
}

#[test]
fn encrypt_into_rejects_an_empty_buffer() {
    for mut case in cases() {
        let mut out = [0u8; 0];
        assert_eq!(
            case.enc.encrypt_into(
                message(ContentType::ApplicationData, OutboundChunks::Single(b"x")),
                0,
                &mut out,
            ),
            Err(Error::EncryptError),
            "{}",
            case.name
        );
    }
}

/// The record every AEAD record protection made of `known_plaintext()` as an
/// alert of version 0x0301 with sequence number 0x0102030405060708 and the
/// keys of `cases()`, before `encrypt` shared its record building with
/// `encrypt_into`. Each is listed by the part of the suite name that names
/// the record protection.
const KNOWN_RECORDS: &[(&str, &str)] = &[
    (
        "TLS13_AES_128_GCM_SHA256",
        "1703030022e9ee25262183955c093b73a80eee4a9e525a6d972538c8b7054bf8e71619ca05bb95",
    ),
    (
        "TLS13_AES_256_GCM_SHA384",
        "1703030022062bedf234389badd42558a18bddec94e99b96c9df6b7f11bcb406a9ab4dc8ead664",
    ),
    (
        "TLS13_CHACHA20_POLY1305_SHA256",
        "170303002201d74e6cbf84117167f51411f201d98e9bc89d239975784aa7b921300708c67180ae",
    ),
    (
        "TLS13_AES_128_CCM_SHA256",
        "170303002274c3ca4451c71009bc4e4934afff14f051fc8661cff562c66038ad642c4a1e62d1f4",
    ),
    (
        "TLS13_AES_128_CCM_8_SHA256",
        "170303001a74c3ca4451c71009bc4e4934afff14f051fc0a8e3616591b37ea",
    ),
    (
        "_WITH_AES_128_GCM_SHA256",
        "15030100290102030405060707bf4b4ae33575c8a161b17b40c0633b63df79a0a06823641d9a7f97dace83b9dec3",
    ),
    (
        "_WITH_AES_256_GCM_SHA384",
        "15030100290102030405060707272fa622d19e39f681ed813ebbf43be584502f72d866e64292f48a3272aa439cab",
    ),
    (
        "_WITH_CHACHA20_POLY1305_SHA256",
        "1503010021b82f2201d130e9468f36a1704c77ba7c345da34058516586c53937d328b2d51291",
    ),
];

fn known_plaintext() -> Vec<u8> {
    (0..17usize).map(|i| (i * 7 % 251) as u8).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn both_methods_make_the_known_records() {
    const SEQ: u64 = 0x0102_0304_0506_0708;
    let data = known_plaintext();
    let msg = || OutboundPlainMessage {
        typ: ContentType::Alert,
        version: ProtocolVersion::TLSv1_0,
        payload: OutboundChunks::Single(&data),
    };
    let mut checked = 0;
    for mut case in cases() {
        if !case.deterministic {
            continue;
        }
        let known: Vec<&str> = KNOWN_RECORDS
            .iter()
            .filter(|(suite, _)| case.name.ends_with(suite))
            .map(|(_, record)| *record)
            .collect();
        let [known] = known[..] else {
            panic!("{}: {} known records", case.name, known.len());
        };
        let record = case.enc.encrypt(msg(), SEQ).unwrap().encode();
        assert_eq!(hex(&record), known, "{}: encrypt", case.name);
        let mut out = vec![FILL; record.len()];
        assert_eq!(
            case.enc.encrypt_into(msg(), SEQ, &mut out),
            Ok(record.len())
        );
        assert_eq!(hex(&out), known, "{}: encrypt_into", case.name);
        let mut provided = EncryptOnly(case.enc);
        out.fill(FILL);
        assert_eq!(
            provided.encrypt_into(msg(), SEQ, &mut out),
            Ok(record.len())
        );
        assert_eq!(hex(&out), known, "{}: provided encrypt_into", case.name);
        assert_eq!(
            open(&mut *case.dec, &out, SEQ),
            (ContentType::Alert, data.clone()),
            "{}",
            case.name
        );
        checked += 1;
    }
    // Native: five TLS 1.3 suites and six TLS 1.2 AEAD suites; RustCrypto:
    // three and six.
    let tls12 = cfg!(feature = "tls12");
    let expected = usize::from(cfg!(feature = "native")) * if tls12 { 11 } else { 5 }
        + usize::from(cfg!(feature = "rustcrypto")) * if tls12 { 9 } else { 3 };
    assert_eq!(checked, expected);
}

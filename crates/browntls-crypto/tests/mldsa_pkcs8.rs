//! RFC 9881 encodings of ML-DSA keys: PKCS #8 `OneAsymmetricKey` private
//! keys and `SubjectPublicKeyInfo` public keys. Covers the RFC 9881
//! Appendix C examples, a differential against the RustCrypto `ml-dsa`
//! crate, a negative DER matrix and the encoders' buffer handling.
#![allow(clippy::unwrap_used, clippy::panic, clippy::cast_possible_truncation)]

use browntls_crypto::Error;
use browntls_crypto::der::Reader;
use browntls_crypto::mldsa::{
    MlDsa44, MlDsa65, MlDsa87, ParameterSet, PrivateKeyFormat, SigningKey, VerifyingKey,
};

const FORMATS: [PrivateKeyFormat; 3] = [
    PrivateKeyFormat::Seed,
    PrivateKeyFormat::Expanded,
    PrivateKeyFormat::Both,
];

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// A DER TLV with a minimal definite length.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let n = value.len();
    let mut out = vec![tag];
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend([0x81, n as u8]);
    } else {
        assert!(n < 0x1_0000);
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(value);
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn alg(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &tlv(0x06, oid))
}

/// `OneAsymmetricKey` from its parts: version contents, algorithm TLV,
/// `privateKey` contents and any further TLVs.
fn pkcs8(version: u8, alg: &[u8], private_key: &[u8], tail: &[&[u8]]) -> Vec<u8> {
    let mut content = cat(&[&tlv(0x02, &[version]), alg, &tlv(0x04, private_key)]);
    for t in tail {
        content.extend_from_slice(t);
    }
    tlv(0x30, &content)
}

fn seed_choice(seed: &[u8]) -> Vec<u8> {
    tlv(0x80, seed)
}

fn expanded_choice(sk: &[u8]) -> Vec<u8> {
    tlv(0x04, sk)
}

fn both_choice(seed: &[u8], sk: &[u8]) -> Vec<u8> {
    tlv(0x30, &cat(&[&tlv(0x04, seed), &tlv(0x04, sk)]))
}

/// `publicKey [1] IMPLICIT BIT STRING` with zero unused bits.
fn public_key_field(pk: &[u8]) -> Vec<u8> {
    tlv(0x81, &cat(&[&[0], pk]))
}

fn spki(alg: &[u8], bits: &[u8]) -> Vec<u8> {
    tlv(0x30, &cat(&[alg, &tlv(0x03, bits)]))
}

/// PKCS #9 `friendlyName` (1.2.840.113549.1.9.20).
const FRIENDLY_NAME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14];

/// A well-formed `Attribute`: `friendlyName` with the BMPString "A".
fn attribute() -> Vec<u8> {
    let values = tlv(0x31, &[0x1e, 0x02, 0x00, 0x41]);
    tlv(0x30, &cat(&[&tlv(0x06, FRIENDLY_NAME), &values]))
}

fn sk_err<P: ParameterSet>(der: &[u8]) -> Error {
    SigningKey::<P>::from_pkcs8_der(der).unwrap_err()
}

fn vk_err<P: ParameterSet>(der: &[u8]) -> Error {
    VerifyingKey::<P>::from_spki_der(der).unwrap_err()
}

fn encode<P: ParameterSet>(key: &SigningKey<P>, format: PrivateKeyFormat) -> Vec<u8> {
    let mut buf = vec![0u8; SigningKey::<P>::PKCS8_MAX_LEN];
    let n = key.to_pkcs8_der(format, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn encode_spki<P: ParameterSet>(vk: &VerifyingKey<P>) -> Vec<u8> {
    let mut buf = vec![0u8; VerifyingKey::<P>::SPKI_LEN];
    assert_eq!(vk.to_spki_der(&mut buf).unwrap(), buf.len());
    buf
}

fn rfc_file(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/rfc9881/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Byte offsets of `rho`, `K`, `tr`, `s1`, `s2` and `t0` in the expanded
/// private key (FIPS 204 Algorithm 24).
fn expanded_offsets<P: ParameterSet>() -> [(&'static str, usize); 6] {
    let eta_bits = if P::ETA == 2 { 3 } else { 4 };
    let s1 = 128;
    let s2 = s1 + 32 * eta_bits * P::L;
    let t0 = s2 + 32 * eta_bits * P::K;
    [
        ("rho", 0),
        ("K", 32),
        ("tr", 64),
        ("s1", s1),
        ("s2", s2),
        ("t0", t0),
    ]
}

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

#[test]
fn constants() {
    let base = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    assert_eq!(MlDsa44::OID, cat(&[&base, &[0x11]]));
    assert_eq!(MlDsa65::OID, cat(&[&base, &[0x12]]));
    assert_eq!(MlDsa87::OID, cat(&[&base, &[0x13]]));
    assert_eq!(VerifyingKey::<MlDsa44>::SPKI_LEN, 1334);
    assert_eq!(VerifyingKey::<MlDsa65>::SPKI_LEN, 1974);
    assert_eq!(VerifyingKey::<MlDsa87>::SPKI_LEN, 2614);
    assert_eq!(SigningKey::<MlDsa44>::PKCS8_MAX_LEN, 2626);
    assert_eq!(SigningKey::<MlDsa65>::PKCS8_MAX_LEN, 4098);
    assert_eq!(SigningKey::<MlDsa87>::PKCS8_MAX_LEN, 4962);
}

// ---------------------------------------------------------------------------
// RFC 9881 Appendix C.
// ---------------------------------------------------------------------------

/// C.1 (all three forms), C.2 and, when present, C.3 for one parameter set.
fn rfc_examples<P: ParameterSet>(level: &str) {
    let seed_der = rfc_file(&format!("ml-dsa-{level}-seed.der"));
    let expanded_der = rfc_file(&format!("ml-dsa-{level}-expanded.der"));
    let both_der = rfc_file(&format!("ml-dsa-{level}-both.der"));
    let spki_der = rfc_file(&format!("ml-dsa-{level}-public-key.der"));

    let from_seed = SigningKey::<P>::from_pkcs8_der(&seed_der).unwrap();
    let from_expanded = SigningKey::<P>::from_pkcs8_der(&expanded_der).unwrap();
    let from_both = SigningKey::<P>::from_pkcs8_der(&both_der).unwrap();

    // C.1: the seed is 000102...1f in every example.
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(from_seed.seed(), Some(&seed));
    assert_eq!(from_both.seed(), Some(&seed));
    assert_eq!(from_expanded.seed(), None);
    let expanded = from_seed.to_expanded_bytes();
    assert_eq!(
        from_expanded.to_expanded_bytes().as_ref(),
        expanded.as_ref()
    );
    assert_eq!(from_both.to_expanded_bytes().as_ref(), expanded.as_ref());
    assert_eq!(from_seed.verifying_key(), from_expanded.verifying_key());
    assert_eq!(from_seed.verifying_key(), from_both.verifying_key());

    // The seed form: 54 bytes with a fixed prefix.
    let mut prefix = vec![0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09];
    prefix.extend_from_slice(P::OID);
    prefix.extend_from_slice(&[0x04, 0x22, 0x80, 0x20]);
    assert_eq!(seed_der.len(), 54);
    assert_eq!(&seed_der[..22], prefix.as_slice());

    // The RFC examples are all version 0 without attributes or public key,
    // the shape the encoder writes, so re-encoding reproduces them.
    for key in [&from_seed, &from_both] {
        assert_eq!(encode(key, PrivateKeyFormat::Seed), seed_der);
        assert_eq!(encode(key, PrivateKeyFormat::Expanded), expanded_der);
        assert_eq!(encode(key, PrivateKeyFormat::Both), both_der);
    }
    assert_eq!(
        encode(&from_expanded, PrivateKeyFormat::Expanded),
        expanded_der
    );
    let mut buf = vec![0u8; SigningKey::<P>::PKCS8_MAX_LEN];
    for format in [PrivateKeyFormat::Seed, PrivateKeyFormat::Both] {
        assert_eq!(
            from_expanded.to_pkcs8_der(format, &mut buf),
            Err(Error::Unsupported)
        );
    }
    assert_eq!(both_der.len(), SigningKey::<P>::PKCS8_MAX_LEN);

    // C.2: the public key.
    let vk = from_seed.verifying_key();
    assert_eq!(encode_spki(vk), spki_der);
    assert_eq!(&VerifyingKey::<P>::from_spki_der(&spki_der).unwrap(), vk);

    // C.3: the self-signed certificate (kept by browntls-pki) carries the
    // same SubjectPublicKeyInfo and verifies under it.
    let cert_path = format!(
        "{}/../browntls-pki/tests/data/rfc9881/ml-dsa-{level}-certificate.der",
        env!("CARGO_MANIFEST_DIR")
    );
    let cert = std::fs::read(&cert_path).unwrap_or_else(|e| panic!("{cert_path}: {e}"));
    assert_eq!(
        cert.windows(spki_der.len())
            .filter(|w| *w == spki_der.as_slice())
            .count(),
        1
    );
    let mut outer = Reader::new(&cert);
    let mut body = outer.read_sequence().unwrap();
    outer.finish().unwrap();
    let before = body.remaining();
    body.read_any().unwrap();
    let tbs = &before[..before.len() - body.remaining().len()];
    let mut sig_alg = body.read_sequence().unwrap();
    assert_eq!(sig_alg.read_oid().unwrap(), P::OID);
    sig_alg.finish().unwrap();
    let sig = body.read_bit_string_octets().unwrap();
    body.finish().unwrap();
    vk.verify(tbs, sig).unwrap();
    let mut bad = tbs.to_vec();
    bad[10] ^= 1;
    assert_eq!(vk.verify(&bad, sig), Err(Error::InvalidSignature));
}

#[test]
fn rfc9881_examples_44() {
    rfc_examples::<MlDsa44>("44");
}

#[test]
fn rfc9881_examples_65() {
    rfc_examples::<MlDsa65>("65");
}

#[test]
fn rfc9881_examples_87() {
    rfc_examples::<MlDsa87>("87");
}

/// C.4: three ML-DSA-44 keys whose parts are inconsistent.
#[test]
fn rfc9881_inconsistent_examples() {
    let good = rfc_file("ml-dsa-44-both.der");
    let good_sk = &good[good.len() - MlDsa44::SIGNING_KEY_LEN..];
    let offsets = expanded_offsets::<MlDsa44>();
    let region = |i: usize| offsets.iter().rev().find(|(_, o)| *o <= i).unwrap().0;

    // 1: `both`; the seed is the C.1 seed but the expanded key is not the
    // one it derives (it differs throughout), so the RFC 9881 §8.2 check
    // fails. The expanded key on its own is a valid key of another seed.
    let der = rfc_file("ml-dsa-44-inconsistent-1.der");
    assert_eq!(der.len(), good.len());
    assert_eq!(der[..62], good[..62]);
    let sk = &der[der.len() - MlDsa44::SIGNING_KEY_LEN..];
    assert!(sk.iter().zip(good_sk).filter(|(a, b)| a != b).count() > 2000);
    assert_eq!(sk_err::<MlDsa44>(&der), Error::InvalidKey);
    let alone = pkcs8(0, &alg(MlDsa44::OID), &expanded_choice(sk), &[]);
    let other = SigningKey::<MlDsa44>::from_pkcs8_der(&alone).unwrap();
    assert_eq!(other.seed(), None);

    // 2 and 3: `expandedKey` alone, each one byte away from the C.1 key:
    // in `tr` (no longer H(pk)) and in `t0` (no longer the low bits of the
    // `t` that `s1` and `s2` imply). Expanded-key validation rejects both.
    for (n, part) in [(2, "tr"), (3, "t0")] {
        let der = rfc_file(&format!("ml-dsa-44-inconsistent-{n}.der"));
        let sk = &der[der.len() - MlDsa44::SIGNING_KEY_LEN..];
        let diffs: Vec<usize> = (0..sk.len()).filter(|&i| sk[i] != good_sk[i]).collect();
        assert_eq!(diffs.len(), 1, "example {n}");
        assert_eq!(region(diffs[0]), part, "example {n}");
        assert_eq!(sk_err::<MlDsa44>(&der), Error::InvalidKey, "example {n}");
        // Wrapped in `both` with the right seed, the §8.2 check fails too.
        let both = pkcs8(0, &alg(MlDsa44::OID), &both_choice(&good[30..62], sk), &[]);
        assert_eq!(sk_err::<MlDsa44>(&both), Error::InvalidKey, "example {n}");
    }
}

// ---------------------------------------------------------------------------
// Round trips and the encoders.
// ---------------------------------------------------------------------------

fn round_trips<P: ParameterSet>() {
    for i in 0..3u8 {
        let key = SigningKey::<P>::from_seed(&[i.wrapping_mul(37); 32]);
        let expanded = key.to_expanded_bytes();
        for format in FORMATS {
            let der = encode(&key, format);
            let back = SigningKey::<P>::from_pkcs8_der(&der).unwrap();
            assert_eq!(back.to_expanded_bytes().as_ref(), expanded.as_ref());
            assert_eq!(back.verifying_key(), key.verifying_key());
            let has_seed = format != PrivateKeyFormat::Expanded;
            assert_eq!(back.seed(), has_seed.then(|| key.seed().unwrap()));
            assert_eq!(encode(&back, PrivateKeyFormat::Expanded), {
                encode(&key, PrivateKeyFormat::Expanded)
            });
        }
        let spki = encode_spki(key.verifying_key());
        let vk = VerifyingKey::<P>::from_spki_der(&spki).unwrap();
        assert_eq!(&vk, key.verifying_key());
    }
}

#[test]
fn round_trips_all() {
    round_trips::<MlDsa44>();
    round_trips::<MlDsa65>();
    round_trips::<MlDsa87>();
}

fn encoder_buffers<P: ParameterSet>() {
    let key = SigningKey::<P>::from_seed(&[9; 32]);
    let expanded_only =
        SigningKey::<P>::from_expanded_bytes(key.to_expanded_bytes().as_ref()).unwrap();
    for format in FORMATS {
        let der = encode(&key, format);
        let n = der.len();
        let mut small = vec![0xa5u8; n - 1];
        assert_eq!(
            key.to_pkcs8_der(format, &mut small),
            Err(Error::InvalidLength)
        );
        assert!(small.iter().all(|&b| b == 0xa5), "unchanged on error");
        let mut exact = vec![0u8; n];
        assert_eq!(key.to_pkcs8_der(format, &mut exact), Ok(n));
        assert_eq!(exact, der);
        let mut large = vec![0xa5u8; n + 10];
        assert_eq!(key.to_pkcs8_der(format, &mut large), Ok(n));
        assert_eq!(&large[..n], der.as_slice());
        assert!(large[n..].iter().all(|&b| b == 0xa5));
        assert!(n <= SigningKey::<P>::PKCS8_MAX_LEN);
        let expect = if format == PrivateKeyFormat::Expanded {
            Ok(n)
        } else {
            Err(Error::Unsupported)
        };
        assert_eq!(expanded_only.to_pkcs8_der(format, &mut large), expect);
        // A key with no seed is unsupported whatever the buffer.
        if format != PrivateKeyFormat::Expanded {
            assert_eq!(
                expanded_only.to_pkcs8_der(format, &mut []),
                Err(Error::Unsupported)
            );
        }
    }
    assert_eq!(encode(&key, PrivateKeyFormat::Seed).len(), 54);

    let vk = key.verifying_key();
    let n = VerifyingKey::<P>::SPKI_LEN;
    let mut small = vec![0xa5u8; n - 1];
    assert_eq!(vk.to_spki_der(&mut small), Err(Error::InvalidLength));
    assert!(small.iter().all(|&b| b == 0xa5));
    let mut large = vec![0xa5u8; n + 3];
    assert_eq!(vk.to_spki_der(&mut large), Ok(n));
    assert_eq!(&large[..n], encode_spki(vk).as_slice());
    assert_eq!(&large[n..], &[0xa5; 3]);
    let alg_tlv = alg(P::OID);
    let expect = spki(&alg_tlv, &cat(&[&[0], vk.as_bytes()]));
    assert_eq!(encode_spki(vk), expect);
}

#[test]
fn encoder_buffers_all() {
    encoder_buffers::<MlDsa44>();
    encoder_buffers::<MlDsa65>();
    encoder_buffers::<MlDsa87>();
}

// ---------------------------------------------------------------------------
// Differential against RustCrypto `ml-dsa` (seed form and SPKI; it supports
// neither `expandedKey` nor `both`).
// ---------------------------------------------------------------------------

macro_rules! differential {
    ($name:ident, $ours:ty, $theirs:ty) => {
        #[test]
        fn $name() {
            use ml_dsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
            use ml_dsa::pkcs8::{DecodePublicKey, EncodePublicKey};
            for i in 0..3u8 {
                let seed = [i ^ 0x5c; 32];
                let ours = SigningKey::<$ours>::from_seed(&seed);
                let theirs = ml_dsa::SigningKey::<$theirs>::from_seed(&seed.into());

                let our_der = encode(&ours, PrivateKeyFormat::Seed);
                let their_der = theirs.to_pkcs8_der().unwrap();
                assert_eq!(their_der.as_bytes(), our_der.as_slice());
                let theirs_back = ml_dsa::SigningKey::<$theirs>::from_pkcs8_der(&our_der).unwrap();
                #[allow(deprecated)]
                let their_expanded = theirs_back.expanded_key().to_expanded();
                assert_eq!(their_expanded.as_slice(), ours.to_expanded_bytes().as_ref());
                let ours_back = SigningKey::<$ours>::from_pkcs8_der(their_der.as_bytes()).unwrap();
                assert_eq!(ours_back.seed(), Some(&seed));
                // Our other forms are outside what it reads.
                for format in [PrivateKeyFormat::Expanded, PrivateKeyFormat::Both] {
                    let der = encode(&ours, format);
                    assert!(ml_dsa::SigningKey::<$theirs>::from_pkcs8_der(&der).is_err());
                }

                let their_vk = theirs.expanded_key().verifying_key();
                let their_spki = their_vk.to_public_key_der().unwrap();
                let our_spki = encode_spki(ours.verifying_key());
                assert_eq!(their_spki.as_bytes(), our_spki.as_slice());
                let vk = ml_dsa::VerifyingKey::<$theirs>::from_public_key_der(&our_spki).unwrap();
                assert_eq!(vk.encode().as_slice(), ours.verifying_key().as_bytes());
                let vk = VerifyingKey::<$ours>::from_spki_der(their_spki.as_bytes()).unwrap();
                assert_eq!(&vk, ours.verifying_key());
            }
        }
    };
}

differential!(differential_44, MlDsa44, ml_dsa::MlDsa44);
differential!(differential_65, MlDsa65, ml_dsa::MlDsa65);
differential!(differential_87, MlDsa87, ml_dsa::MlDsa87);

// ---------------------------------------------------------------------------
// Negative matrix: PKCS #8.
// ---------------------------------------------------------------------------

/// OIDs that must never be accepted for `P`: the other ML-DSA sets,
/// HashML-DSA, ML-KEM, round-3 Dilithium and Ed25519.
fn foreign_oids<P: ParameterSet>() -> Vec<Vec<u8>> {
    let nist = |a: u8, b: u8| vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, a, b];
    let dilithium = |a: u8, b: u8| vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b, 0x07, a, b];
    let mut oids = vec![
        nist(3, 0x20),
        nist(3, 0x21),
        nist(3, 0x22),
        nist(4, 1),
        nist(4, 2),
        nist(4, 3),
        dilithium(4, 4),
        dilithium(6, 5),
        dilithium(8, 7),
        vec![0x2b, 0x65, 0x70],
        // A prefix and an extension of the right OID.
        P::OID[..8].to_vec(),
        cat(&[P::OID, &[0x01]]),
    ];
    for own in [MlDsa44::OID, MlDsa65::OID, MlDsa87::OID] {
        if own != P::OID {
            oids.push(own.to_vec());
        }
    }
    oids
}

fn pkcs8_negative<P: ParameterSet, Other: ParameterSet>() {
    use Error::{InvalidEncoding as Enc, InvalidKey as Key};
    let key = SigningKey::<P>::from_seed(&[3; 32]);
    let seed = *key.seed().unwrap();
    let sk = key.to_expanded_bytes();
    let sk = sk.as_ref();
    let pk = key.verifying_key().as_bytes();
    let a = alg(P::OID);
    let valid = [
        seed_choice(&seed),
        expanded_choice(sk),
        both_choice(&seed, sk),
    ];

    // Sanity: the builders produce what the encoder writes and is accepted.
    for (choice, format) in valid.iter().zip(FORMATS) {
        assert_eq!(pkcs8(0, &a, choice, &[]), encode(&key, format));
        // Version 1 (RFC 5958 v2) with attributes and the right public key,
        // version 1 without public key, and attributes (IMPLICIT [0]: the
        // contents are the Attribute SEQUENCEs): none, one and two.
        let one = tlv(0xa0, &attribute());
        let two = tlv(0xa0, &cat(&[&attribute(), &attribute()]));
        let der = pkcs8(1, &a, choice, &[&one, &public_key_field(pk)]);
        SigningKey::<P>::from_pkcs8_der(&der).unwrap();
        SigningKey::<P>::from_pkcs8_der(&pkcs8(1, &a, choice, &[])).unwrap();
        for attrs in [vec![0xa0, 0x00], one, two] {
            let der = pkcs8(0, &a, choice, &[&attrs]);
            SigningKey::<P>::from_pkcs8_der(&der).unwrap();
        }
    }

    let mut cases: Vec<(String, Vec<u8>, Error)> = Vec::new();
    let mut case = |name: &str, der: Vec<u8>, err: Error| cases.push((name.into(), der, err));

    for (i, choice) in valid.iter().enumerate() {
        // Algorithm identifier.
        let null = tlv(0x30, &cat(&[&tlv(0x06, P::OID), &[0x05, 0x00]]));
        case(
            &format!("NULL parameters {i}"),
            pkcs8(0, &null, choice, &[]),
            Key,
        );
        let empty_seq = tlv(0x30, &cat(&[&tlv(0x06, P::OID), &[0x30, 0x00]]));
        case(
            &format!("SEQUENCE parameters {i}"),
            pkcs8(0, &empty_seq, choice, &[]),
            Key,
        );
        for oid in foreign_oids::<P>() {
            case(
                &format!("OID {oid:02x?} {i}"),
                pkcs8(0, &alg(&oid), choice, &[]),
                Key,
            );
        }
        case(
            &format!("no OID {i}"),
            pkcs8(0, &[0x30, 0x00], choice, &[]),
            Enc,
        );
        case(
            &format!("bad OID {i}"),
            pkcs8(0, &alg(&[0x80]), choice, &[]),
            Enc,
        );

        // Version.
        for (v, err) in [(2u8, Enc), (0xff, Enc)] {
            case(&format!("version {v} {i}"), pkcs8(v, &a, choice, &[]), err);
        }
        let body = |version: &[u8]| {
            let content = cat(&[version, &a, &tlv(0x04, choice)]);
            tlv(0x30, &content)
        };
        case(
            &format!("version non-minimal {i}"),
            body(&[2, 2, 0, 0]),
            Enc,
        );
        case(&format!("version huge {i}"), body(&tlv(2, &[1; 9])), Enc);
        case(&format!("version missing {i}"), body(&[]), Enc);

        // publicKey.
        let pkf = public_key_field(pk);
        case(
            &format!("publicKey with v0 {i}"),
            pkcs8(0, &a, choice, &[&pkf]),
            Enc,
        );
        let mut wrong = pk.to_vec();
        wrong[pk.len() / 2] ^= 0x10;
        let wrong = public_key_field(&wrong);
        case(
            &format!("publicKey mismatch {i}"),
            pkcs8(1, &a, choice, &[&wrong]),
            Key,
        );
        let short = public_key_field(&pk[1..]);
        case(
            &format!("publicKey short {i}"),
            pkcs8(1, &a, choice, &[&short]),
            Key,
        );
        let unused = tlv(0x81, &cat(&[&[1], pk]));
        case(
            &format!("publicKey unused bits {i}"),
            pkcs8(1, &a, choice, &[&unused]),
            Enc,
        );
        let constructed = tlv(0xa1, &tlv(0x03, &cat(&[&[0], pk])));
        case(
            &format!("publicKey [1] constructed {i}"),
            { pkcs8(1, &a, choice, &[&constructed]) },
            Enc,
        );
        let attrs = tlv(0xa0, &[]);
        case(
            &format!("publicKey before attributes {i}"),
            { pkcs8(1, &a, choice, &[&pkf, &attrs]) },
            Enc,
        );

        // Trailing data at each level.
        let mut outer = pkcs8(0, &a, choice, &[]);
        outer.push(0);
        case(&format!("trailing outer {i}"), outer, Enc);
        let extra = [0x02, 0x01, 0x00];
        case(
            &format!("trailing element {i}"),
            pkcs8(0, &a, choice, &[&extra]),
            Enc,
        );
        let inner = cat(&[choice, &[0x04, 0x00]]);
        case(
            &format!("trailing in privateKey {i}"),
            pkcs8(0, &a, &inner, &[]),
            Enc,
        );
    }

    // Attributes.
    let attr_case = |attrs: &[u8]| pkcs8(0, &a, &valid[0], &[attrs]);
    let oid_tlv = tlv(0x06, FRIENDLY_NAME);
    let value_set = tlv(0x31, &[0x1e, 0x02, 0x00, 0x41]);
    let attr_with = |parts: &[&[u8]]| tlv(0xa0, &tlv(0x30, &cat(parts)));
    case(
        "attributes garbage",
        attr_case(&[0xa0, 3, 0xff, 0xff, 0xff]),
        Enc,
    );
    let trailing_inside = attr_with(&[&oid_tlv, &value_set, &[0x05, 0x00]]);
    case(
        "attribute trailing element",
        attr_case(&trailing_inside),
        Enc,
    );
    let after = tlv(0xa0, &cat(&[&attribute(), &[0x00]]));
    case("attributes trailing byte", attr_case(&after), Enc);
    let empty_set = attr_with(&[&oid_tlv, &[0x31, 0x00]]);
    case("attribute without values", attr_case(&empty_set), Enc);
    case(
        "attribute without SET",
        attr_case(&attr_with(&[&oid_tlv])),
        Enc,
    );
    let no_oid = attr_with(&[&value_set]);
    case("attribute without OID", attr_case(&no_oid), Enc);
    let int_type = attr_with(&[&[0x02, 0x01, 0x01], &value_set]);
    case("attribute type not an OID", attr_case(&int_type), Enc);
    let seq_values = tlv(0x30, &[0x1e, 0x02, 0x00, 0x41]);
    let not_set = attr_with(&[&oid_tlv, &seq_values]);
    case("attribute values not a SET", attr_case(&not_set), Enc);
    let bad_value = attr_with(&[&oid_tlv, &tlv(0x31, &[0x04, 0x05, 0x00])]);
    case("attribute truncated value", attr_case(&bad_value), Enc);
    let dup = pkcs8(0, &a, &valid[0], &[&[0xa0, 0x00], &[0xa0, 0x00]]);
    case("attributes duplicated", dup, Enc);
    case("attributes primitive", attr_case(&[0x80, 0x00]), Enc);

    // CHOICE selection and sizes.
    for n in [0, 31, 33, 64] {
        case(
            &format!("seed {n}"),
            pkcs8(0, &a, &seed_choice(&vec![1; n]), &[]),
            Key,
        );
    }
    case(
        "seed under 0x04",
        pkcs8(0, &a, &expanded_choice(&seed), &[]),
        Key,
    );
    let constructed = tlv(0xa0, &tlv(0x04, &seed));
    case("seed [0] constructed", pkcs8(0, &a, &constructed, &[]), Enc);
    case("seed [1]", pkcs8(0, &a, &tlv(0x81, &seed), &[]), Enc);
    case(
        "seed as BIT STRING",
        pkcs8(0, &a, &tlv(0x03, &seed), &[]),
        Enc,
    );
    case("empty privateKey", pkcs8(0, &a, &[], &[]), Enc);
    let long = cat(&[sk, &[0]]);
    case(
        "expanded short",
        pkcs8(0, &a, &expanded_choice(&sk[1..]), &[]),
        Key,
    );
    case(
        "expanded long",
        pkcs8(0, &a, &expanded_choice(&long), &[]),
        Key,
    );
    let other_sk = SigningKey::<Other>::from_seed(&[3; 32]).to_expanded_bytes();
    let other_choice = expanded_choice(other_sk.as_ref());
    case(
        "other set's expanded",
        pkcs8(0, &a, &other_choice, &[]),
        Key,
    );
    let other_both = both_choice(&seed, other_sk.as_ref());
    case("other set's both", pkcs8(0, &a, &other_both, &[]), Key);
    let under_other = alg(Other::OID);
    case(
        "this set under other OID",
        pkcs8(0, &under_other, &valid[1], &[]),
        Key,
    );

    // `both`.
    let both = |content: &[&[u8]]| pkcs8(0, &a, &tlv(0x30, &cat(content)), &[]);
    let seed_os = tlv(0x04, &seed);
    let sk_os = tlv(0x04, sk);
    case("both swapped", both(&[&sk_os, &seed_os]), Key);
    case("both [0] seed", both(&[&seed_choice(&seed), &sk_os]), Enc);
    case(
        "both third element",
        both(&[&seed_os, &sk_os, &seed_os]),
        Enc,
    );
    case("both seed only", both(&[&seed_os]), Enc);
    case("both empty", both(&[]), Enc);
    case(
        "both short seed",
        both(&[&tlv(0x04, &seed[1..]), &sk_os]),
        Key,
    );
    case(
        "both short expanded",
        both(&[&seed_os, &tlv(0x04, &sk[1..])]),
        Key,
    );
    case(
        "both long expanded",
        both(&[&seed_os, &tlv(0x04, &long)]),
        Key,
    );
    case(
        "both constructed [0]",
        pkcs8(0, &a, &tlv(0xa0, &cat(&[&seed_os, &sk_os])), &[]),
        Enc,
    );
    let other_seed = cat(&[&seed[..31], &[seed[31] ^ 1]]);
    case(
        "both other seed",
        both(&[&tlv(0x04, &other_seed), &sk_os]),
        Key,
    );
    let mut offsets: Vec<(&str, usize)> = expanded_offsets::<P>().to_vec();
    offsets.push(("last byte", sk.len() - 1));
    for (part, off) in offsets {
        for bit in [0, 7] {
            let mut flipped = sk.to_vec();
            flipped[off] ^= 1 << bit;
            let name = format!("both {part} bit {bit}");
            case(&name, both(&[&seed_os, &tlv(0x04, &flipped)]), Key);
            let alone = pkcs8(0, &a, &expanded_choice(&flipped), &[]);
            if part == "K" {
                // `K` is not bound to the rest: only `both` detects this.
                SigningKey::<P>::from_pkcs8_der(&alone).unwrap();
            } else {
                case(&format!("expanded {part} bit {bit}"), alone, Key);
            }
        }
    }

    // Lengths.
    let good = pkcs8(0, &a, &valid[0], &[]);
    case("empty input", Vec::new(), Enc);
    case(
        "non-minimal outer length",
        cat(&[&[0x30, 0x81, 0x34], &good[2..]]),
        Enc,
    );
    case(
        "indefinite length",
        cat(&[&[0x30, 0x80], &good[2..], &[0, 0]]),
        Enc,
    );
    let mut non_minimal = good[..18].to_vec();
    non_minimal[1] += 1;
    non_minimal.extend_from_slice(&[0x04, 0x81, 0x22]);
    non_minimal.extend_from_slice(&good[20..]);
    case("non-minimal privateKey length", non_minimal, Enc);
    case("outer is SET", cat(&[&[0x31], &good[1..]]), Enc);
    case("outer is OCTET STRING", cat(&[&[0x04], &good[1..]]), Enc);

    for (name, der, err) in &cases {
        assert_eq!(&sk_err::<P>(der), err, "{} {name}", P::NAME);
    }

    // Every proper prefix of a valid encoding is an error.
    let with_pk = pkcs8(1, &a, &valid[2], &[&public_key_field(pk)]);
    for der in valid.iter().map(|c| pkcs8(0, &a, c, &[])).chain([with_pk]) {
        for n in 0..der.len() {
            assert!(SigningKey::<P>::from_pkcs8_der(&der[..n]).is_err());
        }
    }

    // Every bit of the seed form's header: no panic, and anything accepted
    // is the same key.
    for i in 0..22 {
        for bit in 0..8 {
            let mut der = good.clone();
            der[i] ^= 1 << bit;
            if let Ok(k) = SigningKey::<P>::from_pkcs8_der(&der) {
                // Only the version (0 to 1) may change.
                assert_eq!((i, bit), (4, 0), "{}", P::NAME);
                assert_eq!(k.seed(), Some(&seed));
            }
        }
    }
}

#[test]
fn pkcs8_negative_44() {
    pkcs8_negative::<MlDsa44, MlDsa65>();
}

#[test]
fn pkcs8_negative_65() {
    pkcs8_negative::<MlDsa65, MlDsa87>();
}

#[test]
fn pkcs8_negative_87() {
    pkcs8_negative::<MlDsa87, MlDsa44>();
}

// ---------------------------------------------------------------------------
// Negative matrix: SubjectPublicKeyInfo.
// ---------------------------------------------------------------------------

fn spki_negative<P: ParameterSet, Other: ParameterSet>() {
    use Error::{InvalidEncoding as Enc, InvalidKey as Key};
    let key = SigningKey::<P>::from_seed(&[4; 32]);
    let pk = key.verifying_key().as_bytes();
    let bits = cat(&[&[0], pk]);
    let a = alg(P::OID);
    let good = spki(&a, &bits);
    assert_eq!(good, encode_spki(key.verifying_key()));

    let mut cases: Vec<(String, Vec<u8>, Error)> = Vec::new();
    let null = tlv(0x30, &cat(&[&tlv(0x06, P::OID), &[0x05, 0x00]]));
    cases.push(("NULL parameters".into(), spki(&null, &bits), Key));
    for oid in foreign_oids::<P>() {
        cases.push((format!("OID {oid:02x?}"), spki(&alg(&oid), &bits), Key));
    }
    let other_pk = SigningKey::<Other>::from_seed(&[4; 32]);
    let other_bits = cat(&[&[0], other_pk.verifying_key().as_bytes()]);
    cases.push(("other set's key".into(), spki(&a, &other_bits), Key));
    cases.push(("under other OID".into(), spki(&alg(Other::OID), &bits), Key));
    cases.push(("key short".into(), spki(&a, &bits[..bits.len() - 1]), Key));
    cases.push(("key long".into(), spki(&a, &cat(&[&bits, &[0]])), Key));
    cases.push(("key empty".into(), spki(&a, &[0]), Key));
    cases.push(("no unused-bits octet".into(), spki(&a, &[]), Enc));
    for u in [1, 7, 8] {
        let b = cat(&[&[u], pk]);
        cases.push((format!("unused bits {u}"), spki(&a, &b), Enc));
    }
    let as_octets = tlv(0x30, &cat(&[&a, &tlv(0x04, pk)]));
    cases.push(("OCTET STRING key".into(), as_octets, Enc));
    let mut trailing = good.clone();
    trailing.push(0);
    cases.push(("trailing outer".into(), trailing, Enc));
    let inner_extra = tlv(0x30, &cat(&[&a, &tlv(0x03, &bits), &[0x05, 0x00]]));
    cases.push(("trailing element".into(), inner_extra, Enc));
    cases.push(("missing key".into(), tlv(0x30, &a), Enc));
    cases.push((
        "missing algorithm".into(),
        tlv(0x30, &tlv(0x03, &bits)),
        Enc,
    ));
    cases.push(("empty input".into(), Vec::new(), Enc));
    let mut non_minimal = vec![0x30, 0x83, 0x00];
    non_minimal.extend_from_slice(&good[2..]);
    cases.push(("non-minimal length".into(), non_minimal, Enc));
    let indefinite = cat(&[&[0x30, 0x80], &good[4..], &[0, 0]]);
    cases.push(("indefinite length".into(), indefinite, Enc));

    for (name, der, err) in &cases {
        assert_eq!(&vk_err::<P>(der), err, "{} {name}", P::NAME);
    }
    for n in 0..good.len() {
        assert!(VerifyingKey::<P>::from_spki_der(&good[..n]).is_err());
    }
}

#[test]
fn spki_negative_44() {
    spki_negative::<MlDsa44, MlDsa87>();
}

#[test]
fn spki_negative_65() {
    spki_negative::<MlDsa65, MlDsa44>();
}

#[test]
fn spki_negative_87() {
    spki_negative::<MlDsa87, MlDsa65>();
}

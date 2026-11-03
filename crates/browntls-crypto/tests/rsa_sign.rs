//! RSA key generation, signing round trips, DER round trips, negative tests
//! and an ignored throughput test. All private keys are generated at run
//! time; nothing secret is committed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Acceleration, Algorithm, Policy};
use browntls_crypto::der::{self, Reader, Writer, tag};
use browntls_crypto::hash::HashAlgorithm;
use browntls_crypto::rand::{FixedRng, OsRng, SecureRandom};
use browntls_crypto::rsa::{
    MAX_PKCS1_PRIVATE_KEY_DER_LEN, MAX_PKCS8_PRIVATE_KEY_DER_LEN, RsaPrivateKey, RsaPublicKey,
    verify_pkcs1v15, verify_pss,
};

const HASHES: [HashAlgorithm; 7] = [
    HashAlgorithm::Sha224,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha3_256,
    HashAlgorithm::Sha3_384,
    HashAlgorithm::Sha3_512,
];

fn roundtrip(key: &RsaPrivateKey, hashes: &[HashAlgorithm]) {
    let public = key.public_key();
    let k = key.modulus_len_bytes();
    assert_eq!(public.modulus_len_bytes(), k);
    assert_eq!(public.e(), 65537);
    let msg = b"The quick brown fox jumps over the lazy dog";
    for &hash in hashes {
        // PKCS #1 v1.5: deterministic, verifies, and only with the same hash.
        let mut sig = vec![0u8; k + 7];
        let n = key.sign_pkcs1v15(hash, msg, &mut sig).unwrap();
        assert_eq!(n, k);
        let mut sig2 = vec![0u8; k];
        key.sign_pkcs1v15_with_rng(hash, msg, &OsRng, &mut sig2)
            .unwrap();
        assert_eq!(&sig[..k], &sig2[..], "PKCS#1 v1.5 must be deterministic");
        verify_pkcs1v15(public, hash, msg, &sig[..k]).unwrap();
        for &other in hashes {
            if other != hash {
                assert_eq!(
                    verify_pkcs1v15(public, other, msg, &sig[..k]),
                    Err(Error::InvalidSignature)
                );
            }
        }
        assert_eq!(
            verify_pss(public, hash, msg, &sig[..k]),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            verify_pkcs1v15(public, hash, b"other message", &sig[..k]),
            Err(Error::InvalidSignature)
        );
        negative_signature_shapes(public, hash, msg, &sig[..k], false);

        // PSS: randomised, verifies, and only with the same hash.
        let mut pss = vec![0u8; k];
        assert_eq!(key.sign_pss(hash, msg, &OsRng, &mut pss).unwrap(), k);
        let mut pss2 = vec![0u8; k];
        key.sign_pss(hash, msg, &OsRng, &mut pss2).unwrap();
        assert_ne!(pss, pss2, "PSS signatures must use fresh salts");
        verify_pss(public, hash, msg, &pss).unwrap();
        verify_pss(public, hash, msg, &pss2).unwrap();
        for &other in hashes {
            if other != hash {
                assert_eq!(
                    verify_pss(public, other, msg, &pss),
                    Err(Error::InvalidSignature)
                );
            }
        }
        assert_eq!(
            verify_pkcs1v15(public, hash, msg, &pss),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            verify_pss(public, hash, b"other message", &pss),
            Err(Error::InvalidSignature)
        );
        negative_signature_shapes(public, hash, msg, &pss, true);
    }
    // Output buffer too small.
    let mut short = vec![0u8; k - 1];
    assert_eq!(
        key.sign_pkcs1v15(HashAlgorithm::Sha256, msg, &mut short),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        key.sign_pss(HashAlgorithm::Sha256, msg, &OsRng, &mut short),
        Err(Error::InvalidLength)
    );
}

fn negative_signature_shapes(
    public: &RsaPublicKey,
    hash: HashAlgorithm,
    msg: &[u8],
    sig: &[u8],
    pss: bool,
) {
    let verify = |s: &[u8]| {
        if pss {
            verify_pss(public, hash, msg, s)
        } else {
            verify_pkcs1v15(public, hash, msg, s)
        }
    };
    let k = sig.len();
    // Truncated and extended signatures.
    assert_eq!(verify(&sig[..k - 1]), Err(Error::InvalidSignature));
    assert_eq!(verify(&sig[1..]), Err(Error::InvalidSignature));
    let mut extended = vec![0u8];
    extended.extend_from_slice(sig);
    assert_eq!(verify(&extended), Err(Error::InvalidSignature));
    let mut trailing = sig.to_vec();
    trailing.push(0);
    assert_eq!(verify(&trailing), Err(Error::InvalidSignature));
    assert_eq!(verify(&[]), Err(Error::InvalidSignature));
    // s >= n: s = n, s = n + 1 (mod 2^8k), s = 2^8k - 1, and s + n.
    let n = public.n_be();
    assert_eq!(n.len(), k);
    assert_eq!(verify(n), Err(Error::InvalidSignature));
    let mut n_plus_one = n.to_vec();
    n_plus_one[k - 1] = n_plus_one[k - 1].wrapping_add(1);
    assert_eq!(verify(&n_plus_one), Err(Error::InvalidSignature));
    assert_eq!(verify(&vec![0xffu8; k]), Err(Error::InvalidSignature));
    let mut s_plus_n = sig.to_vec();
    let mut carry = 0u16;
    for i in (0..k).rev() {
        let v = u16::from(s_plus_n[i]) + u16::from(n[i]) + carry;
        s_plus_n[i] = v as u8;
        carry = v >> 8;
    }
    // s + n may overflow k bytes; when it does not, it is >= n and rejected.
    if carry == 0 {
        assert_eq!(verify(&s_plus_n), Err(Error::InvalidSignature));
    }
    // Small integers and bit flips.
    assert_eq!(verify(&vec![0u8; k]), Err(Error::InvalidSignature));
    let mut one = vec![0u8; k];
    one[k - 1] = 1;
    assert_eq!(verify(&one), Err(Error::InvalidSignature));
    let mut flipped = sig.to_vec();
    flipped[k / 2] ^= 0x01;
    assert_eq!(verify(&flipped), Err(Error::InvalidSignature));
    flipped[k / 2] ^= 0x01;
    flipped[0] ^= 0x80;
    assert_eq!(verify(&flipped), Err(Error::InvalidSignature));
}

#[test]
fn generate_2048_sign_verify() {
    let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    assert_eq!(key.modulus_bits(), 2048);
    assert_eq!(key.modulus_len_bytes(), 256);
    roundtrip(&key, &HASHES);
}

#[test]
fn generate_3072_sign_verify() {
    let key = RsaPrivateKey::generate(3072, &OsRng).unwrap();
    assert_eq!(key.modulus_bits(), 3072);
    roundtrip(&key, &[HashAlgorithm::Sha256, HashAlgorithm::Sha384]);
}

/// RSA policies selecting, in turn, every backend this CPU offers (AVX-512
/// IFMA, BMI2/ADX, portable), each with the backend it selects.
fn rsa_backends() -> Vec<(Policy, &'static str)> {
    let mut out: Vec<(Policy, &'static str)> = Vec::new();
    for policy in [
        Policy::PREFERRED,
        Policy::new(Acceleration::None, Acceleration::Preferred),
        Policy::NONE,
    ] {
        accel::set_policy(Algorithm::Rsa, policy).unwrap();
        let backend = accel::status(Algorithm::Rsa).backend;
        if out.iter().all(|&(_, b)| b != backend) {
            out.push((policy, backend));
        }
    }
    accel::set_policy(Algorithm::Rsa, Policy::PREFERRED).unwrap();
    out
}

/// Keys loaded under each backend produce identical PKCS #1 v1.5
/// signatures and identical PSS signatures for fixed salt and blinding
/// entropy, and verify each other's signatures, at 2048, 3072 and 4096 bits
/// (CRT halves of 1024, 1536 and 2048 bits). The policy is process-wide;
/// other tests in this binary may run under a different backend meanwhile,
/// which does not change their results.
#[test]
fn backends_agree_on_signatures() {
    let backends = rsa_backends();
    println!("RSA backends: {backends:?}");
    let long: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
    let msgs: [&[u8]; 3] = [b"", b"abc", &long];
    for bits in [2048usize, 3072, 4096] {
        let key = RsaPrivateKey::generate(bits, &OsRng).unwrap();
        let mut der = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
        let n = key.to_pkcs1_der(&mut der).unwrap();
        der.truncate(n);
        let mut pub_der = vec![0u8; 1100];
        let pn = key.public_key().to_pkcs1_der(&mut pub_der).unwrap();
        pub_der.truncate(pn);
        let k = key.modulus_len_bytes();
        let mut reference: Option<Vec<Vec<u8>>> = None;
        for &(policy, backend) in &backends {
            accel::set_policy(Algorithm::Rsa, policy).unwrap();
            let loaded = RsaPrivateKey::from_pkcs1_der(&der).unwrap();
            let public = RsaPublicKey::from_pkcs1_der(&pub_der).unwrap();
            let mut sigs = Vec::new();
            for msg in msgs {
                for hash in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
                    let mut sig = vec![0u8; k];
                    loaded.sign_pkcs1v15(hash, msg, &mut sig).unwrap();
                    verify_pkcs1v15(&public, hash, msg, &sig).unwrap();
                    verify_pkcs1v15(loaded.public_key(), hash, msg, &sig).unwrap();
                    sigs.push(sig);
                    let entropy = [0x3cu8; 96];
                    let mut sig = vec![0u8; k];
                    loaded
                        .sign_pss(hash, msg, &FixedRng::new(&entropy), &mut sig)
                        .unwrap();
                    verify_pss(&public, hash, msg, &sig).unwrap();
                    sigs.push(sig);
                }
            }
            match &reference {
                None => reference = Some(sigs),
                Some(r) => assert_eq!(&sigs, r, "{bits}-bit, backend {backend}"),
            }
        }
        accel::set_policy(Algorithm::Rsa, Policy::PREFERRED).unwrap();
    }
}

#[test]
fn generate_rejects_other_sizes() {
    for bits in [1024usize, 2047, 2049, 2560, 8192] {
        assert_eq!(
            RsaPrivateKey::generate(bits, &OsRng).err(),
            Some(Error::Unsupported),
            "{bits}"
        );
    }
}

#[test]
fn rng_failure_is_reported() {
    let empty = FixedRng::new(&[]);
    assert_eq!(
        RsaPrivateKey::generate(2048, &empty).err(),
        Some(Error::RandomFailure)
    );
    let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let mut sig = [0u8; 256];
    assert_eq!(
        key.sign_pss(HashAlgorithm::Sha256, b"m", &empty, &mut sig),
        Err(Error::RandomFailure)
    );
    assert_eq!(
        key.sign_pkcs1v15_with_rng(HashAlgorithm::Sha256, b"m", &empty, &mut sig),
        Err(Error::RandomFailure)
    );
    // With a fixed RNG the PSS signature is reproducible (salt + blinding
    // entropy come from the RNG) and still verifies.
    let bytes = [0x5au8; 96];
    let mut a = [0u8; 256];
    let mut b = [0u8; 256];
    key.sign_pss(HashAlgorithm::Sha256, b"m", &FixedRng::new(&bytes), &mut a)
        .unwrap();
    key.sign_pss(HashAlgorithm::Sha256, b"m", &FixedRng::new(&bytes), &mut b)
        .unwrap();
    assert_eq!(a, b);
    verify_pss(key.public_key(), HashAlgorithm::Sha256, b"m", &a).unwrap();
}

#[test]
fn private_key_der_roundtrip() {
    let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let msg = b"der round trip";
    let mut sig = [0u8; 256];
    key.sign_pkcs1v15(HashAlgorithm::Sha256, msg, &mut sig)
        .unwrap();

    let mut pkcs1 = [0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let n1 = key.to_pkcs1_der(&mut pkcs1).unwrap();
    assert!(n1 < 1300 && n1 > 1150, "{n1}");
    let key2 = RsaPrivateKey::from_pkcs1_der(&pkcs1[..n1]).unwrap();
    assert_eq!(key2.public_key().n_be(), key.public_key().n_be());
    let mut sig2 = [0u8; 256];
    key2.sign_pkcs1v15(HashAlgorithm::Sha256, msg, &mut sig2)
        .unwrap();
    assert_eq!(sig, sig2);
    let mut pkcs1_again = [0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let n1b = key2.to_pkcs1_der(&mut pkcs1_again).unwrap();
    assert_eq!(&pkcs1[..n1], &pkcs1_again[..n1b]);

    let mut pkcs8 = [0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
    let n8 = key.to_pkcs8_der(&mut pkcs8).unwrap();
    assert_eq!(n8, n1 + 26);
    let key3 = RsaPrivateKey::from_pkcs8_der(&pkcs8[..n8]).unwrap();
    let mut sig3 = [0u8; 256];
    key3.sign_pkcs1v15(HashAlgorithm::Sha256, msg, &mut sig3)
        .unwrap();
    assert_eq!(sig, sig3);
    // PKCS #8 wrapped around garbage, wrong algorithm or wrong version fails.
    assert!(RsaPrivateKey::from_pkcs8_der(&pkcs1[..n1]).is_err());
    assert!(RsaPrivateKey::from_pkcs1_der(&pkcs8[..n8]).is_err());
    let mut bad_alg = pkcs8[..n8].to_vec();
    bad_alg[9 + 10] ^= 1; // last OID byte inside the AlgorithmIdentifier
    assert_eq!(
        RsaPrivateKey::from_pkcs8_der(&bad_alg).err(),
        Some(Error::InvalidEncoding)
    );
    // Trailing byte.
    let mut trailing = pkcs1[..n1].to_vec();
    trailing.push(0);
    assert_eq!(
        RsaPrivateKey::from_pkcs1_der(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    // Buffer too small.
    let mut small = [0u8; 100];
    assert_eq!(key.to_pkcs1_der(&mut small), Err(Error::InvalidLength));
    assert_eq!(key.to_pkcs8_der(&mut small), Err(Error::InvalidLength));

    // Public key export/import.
    let mut pubder = [0u8; 300];
    let np = key.public_key().to_pkcs1_der(&mut pubder).unwrap();
    let public = RsaPublicKey::from_pkcs1_der(&pubder[..np]).unwrap();
    assert_eq!(public.n_be(), key.public_key().n_be());
    verify_pkcs1v15(&public, HashAlgorithm::Sha256, msg, &sig).unwrap();
}

/// Splits an `RSAPrivateKey` into its nine INTEGER contents.
fn split_pkcs1(der: &[u8]) -> Vec<Vec<u8>> {
    der::parse_sequence(der, |r| {
        let mut out = Vec::new();
        for _ in 0..9 {
            out.push(r.read_positive_integer()?.to_vec());
        }
        Ok(out)
    })
    .unwrap()
}

fn join_pkcs1(parts: &[Vec<u8>]) -> Vec<u8> {
    let content: usize = parts.iter().map(|p| Writer::positive_integer_len(p)).sum();
    let mut out = vec![0u8; content + 8];
    let mut w = Writer::new(&mut out);
    w.header(tag::SEQUENCE, content).unwrap();
    for p in parts {
        w.positive_integer(p).unwrap();
    }
    let n = w.len();
    out.truncate(n);
    out
}

fn increment(bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8];
    v.extend_from_slice(bytes);
    for b in v.iter_mut().rev() {
        let (s, c) = b.overflowing_add(1);
        *b = s;
        if !c {
            break;
        }
    }
    v
}

#[test]
fn inconsistent_private_keys_are_rejected() {
    let k1 = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let k2 = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let mut buf = [0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let n = k1.to_pkcs1_der(&mut buf).unwrap();
    let parts1 = split_pkcs1(&buf[..n]);
    let n = k2.to_pkcs1_der(&mut buf).unwrap();
    let parts2 = split_pkcs1(&buf[..n]);
    assert_eq!(parts1[0], vec![0]); // version
    assert!(RsaPrivateKey::from_pkcs1_der(&join_pkcs1(&parts1)).is_ok());

    // Each component of k2 substituted into k1 (indices: 1 n, 2 e, 3 d, 4 p,
    // 5 q, 6 dP, 7 dQ, 8 qInv) must be detected.
    assert_eq!(parts1[2], parts2[2], "both keys use e = 65537");
    for i in [1usize, 3, 4, 5, 6, 7, 8] {
        let mut mixed = parts1.clone();
        mixed[i] = parts2[i].clone();
        let result = RsaPrivateKey::from_pkcs1_der(&join_pkcs1(&mixed));
        assert_eq!(
            result.err(),
            Some(Error::InvalidKey),
            "component {i} from another key accepted"
        );
    }
    // Off-by-one tampering of each secret component.
    for i in 3..9 {
        let mut tampered = parts1.clone();
        tampered[i] = increment(&parts1[i]);
        assert_eq!(
            RsaPrivateKey::from_pkcs1_der(&join_pkcs1(&tampered)).err(),
            Some(Error::InvalidKey),
            "component {i} + 1 accepted"
        );
    }
    // Swapping p and q (with dP/dQ) breaks qInv.
    let mut swapped = parts1.clone();
    swapped.swap(4, 5);
    swapped.swap(6, 7);
    assert_eq!(
        RsaPrivateKey::from_pkcs1_der(&join_pkcs1(&swapped)).err(),
        Some(Error::InvalidKey)
    );
    // Multi-prime version.
    let mut v1 = parts1.clone();
    v1[0] = vec![1];
    assert_eq!(
        RsaPrivateKey::from_pkcs1_der(&join_pkcs1(&v1)).err(),
        Some(Error::Unsupported)
    );
    // Even public exponent.
    let mut even = parts1.clone();
    even[2] = vec![1, 0, 0];
    assert_eq!(
        RsaPrivateKey::from_pkcs1_der(&join_pkcs1(&even)).err(),
        Some(Error::InvalidKey)
    );
    // Negative INTEGER encoding of n (sign bit set, no leading zero octet).
    let n_bytes = &parts1[1];
    assert!(n_bytes[0] & 0x80 != 0);
    let content = Writer::positive_integer_len(&parts1[0])
        + der::header_len(n_bytes.len())
        + n_bytes.len()
        + parts1[2..]
            .iter()
            .map(|p| Writer::positive_integer_len(p))
            .sum::<usize>();
    let mut raw = vec![0u8; content + 8];
    let mut w = Writer::new(&mut raw);
    w.header(tag::SEQUENCE, content).unwrap();
    w.positive_integer(&parts1[0]).unwrap();
    w.tlv(tag::INTEGER, n_bytes).unwrap();
    for p in &parts1[2..] {
        w.positive_integer(p).unwrap();
    }
    let len = w.len();
    assert_eq!(
        RsaPrivateKey::from_pkcs1_der(&raw[..len]).err(),
        Some(Error::InvalidEncoding)
    );
}

#[test]
fn public_key_size_policy() {
    // A 1024-bit modulus is rejected by default and accepted as legacy.
    let mut n = vec![0u8; 128];
    n[0] = 0xc3;
    n[127] = 0x01;
    assert_eq!(
        RsaPublicKey::from_components(&n, &[1, 0, 1]).err(),
        Some(Error::InvalidKey)
    );
    let legacy = RsaPublicKey::from_components_with_min_bits(&n, &[1, 0, 1], 1024).unwrap();
    assert_eq!(legacy.modulus_bits(), 1024);
    assert_eq!(
        RsaPublicKey::from_components_with_min_bits(&n, &[1, 0, 1], 1023).err(),
        Some(Error::Unsupported)
    );
    // Signature verification on a legacy key with a 1024-bit modulus still
    // enforces the length rule.
    assert_eq!(
        verify_pkcs1v15(&legacy, HashAlgorithm::Sha256, b"", &[0u8; 256]).err(),
        Some(Error::InvalidSignature)
    );
    // Leading zero bytes in n and e are tolerated.
    let mut padded = vec![0u8, 0];
    padded.extend_from_slice(&n);
    let k = RsaPublicKey::from_components_with_min_bits(&padded, &[0, 0, 1, 0, 1], 1024).unwrap();
    assert_eq!(k.n_be(), &n[..]);
    assert_eq!(k.e_be(), &[1, 0, 1]);
    // SPKI built around the legacy key, then corrupted variants.
    let mut r = [0u8; 300];
    let np = legacy.to_pkcs1_der(&mut r).unwrap();
    let alg_content = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut bits = vec![0u8];
    bits.extend_from_slice(&r[..np]);
    let content = der::header_len(alg_content.len())
        + alg_content.len()
        + der::header_len(bits.len())
        + bits.len();
    let mut spki = vec![0u8; content + 8];
    let mut w = Writer::new(&mut spki);
    w.header(tag::SEQUENCE, content).unwrap();
    w.tlv(tag::SEQUENCE, &alg_content).unwrap();
    w.tlv(tag::BIT_STRING, &bits).unwrap();
    let total = w.len();
    spki.truncate(total);
    let parsed = RsaPublicKey::from_spki_der_with_min_bits(&spki, 1024).unwrap();
    assert_eq!(parsed.n_be(), &n[..]);
    let oid_pos = spki
        .windows(9)
        .position(|w| w == &alg_content[2..11])
        .unwrap();
    let mut wrong_oid = spki.clone();
    wrong_oid[oid_pos + 8] ^= 1;
    assert_eq!(
        RsaPublicKey::from_spki_der_with_min_bits(&wrong_oid, 1024).err(),
        Some(Error::InvalidEncoding)
    );
    let unused_pos = der::header_len(content)
        + der::header_len(alg_content.len())
        + alg_content.len()
        + der::header_len(bits.len());
    assert_eq!(spki[unused_pos], 0);
    let mut unused_bits = spki.clone();
    unused_bits[unused_pos] = 1;
    assert_eq!(
        RsaPublicKey::from_spki_der_with_min_bits(&unused_bits, 1024).err(),
        Some(Error::InvalidEncoding)
    );
    // Missing NULL parameters.
    let short_alg = &alg_content[..11];
    let content2 = der::header_len(short_alg.len())
        + short_alg.len()
        + der::header_len(bits.len())
        + bits.len();
    let mut spki2 = vec![0u8; content2 + 8];
    let mut w = Writer::new(&mut spki2);
    w.header(tag::SEQUENCE, content2).unwrap();
    w.tlv(tag::SEQUENCE, short_alg).unwrap();
    w.tlv(tag::BIT_STRING, &bits).unwrap();
    let total2 = w.len();
    assert_eq!(
        RsaPublicKey::from_spki_der_with_min_bits(&spki2[..total2], 1024).err(),
        Some(Error::InvalidEncoding)
    );
    // Reader sanity: the hand-built SPKI parses with the DER reader too.
    let mut reader = Reader::new(&spki);
    let seq = reader.read_sequence().unwrap();
    assert!(reader.finish().is_ok());
    assert!(!seq.is_empty());
}

#[test]
fn hash_too_large_for_modulus() {
    // PSS with SHA-512 needs emLen >= 130 bytes; a 1024-bit key has 128.
    let mut n = vec![0u8; 128];
    n[0] = 0xc3;
    n[127] = 0x01;
    let key = RsaPublicKey::from_components_with_min_bits(&n, &[1, 0, 1], 1024).unwrap();
    let sig = vec![1u8; 128];
    assert_eq!(
        verify_pss(&key, HashAlgorithm::Sha512, b"", &sig).err(),
        Some(Error::InvalidSignature)
    );
}

#[test]
#[ignore = "throughput measurement; run with --release -- --ignored --nocapture"]
fn throughput() {
    use std::time::Instant;
    let msg = [0x42u8; 1000];
    for bits in [2048usize, 3072, 4096] {
        let start = Instant::now();
        let key = RsaPrivateKey::generate(bits, &OsRng).unwrap();
        let gen_ms = start.elapsed().as_secs_f64() * 1e3;
        let k = key.modulus_len_bytes();
        let mut sig = vec![0u8; k];
        let iters: u32 = match bits {
            2048 => 200,
            3072 => 80,
            _ => 30,
        };
        let start = Instant::now();
        for _ in 0..iters {
            key.sign_pkcs1v15(HashAlgorithm::Sha256, &msg, &mut sig)
                .unwrap();
        }
        let sign_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        for _ in 0..iters {
            key.sign_pss(HashAlgorithm::Sha256, &msg, &OsRng, &mut sig)
                .unwrap();
        }
        let pss_s = start.elapsed().as_secs_f64();
        let viters = iters * 20;
        let start = Instant::now();
        for _ in 0..viters {
            verify_pss(key.public_key(), HashAlgorithm::Sha256, &msg, &sig).unwrap();
        }
        let verify_s = start.elapsed().as_secs_f64();
        println!(
            "RSA-{bits}: keygen {gen_ms:.0} ms; sign pkcs1 {:.0}/s ({:.2} ms); sign pss {:.0}/s; verify {:.0}/s ({:.3} ms)",
            f64::from(iters) / sign_s,
            sign_s / f64::from(iters) * 1e3,
            f64::from(iters) / pss_s,
            f64::from(viters) / verify_s,
            verify_s / f64::from(viters) * 1e3,
        );
    }
}

#[test]
fn secure_random_trait_object_works() {
    // `generate` and the signing functions accept any `SecureRandom`.
    struct Counter(std::cell::Cell<u64>);
    impl SecureRandom for Counter {
        fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
            for b in dest {
                let v = self
                    .0
                    .get()
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                self.0.set(v);
                *b = (v >> 56) as u8;
            }
            Ok(())
        }
    }
    let rng = Counter(std::cell::Cell::new(7));
    let key = RsaPrivateKey::generate(2048, &rng).unwrap();
    let mut sig = [0u8; 256];
    key.sign_pss(HashAlgorithm::Sha384, b"x", &rng, &mut sig)
        .unwrap();
    verify_pss(key.public_key(), HashAlgorithm::Sha384, b"x", &sig).unwrap();
}

/// Child half of the stack probe: runs one operation on a thread whose stack
/// size comes from `BROWNTLS_RSA_STACK_PROBE=<op>:<bytes>`. Without the
/// variable it does nothing, so it passes in a normal run.
#[test]
fn stack_probe_child() {
    let Ok(spec) = std::env::var("BROWNTLS_RSA_STACK_PROBE") else {
        return;
    };
    let (op, bytes) = spec.split_once(':').unwrap();
    let bytes: usize = bytes.parse().unwrap();
    let op = op.to_string();
    let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let mut der = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let n = key.to_pkcs1_der(&mut der).unwrap();
    der.truncate(n);
    let mut sig = vec![0u8; 256];
    key.sign_pss(HashAlgorithm::Sha256, b"m", &OsRng, &mut sig)
        .unwrap();
    std::thread::Builder::new()
        .stack_size(bytes)
        .spawn(move || match op.as_str() {
            "noop" => {
                // Baseline: thread start-up and the closure itself.
                std::hint::black_box(&sig);
            }
            "generate" => {
                RsaPrivateKey::generate(2048, &OsRng).unwrap();
            }
            "sign_pkcs1" => {
                key.sign_pkcs1v15(HashAlgorithm::Sha256, b"m", &mut sig)
                    .unwrap();
            }
            "sign_pss" => {
                key.sign_pss(HashAlgorithm::Sha256, b"m", &OsRng, &mut sig)
                    .unwrap();
            }
            "verify" => verify_pss(key.public_key(), HashAlgorithm::Sha256, b"m", &sig).unwrap(),
            "load" => {
                RsaPrivateKey::from_pkcs1_der(&der).unwrap();
            }
            other => panic!("unknown op {other}"),
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Smallest thread stack (4 KiB granularity) on which `op` completes,
/// found by binary search over child processes (an overflow aborts only the
/// child).
fn min_stack_for(op: &str) -> usize {
    let exe = std::env::current_exe().unwrap();
    let works = |bytes: usize| {
        std::process::Command::new(&exe)
            .args(["--exact", "stack_probe_child", "--quiet"])
            .env("BROWNTLS_RSA_STACK_PROBE", format!("{op}:{bytes}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    let (mut lo, mut hi) = (8 * 1024usize, 1 << 20);
    assert!(works(hi), "{op} does not fit in 1 MiB");
    while hi - lo > 4096 {
        let mid = (lo + hi) / 2 / 4096 * 4096;
        if works(mid) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    hi
}

#[test]
#[ignore = "stack usage probe; run with --release -- --ignored --nocapture"]
fn stack_usage_probe() {
    for op in [
        "noop",
        "sign_pkcs1",
        "sign_pss",
        "verify",
        "load",
        "generate",
    ] {
        println!(
            "RSA-2048 {op}: minimum thread stack {} KiB",
            min_stack_for(op) / 1024
        );
    }
}

#[test]
fn signing_fits_in_a_small_stack() {
    // Signing, verification and key loading must stay within a modest stack
    // budget: the measured peaks are ~24 KiB (sign), ~12 KiB (verify) and
    // ~64 KiB (load) on top of a ~68 KiB thread start-up baseline, so 256 KiB
    // leaves a wide margin on every supported target.
    let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let mut der = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let n = key.to_pkcs1_der(&mut der).unwrap();
    der.truncate(n);
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let loaded = RsaPrivateKey::from_pkcs1_der(&der).unwrap();
            let mut sig = [0u8; 256];
            loaded
                .sign_pss(HashAlgorithm::Sha256, b"stack", &OsRng, &mut sig)
                .unwrap();
            verify_pss(loaded.public_key(), HashAlgorithm::Sha256, b"stack", &sig).unwrap();
            loaded
                .sign_pkcs1v15(HashAlgorithm::Sha512, b"stack", &mut sig)
                .unwrap();
            verify_pkcs1v15(loaded.public_key(), HashAlgorithm::Sha512, b"stack", &sig).unwrap();
        })
        .unwrap();
    handle.join().unwrap();
}

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
    MAX_ALGORITHM_IDENTIFIER_LEN, MAX_MODULUS_BYTES, MAX_PKCS1_PRIVATE_KEY_DER_LEN,
    MAX_PKCS8_PRIVATE_KEY_DER_LEN, RsaKeyAlgorithm, RsaPrivateKey, RsaPublicKey, verify_pkcs1v15,
    verify_pss,
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
/// Name of the AVX-512 IFMA RSA backend in status reports.
const IFMA: &str = "AVX-512 IFMA + BMI2/ADX";

#[test]
fn backends_agree_on_signatures() {
    let backends = rsa_backends();
    println!("RSA backends: {backends:?}");
    // Only the IFMA backend uses SIMD, so a CPU offering SIMD for RSA must
    // have it exercised here.
    if accel::status(Algorithm::Rsa).available.simd {
        assert!(backends.iter().any(|&(_, b)| b == IFMA), "{backends:?}");
    }
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
            // The key uses the IFMA exponentiation exactly when the policy
            // selected that backend.
            assert_eq!(
                format!("{loaded:?}").contains("avx512-ifma"),
                backend == IFMA,
                "{bits}-bit key loaded under {backend}: {loaded:?}"
            );
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

/// The key algorithms an RSA key can be exported and loaded with.
const KEY_ALGORITHMS: [RsaKeyAlgorithm; 5] = [
    RsaKeyAlgorithm::RsaEncryption,
    RsaKeyAlgorithm::RsassaPss(None),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha256)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha384)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha512)),
];

/// A `SubjectPublicKeyInfo` for `key` identified by `algorithm`.
fn spki_for(key: &RsaPublicKey, algorithm: RsaKeyAlgorithm) -> Vec<u8> {
    let mut alg = [0u8; MAX_ALGORITHM_IDENTIFIER_LEN];
    let alg_len = algorithm.encode_algorithm_identifier(&mut alg).unwrap();
    let mut bits = vec![0u8; MAX_MODULUS_BYTES + 32];
    let n = key.to_pkcs1_der(&mut bits[1..]).unwrap();
    bits.truncate(n + 1);
    let content = der::header_len(alg_len) + alg_len + der::header_len(bits.len()) + bits.len();
    let mut out = vec![0u8; content + 8];
    let mut w = Writer::new(&mut out);
    w.header(tag::SEQUENCE, content).unwrap();
    w.tlv(tag::SEQUENCE, &alg[..alg_len]).unwrap();
    w.tlv(tag::BIT_STRING, &bits).unwrap();
    let len = w.len();
    out.truncate(len);
    out
}

#[test]
fn rsassa_pss_keys_round_trip() {
    let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let mut sig = [0u8; 256];
    for algorithm in KEY_ALGORITHMS {
        // PKCS #8 (RFC 5208 §5; RFC 4055 §1.2: the same RSAPrivateKey).
        let mut pkcs8 = [0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
        let n = key
            .to_pkcs8_der_with_algorithm(algorithm, &mut pkcs8)
            .unwrap();
        let (loaded, found) = RsaPrivateKey::from_pkcs8_der_with_algorithm(&pkcs8[..n]).unwrap();
        assert_eq!(found, algorithm);
        assert_eq!(loaded.public_key().n_be(), key.public_key().n_be());
        loaded
            .sign_pss(HashAlgorithm::Sha256, b"m", &OsRng, &mut sig)
            .unwrap();
        verify_pss(key.public_key(), HashAlgorithm::Sha256, b"m", &sig).unwrap();
        // The rsaEncryption-only loaders refuse RSASSA-PSS keys.
        let legacy = RsaPrivateKey::from_pkcs8_der(&pkcs8[..n]);
        let spki = spki_for(key.public_key(), algorithm);
        let legacy_spki = RsaPublicKey::from_spki_der(&spki);
        if algorithm == RsaKeyAlgorithm::RsaEncryption {
            assert!(legacy.is_ok() && legacy_spki.is_ok());
            let mut plain = [0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
            let m = key.to_pkcs8_der(&mut plain).unwrap();
            assert_eq!(&plain[..m], &pkcs8[..n]);
        } else {
            assert_eq!(legacy.err(), Some(Error::InvalidEncoding));
            assert_eq!(legacy_spki.err(), Some(Error::InvalidEncoding));
        }
        // SubjectPublicKeyInfo.
        let (public, found) = RsaPublicKey::from_spki_der_with_algorithm(&spki).unwrap();
        assert_eq!(found, algorithm);
        assert_eq!(public.n_be(), key.public_key().n_be());
        // Truncations and a trailing byte are rejected.
        for len in [0, 1, 20, n - 1] {
            assert!(RsaPrivateKey::from_pkcs8_der_with_algorithm(&pkcs8[..len]).is_err());
        }
        let mut trailing = spki.clone();
        trailing.push(0);
        assert!(RsaPublicKey::from_spki_der_with_algorithm(&trailing).is_err());
    }
    let mut small = [0u8; 1000];
    assert_eq!(
        key.to_pkcs8_der_with_algorithm(KEY_ALGORITHMS[2], &mut small),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        key.to_pkcs8_der_with_algorithm(
            RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha224)),
            &mut [0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN]
        ),
        Err(Error::Unsupported)
    );
}

// Public keys and signatures made by OpenSSL 3.0.13 for these tests (the
// private keys were discarded):
//
//   openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out a.pem
//   openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 \
//     -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 \
//     -pkeyopt rsa_pss_keygen_saltlen:32 -out b.pem
//   openssl pkey -in a.pem -pubout -outform DER          (OPENSSL_PSS_SPKI)
//   openssl dgst -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:64 \
//     -sigopt rsa_mgf1_md:sha512 -sign a.pem msg         (OPENSSL_PSS_SHA512_SIG)
//
// and likewise for b.pem with SHA-256 and a 32-byte salt.
const OPENSSL_MSG: &[u8] = b"browntls RSASSA-PSS test vector";
const OPENSSL_PSS_SPKI: &str = concat!(
    "30820120300b06092a864886f70d01010a0382010f003082010a0282010100af",
    "44706e28928bb898b9da6b657ca711e2edd287181904fe632899fab589edbb1c",
    "8cf30da93dec59859ab3d0fa1ef7cf26624cb35024607a1dcb15800949e091e8",
    "f6821e46a2deebe55de982adfe235fff0cd21a1b60c28d08dda7ff635045e9e2",
    "cabe0006720c1267fd8b747415d00a8d06a91eed75f5fb38deffed32154d4c15",
    "6363fb974787748eae2438fa4a549bbeab5dc366b9ca7801caaf618852d41ce5",
    "9d613a4750cd8186f68e18a9de1618cd613386f827326931ecf73a9fdfa3b713",
    "899d4e961ff931b4c542a3569dab2d6f77882d671d6b9f34868005585a632c87",
    "f4e1eceb193a56d842e3585f6ce3a7a44ea7283bbdd3863268d3eaf18fe66302",
    "03010001",
);
const OPENSSL_PSS_SHA512_SIG: &str = concat!(
    "3f90c4862183f6072d95b3bd076fd375622a7216bd17c2bd6d2c1f26deef9917",
    "59748af3dda4d066da226f025a1b76a602b2784ed310dc50e666f93e64153b5e",
    "a531ae8a9a513168d69edccb9e6767304b17d085c5e9a02307880ee239f68dd0",
    "2f637eaf5f1ddebbb1d88962864c66259728a364f330da985f53105c8561fbe0",
    "7bcb36aca0ebab1dbeba9ca96253d8df20a15fbc3f6cbdbd73a0062cc98f4326",
    "227a416e7949d80f4a3b326d6ba8854f22de9fb0e3e6a7b7127ecf313de960ff",
    "61fee2277df5b7f5dc176fa3044e3a2a160075c17f56202987c70e0efc6fce0a",
    "c6e8f6e7410503f89ab3f534f27cc0a305d28ee49924fcccdc87a17602d78e89",
);
const OPENSSL_PSS_SHA256_SPKI: &str = concat!(
    "30820156304106092a864886f70d01010a3034a00f300d060960864801650304",
    "02010500a11c301a06092a864886f70d010108300d0609608648016503040201",
    "0500a2030201200382010f003082010a0282010100a9cb3bd5a02e5eee5eb103",
    "a87e19eadedc9bd44c12bfc6fa189c1ff7f790ab8cd20bbf98f7d40b0c206e10",
    "1baaa398a1dc6cf7652ce86bef43215d2438fc65c09e4e767ef263c350d2b568",
    "b538dc1f6dc6af9585692587599a039b337e15964711236111c99131c0dce053",
    "367bafe29831ff44ec67a2d43c54dd310a260d7cdc73794e2e2792b91841091f",
    "4ece9f75435746a39c76fb45db30473be87cc507313e58fadde9f4a9ec56ea2f",
    "eb9d9d432b2d06aa0fc8b22db7280c00222a6f8829ee62d3e83bdd52c9aba5c6",
    "e360a01c1cbfee0048cf429ccb3c4f7f7b8d929d966326257101b395d3d9c231",
    "38f2566ae7a123b13cb683eb9abe362fa6749d3add0203010001",
);
const OPENSSL_PSS_SHA256_SIG: &str = concat!(
    "3b5c48fc32708b0875acfbab1f5bffc19e19af234ce6785b2e5baa8f45d04ba5",
    "d628b678ffef425e8199b43f516f02df2c00ef2d9d2962df46d931f086f5871c",
    "799895cee57aa53908687ecb41f1b0a219b481e022a1095ac01dda13479eeacc",
    "02cbc22754f8de487e093dbff2f77e8182e26d997d01187be3a989d6444c90cc",
    "024c009818115665425e96f576d537cd033cebcf5fcf6c2c0310115fe64ae61b",
    "b7d3fbbf8da0f4043aaffc7e0c02a49e8d7fbc843bc7f900bf2b470e0718fd2c",
    "1c8253e74f6ddfb62ab8fae0b823a12d649d004f9a559514271e012efb36258e",
    "730bcbc1a78ac5619bd511b4306b297ae48fc5f0ca366589ad138116664b2c08",
);

#[test]
fn openssl_rsassa_pss_public_keys() {
    for (spki, sig, algorithm, hash) in [
        (
            OPENSSL_PSS_SPKI,
            OPENSSL_PSS_SHA512_SIG,
            RsaKeyAlgorithm::RsassaPss(None),
            HashAlgorithm::Sha512,
        ),
        (
            OPENSSL_PSS_SHA256_SPKI,
            OPENSSL_PSS_SHA256_SIG,
            RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha256)),
            HashAlgorithm::Sha256,
        ),
    ] {
        let spki = hex::decode(spki).unwrap();
        let sig = hex::decode(sig).unwrap();
        let (key, found) = RsaPublicKey::from_spki_der_with_algorithm(&spki).unwrap();
        assert_eq!(found, algorithm);
        assert_eq!(key.modulus_bits(), 2048);
        assert!(found.allows_pss(hash) && !found.allows_pkcs1v15());
        verify_pss(&key, hash, OPENSSL_MSG, &sig).unwrap();
        assert!(verify_pss(&key, hash, b"other", &sig).is_err());
        assert!(verify_pss(&key, HashAlgorithm::Sha384, OPENSSL_MSG, &sig).is_err());
        // Re-encoding the parsed key and algorithm reproduces OpenSSL's SPKI.
        assert_eq!(spki_for(&key, found), spki);
        assert_eq!(
            RsaPublicKey::from_spki_der(&spki).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let restricted = RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha256));
    assert!(!restricted.allows_pss(HashAlgorithm::Sha512));
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
    let der = probe_key_der();
    let key = RsaPrivateKey::from_pkcs1_der(&der).unwrap();
    let mut sig = vec![0u8; key.modulus_len_bytes()];
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

/// The key for the stack probe: the PKCS #1 DER file named by
/// `BROWNTLS_RSA_STACK_PROBE_KEY` (any loadable size, e.g. an 8192-bit key
/// made with another tool), or a fresh 2048-bit key.
fn probe_key_der() -> Vec<u8> {
    if let Ok(path) = std::env::var("BROWNTLS_RSA_STACK_PROBE_KEY") {
        return std::fs::read(path).unwrap();
    }
    let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let mut der = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let n = key.to_pkcs1_der(&mut der).unwrap();
    der.truncate(n);
    der
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
    let bits = RsaPrivateKey::from_pkcs1_der(&probe_key_der())
        .unwrap()
        .modulus_bits();
    println!("RSA backend: {}", accel::status(Algorithm::Rsa).backend);
    for op in [
        "noop",
        "sign_pkcs1",
        "sign_pss",
        "verify",
        "load",
        "generate",
    ] {
        // `generate` always makes a 2048-bit key.
        println!(
            "RSA-{bits} {op}: minimum thread stack {} KiB",
            min_stack_for(op) / 1024
        );
    }
}

#[test]
fn signing_fits_in_a_small_stack() {
    // Signing, verification and key loading must stay within a modest stack
    // budget at every generated size. Signing on the IFMA backend grows with
    // the key (its window table is per size); the measured peaks, documented
    // in the `rsa` module, stay well below 256 KiB on every supported target.
    for bits in [2048usize, 4096] {
        signing_fits_in_256_kib(bits);
    }
}

fn signing_fits_in_256_kib(bits: usize) {
    let key = RsaPrivateKey::generate(bits, &OsRng).unwrap();
    let mut der = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let n = key.to_pkcs1_der(&mut der).unwrap();
    der.truncate(n);
    let k = key.modulus_len_bytes();
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let loaded = RsaPrivateKey::from_pkcs1_der(&der).unwrap();
            let mut sig = vec![0u8; k];
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

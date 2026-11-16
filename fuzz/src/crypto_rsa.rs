//! `browntls_crypto::rsa`: public and private key encodings, key algorithm
//! identifiers, PKCS #1 v1.5 and PSS signing and verification, key
//! generation.
//!
//! Two RSA keys (2048 and 3072 bits) are generated once per process by the
//! crate's own key generation from a fixed deterministic byte source, so
//! inputs replay exactly; each is loaded again under every RSA backend the
//! CPU offers (AVX-512 IFMA, BMI2/ADX, portable). Nothing secret is
//! committed. The reference (`crypto_rsa/oracle.rs`) is raw RSA with
//! `num-bigint` and EMSA-PKCS1-v1_5 / EMSA-PSS written from RFC 8017 over
//! the RustCrypto hashes.
//!
//! The input is a program of up to [`MAX_OPS`] operations, each a selector
//! byte followed by its arguments (fields have a 16-bit length prefix, short
//! fields an 8-bit one):
//!
//! | Op | Arguments | Checks |
//! |---|---|---|
//! | 0 components | modulus source, exponent, minimum size, buffer size, hash, message, signature | acceptance exactly as documented; accessors; PKCS #1 and SPKI round trips; fuzzed signatures against an arbitrary odd modulus verified by every backend and by the reference |
//! | 1 public DER | source, minimum size | the default bounds equal `*_with_min_bits(2048)`; an `rsaEncryption` SPKI reads the same with its algorithm; re-encoding is stable |
//! | 2 algorithm | source, algorithm, buffer size | parse, encode, parse round trip; permissions; short buffers fail cleanly |
//! | 3 sign PKCS #1 | key, hash, message, blinding entropy, buffer size, backend, bit | exact errors; one signature whatever the entropy and backend; the reference verifies it; a flipped bit fails everywhere |
//! | 4 sign PSS | key, hash, message, salt and entropy, buffer size, backend, bit | exact errors; backends agree for fixed randomness; the reference recovers the salt; a flipped bit fails |
//! | 5 verify | key, hash, message, signature source | browntls and the reference agree for both paddings |
//! | 6 forge | key, hash, message, salt length or encoding edit | encodings signed by the reference: PSS accepts only `sLen = hLen`, PKCS #1 v1.5 only the canonical encoding |
//! | 7 private DER | parser, source, hash, algorithm, buffer size | accepted keys sign correctly; unedited encodings load and re-encode byte for byte; failed writes leave the buffer zeroed |
//! | 8 generate | size, byte source | `Unsupported` sizes, `RandomFailure` for sources too short for two primes |
//!
//! A "source" is raw fuzzed bytes, or a valid encoding made by the harness
//! with one fuzzed edit (none, flip, truncate, insert or delete a byte).
//! Private-key loads (each runs a signing self-test) and signatures made by
//! the reference are limited to two each per input.

mod oracle;

use std::cell::Cell;
use std::sync::OnceLock;

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Acceleration, Algorithm, Policy};
use browntls_crypto::der;
use browntls_crypto::hash::HashAlgorithm;
use browntls_crypto::rand::{FixedRng, SecureRandom};
use browntls_crypto::rsa::{
    LEGACY_MIN_MODULUS_BITS, MAX_ALGORITHM_IDENTIFIER_LEN, MAX_MODULUS_BITS,
    MAX_PKCS1_PRIVATE_KEY_DER_LEN, MAX_PKCS8_PRIVATE_KEY_DER_LEN, MIN_MODULUS_BITS,
    RsaKeyAlgorithm, RsaPrivateKey, RsaPublicKey, verify_pkcs1v15, verify_pss,
};
use num_bigint::BigUint;
use sha2::Digest as _;

use self::oracle::HASHES;
use crate::input::{Input, put_field, put_short_field};

/// Most operations per input.
pub const MAX_OPS: usize = 8;
/// Most private-key loads per input.
const MAX_PRIVATE_LOADS: usize = 2;
/// Most signatures made by the reference per input.
const MAX_FORGERIES: usize = 2;
/// Longest message.
const MAX_MSG: usize = 1024;

/// RSA backend policies, one per distinct backend on this CPU, PREFERRED
/// first.
fn backend_policies() -> Vec<Policy> {
    let mut seen: Vec<&'static str> = Vec::new();
    let mut out = Vec::new();
    for policy in [
        Policy::PREFERRED,
        Policy::new(Acceleration::None, Acceleration::Preferred),
        Policy::NONE,
    ] {
        let backend = with_policy(policy, || accel::status(Algorithm::Rsa).backend);
        if !seen.contains(&backend) {
            seen.push(backend);
            out.push(policy);
        }
    }
    out
}

/// Runs `f` with the RSA policy set to `policy`, then restores PREFERRED.
fn with_policy<T>(policy: Policy, f: impl FnOnce() -> T) -> T {
    accel::set_policy(Algorithm::Rsa, policy).expect("RSA policy");
    let out = f();
    accel::set_policy(Algorithm::Rsa, Policy::PREFERRED).expect("RSA policy");
    out
}

/// A deterministic byte source (SHA-256 in counter mode) for key generation.
struct Drbg {
    seed: &'static [u8],
    counter: Cell<u64>,
}

impl SecureRandom for Drbg {
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        for chunk in dest.chunks_mut(32) {
            let n = self.counter.get();
            self.counter.set(n + 1);
            let block = sha2::Sha256::new()
                .chain_update(self.seed)
                .chain_update(n.to_be_bytes())
                .finalize();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

/// A DER TLV with a definite length (below 64 KiB).
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// The contents of `algorithm`'s AlgorithmIdentifier.
fn algorithm_identifier(algorithm: RsaKeyAlgorithm) -> Vec<u8> {
    let mut buf = [0u8; MAX_ALGORITHM_IDENTIFIER_LEN];
    let n = algorithm
        .encode_algorithm_identifier(&mut buf)
        .expect("supported algorithm");
    buf[..n].to_vec()
}

/// A `SubjectPublicKeyInfo` around a PKCS #1 `RSAPublicKey`.
fn spki(algorithm: RsaKeyAlgorithm, pkcs1: &[u8]) -> Vec<u8> {
    let mut bits = vec![0u8];
    bits.extend_from_slice(pkcs1);
    let mut body = tlv(0x30, &algorithm_identifier(algorithm));
    body.extend_from_slice(&tlv(0x03, &bits));
    tlv(0x30, &body)
}

/// The PKCS #1 `RSAPublicKey` of `key`.
fn public_pkcs1(key: &RsaPublicKey) -> Vec<u8> {
    let mut buf = vec![0u8; 1100];
    let n = key.to_pkcs1_der(&mut buf).expect("public key encoding");
    buf.truncate(n);
    buf
}

/// The algorithms the fixture encodes keys with.
const KEY_ALGORITHMS: [RsaKeyAlgorithm; 5] = [
    RsaKeyAlgorithm::RsaEncryption,
    RsaKeyAlgorithm::RsassaPss(None),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha256)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha384)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha512)),
];

/// [`KEY_ALGORITHMS`] and restrictions that cannot be encoded.
const ALL_ALGORITHMS: [RsaKeyAlgorithm; 9] = [
    RsaKeyAlgorithm::RsaEncryption,
    RsaKeyAlgorithm::RsassaPss(None),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha256)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha384)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha512)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha224)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha3_256)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha3_384)),
    RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha3_512)),
];

/// A generated key, its encodings and its reference form.
struct FixedKey {
    /// The key loaded under each backend policy, PREFERRED first.
    loaded: Vec<RsaPrivateKey>,
    reference: oracle::Private,
    /// PKCS #1 `RSAPrivateKey`.
    pkcs1: Vec<u8>,
    /// PKCS #8 encodings, one per entry of [`KEY_ALGORITHMS`].
    pkcs8: Vec<Vec<u8>>,
    /// PKCS #1 `RSAPublicKey`.
    public_pkcs1: Vec<u8>,
    /// `SubjectPublicKeyInfo`s, one per entry of [`KEY_ALGORITHMS`].
    spki: Vec<Vec<u8>>,
}

impl FixedKey {
    fn generate(bits: usize, seed: &'static [u8], policies: &[Policy]) -> Self {
        let rng = Drbg {
            seed,
            counter: Cell::new(0),
        };
        let generated = RsaPrivateKey::generate(bits, &rng).expect("RSA key generation");
        assert_eq!(generated.modulus_bits(), bits);
        let mut buf = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
        let n = generated.to_pkcs1_der(&mut buf).expect("PKCS #1");
        let pkcs1 = buf[..n].to_vec();
        let loaded: Vec<RsaPrivateKey> = policies
            .iter()
            .map(|&p| with_policy(p, || RsaPrivateKey::from_pkcs1_der(&pkcs1)).expect("load"))
            .collect();
        let pkcs8: Vec<Vec<u8>> = KEY_ALGORITHMS
            .iter()
            .map(|&alg| {
                let n = generated
                    .to_pkcs8_der_with_algorithm(alg, &mut buf)
                    .expect("PKCS #8");
                buf[..n].to_vec()
            })
            .collect();
        let public_pkcs1 = public_pkcs1(generated.public_key());
        let spki = KEY_ALGORITHMS
            .iter()
            .map(|&alg| spki(alg, &public_pkcs1))
            .collect();
        let reference = reference_key(&pkcs1);
        assert_eq!(reference.public.bits, bits);
        Self {
            loaded,
            reference,
            pkcs1,
            pkcs8,
            public_pkcs1,
            spki,
        }
    }

    fn public(&self) -> &RsaPublicKey {
        self.loaded[0].public_key()
    }

    fn k(&self) -> usize {
        self.reference.public.k
    }
}

/// The reference form of a PKCS #1 `RSAPrivateKey`.
fn reference_key(pkcs1: &[u8]) -> oracle::Private {
    let ints = der::parse_sequence(pkcs1, |r| {
        assert_eq!(r.read_small_integer()?, 0);
        let mut ints = Vec::new();
        for _ in 0..8 {
            ints.push(BigUint::from_bytes_be(r.read_positive_integer()?));
        }
        Ok(ints)
    })
    .expect("RSAPrivateKey");
    let [n, e, _d, p, q, dp, dq, qinv] = <[BigUint; 8]>::try_from(ints).expect("8 integers");
    oracle::Private {
        public: oracle::Public::new(&n.to_bytes_be(), &e.to_bytes_be()),
        p,
        q,
        dp,
        dq,
        qinv,
    }
}

struct Fixture {
    keys: Vec<FixedKey>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let policies = backend_policies();
        Fixture {
            keys: vec![
                FixedKey::generate(2048, b"browntls-fuzz rsa 2048", &policies),
                FixedKey::generate(3072, b"browntls-fuzz rsa 3072", &policies),
            ],
        }
    })
}

/// Applies one fuzzed edit to `bytes` (none, flip, truncate, insert,
/// delete); returns whether it changed anything.
fn edit(bytes: &mut Vec<u8>, input: &mut Input<'_>) -> bool {
    let before = bytes.clone();
    let kind = input.choose(5);
    let at = usize::from(input.u16());
    let value = input.byte();
    match kind {
        1 if !bytes.is_empty() => {
            let at = at % bytes.len();
            bytes[at] ^= value.max(1);
        }
        2 => bytes.truncate(at % (bytes.len() + 1)),
        3 => bytes.insert(at % (bytes.len() + 1), value),
        4 if !bytes.is_empty() => {
            bytes.remove(at % bytes.len());
        }
        _ => {}
    }
    *bytes != before
}

/// A message of at most [`MAX_MSG`] bytes.
fn message<'a>(input: &mut Input<'a>) -> &'a [u8] {
    let msg = input.field();
    &msg[..msg.len().min(MAX_MSG)]
}

/// Verifies `sig` with both paddings in browntls and in the reference,
/// requires the same verdicts and returns them.
fn check_verify(
    key: &RsaPublicKey,
    reference: &oracle::Public,
    hash: HashAlgorithm,
    msg: &[u8],
    sig: &[u8],
) -> (bool, bool) {
    let pkcs1 = verify_pkcs1v15(key, hash, msg, sig);
    let pss = verify_pss(key, hash, msg, sig);
    for result in [pkcs1, pss] {
        assert!(
            matches!(result, Ok(()) | Err(Error::InvalidSignature)),
            "{result:?}"
        );
    }
    // One public operation for both paddings.
    let em = reference.open(sig);
    let pkcs1_ref = em
        .as_ref()
        .is_some_and(|em| reference.pkcs1v15_matches(hash, msg, em));
    let pss_ref = em
        .as_ref()
        .is_some_and(|em| reference.pss_salt(hash, msg, em).is_some());
    assert_eq!(pkcs1.is_ok(), pkcs1_ref, "PKCS #1 v1.5 verdict ({hash:?})");
    assert_eq!(pss.is_ok(), pss_ref, "PSS verdict ({hash:?})");
    (pkcs1_ref, pss_ref)
}

/// `sig` with one fuzzed bit flipped.
fn tamper(sig: &[u8], input: &mut Input<'_>) -> Vec<u8> {
    let mut bad = sig.to_vec();
    let bit = usize::from(input.u16()) % (8 * bad.len());
    bad[bit / 8] ^= 1 << (bit % 8);
    bad
}

/// An output buffer size for a `k`-byte signature: exact, larger or too
/// small.
fn out_len(k: usize, input: &mut Input<'_>) -> usize {
    match input.choose(3) {
        0 => k,
        1 => k + 3,
        _ => usize::from(input.u16()) % k,
    }
}

/// The documented rule of `RsaPublicKey::from_components_with_min_bits`.
fn expected_components(n_be: &[u8], e_be: &[u8], min_bits: usize) -> Result<(), Error> {
    if !(LEGACY_MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&min_bits) {
        return Err(Error::Unsupported);
    }
    let n = BigUint::from_bytes_be(n_be);
    let bits = usize::try_from(n.bits()).expect("bits");
    let e = BigUint::from_bytes_be(e_be);
    let n_ok = n.bit(0) && bits >= min_bits && bits <= MAX_MODULUS_BITS;
    let e_ok = e.bit(0) && e >= BigUint::from(3u8) && e < BigUint::from(1u64 << 33);
    if n_ok && e_ok {
        Ok(())
    } else {
        Err(Error::InvalidKey)
    }
}

/// `len` bytes expanded from a 64-bit seed (xorshift).
fn expand(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 32) as u8
        })
        .collect()
}

/// Modulus sizes for structured moduli.
const MODULUS_SIZES: [usize; 12] = [
    1023, 1024, 1025, 1088, 2047, 2048, 2056, 2080, 3072, 4096, 8192, 8193,
];
/// Minimum sizes passed to `*_with_min_bits`.
const MIN_BITS: [usize; 7] = [1024, 2048, 1023, 4096, 8192, 8193, 0];

/// Op 0: a public key from fuzzed components.
fn op_components(fx: &Fixture, input: &mut Input<'_>) {
    let n_be: Vec<u8> = match input.choose(3) {
        0 => input.field().to_vec(),
        1 => {
            let bits = match input.choose(4) {
                0 => usize::from(input.u16()) % 8300 + 1,
                _ => *input.pick(&MODULUS_SIZES),
            };
            let mut n = expand(input.u64(), bits.div_ceil(8));
            let top = (bits - 1) % 8;
            n[0] &= 0xffu8 >> (7 - top);
            n[0] |= 1 << top;
            let mut padded = vec![0u8; input.choose(3)];
            padded.extend_from_slice(&n);
            let last = padded.len() - 1;
            padded[last] |= u8::from(input.bool());
            padded
        }
        _ => {
            let key = input.pick(&fx.keys);
            let mut n = key.public().n_be().to_vec();
            edit(&mut n, input);
            n
        }
    };
    let e_be: Vec<u8> = match input.choose(3) {
        0 => vec![1, 0, 1],
        1 => vec![3],
        _ => input.short_field().iter().take(7).copied().collect(),
    };
    let min_bits = match input.choose(4) {
        0 => usize::from(input.u16()),
        _ => *input.pick(&MIN_BITS),
    };
    let expected = expected_components(&n_be, &e_be, min_bits);
    let result = RsaPublicKey::from_components_with_min_bits(&n_be, &e_be, min_bits);
    assert_eq!(result.as_ref().err().copied(), expected.err(), "components");
    let default = RsaPublicKey::from_components(&n_be, &e_be);
    assert_eq!(
        default.as_ref().err().copied(),
        expected_components(&n_be, &e_be, MIN_MODULUS_BITS).err()
    );
    let Ok(key) = result else {
        return;
    };
    let reference = oracle::Public::new(&n_be, &e_be);
    assert_eq!(key.modulus_bits(), reference.bits);
    assert_eq!(key.modulus_len_bytes(), reference.k);
    assert_eq!(key.n_be().len(), reference.k);
    assert_eq!(BigUint::from_bytes_be(key.n_be()), reference.n);
    assert_eq!(BigUint::from_bytes_be(key.e_be()), reference.e);
    assert_eq!(BigUint::from(key.e()), reference.e);
    assert!(key.e_be().first().is_some_and(|&b| b != 0));
    // PKCS #1 encoding into a fuzzed buffer, and back.
    let full = public_pkcs1(&key);
    let mut out = vec![0u8; usize::from(input.u16()) % (full.len() + 8)];
    match key.to_pkcs1_der(&mut out) {
        Ok(n) => assert_eq!(out[..n], full[..]),
        Err(e) => {
            assert_eq!(e, Error::InvalidLength);
            assert!(out.len() < full.len());
        }
    }
    let back = RsaPublicKey::from_pkcs1_der_with_min_bits(&full, min_bits).expect("own encoding");
    assert_eq!((back.n_be(), back.e_be()), (key.n_be(), key.e_be()));
    assert_eq!(public_pkcs1(&back), full);
    let info = spki(RsaKeyAlgorithm::RsaEncryption, &full);
    let back = RsaPublicKey::from_spki_der_with_min_bits(&info, min_bits).expect("own SPKI");
    assert_eq!((back.n_be(), back.e_be()), (key.n_be(), key.e_be()));
    // Fuzzed signatures against an arbitrary odd modulus: the public
    // exponentiation of every backend against num-bigint.
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let sig = match input.choose(3) {
        0 => input.field().to_vec(),
        1 => oracle::to_fixed(&BigUint::from(input.u64()), reference.k),
        _ => expand(input.u64(), reference.k),
    };
    let policies = if reference.bits <= 4096 {
        backend_policies()
    } else {
        vec![Policy::PREFERRED]
    };
    for policy in policies {
        let key = with_policy(policy, || {
            RsaPublicKey::from_components_with_min_bits(&n_be, &e_be, min_bits)
        })
        .expect("accepted under another policy");
        check_verify(&key, &reference, hash, msg, &sig);
    }
}

/// Whether two parse results are the same key or the same error.
fn same_key(a: &Result<RsaPublicKey, Error>, b: &Result<RsaPublicKey, Error>) -> bool {
    match (a, b) {
        (Ok(a), Ok(b)) => a.n_be() == b.n_be() && a.e_be() == b.e_be(),
        (Err(a), Err(b)) => a == b,
        _ => false,
    }
}

/// Op 1: public-key DER.
fn op_public_der(fx: &Fixture, input: &mut Input<'_>) {
    let bytes: Vec<u8> = if input.bool() {
        input.field().to_vec()
    } else {
        let key = input.pick(&fx.keys);
        let mut v = if input.bool() {
            key.public_pkcs1.clone()
        } else {
            input.pick(&key.spki).clone()
        };
        edit(&mut v, input);
        v
    };
    let min_bits = match input.choose(3) {
        0 => LEGACY_MIN_MODULUS_BITS,
        1 => MIN_MODULUS_BITS,
        _ => usize::from(input.u16()),
    };
    let pkcs1 = RsaPublicKey::from_pkcs1_der(&bytes);
    assert!(same_key(
        &pkcs1,
        &RsaPublicKey::from_pkcs1_der_with_min_bits(&bytes, MIN_MODULUS_BITS)
    ));
    let pkcs1_min = RsaPublicKey::from_pkcs1_der_with_min_bits(&bytes, min_bits);
    let spki_default = RsaPublicKey::from_spki_der(&bytes);
    assert!(same_key(
        &spki_default,
        &RsaPublicKey::from_spki_der_with_min_bits(&bytes, MIN_MODULUS_BITS)
    ));
    let spki_min = RsaPublicKey::from_spki_der_with_min_bits(&bytes, min_bits);
    let with_alg = RsaPublicKey::from_spki_der_with_algorithm(&bytes);
    match (&spki_default, &with_alg) {
        (Ok(a), Ok((b, alg))) => {
            assert_eq!(*alg, RsaKeyAlgorithm::RsaEncryption);
            assert_eq!((a.n_be(), a.e_be()), (b.n_be(), b.e_be()));
        }
        (Ok(_), Err(e)) => panic!("rsaEncryption SPKI rejected with its algorithm: {e:?}"),
        (Err(_), Ok((_, alg))) => assert_ne!(*alg, RsaKeyAlgorithm::RsaEncryption),
        (Err(_), Err(_)) => {}
    }
    if let Ok((_, alg)) = &with_alg {
        let back = RsaKeyAlgorithm::from_algorithm_identifier(&algorithm_identifier(*alg));
        assert_eq!(back, Ok(*alg));
    }
    let keys = [
        pkcs1.ok(),
        pkcs1_min.ok(),
        spki_min.ok(),
        with_alg.ok().map(|(k, _)| k),
    ];
    for key in keys.into_iter().flatten() {
        let der = public_pkcs1(&key);
        let back = RsaPublicKey::from_pkcs1_der_with_min_bits(&der, LEGACY_MIN_MODULUS_BITS)
            .expect("own encoding");
        assert_eq!(public_pkcs1(&back), der);
        assert_eq!(back.modulus_bits(), key.modulus_bits());
        assert_eq!(back.e(), key.e());
    }
}

/// Op 2: key algorithm identifiers.
fn op_algorithm(input: &mut Input<'_>) {
    let bytes: Vec<u8> = if input.bool() {
        input.short_field().to_vec()
    } else {
        let mut v = algorithm_identifier(*input.pick(&KEY_ALGORITHMS));
        edit(&mut v, input);
        v
    };
    if let Ok(alg) = RsaKeyAlgorithm::from_algorithm_identifier(&bytes) {
        let canonical = algorithm_identifier(alg);
        assert_eq!(
            RsaKeyAlgorithm::from_algorithm_identifier(&canonical),
            Ok(alg)
        );
        assert_eq!(alg.allows_pkcs1v15(), alg == RsaKeyAlgorithm::RsaEncryption);
        for hash in HASHES {
            let expected = match alg {
                RsaKeyAlgorithm::RsaEncryption | RsaKeyAlgorithm::RsassaPss(None) => true,
                RsaKeyAlgorithm::RsassaPss(Some(h)) => h == hash,
            };
            assert_eq!(alg.allows_pss(hash), expected);
        }
    }
    // Any algorithm into a fuzzed buffer.
    let alg = *input.pick(&ALL_ALGORITHMS);
    let mut full = [0u8; MAX_ALGORITHM_IDENTIFIER_LEN];
    let full_result = alg.encode_algorithm_identifier(&mut full);
    let mut out = vec![0u8; input.choose(MAX_ALGORITHM_IDENTIFIER_LEN + 8)];
    let result = alg.encode_algorithm_identifier(&mut out);
    match full_result {
        Ok(n) => {
            assert!(KEY_ALGORITHMS.contains(&alg));
            assert_eq!(
                RsaKeyAlgorithm::from_algorithm_identifier(&full[..n]),
                Ok(alg)
            );
            match result {
                Ok(m) => assert_eq!(out[..m], full[..n]),
                Err(e) => {
                    assert_eq!(e, Error::InvalidLength);
                    assert!(out.len() < n);
                }
            }
        }
        Err(e) => {
            assert_eq!(e, Error::Unsupported);
            assert!(!KEY_ALGORITHMS.contains(&alg));
            assert!(result.is_err());
        }
    }
}

/// Op 3: PKCS #1 v1.5 signing.
fn op_sign_pkcs1(fx: &Fixture, input: &mut Input<'_>) {
    let key = input.pick(&fx.keys);
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let entropy = input.short_field();
    let k = key.k();
    let mut out = vec![0u8; out_len(k, input)];
    let signer = input.pick(&key.loaded);
    let result = signer.sign_pkcs1v15_with_rng(hash, msg, &FixedRng::new(entropy), &mut out);
    if entropy.len() < 32 {
        assert_eq!(result, Err(Error::RandomFailure));
        return;
    }
    if out.len() < k {
        assert_eq!(result, Err(Error::InvalidLength));
        let mut short = vec![0u8; out.len()];
        assert_eq!(
            signer.sign_pkcs1v15(hash, msg, &mut short),
            Err(Error::InvalidLength)
        );
        return;
    }
    assert_eq!(result, Ok(k));
    let sig = &out[..k];
    // One signature whatever the blinding entropy and the backend.
    let other = input.pick(&key.loaded);
    let mut again = vec![0u8; k];
    assert_eq!(other.sign_pkcs1v15(hash, msg, &mut again), Ok(k));
    assert_eq!(again, sig);
    let public = &key.reference.public;
    assert_eq!(
        check_verify(key.public(), public, hash, msg, sig),
        (true, false)
    );
    let bad = tamper(sig, input);
    assert_eq!(
        check_verify(key.public(), public, hash, msg, &bad),
        (false, false)
    );
    let other = *input.pick(&HASHES);
    if other != hash {
        assert!(verify_pkcs1v15(key.public(), other, msg, sig).is_err());
    }
}

/// Op 4: PSS signing.
fn op_sign_pss(fx: &Fixture, input: &mut Input<'_>) {
    let key = input.pick(&fx.keys);
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let rng_bytes = input.short_field();
    let k = key.k();
    let mut out = vec![0u8; out_len(k, input)];
    let signer = input.pick(&key.loaded);
    let result = signer.sign_pss(hash, msg, &FixedRng::new(rng_bytes), &mut out);
    let h_len = hash.output_len();
    if out.len() < k {
        assert_eq!(result, Err(Error::InvalidLength));
        return;
    }
    if rng_bytes.len() < h_len + 32 {
        assert_eq!(result, Err(Error::RandomFailure));
        return;
    }
    assert_eq!(result, Ok(k));
    let sig = &out[..k];
    let public = &key.reference.public;
    let salt = public.verify_pss(hash, msg, sig);
    assert_eq!(salt.as_deref(), Some(&rng_bytes[..h_len]), "PSS salt");
    assert_eq!(
        check_verify(key.public(), public, hash, msg, sig),
        (false, true)
    );
    // Fixed salt and blinding entropy: every backend signs identically.
    let other = input.pick(&key.loaded);
    let mut again = vec![0u8; k];
    let rng = FixedRng::new(rng_bytes);
    assert_eq!(other.sign_pss(hash, msg, &rng, &mut again), Ok(k));
    assert_eq!(again, sig);
    let bad = tamper(sig, input);
    assert_eq!(
        check_verify(key.public(), public, hash, msg, &bad),
        (false, false)
    );
}

/// Op 5: fuzzed signatures under the fixed keys.
fn op_verify(fx: &Fixture, input: &mut Input<'_>) {
    let key = input.pick(&fx.keys);
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let k = key.k();
    let n = &key.reference.public.n;
    let sig: Vec<u8> = match input.choose(5) {
        0 => input.field().iter().take(k + 2).copied().collect(),
        1 => {
            let mut sig = vec![0u8; k];
            key.loaded[0]
                .sign_pkcs1v15(hash, msg, &mut sig)
                .expect("signing");
            edit(&mut sig, input);
            sig
        }
        2 => {
            let mut sig = vec![0u8; k];
            key.loaded[0]
                .sign_pss(hash, msg, &FixedRng::new(&[0x5a; 96]), &mut sig)
                .expect("signing");
            edit(&mut sig, input);
            sig
        }
        3 => oracle::to_fixed(&BigUint::from(input.u64()), k),
        _ => {
            let small = BigUint::from(input.u64()) % n;
            oracle::to_fixed(&(n - small), k)
        }
    };
    check_verify(key.public(), &key.reference.public, hash, msg, &sig);
}

/// Op 6: encodings built and signed by the reference.
fn op_forge(fx: &Fixture, input: &mut Input<'_>) {
    let key = input.pick(&fx.keys);
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let reference = &key.reference;
    let k = reference.public.k;
    let h_len = hash.output_len();
    if input.bool() {
        // PSS with a fuzzed salt length: only sLen = hLen verifies.
        let em_bits = reference.public.bits - 1;
        let max_salt = em_bits.div_ceil(8) - h_len - 2;
        let salt_len = if input.bool() {
            h_len
        } else {
            usize::from(input.u16()) % (max_salt + 1)
        };
        let mut salt = input.bytes(salt_len).to_vec();
        salt.resize(salt_len, 0);
        let em = oracle::pss_encode(hash, msg, &salt, em_bits).expect("salt fits");
        let mut padded = vec![0u8; k - em.len()];
        padded.extend_from_slice(&em);
        let sig = reference.sign_raw(&padded).expect("EM < n");
        let accepted = salt_len == h_len;
        assert_eq!(
            verify_pss(key.public(), hash, msg, &sig).is_ok(),
            accepted,
            "salt length {salt_len}"
        );
        assert_eq!(
            check_verify(key.public(), &reference.public, hash, msg, &sig).1,
            accepted
        );
    } else {
        // PKCS #1 v1.5 encodings near the canonical one.
        let digest = oracle::digest(hash, &[msg]);
        let canonical =
            oracle::pkcs1_em(&oracle::digest_info(hash, &digest, true), k).expect("fits");
        let mut em = canonical.clone();
        match input.choose(3) {
            0 => {
                let at = usize::from(input.u16()) % k;
                em[at] ^= input.byte().max(1);
            }
            1 => {
                // Garbage after the DigestInfo, taken from the padding.
                let ps_len = em[2..].iter().take_while(|&&b| b == 0xff).count();
                let g = usize::from(input.u16()) % (ps_len + 1);
                em.drain(2..2 + g);
                for _ in 0..g {
                    em.push(input.byte());
                }
            }
            _ => {
                // A DigestInfo without the NULL parameters.
                em = oracle::pkcs1_em(&oracle::digest_info(hash, &digest, false), k).expect("fits");
            }
        }
        let Some(sig) = reference.sign_raw(&em) else {
            return;
        };
        let accepted = em == canonical;
        assert_eq!(
            verify_pkcs1v15(key.public(), hash, msg, &sig).is_ok(),
            accepted
        );
        assert_eq!(
            check_verify(key.public(), &reference.public, hash, msg, &sig).0,
            accepted
        );
    }
}

/// Number of private-key encodings per fixed key: PKCS #8 for each of
/// [`KEY_ALGORITHMS`], then PKCS #1.
const PRIVATE_ENCODINGS: usize = KEY_ALGORITHMS.len() + 1;

/// Op 7: private-key DER.
fn op_private_der(fx: &Fixture, input: &mut Input<'_>) {
    let parser = input.choose(3);
    // `Some(which)` for an unedited fixture encoding.
    let (bytes, unedited) = if input.bool() {
        let raw = input.field();
        let raw = &raw[..raw.len().min(MAX_PKCS8_PRIVATE_KEY_DER_LEN + 16)];
        (raw.to_vec(), None)
    } else {
        let key = input.pick(&fx.keys);
        let which = input.choose(PRIVATE_ENCODINGS);
        let mut v = key.pkcs8.get(which).unwrap_or(&key.pkcs1).clone();
        let changed = edit(&mut v, input);
        (v, (!changed).then_some(which))
    };
    let result = match parser {
        0 => RsaPrivateKey::from_pkcs1_der(&bytes).map(|k| (k, None)),
        1 => RsaPrivateKey::from_pkcs8_der(&bytes).map(|k| (k, None)),
        _ => RsaPrivateKey::from_pkcs8_der_with_algorithm(&bytes).map(|(k, a)| (k, Some(a))),
    };
    // Unedited encodings load with the parser for their form.
    let must_load = unedited.is_some_and(|which| match parser {
        0 => which == KEY_ALGORITHMS.len(),
        1 => which == 0,
        _ => which < KEY_ALGORITHMS.len(),
    });
    let (key, alg) = match result {
        Ok(loaded) => loaded,
        Err(e) => {
            assert!(!must_load, "fixture encoding rejected: {e:?}");
            return;
        }
    };
    let public = key.public_key();
    assert_eq!(key.modulus_len_bytes(), public.modulus_len_bytes());
    assert_eq!(key.modulus_bits(), public.modulus_bits());
    let reference = oracle::Public::new(public.n_be(), public.e_be());
    // An accepted key signs correctly with both paddings.
    let hash = *input.pick(&HASHES);
    let k = key.modulus_len_bytes();
    let mut sig = vec![0u8; k];
    let msg = b"key check";
    let result = key.sign_pkcs1v15_with_rng(hash, msg, &FixedRng::new(&[7; 32]), &mut sig);
    assert_eq!(result, Ok(k));
    assert!(reference.verify_pkcs1v15(hash, msg, &sig));
    let result = key.sign_pss(hash, msg, &FixedRng::new(&[9; 96]), &mut sig);
    assert_eq!(result, Ok(k));
    assert!(reference.verify_pss(hash, msg, &sig).is_some());
    // Encodings into full and fuzzed buffers.
    let mut full1 = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let n1 = key.to_pkcs1_der(&mut full1).expect("PKCS #1");
    full1.truncate(n1);
    let out_alg = *input.pick(&ALL_ALGORITHMS);
    let mut full8 = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
    let result = key.to_pkcs8_der_with_algorithm(out_alg, &mut full8);
    if KEY_ALGORITHMS.contains(&out_alg) {
        full8.truncate(result.expect("PKCS #8"));
    } else {
        assert_eq!(result, Err(Error::Unsupported));
        assert!(full8.iter().all(|&b| b == 0), "failed write left data");
    }
    let mut buf8 = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
    let n8 = key.to_pkcs8_der(&mut buf8).expect("PKCS #8");
    if out_alg == RsaKeyAlgorithm::RsaEncryption {
        assert_eq!(buf8[..n8], full8[..]);
    }
    let size = usize::from(input.u16()) % (MAX_PKCS8_PRIVATE_KEY_DER_LEN + 1);
    let mut out = vec![0xa5u8; size];
    match key.to_pkcs1_der(&mut out) {
        Ok(n) => assert_eq!(out[..n], full1[..]),
        Err(e) => {
            assert_eq!(e, Error::InvalidLength);
            assert!(size < n1);
            assert!(out.iter().all(|&b| b == 0), "failed write left data");
        }
    }
    let mut out = vec![0xa5u8; size];
    match key.to_pkcs8_der_with_algorithm(out_alg, &mut out) {
        Ok(n) => assert_eq!(out[..n], full8[..]),
        // A failed write leaves the buffer untouched or zeroed.
        Err(_) => assert!(
            out.iter().all(|&b| b == 0) || out.iter().all(|&b| b == 0xa5),
            "failed write left data"
        ),
    }
    // Unedited encodings re-encode byte for byte.
    if let Some(which) = unedited {
        match (parser, alg) {
            (0, _) => assert_eq!(full1, bytes),
            (1, _) => assert_eq!(buf8[..n8], bytes[..]),
            (_, Some(alg)) => {
                assert_eq!(alg, KEY_ALGORITHMS[which]);
                let mut out = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
                let n = key
                    .to_pkcs8_der_with_algorithm(alg, &mut out)
                    .expect("PKCS #8");
                assert_eq!(out[..n], bytes[..]);
            }
            _ => unreachable!("the algorithm parser returns one"),
        }
    }
}

/// Op 8: key generation that must fail, cheaply.
fn op_generate(input: &mut Input<'_>) {
    const SIZES: [usize; 8] = [0, 1024, 2047, 2048, 3072, 4096, 8192, 2049];
    let bits = match input.choose(4) {
        0 => usize::from(input.u16()),
        _ => *input.pick(&SIZES),
    };
    // At most 255 bytes: too few for two prime candidates of 1024 bits.
    let bytes = input.short_field();
    let result = RsaPrivateKey::generate(bits, &FixedRng::new(bytes)).map(|_| ());
    if matches!(bits, 2048 | 3072 | 4096) {
        assert_eq!(result, Err(Error::RandomFailure));
    } else {
        assert_eq!(result, Err(Error::Unsupported));
    }
}

/// The `crypto_rsa` fuzz target.
pub fn run(data: &[u8]) {
    let fx = fixture();
    let mut input = Input::new(data);
    let mut loads = 0;
    let mut forgeries = 0;
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match input.choose(9) {
            0 => op_components(fx, &mut input),
            1 => op_public_der(fx, &mut input),
            2 => op_algorithm(&mut input),
            3 => op_sign_pkcs1(fx, &mut input),
            4 => op_sign_pss(fx, &mut input),
            5 => op_verify(fx, &mut input),
            6 if forgeries < MAX_FORGERIES => {
                forgeries += 1;
                op_forge(fx, &mut input);
            }
            7 if loads < MAX_PRIVATE_LOADS => {
                loads += 1;
                op_private_der(fx, &mut input);
            }
            8 => op_generate(&mut input),
            _ => {}
        }
    }
}

/// `id-RSASSA-PSS` AlgorithmIdentifier contents in the accepted
/// non-canonical forms, and rejected ones.
fn algorithm_variants() -> Vec<Vec<u8>> {
    const PSS_OID: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    ];
    let sha256 = |null: bool| {
        let mut v = vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        if null {
            v.extend_from_slice(&[0x05, 0x00]);
        }
        tlv(0x30, &v)
    };
    let mgf1 = |null: bool| {
        let mut v = vec![
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
        ];
        v.extend_from_slice(&sha256(null));
        tlv(0x30, &v)
    };
    let params = |fields: &[Vec<u8>]| {
        let mut v = PSS_OID.to_vec();
        v.extend_from_slice(&tlv(0x30, &fields.concat()));
        v
    };
    let int = |v: u8| vec![0x02, 0x01, v];
    vec![
        // Hash parameters absent, salt length absent (DEFAULT 20).
        params(&[tlv(0xa0, &sha256(false)), tlv(0xa1, &mgf1(false))]),
        // Salt length 0, explicit trailer field 1.
        params(&[
            tlv(0xa0, &sha256(true)),
            tlv(0xa1, &mgf1(true)),
            tlv(0xa2, &int(0)),
            tlv(0xa3, &int(1)),
        ]),
        // Explicit DEFAULT salt length (not DER), salt longer than the
        // digest, trailer field 2.
        params(&[
            tlv(0xa0, &sha256(true)),
            tlv(0xa1, &mgf1(true)),
            tlv(0xa2, &int(20)),
        ]),
        params(&[
            tlv(0xa0, &sha256(true)),
            tlv(0xa1, &mgf1(true)),
            tlv(0xa2, &int(33)),
        ]),
        params(&[
            tlv(0xa0, &sha256(true)),
            tlv(0xa1, &mgf1(true)),
            tlv(0xa3, &int(2)),
        ]),
        // Empty parameters (SHA-1 defaults); NULL parameters.
        params(&[]),
        [PSS_OID.as_slice(), &[0x05, 0x00]].concat(),
        // rsaEncryption without its NULL.
        vec![
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ],
    ]
}

/// Starting inputs for `crypto_rsa`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let fx = fixture();
    let msg = b"browntls fuzz message";
    let mut seeds = Vec::new();
    // 0: a structured modulus of each listed size with e = 65537, minimum
    // 1024, then a random signature.
    for size in 0..MODULUS_SIZES.len() as u8 {
        let mut s = vec![0, 1, 1, size];
        s.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x12, size + 1]);
        s.extend_from_slice(&[0, 1, 0, 1, 0]); // no zeros, odd; 65537; 1024
        s.extend_from_slice(&[0xff, 0xff, 1]); // buffer; SHA-256
        put_field(&mut s, msg);
        s.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, size]);
        seeds.push(s);
    }
    // A raw modulus, e from a short field, minimum 2048; a fixed key's
    // modulus with a flipped byte and e = 3; an even modulus.
    let mut s = vec![0, 0];
    put_field(&mut s, &[0xc3; 256]);
    s.push(2);
    put_short_field(&mut s, &[0, 0, 1, 0, 1]);
    s.extend_from_slice(&[1, 1, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    seeds.push(s);
    seeds.push(vec![0, 2, 0, 1, 0, 9, 0x40, 1, 2, 0, 0, 3, 1, 0]);
    seeds.push(vec![
        0, 1, 1, 5, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0x10, 0x01,
    ]);
    // 1: every public encoding of every key, unedited.
    for key in 0..2u8 {
        seeds.push(vec![1, 0, key, 1, 0, 0, 0, 0, 0]);
        seeds.push(vec![1, 0, key, 1, 0, 0, 0, 0, 2, 0x04, 0x00]);
        for spki in 0..5u8 {
            seeds.push(vec![1, 0, key, 0, spki, 0, 0, 0, 0, 1]);
        }
    }
    let mut s = vec![1, 1];
    put_field(&mut s, &fx.keys[0].spki[0]);
    s.push(0);
    seeds.push(s);
    // 2: the canonical identifiers and the hand-made variants, each with a
    // full and a short output buffer.
    for alg in 0..KEY_ALGORITHMS.len() as u8 {
        seeds.push(vec![2, 0, alg, 0, 0, 0, 0, alg, 72]);
        seeds.push(vec![2, 0, alg, 1, 0, 3, 0x01, alg + 4, 3]);
    }
    for contents in algorithm_variants() {
        let mut s = vec![2, 1];
        put_short_field(&mut s, &contents);
        s.extend_from_slice(&[5, 72]);
        seeds.push(s);
    }
    // 3, 4: signing with each key and hash, then the error paths.
    // (The 3072-bit key once per operation: debug builds are slow.)
    for hash in 0..HASHES.len() as u8 {
        let key = u8::from(hash == 3);
        let mut s = vec![3, key, hash];
        put_field(&mut s, msg);
        put_short_field(&mut s, &[0x11; 32]);
        s.extend_from_slice(&[hash % 2, hash, hash + 1, 0, 5 * hash, hash + 1]);
        seeds.push(s);
        let mut s = vec![4, key, hash];
        put_field(&mut s, msg);
        put_short_field(&mut s, &[0x22; 96]);
        s.extend_from_slice(&[hash % 2, hash, hash + 2, 0, 9 * hash]);
        seeds.push(s);
    }
    for (op, entropy, out) in [(3u8, 31usize, 0u8), (3, 32, 2), (4, 96, 2), (4, 40, 0)] {
        let mut s = vec![op, 0, 1];
        put_field(&mut s, msg);
        put_short_field(&mut s, &vec![0x33; entropy]);
        s.extend_from_slice(&[out, 0, 100, 0]);
        seeds.push(s);
    }
    // 5: each signature source.
    for mode in 0..5u8 {
        let mut s = vec![5, 0, 1];
        put_field(&mut s, msg);
        s.push(mode);
        match mode {
            0 => put_field(&mut s, &[0x42; 256]),
            1 | 2 => s.extend_from_slice(&[1, 0, 7, 0x80]),
            _ => s.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]),
        }
        seeds.push(s);
    }
    // 6: PSS with sLen = hLen and with 20 bytes; each PKCS #1 variant.
    for tail in [vec![1u8, 1], vec![1, 0, 0, 20]] {
        let mut s = vec![6, 0, 1];
        put_field(&mut s, msg);
        s.extend_from_slice(&tail);
        seeds.push(s);
    }
    for variant in 0..3u8 {
        let mut s = vec![6, 0, 3];
        put_field(&mut s, msg);
        s.extend_from_slice(&[0, variant, 0, 4, 0xff, 1, 2, 3, 4]);
        seeds.push(s);
    }
    // 7: every private encoding through every parser, unedited, with
    // encodings into full and short buffers.
    let pairs: [(u8, u8); 9] = [
        (0, 5),
        (0, 0),
        (1, 0),
        (1, 2),
        (2, 1),
        (2, 2),
        (2, 3),
        (2, 4),
        (2, 5),
    ];
    for (parser, which) in pairs {
        seeds.push(vec![
            7, parser, 0, 0, which, 0, 0, 0, 0, which, which, 0x30, 0,
        ]);
    }
    seeds.push(vec![7, 0, 0, 0, 5, 0, 0, 0, 0, 1, 7, 0x00, 0x10]);
    seeds.push(vec![7, 0, 0, 0, 5, 1, 0, 0x40, 1, 1, 0, 0x00, 0x10]);
    // 8: generation with too little randomness, and unsupported sizes.
    for size in 0..8u8 {
        seeds.push(vec![8, 1, size, 4, 1, 2, 3, 4]);
    }
    seeds.push(vec![8, 0, 0x08, 0x00, 0]);
    seeds
}

//! `browntls_crypto::rsa`: public and private key encodings, key algorithm
//! identifiers, PKCS #1 v1.5 and PSS signing and verification, key
//! generation.
//!
//! Two RSA keys (2048 and 3072 bits) are generated once per process by the
//! crate's own key generation from a fixed deterministic byte source, so
//! inputs replay exactly; each is loaded again under every RSA backend the
//! CPU offers (AVX-512 IFMA, BMI2/ADX, portable). Signatures are repeated
//! with load-aware routing (`accel::load`) sending a fuzzed share of them to
//! a fuzzed alternate backend, which never changes them. Nothing secret is
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
//! | 3 sign PKCS #1 | key, hash, message, blinding entropy, buffer size, backend, bit, hash, routing alternate and share | exact errors; one signature whatever the entropy, the backend and the routing; the reference verifies it; a flipped bit fails everywhere |
//! | 4 sign PSS | key, hash, message, salt and entropy, buffer size, backend, bit, routing alternate and share | exact errors; backends agree for fixed randomness, with and without routing; the reference recovers the salt; a flipped bit fails |
//! | 5 verify | key, hash, message, signature source | browntls and the reference agree for both paddings |
//! | 6 forge | key, hash, message, salt length or encoding edit | encodings signed by the reference: PSS accepts only `sLen = hLen`, PKCS #1 v1.5 only the canonical encoding |
//! | 7 private DER | parser, source, hash, algorithm, buffer size | accepted keys sign correctly; unedited encodings load and re-encode byte for byte; failed writes leave the buffer zeroed |
//! | 8 generate | size, byte source | `Unsupported` sizes, `RandomFailure` for sources too short for two primes |
//!
//! A "source" is raw fuzzed bytes, or a valid encoding made by the harness
//! with one fuzzed edit (none, flip, truncate, insert or delete a byte).
//! Private-key loads (each runs a signing self-test) and signatures made by
//! the reference are limited to two each per input.

mod keys;
mod oracle;
mod sign;

use std::cell::Cell;
use std::sync::OnceLock;

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Acceleration, Algorithm, Policy};
use browntls_crypto::der;
use browntls_crypto::hash::HashAlgorithm;
use browntls_crypto::rand::SecureRandom;
use browntls_crypto::rsa::{
    MAX_ALGORITHM_IDENTIFIER_LEN, MAX_PKCS8_PRIVATE_KEY_DER_LEN, RsaKeyAlgorithm, RsaPrivateKey,
    RsaPublicKey, verify_pkcs1v15, verify_pss,
};
use num_bigint::BigUint;
use sha2::Digest as _;

use self::keys::{
    MODULUS_SIZES, op_algorithm, op_components, op_generate, op_private_der, op_public_der,
};
use self::oracle::HASHES;
use self::sign::{op_forge, op_sign_pkcs1, op_sign_pss, op_verify};
use crate::crypto_hash::with_fixed_share;
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

/// Load-aware routing moves the signatures of a key loaded under the
/// default policy to a lower backend and never changes them: with a fuzzed
/// share of the signatures of every key size fixed on a fuzzed alternate,
/// `sign` gives `sig` through that key (`key.loaded[0]`) and through
/// `signer`, a key of a fuzzed backend, which is routed only if it is the
/// same one.
fn check_routed(
    key: &FixedKey,
    signer: &RsaPrivateKey,
    sig: &[u8],
    input: &mut Input<'_>,
    sign: impl Fn(&RsaPrivateKey, &mut [u8]) -> Result<usize, Error>,
) {
    let (alternate, percent) = (input.byte(), input.byte());
    let routed = with_fixed_share(Algorithm::Rsa, alternate, percent, || {
        [&key.loaded[0], signer].map(|signer| {
            let mut out = vec![0u8; sig.len()];
            sign(signer, &mut out).map(|_| out)
        })
    });
    for out in routed {
        assert_eq!(out.as_deref(), Ok(sig), "RSA with load-aware routing");
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
    // Each ends with a routing alternate and its share of the signatures:
    // all, half and a few of them, on each alternate in turn.
    for hash in 0..HASHES.len() as u8 {
        let key = u8::from(hash == 3);
        let share = [100, 50, 1][usize::from(hash % 3)];
        let mut s = vec![3, key, hash];
        put_field(&mut s, msg);
        put_short_field(&mut s, &[0x11; 32]);
        s.extend_from_slice(&[hash % 2, hash, hash + 1, 0, 5 * hash, hash + 1]);
        s.extend_from_slice(&[hash, share]);
        seeds.push(s);
        let mut s = vec![4, key, hash];
        put_field(&mut s, msg);
        put_short_field(&mut s, &[0x22; 96]);
        s.extend_from_slice(&[hash % 2, hash, hash + 2, 0, 9 * hash]);
        s.extend_from_slice(&[hash + 1, share]);
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

//! `browntls-crypto` HPKE (RFC 9180, base mode) and the TLS-side HPKE
//! provider API (`browntls::crypto::hpke`, implemented by
//! `browntls::crypto::native::hpke`).
//!
//! The input is a program of up to [`MAX_OPS`] operations, each an op byte
//! followed by its arguments:
//!
//! - identifiers: fuzzed KEM, KDF and AEAD identifiers look up exactly the
//!   listed algorithms, `Suite::from_ids` agrees, every length accessor is
//!   consistent, and the TLS-side `HpkeAead::tag_len` agrees with the crate.
//! - keys: `DeriveKeyPair` on fuzzed key material, private and public key
//!   deserialization of fuzzed bytes, serialization, `GenerateKeyPair` from a
//!   fixed random source, and setups with a key of another KEM; checked
//!   against the RustCrypto `hpke` oracle (no oracle for X448).
//! - session: a suite, recipient key material, the sender's ephemeral key
//!   material (a fixed random source, so the encapsulation is deterministic)
//!   and `info`, then a sub-program of seals (in place or not) with fuzzed
//!   aad and plaintext, in-order and out-of-order opens, tampered and fuzzed
//!   ciphertexts, exports of fuzzed lengths and a recipient setup with a
//!   fuzzed `enc`. Sealed ciphertexts and exported secrets must equal the
//!   oracle's byte for byte, both contexts must agree, rejected ciphertexts
//!   must not advance the sequence number, and the oracle must accept and
//!   reject the same `enc` values.
//! - provider: one of the native provider's suites through the `Hpke`,
//!   `HpkeSealer` and `HpkeOpener` traits with fuzzed info, aad, plaintext,
//!   public keys, private keys and `enc`; results must agree with the crate
//!   API underneath.

mod keys;
mod provider;
mod session;

use browntls_crypto::hpke::{Aead, Kdf, Kem, Suite};

use self::keys::{ids, keys, private_bytes};
use self::provider::provider;
use self::session::session;
use crate::input::{Input, put_field, put_short_field};

/// Operations per input.
const MAX_OPS: usize = 8;
/// Steps of one session's sub-program.
const MAX_STEPS: usize = 16;

const OP_IDS: u8 = 0;
const OP_KEYS: u8 = 1;
const OP_SESSION: u8 = 2;
const OP_PROVIDER: u8 = 3;
const OPS: usize = 4;

const STEP_SEAL: u8 = 0;
const STEP_SEAL_IN_PLACE: u8 = 1;
const STEP_OPEN: u8 = 2;
const STEP_OPEN_FUZZED: u8 = 3;
const STEP_EXPORT: u8 = 4;
const STEP_OUT_OF_ORDER: u8 = 5;
const STEP_RECIPIENT: u8 = 6;
const STEPS: usize = 7;

/// The `crypto_hpke` fuzz target.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match u8::try_from(input.choose(OPS)).unwrap_or(0) {
            OP_IDS => ids(&mut input),
            OP_KEYS => keys(&mut input),
            OP_SESSION => session(&mut input),
            _ => provider(&mut input),
        }
    }
}

/// `len` bytes from the input, zero-padded.
fn exact(input: &mut Input<'_>, len: usize) -> Vec<u8> {
    let mut out = input.bytes(len).to_vec();
    out.resize(len, 0);
    out
}

/// Fuzzed byte flips and a fuzzed length change.
fn mutate(input: &mut Input<'_>, bytes: &mut Vec<u8>) {
    for _ in 0..input.choose(3) {
        let pos = input.choose(256) % bytes.len().max(1);
        let flip = input.byte();
        if let Some(b) = bytes.get_mut(pos) {
            *b ^= flip;
        }
    }
    match input.choose(6) {
        1 => {
            bytes.pop();
        }
        2 => bytes.push(input.byte()),
        _ => {}
    }
}

/// A suite chosen by three bytes.
fn suite(input: &mut Input<'_>) -> Suite {
    Suite::new(
        *input.pick(&Kem::ALL),
        *input.pick(&Kdf::ALL),
        *input.pick(&Aead::ALL),
    )
}

/// The steps of a session seed that reach every step kind, for a KEM with
/// `enc_len`-byte encapsulated keys.
fn session_steps(enc_len: usize) -> Vec<u8> {
    let mut steps = Vec::new();
    for (aad, pt) in [(&b"aad"[..], &b"hello"[..]), (b"", b"")] {
        steps.push(STEP_SEAL);
        put_short_field(&mut steps, aad);
        put_field(&mut steps, pt);
    }
    steps.extend_from_slice(&[STEP_SEAL_IN_PLACE, 1, b'a', 0, 9]);
    steps.extend_from_slice(b"in place!");
    steps.extend_from_slice(&[STEP_OUT_OF_ORDER, 0]);
    // tampered: a flipped bit, extra aad, a short ciphertext
    steps.extend_from_slice(&[STEP_OPEN, 0, 1, 0, 3, 5]);
    steps.extend_from_slice(&[STEP_OPEN, 1, 2, 7]);
    steps.extend_from_slice(&[STEP_OPEN, 1, 3]);
    // genuine, then in place
    steps.extend_from_slice(&[STEP_OPEN, 0, 0]);
    steps.extend_from_slice(&[STEP_OPEN, 1, 0]);
    // forgeries: shorter than a tag, and tag-sized
    steps.extend_from_slice(&[STEP_OPEN_FUZZED, 0, 0, 3, 1, 2, 3, 1]);
    steps.extend_from_slice(&[STEP_OPEN_FUZZED, 0, 0, 20]);
    steps.extend_from_slice(&[0; 20]);
    steps.push(1);
    // exports: short, at the limit, past the limit, fuzzed
    steps.extend_from_slice(&[STEP_EXPORT, 3, b'c', b't', b'x', 0, 42]);
    steps.extend_from_slice(&[STEP_EXPORT, 0, 1, 4]);
    steps.extend_from_slice(&[STEP_EXPORT, 0, 1, 5]);
    steps.extend_from_slice(&[STEP_EXPORT, 1, b'e', 2, 0x12, 0x34]);
    // recipients: the genuine enc, a mutated one, a fuzzed one
    steps.extend_from_slice(&[STEP_RECIPIENT, 1, 0, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_RECIPIENT, 1, 1, 0, 9, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_RECIPIENT, 0]);
    steps.extend(core::iter::repeat_n(0x11, enc_len));
    steps.extend_from_slice(&[0, 0, 0]);
    // the last message
    steps.extend_from_slice(&[STEP_OPEN, 0, 0]);
    steps
}

/// Starting inputs for `crypto_hpke`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    // identifiers: valid, unknown, export-only, fully fuzzed
    for ids in [[2u8, 1, 1], [3, 33, 3], [0x23, 0x20, 0], [0x12, 2, 0x10]] {
        seeds.push(vec![OP_IDS, 2, ids[0], 2, ids[1], 2, ids[2]]);
    }
    seeds.push(vec![OP_IDS, 1, 0xff, 2, 1, 1, 0xff]);
    seeds.push(vec![OP_IDS, 0, 0x00, 0x20, 0, 0x00, 0x01, 1, 0xfe]);

    let ikm: Vec<u8> = (0..66u8).map(|i| i.wrapping_mul(47) ^ 0x2d).collect();
    for (k, kem) in (0u8..).zip(Kem::ALL) {
        let nsk = kem.private_key_len();
        let sk = private_bytes(&kem.derive_key_pair(&ikm).expect("long enough"));
        // DeriveKeyPair: long enough, too short
        let mut derive = vec![OP_KEYS, k, 0];
        put_short_field(&mut derive, &ikm);
        derive.extend_from_slice(&[5, 2]);
        seeds.push(derive);
        let mut short = vec![OP_KEYS, k, 0];
        put_short_field(&mut short, &ikm[..20]);
        seeds.push(short);
        // private keys: valid, fuzzed, zero, all ones, a length error
        seeds.push([&[OP_KEYS, k, 1][..], &sk, &[0, 0, 0]].concat());
        seeds.push([&[OP_KEYS, k, 1][..], &ikm[..nsk], &[0, 0, 0]].concat());
        seeds.push([&[OP_KEYS, k, 1][..], &ikm[..nsk], &[0, 0, 1, 1]].concat());
        seeds.push([&[OP_KEYS, k, 1][..], &ikm[..nsk], &[0, 0, 1, 0]].concat());
        seeds.push([&[OP_KEYS, k, 1][..], &sk, &[0, 1, 0]].concat());
        // public keys: genuine, mutated, fuzzed
        seeds.push([&[OP_KEYS, k, 2, 1][..], &ikm[..nsk], &[0, 0]].concat());
        seeds.push([&[OP_KEYS, k, 2, 1][..], &ikm[..nsk], &[1, 40, 1, 0]].concat());
        seeds.push([&[OP_KEYS, k, 2, 1][..], &ikm[..nsk], &[0, 2, 7]].concat());
        seeds.push([&[OP_KEYS, k, 2, 0][..], &ikm, &ikm, &ikm[..1], &[0, 0]].concat());
        // GenerateKeyPair: enough and too few random bytes
        let mut generate = vec![OP_KEYS, k, 3];
        put_short_field(&mut generate, &ikm);
        seeds.push(generate);
        seeds.push(vec![OP_KEYS, k, 3, 4, 1, 2, 3, 4]);
        // a key of another KEM, and of the same KEM
        seeds.push([&[OP_KEYS, k, 4, (k + 1) % 5][..], &ikm, &[0, 0]].concat());
        seeds.push([&[OP_KEYS, k, 4, k][..], &ikm, &[1, 2]].concat());
    }

    // Sessions with every step (the KDF rotates).
    for (k, kem) in (0u8..).zip(Kem::ALL) {
        let nsk = kem.private_key_len();
        let steps = session_steps(kem.enc_len());
        // X25519 with every AEAD; the other KEMs with one sealing AEAD and
        // P-256 also export-only (sessions on the larger curves are slow in
        // debug builds).
        let aeads: &[u8] = match kem {
            Kem::DhX25519HkdfSha256 => &[0, 1, 2, 3],
            Kem::DhP256HkdfSha256 => &[0, 3],
            _ => &[k % 3],
        };
        for &aead in aeads {
            let kdf = (k + aead) % 3;
            let mut seed = vec![OP_SESSION, k, kdf, aead];
            put_short_field(&mut seed, &ikm);
            seed.push(1); // a full random source
            seed.extend_from_slice(&ikm[..nsk]);
            put_short_field(&mut seed, b"info");
            seed.extend_from_slice(&steps);
            seeds.push(seed);
        }
        // short recipient key material, and a short random source
        let mut seed = vec![OP_SESSION, k, 0, 0];
        put_short_field(&mut seed, &ikm[..8]);
        seeds.push(seed);
        let mut seed = vec![OP_SESSION, k, 1, 2];
        put_short_field(&mut seed, &ikm);
        seed.extend_from_slice(&[0, 7]);
        seed.extend_from_slice(&ikm[..7]);
        seeds.push(seed);
    }

    // The provider: derived and generated keys, fuzzed public keys, private
    // keys and enc, seal/open rounds with tampering.
    let mut rounds = Vec::new();
    for tamper in [&[0u8][..], &[1, 0, 3, 5], &[2, 10]] {
        put_short_field(&mut rounds, b"aad");
        put_field(&mut rounds, b"client hello inner");
        rounds.extend_from_slice(tamper);
    }
    let all = browntls::crypto::native::hpke::ALL_SUPPORTED_SUITES;
    for index in [0u8, 9, 18, 27, 36, 2, 13, 44] {
        let tls = all[usize::from(index) % all.len()].suite();
        let kem = Kem::from_id(tls.kem.0).expect("crate KEM");
        let nsk = kem.private_key_len();
        let derived = [&[OP_PROVIDER, index, 0][..], &ikm[..nsk]].concat();
        let mut seed = derived.clone();
        put_short_field(&mut seed, b"info");
        seed.extend_from_slice(&[1, 1, 0]);
        seed.extend_from_slice(&rounds);
        seeds.push(seed);
        let mut seed = vec![OP_PROVIDER, index, 1];
        put_short_field(&mut seed, b"");
        seed.extend_from_slice(&[1, 1, 1, 1, 0, 0x80, 0]);
        seed.extend_from_slice(&rounds);
        seeds.push(seed);
        seeds.push([&derived[..], &[0, 0, 0, 0]].concat());
        seeds.push([&derived[..], &[0, 0, 1, 0, 0x80, 0]].concat());
        seeds.push([&derived[..], &[0, 1, 0, 0, 0]].concat());
        seeds.push([&derived[..], &[0, 1, 0, 0, 1]].concat());
    }
    seeds
}

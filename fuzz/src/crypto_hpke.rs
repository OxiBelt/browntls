//! `browntls-crypto` HPKE (RFC 9180, all four modes) and the TLS-side HPKE
//! provider API (`browntls_core::crypto::hpke`, implemented by
//! `browntls_core::crypto::native::hpke`).
//!
//! The input is a program of up to [`MAX_OPS`] operations, each an op byte
//! followed by its arguments:
//!
//! - identifiers: fuzzed KEM, KDF and AEAD identifiers look up exactly the
//!   listed algorithms, `Suite::from_ids` agrees, every length accessor is
//!   consistent, and the TLS-side `HpkeAead::tag_len` agrees with the crate;
//!   a fuzzed mode identifier looks up exactly the listed modes (`Mode`),
//!   which take a PSK and a sender key as RFC 9180 Table 1 says.
//! - keys: `DeriveKeyPair` on fuzzed key material, private and public key
//!   deserialization of fuzzed bytes, serialization, `GenerateKeyPair` from a
//!   fixed random source, and setups with a key of another KEM; checked
//!   against the RustCrypto `hpke` oracle (no oracle for X448).
//! - session: a suite, recipient key material, the sender's ephemeral key
//!   material (a fixed random source, so the encapsulation is deterministic)
//!   and `info`; bits of the random-source byte select a PSK mode
//!   ([`SETUP_PSK`], with a fuzzed PSK and identifier) and an authenticated
//!   one ([`SETUP_AUTH`], with fuzzed sender key material for
//!   `DeriveKeyPair`). `Psk::new` must refuse exactly a key shorter than
//!   `MIN_PSK_LEN` or an empty identifier, and accept only what the oracle's
//!   `PskBundle::new` accepts; the oracle, which takes shorter keys, is
//!   compared only on PSKs we accept. A refused PSK, or sender key material
//!   too short, leaves the session without it. Then a sub-program of seals
//!   (in place or not) with fuzzed aad and plaintext, in-order and
//!   out-of-order opens, tampered and fuzzed ciphertexts, exports of fuzzed
//!   lengths, a recipient setup with a fuzzed `enc`, and recipients of the
//!   genuine `enc` in other modes, with another PSK (a mutated key or
//!   identifier, or a fuzzed one) or another sender public key (derived
//!   from fuzzed key material, or fuzzed bytes, which may be low-order or
//!   no point), and sender keys of another KEM, which both sides refuse
//!   with `InvalidKey`. Sealed ciphertexts and exported secrets must equal
//!   the oracle's byte for byte, in every mode, both contexts must agree and
//!   report the session's mode, rejected ciphertexts must not advance the
//!   sequence number, and the oracle must accept and reject the same `enc`
//!   values and sender public keys. A recipient with another mode, PSK or
//!   sender key must fail to open the first message and export other
//!   secrets, as the oracle's does, and one with the session's must
//!   succeed. The KEM shared secret that the `key-log` entry points (base
//!   mode) hand out (for RFC 9850's `ECH_SECRET`) must be the same on both
//!   sides and equal the oracle's `Decap`, for the genuine and for every
//!   fuzzed `enc`, and a failed setup must leave the caller's buffer empty.
//! - provider: one of the native provider's suites through the `Hpke`,
//!   `HpkeSealer` and `HpkeOpener` traits with fuzzed info, aad, plaintext,
//!   public keys, private keys and `enc`; results must agree with the crate
//!   API underneath.

mod kem_secret;
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
const STEP_OTHER_RECIPIENT: u8 = 7;
const STEPS: usize = 8;

/// The bit of a session's random-source byte that selects a PSK mode (the
/// byte's value modulo 8 still selects a short random source when 0).
const SETUP_PSK: u8 = 0x08;
/// The bit of a session's random-source byte that selects an authenticated
/// mode.
const SETUP_AUTH: u8 = 0x10;

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

/// The steps of a PSK session seed (at most [`MAX_STEPS`]): two messages,
/// an export, recipients of the genuine and a mutated `enc` with the
/// session's PSK, then recipients of the genuine `enc` in base mode, with
/// a flipped key bit, a shorter identifier, a key one byte shorter, a
/// fuzzed PSK and the session's PSK unchanged, and the two opens.
fn psk_steps() -> Vec<u8> {
    let mut steps = vec![STEP_SEAL];
    put_short_field(&mut steps, b"aad");
    put_field(&mut steps, b"hello");
    steps.extend_from_slice(&[STEP_SEAL_IN_PLACE, 0, 0, 2, b'h', b'i']);
    steps.extend_from_slice(&[STEP_EXPORT, 3, b'c', b't', b'x', 0, 42]);
    steps.extend_from_slice(&[STEP_RECIPIENT, 1, 0, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_RECIPIENT, 1, 1, 0, 9, 0, 1, b'x']);
    // `mutate` arguments: flips (count, then position and mask each), then
    // a length change (1 drops the last byte).
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 1, 1, 0, 1, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 2, 0, 1, 1, b'x']);
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 1, 0, 1, 1, b'x']);
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 3]);
    put_short_field(&mut steps, &[0x5c; 40]);
    put_short_field(&mut steps, b"other");
    put_short_field(&mut steps, b"x");
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 1, 0, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_OPEN, 0, 0]);
    steps.extend_from_slice(&[STEP_OPEN, 1, 0]);
    steps
}

/// The steps of an authenticated session seed (at most [`MAX_STEPS`]) for
/// a KEM with `pk_len`-byte public keys and a sender key derived from
/// `ikm_s`: two messages, an export, recipients of the genuine and a
/// mutated `enc`, then recipients of the genuine `enc` in base mode,
/// without the sender key, with the sender public key of another and of
/// the same `DeriveKeyPair` input, with an all-zero (low-order on X25519
/// and X448, not a point on the NIST curves) and an arbitrary public key,
/// a sender key of another KEM, and a flipped PSK key bit, then the two
/// opens, or for an export-only suite (which seals nothing) opens of a
/// ciphertext shorter than a tag and, in place, of a tag-sized one.
fn auth_steps(pk_len: usize, ikm_s: &[u8], export_only: bool) -> Vec<u8> {
    let mut steps = vec![STEP_SEAL];
    put_short_field(&mut steps, b"aad");
    put_field(&mut steps, b"hello");
    steps.extend_from_slice(&[STEP_SEAL_IN_PLACE, 0, 0, 2, b'h', b'i']);
    steps.extend_from_slice(&[STEP_EXPORT, 3, b'c', b't', b'x', 0, 42]);
    steps.extend_from_slice(&[STEP_RECIPIENT, 1, 0, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_RECIPIENT, 1, 1, 0, 9, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 4, 1, b'x']);
    let other: Vec<u8> = ikm_s.iter().map(|b| b ^ 0x80).collect();
    for derive in [&other[..], ikm_s] {
        steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 5]);
        put_short_field(&mut steps, derive);
        put_short_field(&mut steps, b"x");
    }
    for fill in [0u8, 0x11] {
        steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 6]);
        steps.extend(core::iter::repeat_n(fill, pk_len));
        steps.extend_from_slice(&[0, 0, 1, b'x']);
    }
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 7, 0]);
    put_short_field(&mut steps, ikm_s);
    steps.extend_from_slice(&[STEP_OTHER_RECIPIENT, 1, 1, 0, 1, 0, 1, b'x']);
    if export_only {
        steps.extend_from_slice(&[STEP_OPEN_FUZZED, 0, 0, 3, 1, 2, 3, 0]);
        steps.extend_from_slice(&[STEP_OPEN_FUZZED, 0, 0, 16]);
        steps.extend_from_slice(&[0; 16]);
        steps.push(1);
    } else {
        steps.extend_from_slice(&[STEP_OPEN, 0, 0]);
        steps.extend_from_slice(&[STEP_OPEN, 1, 0]);
    }
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
    // mode identifiers (the seeds above end before theirs, which reads 0):
    // PSK, Auth, unassigned, AuthPSK, unassigned
    for mode in [1u8, 2, 0xff, 3, 4] {
        seeds.push(vec![OP_IDS, 2, 0x20, 2, 1, 2, 1, mode]);
    }

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

    // PSK sessions: a PSK of the minimum length (X25519 with every AEAD; a
    // key one byte shorter is refused) and a longer one (P-256), then PSKs
    // `Psk::new` refuses (a key one byte short, an empty identifier, both
    // empty; the session runs in base mode) and the PSK mode with a short
    // random source.
    let psk: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(29) ^ 0x5a).collect();
    let psk_session = |k: u8, kdf: u8, aead: u8, setup: u8, key: &[u8], id: &[u8]| {
        let kem = Kem::ALL[usize::from(k)];
        let mut seed = vec![OP_SESSION, k, kdf, aead];
        put_short_field(&mut seed, &ikm);
        seed.push(setup);
        seed.extend_from_slice(&ikm[..kem.private_key_len()]);
        put_short_field(&mut seed, b"info");
        put_short_field(&mut seed, key);
        put_short_field(&mut seed, id);
        seed
    };
    let x25519 = 3u8;
    assert_eq!(Kem::ALL[usize::from(x25519)], Kem::DhX25519HkdfSha256);
    for aead in 0u8..4 {
        let mut seed = psk_session(x25519, aead % 3, aead, SETUP_PSK | 1, &psk[..32], b"psk-id");
        seed.extend_from_slice(&psk_steps());
        seeds.push(seed);
    }
    let mut seed = psk_session(0, 1, 0, SETUP_PSK | 1, &psk, b"client psk");
    seed.extend_from_slice(&psk_steps());
    seeds.push(seed);
    for (key, id) in [(&psk[..31], &b"psk-id"[..]), (&psk[..32], b""), (b"", b"")] {
        let mut seed = psk_session(x25519, 0, 2, SETUP_PSK | 1, key, id);
        seed.push(STEP_SEAL);
        put_short_field(&mut seed, b"aad");
        put_field(&mut seed, b"base");
        seed.extend_from_slice(&[STEP_OTHER_RECIPIENT, 0, 1, b'x', STEP_OPEN, 0, 0]);
        seeds.push(seed);
    }
    let mut seed = vec![OP_SESSION, x25519, 0, 0];
    put_short_field(&mut seed, &ikm);
    seed.extend_from_slice(&[SETUP_PSK, 7]);
    seed.extend_from_slice(&ikm[..7]);
    put_short_field(&mut seed, b"info");
    put_short_field(&mut seed, &psk[..32]);
    put_short_field(&mut seed, b"psk-id");
    seeds.push(seed);

    // Authenticated sessions: Auth (X25519 with AES-128-GCM and export-only,
    // and X448, which the oracle lacks), AuthPSK (X25519, P-256), then
    // sender key material too short (the session runs without a sender
    // key).
    let ikm_s: Vec<u8> = (0..66u8).map(|i| i.wrapping_mul(13) ^ 0xa7).collect();
    let auth_session = |k: u8, kdf: u8, aead: u8, key: Option<&[u8]>, ikm_s: &[u8]| {
        let kem = Kem::ALL[usize::from(k)];
        let mut seed = vec![OP_SESSION, k, kdf, aead];
        put_short_field(&mut seed, &ikm);
        seed.push(SETUP_AUTH | if key.is_some() { SETUP_PSK } else { 0 } | 1);
        seed.extend_from_slice(&ikm[..kem.private_key_len()]);
        put_short_field(&mut seed, b"info");
        if let Some(key) = key {
            put_short_field(&mut seed, key);
            put_short_field(&mut seed, b"psk-id");
        }
        put_short_field(&mut seed, ikm_s);
        seed
    };
    let x448 = 4u8;
    assert_eq!(Kem::ALL[usize::from(x448)], Kem::DhX448HkdfSha512);
    for (k, kdf, aead, key) in [
        (x25519, 0, 0, None),
        (x25519, 2, 3, None),
        (x448, 2, 1, None),
        (x25519, 1, 2, Some(&psk[..32])),
        (0, 2, 1, Some(&psk[..])),
    ] {
        let mut seed = auth_session(k, kdf, aead, key, &ikm_s);
        let pk_len = Kem::ALL[usize::from(k)].public_key_len();
        seed.extend_from_slice(&auth_steps(pk_len, &ikm_s, aead == 3));
        seeds.push(seed);
    }
    let mut seed = auth_session(x25519, 0, 0, None, &ikm_s[..31]);
    seed.push(STEP_SEAL);
    put_short_field(&mut seed, b"aad");
    put_field(&mut seed, b"base");
    seed.extend_from_slice(&[STEP_OTHER_RECIPIENT, 0, 1, b'x', STEP_OPEN, 0, 0]);
    seeds.push(seed);

    // The provider: derived and generated keys, fuzzed public keys, private
    // keys and enc, seal/open rounds with tampering.
    let mut rounds = Vec::new();
    for tamper in [&[0u8][..], &[1, 0, 3, 5], &[2, 10]] {
        put_short_field(&mut rounds, b"aad");
        put_field(&mut rounds, b"client hello inner");
        rounds.extend_from_slice(tamper);
    }
    let all = browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
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

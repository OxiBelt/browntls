//! `browntls_crypto` elliptic curves: X25519 and Ed25519 (`curve25519`), X448
//! and Ed448 (`curve448`), and ECDH and ECDSA on P-256, P-384 and P-521
//! (`nist`).
//!
//! Every result is checked against an independent implementation:
//! `x25519-dalek`, `ed25519-dalek`, `x448`, `ed448-goldilocks` and the
//! RustCrypto `p256`, `p384` and `p521` crates. Beyond that: X25519 on every
//! backend, and with load-aware routing (`accel::load`) sending a fuzzed
//! share of the calls to a fuzzed alternate backend; NIST public keys, ECDH,
//! signing and verification also under the portable backend (acceleration
//! policy `NONE`) and with load-aware routing in the same way; agreement is
//! symmetric; signatures round trip through
//! every encoding and verification path; a flipped bit is rejected by both
//! sides; on fuzzed keys, points, DER documents and signatures browntls and
//! the oracle reach the same verdict (browntls is allowed to be stricter
//! only where its documentation says so: Ed25519 and Ed448 keys of small
//! order, non-canonical Ed25519 keys).
//!
//! The input is a program of up to [`MAX_OPS`] operations, each a selector
//! byte (25 operations) followed by its arguments (fields have a 16-bit
//! length prefix, short fields an 8-bit one):
//!
//! | Op | Operation | Arguments |
//! |---|---|---|
//! | 0 | X25519 function, backends, base point, routing | scalar, u, policy flag, routing alternate and share |
//! | 1 | X25519 keys and agreement | key source, peer scalar, fuzzed peer u |
//! | 2 | Ed25519 sign and verify, PKCS #8 | seed or byte source, message, bit, message edit |
//! | 3 | Ed25519 verification of fuzzed keys and signatures | message, mode, key and signature or seed and mask |
//! | 4 | Ed25519 PKCS #8 parsing | raw or a valid v1/v2 encoding with an edit |
//! | 5–9 | the same for X448 and Ed448 (with contexts) | as 0–4 |
//! | 10–14 | P-256: keys, SEC 1 points, DER documents, signing, verification | see `crypto_ecc/nist.rs`; each ends with a routing alternate and share |
//! | 15–19 | P-384 | as 10–14 |
//! | 20–24 | P-521 | as 10–14 |
//!
//! Scalars and seeds come from the input, so every input replays exactly.

mod curve25519;
mod curve448;
mod nist;

use crate::input::{Input, put_field, put_short_field};

/// Most operations per input.
pub const MAX_OPS: usize = 8;
/// Longest message.
const MAX_MSG: usize = 1024;
/// Number of operations.
const OPS: usize = 25;

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

/// `sig` with one fuzzed bit flipped.
fn flip_bit(sig: &[u8], input: &mut Input<'_>) -> Vec<u8> {
    let mut bad = sig.to_vec();
    let bit = usize::from(input.u16()) % (8 * bad.len());
    bad[bit / 8] ^= 1 << (bit % 8);
    bad
}

/// A message of at most [`MAX_MSG`] bytes.
fn message<'a>(input: &mut Input<'a>) -> &'a [u8] {
    let msg = input.field();
    &msg[..msg.len().min(MAX_MSG)]
}

/// The `crypto_ecc` fuzz target.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        let input = &mut input;
        match input.choose(OPS) {
            0 => curve25519::x25519_function(input),
            1 => curve25519::x25519_keys(input),
            2 => curve25519::ed25519_sign(input),
            3 => curve25519::ed25519_verify(input),
            4 => curve25519::ed25519_pkcs8(input),
            5 => curve448::x448_function(input),
            6 => curve448::x448_keys(input),
            7 => curve448::ed448_sign(input),
            8 => curve448::ed448_verify(input),
            9 => curve448::ed448_pkcs8(input),
            10 => nist::p256::keys(input),
            11 => nist::p256::public(input),
            12 => nist::p256::der(input),
            13 => nist::p256::sign(input),
            14 => nist::p256::verify(input),
            15 => nist::p384::keys(input),
            16 => nist::p384::public(input),
            17 => nist::p384::der(input),
            18 => nist::p384::sign(input),
            19 => nist::p384::verify(input),
            20 => nist::p521::keys(input),
            21 => nist::p521::public(input),
            22 => nist::p521::der(input),
            23 => nist::p521::sign(input),
            _ => nist::p521::verify(input),
        }
    }
}

/// Builds one seed.
struct Seed(Vec<u8>);

impl Seed {
    fn op(op: u8) -> Self {
        Self(vec![op])
    }

    fn bytes(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(bytes);
        self
    }

    fn field(mut self, bytes: &[u8]) -> Self {
        put_field(&mut self.0, bytes);
        self
    }

    fn short(mut self, bytes: &[u8]) -> Self {
        put_short_field(&mut self.0, bytes);
        self
    }
}

/// Starting inputs for `crypto_ecc`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    const NONE: [u8; 4] = [0; 4]; // an edit that changes nothing
    let msg = b"browntls fuzz message";
    let mut base25519 = [0u8; 32];
    base25519[0] = 9;
    let mut base448 = [0u8; 56];
    base448[0] = 5;
    let mut seeds: Vec<Seed> = vec![
        // X25519: the base point and a zero u (all-zero output), with the
        // policy flag, then a routing alternate and its share of the calls
        // (all, none, some).
        Seed::op(0)
            .bytes(&[0x11; 32])
            .bytes(&base25519)
            .bytes(&[1])
            .bytes(&[0, 100]),
        Seed::op(0)
            .bytes(&[0x22; 32])
            .bytes(&[0; 32])
            .bytes(&[0])
            .bytes(&[1, 0]),
        Seed::op(0)
            .bytes(&[0x33; 32])
            .bytes(&base25519)
            .bytes(&[0])
            .bytes(&[0, 50]),
        // X25519 keys from bytes, a slice and a byte source; a fuzzed u of
        // zero (rejected) and a random one.
        Seed::op(1)
            .bytes(&[0])
            .bytes(&[0x33; 32])
            .bytes(&[0x44; 32])
            .bytes(&[0x55; 32]),
        Seed::op(1)
            .bytes(&[1])
            .short(&[0x33; 32])
            .bytes(&[0x44; 32])
            .bytes(&[0; 32]),
        Seed::op(1).bytes(&[1]).short(&[0x33; 31]),
        Seed::op(1)
            .bytes(&[2])
            .short(&[0x66; 40])
            .bytes(&[0x44; 32])
            .bytes(&[1; 32]),
        Seed::op(1).bytes(&[2]).short(&[0x66; 31]),
        // Ed25519 from a seed and from a byte source; failing source.
        Seed::op(2)
            .bytes(&[1])
            .bytes(&[0x77; 32])
            .field(msg)
            .bytes(&[0, 9])
            .bytes(&[3, 0, 0, 0x61]),
        Seed::op(2)
            .bytes(&[0])
            .short(&[0x78; 32])
            .field(b"")
            .bytes(&[1, 0])
            .bytes(&NONE),
        Seed::op(2).bytes(&[0]).short(&[0x78; 5]),
        // Ed25519 verification: raw key and signature, a valid signature
        // (zero mask), a masked signature, an edited key.
        Seed::op(3)
            .field(msg)
            .bytes(&[0])
            .bytes(&[0x5a; 32])
            .bytes(&[0xa5; 64])
            .bytes(&[32]),
        Seed::op(3)
            .field(msg)
            .bytes(&[1])
            .bytes(&[0x79; 32])
            .bytes(&[0; 5])
            .bytes(&[31]),
        Seed::op(3)
            .field(msg)
            .bytes(&[1])
            .bytes(&[0x79; 32])
            .bytes(&[1, 0, 0, 0, 40, 32]),
        Seed::op(3)
            .field(msg)
            .bytes(&[2])
            .bytes(&[0x79; 32])
            .bytes(&[0x80, 0, 0, 0, 31, 32]),
        // Ed25519 PKCS #8: v1 and v2 unedited, v1 edited, raw.
        Seed::op(4)
            .bytes(&[0])
            .bytes(&[0x7a; 32])
            .bytes(&[1])
            .bytes(&NONE),
        Seed::op(4)
            .bytes(&[0])
            .bytes(&[0x7a; 32])
            .bytes(&[0])
            .bytes(&NONE),
        Seed::op(4)
            .bytes(&[0])
            .bytes(&[0x7a; 32])
            .bytes(&[1])
            .bytes(&[1, 0, 9, 0xff]),
        Seed::op(4)
            .bytes(&[1])
            .short(&[0x30, 0x03, 0x02, 0x01, 0x00]),
        // X448 likewise.
        Seed::op(5).bytes(&[0x11; 56]).bytes(&base448),
        Seed::op(5).bytes(&[0x22; 56]).bytes(&[0; 56]),
        Seed::op(6)
            .bytes(&[0])
            .bytes(&[0x33; 56])
            .bytes(&[0x44; 56])
            .bytes(&[0x55; 56]),
        Seed::op(6)
            .bytes(&[1])
            .short(&[0x33; 56])
            .bytes(&[0x44; 56])
            .bytes(&[0; 56]),
        Seed::op(6).bytes(&[1]).short(&[0x33; 55]),
        Seed::op(6)
            .bytes(&[2])
            .short(&[0x66; 60])
            .bytes(&[0x44; 56])
            .bytes(&[1; 56]),
        Seed::op(6).bytes(&[2]).short(&[0x66; 55]),
        // Ed448: empty, fuzzed and over-long contexts; byte sources.
        Seed::op(7)
            .bytes(&[1])
            .bytes(&[0x77; 57])
            .bytes(&[0])
            .field(msg)
            .bytes(&[0, 9]),
        Seed::op(7)
            .bytes(&[1])
            .bytes(&[0x77; 57])
            .bytes(&[1])
            .short(b"ctx")
            .field(msg)
            .bytes(&[3, 0]),
        Seed::op(7)
            .bytes(&[1])
            .bytes(&[0x77; 57])
            .bytes(&[2, 0x63])
            .field(msg),
        Seed::op(7)
            .bytes(&[0])
            .short(&[0x78; 57])
            .bytes(&[0])
            .field(b"")
            .bytes(&[0, 0]),
        Seed::op(7).bytes(&[0]).short(&[0x78; 56]),
        Seed::op(8)
            .bytes(&[0])
            .field(msg)
            .bytes(&[0])
            .bytes(&[0x5a; 57])
            .bytes(&[0xa5; 114])
            .bytes(&[57]),
        Seed::op(8)
            .bytes(&[0])
            .field(msg)
            .bytes(&[1])
            .bytes(&[0x79; 57])
            .bytes(&[0; 5])
            .bytes(&[56]),
        Seed::op(8)
            .bytes(&[1])
            .short(b"ctx")
            .field(msg)
            .bytes(&[1])
            .bytes(&[0x79; 57])
            .bytes(&[0; 5])
            .bytes(&[57]),
        Seed::op(8)
            .bytes(&[2, 0])
            .field(msg)
            .bytes(&[1])
            .bytes(&[0x79; 57])
            .bytes(&[0; 5])
            .bytes(&[57]),
        Seed::op(8)
            .bytes(&[0])
            .field(msg)
            .bytes(&[1])
            .bytes(&[0x79; 57])
            .bytes(&[4, 0, 0, 0, 60, 57]),
        Seed::op(8)
            .bytes(&[0])
            .field(msg)
            .bytes(&[2])
            .bytes(&[0x79; 57])
            .bytes(&[0x80, 0, 0, 0, 56, 57]),
        Seed::op(9)
            .bytes(&[0])
            .bytes(&[0x7a; 57])
            .bytes(&[0])
            .bytes(&NONE),
        Seed::op(9)
            .bytes(&[0])
            .bytes(&[0x7a; 57])
            .bytes(&[1])
            .bytes(&NONE),
        Seed::op(9)
            .bytes(&[0])
            .bytes(&[0x7a; 57])
            .bytes(&[2])
            .bytes(&NONE),
        Seed::op(9)
            .bytes(&[0])
            .bytes(&[0x7a; 57])
            .bytes(&[0])
            .bytes(&[2, 0, 30, 0]),
        Seed::op(9).bytes(&[1]).short(&[0x30, 0x00]),
    ];
    for (curve, fl) in [(0u8, 32usize), (1, 48), (2, 66)] {
        let op = 10 + 5 * curve;
        // A valid scalar (below the order for every curve).
        let mut d = vec![0x42u8; fl];
        d[0] = 0;
        let mut d2 = vec![0x24u8; fl];
        d2[0] = 0;
        let scalar = |d: &[u8]| [&[0u8][..], d].concat();
        seeds.extend([
            // Keys: valid scalar with a peer and a full buffer; zero scalar
            // then each byte source; a failing source; n - 1 with a short
            // buffer.
            Seed::op(op)
                .bytes(&scalar(&d))
                .bytes(&scalar(&d2))
                .bytes(&[0xff])
                .bytes(&[0, 100]),
            Seed::op(op)
                .bytes(&[1, 0, 0])
                .short(&[0x55; 96])
                .bytes(&[1])
                .bytes(&scalar(&d2))
                .bytes(&[7])
                .bytes(&[1, 50]),
            Seed::op(op)
                .bytes(&[1, 0, 0])
                .short(&[0x55; 96])
                .bytes(&[0])
                .bytes(&[3]),
            Seed::op(op).bytes(&[1, 0, 0]).short(&[0x55; 8]).bytes(&[1]),
            Seed::op(op).bytes(&[2, 0, 1]).bytes(&[3]).bytes(&[1, 0, 9]),
            // Public keys: a valid point in both forms, random coordinates
            // behind tags 2 and 4, raw bytes.
            Seed::op(op + 1)
                .bytes(&[1])
                .bytes(&scalar(&d))
                .bytes(&[1])
                .bytes(&NONE)
                .bytes(&[0xff])
                .bytes(&scalar(&d2))
                .bytes(&[0, 100]),
            Seed::op(op + 1)
                .bytes(&[1])
                .bytes(&scalar(&d))
                .bytes(&[0])
                .bytes(&NONE)
                .bytes(&[0xff])
                .bytes(&[1, 0, 5])
                .bytes(&[0, 50]),
            Seed::op(op + 1).bytes(&[2, 2]).bytes(&d2),
            Seed::op(op + 1).bytes(&[2, 4]).bytes(&d).bytes(&d2),
            Seed::op(op + 1).bytes(&[0]).short(&[0]),
            // DER: each document unedited (the private keys then loaded
            // with routing), one edited, raw.
            Seed::op(op + 2)
                .bytes(&[0, 0])
                .bytes(&scalar(&d))
                .bytes(&NONE)
                .bytes(&[0, 100]),
            Seed::op(op + 2)
                .bytes(&[1, 0])
                .bytes(&scalar(&d))
                .bytes(&NONE)
                .bytes(&[0, 50]),
            Seed::op(op + 2)
                .bytes(&[2, 0])
                .bytes(&scalar(&d))
                .bytes(&NONE),
            Seed::op(op + 2)
                .bytes(&[0, 0])
                .bytes(&scalar(&d))
                .bytes(&[1, 0, 6, 0x01]),
            Seed::op(op + 2).bytes(&[2, 1]).field(&[0x30, 0x00]),
            // Signing with the curve's hash and another; hedged with enough
            // and too little randomness; wrong digest lengths; then routed
            // with every call, half of the calls and a few on the alternate.
            Seed::op(op + 3)
                .bytes(&scalar(&d))
                .bytes(&[curve + 1])
                .field(msg)
                .bytes(&[0, 3])
                .short(&[0x5c; 32])
                .bytes(&[4, 0, 0, 0])
                .bytes(&[0, 100]),
            Seed::op(op + 3)
                .bytes(&scalar(&d))
                .bytes(&[4])
                .field(msg)
                .bytes(&[1, 0])
                .short(&[0x5c; 8])
                .bytes(&[3, 0, 1, 0])
                .bytes(&[0, 50]),
            Seed::op(op + 3)
                .bytes(&scalar(&d2))
                .bytes(&[0])
                .field(b"")
                .bytes(&[0, 0])
                .short(&[0; 40])
                .bytes(&NONE)
                .bytes(&[1, 1]),
            // Verification: each signature source; a zero mask keeps the
            // signature valid. Rejected and accepted signatures are then
            // verified with routing.
            Seed::op(op + 4)
                .bytes(&scalar(&d))
                .bytes(&[curve + 1])
                .field(msg)
                .bytes(&[0])
                .bytes(&vec![0x31; 2 * fl])
                .bytes(&[0, 100]),
            Seed::op(op + 4)
                .bytes(&scalar(&d))
                .bytes(&[curve + 1])
                .field(msg)
                .bytes(&[1])
                .short(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            Seed::op(op + 4)
                .bytes(&scalar(&d))
                .bytes(&[curve + 1])
                .field(msg)
                .bytes(&[2])
                .bytes(&NONE)
                .bytes(&[0])
                .bytes(&[0, 100]),
            Seed::op(op + 4)
                .bytes(&scalar(&d))
                .bytes(&[5])
                .field(msg)
                .bytes(&[2])
                .bytes(&[0, 0, 1, 0, 3]),
            Seed::op(op + 4)
                .bytes(&scalar(&d))
                .bytes(&[curve + 1])
                .field(msg)
                .bytes(&[3])
                .bytes(&NONE),
            Seed::op(op + 4)
                .bytes(&scalar(&d))
                .bytes(&[curve + 1])
                .field(msg)
                .bytes(&[3])
                .bytes(&[1, 0, 2, 0x80]),
            Seed::op(op + 4)
                .bytes(&scalar(&d))
                .bytes(&[curve + 1])
                .field(msg)
                .bytes(&[4, 0])
                .bytes(&[0, 50]),
            Seed::op(op + 4)
                .bytes(&scalar(&d))
                .bytes(&[curve + 1])
                .field(msg)
                .bytes(&[4, 1])
                .bytes(&[0, 100]),
        ]);
    }
    seeds.into_iter().map(|s| s.0).collect()
}

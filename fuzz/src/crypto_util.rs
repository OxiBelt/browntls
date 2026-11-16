//! `browntls-crypto` support modules: DER (`der`), constant-time helpers
//! (`ct`), zeroisation (`zeroize`), randomness sources (`rand`), CPU feature
//! detection (`cpu`), acceleration policies (`accel`) and `Error`.
//!
//! The input is a program of up to [`MAX_OPS`] operations, each an op byte
//! followed by its arguments:
//!
//! - DER reading: fuzzed bytes walked by a fuzzed sequence of reader calls
//!   (nested through `read_sequence` and `parse_sequence`). Every result is
//!   checked against a reference TLV parser written here, and every value
//!   read re-encodes with `Writer` to exactly the bytes consumed.
//! - DER writing: a fuzzed list of TLVs, headers and integers into a buffer
//!   of fuzzed capacity; the output equals a reference encoding, lengths
//!   agree with `header_len` and `positive_integer_len`, overflow is an error
//!   and the output reads back.
//! - `ct`: every helper on fuzzed values against the obvious
//!   non-constant-time result.
//! - `zeroize` and `rand`: buffers are zeroed; `FixedRng` replays exactly its
//!   bytes and then fails; `OsRng` works.
//! - `cpu`: features are stable, `without` removes exactly the masked bits,
//!   accessors agree with `std` detection and are false on other
//!   architectures.
//! - `accel`: fuzzed policies set per algorithm, per kind and for all
//!   algorithms; success, failure (`Required` without hardware leaves the
//!   policy unchanged) and the reported status must be consistent. Every
//!   policy is restored to `Policy::PREFERRED` before `run` returns.
//! - `accel::load`: between those policy changes, load-aware routing is
//!   enabled with fuzzed configurations (reported back clamped) and disabled
//!   (every stream steady, statistics forgotten), fixed shares are set with
//!   fuzzed lanes, alternates and percentages and cleared, and an X25519 key
//!   exchange is run (timed exactly while routing is enabled). A call
//!   succeeds exactly when its documentation says so and a failed one
//!   changes nothing; after every operation each stream's status agrees with
//!   `lanes`, `status_all`, the acceleration status and the configuration.
//!   Routing is disabled before `run` returns.

mod cpu_accel;
mod ct_zeroize_rand;
mod der;

use browntls_crypto::accel::{self, Algorithm, Policy};
use browntls_crypto::der::Reader;

use self::cpu_accel::{
    ACCEL_LOAD, LOAD_CLEAR_FIXED, LOAD_DISABLE, LOAD_ENABLE, LOAD_KEY_EXCHANGE, LOAD_SET_FIXED,
    accel_op, cpu_op, disable_load, error_op,
};
use self::ct_zeroize_rand::{ct_op, rand_op, zeroize_op};
use self::der::{der_write, parse_sequence, walk};
use crate::input::{Input, put_field, put_short_field};

/// Operations per input.
const MAX_OPS: usize = 32;
/// Reader calls per DER walk, across all nesting levels.
const MAX_READS: usize = 64;
/// Writer calls per DER write.
const MAX_WRITES: usize = 16;

const OP_DER_READ: u8 = 0;
const OP_DER_PARSE_SEQUENCE: u8 = 1;
const OP_DER_WRITE: u8 = 2;
const OP_CT: u8 = 3;
const OP_ZEROIZE: u8 = 4;
const OP_RAND: u8 = 5;
const OP_CPU: u8 = 6;
const OP_ACCEL: u8 = 7;
const OP_ERROR: u8 = 8;
const OPS: usize = 9;

/// The `crypto_util` fuzz target.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match u8::try_from(input.choose(OPS)).unwrap_or(0) {
            OP_DER_READ => {
                let der = input.field();
                let mut budget = MAX_READS;
                let mut reader = Reader::new(der);
                walk(&mut reader, &mut input, &mut budget, 0);
            }
            OP_DER_PARSE_SEQUENCE => parse_sequence(&mut input),
            OP_DER_WRITE => der_write(&mut input),
            OP_CT => ct_op(&mut input),
            OP_ZEROIZE => zeroize_op(&mut input),
            OP_RAND => rand_op(&mut input),
            OP_CPU => cpu_op(&mut input),
            OP_ACCEL => accel_op(&mut input),
            _ => error_op(),
        }
    }
    accel::set_policy_all(Policy::PREFERRED).expect("PREFERRED is always satisfiable");
    disable_load();
}

/// Starting inputs for `crypto_util`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();

    // DER: a structure with every universal type, walked with every call.
    let mut body = Vec::new();
    body.extend_from_slice(&[0x02, 0x02, 0x00, 0x80]); // INTEGER 128
    body.extend_from_slice(&[0x02, 0x01, 0x05]); // INTEGER 5
    body.extend_from_slice(&[0x03, 0x03, 0x00, 0xaa, 0xbb]); // BIT STRING
    body.extend_from_slice(&[0x04, 0x02, 0x01, 0x02]); // OCTET STRING
    body.extend_from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x70]); // OID 1.3.101.112
    body.extend_from_slice(&[0x05, 0x00]); // NULL
    body.extend_from_slice(&[0xa0, 0x03, 0x01, 0x01, 0xff]); // [0] { TRUE }
    body.extend_from_slice(&[0x04, 0x81, 0x80]); // long-form length
    body.extend_from_slice(&[0x5a; 0x80]);
    let mut der = vec![0x30, 0x81, u8::try_from(body.len()).expect("short")];
    der.extend_from_slice(&body);

    // read_sequence, then each reader in turn, then finish
    let walk_all = [
        3, 9, 4, 5, 6, 7, 8, 2, 0x05, 2, 7, 0x03, 1, 0x04, 0, 9, 10, 1, 11,
    ];
    let mut seed = vec![OP_DER_READ];
    put_field(&mut seed, &der);
    seed.extend_from_slice(&walk_all);
    seeds.push(seed);
    // the same calls on non-matching or malformed input
    for bad in [
        &[0x02, 0x01, 0x80][..],                     // negative INTEGER
        &[0x02, 0x02, 0x00, 0x01],                   // non-minimal INTEGER
        &[0x02, 0x00],                               // empty INTEGER
        &[0x02, 0x81, 0x01, 0x00],                   // non-minimal length
        &[0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0], // too large for u64
        &[0x03, 0x02, 0x01, 0xff],                   // unused bits
        &[0x06, 0x02, 0x80, 0x01],                   // padded OID
        &[0x06, 0x01, 0x81],                         // truncated OID
        &[0x1f, 0x01, 0x00],                         // multi-byte tag
        &[0x04, 0x85, 1, 0, 0, 0, 0],                // five length bytes
        &[0x04, 0x05, 0x00],                         // truncated value
        &[],
    ] {
        for call in [0u8, 3, 4, 5, 6, 7, 8, 9] {
            let mut seed = vec![OP_DER_READ];
            put_field(&mut seed, bad);
            seed.push(call);
            seeds.push(seed);
        }
    }
    // parse_sequence: whole, failing closure, trailing data, not a sequence
    for (input, reads) in [
        (&der[..], &[4u8, 4, 6, 7, 8, 11][..]),
        (&der[..], &[4u8, 11, 0xff]),
        (&[0x30, 0x00, 0x00][..], &[]),
        (&[0x30, 0x03, 0x02, 0x01, 0x01][..], &[11]),
        (&[0x31, 0x00][..], &[]),
    ] {
        let mut seed = vec![OP_DER_PARSE_SEQUENCE];
        put_field(&mut seed, input);
        put_field(&mut seed, reads);
        seeds.push(seed);
    }
    // DER writing: TLVs, a long header, integers; then too little room
    let mut writes = vec![0u8, 3];
    put_field(&mut writes, b"value");
    writes.extend_from_slice(&[0, 0, 0]);
    put_field(&mut writes, &[0x33; 200]);
    writes.extend_from_slice(&[2]);
    put_short_field(&mut writes, &[0, 0, 0x80, 1]);
    writes.extend_from_slice(&[2]);
    put_short_field(&mut writes, &[0, 0]);
    writes.extend_from_slice(&[2]);
    put_short_field(&mut writes, &[0x12]);
    seeds.push([&[OP_DER_WRITE, 0x01, 0x00][..], &writes].concat());
    seeds.push([&[OP_DER_WRITE, 0x00, 0x40][..], &writes].concat());
    seeds.push(vec![
        OP_DER_WRITE,
        0x01,
        0x00,
        1,
        6,
        1,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
    ]);
    seeds.push(vec![
        OP_DER_WRITE,
        0x03,
        0xff,
        1,
        6,
        0,
        0xff,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);

    // ct: equal and different values, both choices
    for (same, bit) in [(1u8, 1u8), (0, 0)] {
        let mut seed = vec![OP_CT];
        seed.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7, same]);
        if same == 0 {
            seed.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 9]);
        }
        seed.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, bit]);
        put_short_field(&mut seed, b"src");
        seed.extend_from_slice(b"dst");
        seed.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
        put_short_field(&mut seed, b"abc");
        seed.push(same);
        if same == 0 {
            put_short_field(&mut seed, b"abd");
        }
        seeds.push(seed);
    }
    // zeroize
    let mut seed = vec![OP_ZEROIZE];
    put_field(&mut seed, b"secret key bytes");
    seed.extend_from_slice(&[0x55; 40]);
    seeds.push(seed);
    // rand: draws of every size until the bytes run out, OsRng
    let mut seed = vec![OP_RAND];
    put_field(&mut seed, &[0x42; 40]);
    seed.extend_from_slice(&[5, 0, 1, 2, 2, 1, 1]);
    seeds.push(seed);
    // cpu: every mask
    for mask in 0..3u8 {
        seeds.push(vec![OP_CPU, mask]);
    }
    // accel: every call; Required for every algorithm and kind
    for op in 0..6u8 {
        for level in 0..3u8 {
            seeds.push(vec![OP_ACCEL, 11, level % 2, level, level, 2 - level, op]);
        }
    }
    for alg in 0..15u8 {
        for kind in 0..2u8 {
            seeds.push(vec![OP_ACCEL, alg, kind, 0, 0, 0, 1]);
        }
        seeds.push(vec![OP_ACCEL, alg, 0, 0, 0, 0, 0]);
        seeds.push(vec![
            OP_ACCEL, alg, 0, 0, 2, 2, 0, OP_ACCEL, alg, 0, 1, 1, 1, 0,
        ]);
    }
    for text in [&b"PreFered"[..], b"required", b"NONE", b"fast", b""] {
        let mut seed = vec![OP_ACCEL, 0, 0, 0, 0, 0, 5];
        put_short_field(&mut seed, text);
        seeds.push(seed);
    }
    seeds.push(vec![OP_ACCEL, 0, 1, 0, 1, 1, 4, 1, 0]);
    // accel::load. One `accel` operation making the load call `call` on
    // stream `lane` of algorithm `alg`, and one setting a policy.
    let call = |alg: u8, lane: u8, alternate: u8, percent: u8, call: u8| {
        vec![
            OP_ACCEL, alg, 0, 1, 1, 1, ACCEL_LOAD, lane, alternate, percent, call,
        ]
    };
    let enable = |threshold: u8, max_shift: u8, portable: u8| {
        [
            call(0, 0, 0, 0, LOAD_ENABLE),
            vec![threshold, max_shift, portable],
        ]
        .concat()
    };
    let policy = |alg: u8, simd: u8, dedicated: u8| vec![OP_ACCEL, alg, 0, 1, simd, dedicated, 0];
    // The two families with streams.
    let index = |alg: Algorithm| {
        let at = Algorithm::ALL.iter().position(|a| *a == alg);
        u8::try_from(at.expect("every algorithm is in ALL")).expect("few algorithms")
    };
    for alg in [index(Algorithm::ChaCha20), index(Algorithm::X25519)] {
        seeds.push(
            [
                // Disabled: no share, an untimed key exchange.
                call(alg, 0, 0, 50, LOAD_SET_FIXED),
                call(alg, 0, 0, 0, LOAD_KEY_EXCHANGE),
                // The default configuration; every share on each alternate,
                // with a key exchange under it.
                enable(25, 90, 1),
                call(alg, 0, 0, 100, LOAD_SET_FIXED),
                call(alg, 0, 0, 0, LOAD_KEY_EXCHANGE),
                call(alg, 0, 1, 50, LOAD_SET_FIXED),
                call(alg, 0, 1, 1, LOAD_SET_FIXED),
                call(alg, 0, 0, 0, LOAD_SET_FIXED),
                // No such alternate, share or lane.
                call(alg, 0, 3, 50, LOAD_SET_FIXED),
                call(alg, 0, 0, 101, LOAD_SET_FIXED),
                call(alg, 1, 0, 50, LOAD_SET_FIXED),
                // Cleared, also where nothing is fixed.
                call(alg, 1, 0, 0, LOAD_CLEAR_FIXED),
                call(alg, 0, 0, 0, LOAD_CLEAR_FIXED),
                call(alg, 0, 0, 0, LOAD_CLEAR_FIXED),
                call(alg, 0, 0, 0, LOAD_KEY_EXCHANGE),
                // Clamped configurations, then off.
                enable(0, 255, 0),
                enable(255, 0, 1),
                call(alg, 0, 0, 100, LOAD_SET_FIXED),
                call(alg, 0, 0, 0, LOAD_DISABLE),
                call(alg, 0, 0, 0, LOAD_KEY_EXCHANGE),
            ]
            .concat(),
        );
        // A share under one policy is ignored under another (portable only,
        // then without SIMD), reappears with the policy and is cleared; a
        // share on the portable backend is hidden once it may take no work.
        seeds.push(
            [
                enable(25, 90, 1),
                call(alg, 0, 0, 100, LOAD_SET_FIXED),
                policy(alg, 2, 2),
                call(alg, 0, 0, 0, LOAD_KEY_EXCHANGE),
                call(alg, 0, 0, 100, LOAD_SET_FIXED),
                policy(alg, 2, 1),
                call(alg, 0, 0, 100, LOAD_SET_FIXED),
                policy(alg, 1, 1),
                call(alg, 0, 0, 0, LOAD_KEY_EXCHANGE),
                call(alg, 0, 0, 0, LOAD_CLEAR_FIXED),
                call(alg, 0, 1, 75, LOAD_SET_FIXED),
                enable(25, 90, 0),
                call(alg, 0, 0, 0, LOAD_CLEAR_FIXED),
                call(alg, 0, 1, 75, LOAD_SET_FIXED),
                call(alg, 0, 0, 75, LOAD_SET_FIXED),
            ]
            .concat(),
        );
    }
    // Every algorithm, most of them without a stream.
    for alg in 0..15u8 {
        seeds.push(
            [
                enable(25, 90, 1),
                call(alg, 0, 0, 50, LOAD_SET_FIXED),
                call(alg, 0, 0, 0, LOAD_CLEAR_FIXED),
                call(alg, 0, 0, 0, LOAD_DISABLE),
            ]
            .concat(),
        );
    }
    seeds.push(vec![OP_ERROR]);
    seeds
}

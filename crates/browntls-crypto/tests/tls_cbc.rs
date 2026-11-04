//! TLS 1.2 CBC record protection (`browntls_crypto::tls_cbc`) against an
//! independent construction of the records with RustCrypto `aes`, `cbc`,
//! `hmac`, `sha1` and `sha2`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aes::cipher::{BlockModeDecrypt as _, BlockModeEncrypt as _, KeyIvInit as _};
use browntls_crypto::Error;
use browntls_crypto::tls_cbc::{
    CbcBlockCipher, IV_LEN, MAX_FRAGMENT_LEN, MAX_PLAINTEXT_LEN, MacAlgorithm, MacOrder, RecordKey,
};
use hmac::{KeyInit as _, Mac as _};

/// Test-only AES-CBC adapter over RustCrypto `aes` + `cbc`.
struct RcAesCbc(Vec<u8>);

impl CbcBlockCipher for RcAesCbc {
    fn cbc_encrypt(&self, iv: &[u8; 16], buf: &mut [u8]) {
        assert_eq!(buf.len() % 16, 0);
        macro_rules! run {
            ($aes:ty) => {{
                let mut e = cbc::Encryptor::<$aes>::new_from_slices(&self.0, iv).unwrap();
                for block in buf.chunks_exact_mut(16) {
                    e.encrypt_block(block.try_into().unwrap());
                }
            }};
        }
        match self.0.len() {
            16 => run!(aes::Aes128),
            32 => run!(aes::Aes256),
            _ => unreachable!(),
        }
    }

    fn cbc_decrypt(&self, iv: &[u8; 16], buf: &mut [u8]) {
        assert_eq!(buf.len() % 16, 0);
        macro_rules! run {
            ($aes:ty) => {{
                let mut d = cbc::Decryptor::<$aes>::new_from_slices(&self.0, iv).unwrap();
                for block in buf.chunks_exact_mut(16) {
                    d.decrypt_block(block.try_into().unwrap());
                }
            }};
        }
        match self.0.len() {
            16 => run!(aes::Aes128),
            32 => run!(aes::Aes256),
            _ => unreachable!(),
        }
    }
}

const ALGS: [MacAlgorithm; 3] = [
    MacAlgorithm::HmacSha1,
    MacAlgorithm::HmacSha256,
    MacAlgorithm::HmacSha384,
];
const ORDERS: [MacOrder; 2] = [MacOrder::MacThenEncrypt, MacOrder::EncryptThenMac];
const VERSION: [u8; 2] = [3, 3];
const TYPE: u8 = 23;

fn ref_hmac(alg: MacAlgorithm, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    macro_rules! run {
        ($h:ty) => {{
            let mut m = hmac::Hmac::<$h>::new_from_slice(key).unwrap();
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }};
    }
    match alg {
        MacAlgorithm::HmacSha1 => run!(sha1::Sha1),
        MacAlgorithm::HmacSha256 => run!(sha2::Sha256),
        MacAlgorithm::HmacSha384 => run!(sha2::Sha384),
    }
}

fn header(seq: u64, len: usize) -> Vec<u8> {
    let mut h = seq.to_be_bytes().to_vec();
    h.push(TYPE);
    h.extend_from_slice(&VERSION);
    h.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    h
}

/// Builds a record independently, with `pad_len` padding bytes (plus the
/// length byte) whose values are given by `pad_byte(i)` (normally
/// `pad_len`). The padded length must be block aligned.
struct Params<'a> {
    alg: MacAlgorithm,
    order: MacOrder,
    mac_key: &'a [u8],
    cipher: &'a RcAesCbc,
    seq: u64,
    iv: [u8; 16],
}

fn ref_record(
    p: &Params<'_>,
    plaintext: &[u8],
    pad_len: usize,
    pad_byte: impl Fn(usize) -> u8,
) -> Vec<u8> {
    let padding: Vec<u8> = (0..pad_len)
        .map(&pad_byte)
        .chain([u8::try_from(pad_len).unwrap()])
        .collect();
    let mut frag = p.iv.to_vec();
    match p.order {
        MacOrder::MacThenEncrypt => {
            let mut body = plaintext.to_vec();
            body.extend(ref_hmac(
                p.alg,
                p.mac_key,
                &[&header(p.seq, plaintext.len()), plaintext],
            ));
            body.extend(&padding);
            assert_eq!(body.len() % 16, 0);
            p.cipher.cbc_encrypt(&p.iv, &mut body);
            frag.extend(body);
        }
        MacOrder::EncryptThenMac => {
            let mut body = plaintext.to_vec();
            body.extend(&padding);
            assert_eq!(body.len() % 16, 0);
            p.cipher.cbc_encrypt(&p.iv, &mut body);
            frag.extend(body);
            let tag = ref_hmac(p.alg, p.mac_key, &[&header(p.seq, frag.len()), &frag]);
            frag.extend(tag);
        }
    }
    frag
}

fn mac_key(alg: MacAlgorithm) -> Vec<u8> {
    (0..alg.mac_len()).map(|i| (i * 11 + 3) as u8).collect()
}

fn cipher_for(alg: MacAlgorithm) -> RcAesCbc {
    // AES-128 with SHA-1/SHA-256, AES-256 with SHA-384 (as in TLS suites).
    let len = if alg == MacAlgorithm::HmacSha384 {
        32
    } else {
        16
    };
    RcAesCbc((0..len).map(|i| (i * 5 + 9) as u8).collect())
}

fn key(alg: MacAlgorithm, order: MacOrder) -> RecordKey<RcAesCbc> {
    RecordKey::new(cipher_for(alg), alg, &mac_key(alg), order).unwrap()
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 131 + 17) as u8).collect()
}

fn iv(n: u64) -> [u8; 16] {
    core::array::from_fn(|i| (n as u8).wrapping_mul(29).wrapping_add(i as u8))
}

/// Minimal padding length for `len` bytes before the padding.
fn min_pad(len: usize) -> usize {
    (16 - (len + 1) % 16) % 16
}

fn open_ok(k: &RecordKey<RcAesCbc>, seq: u64, frag: &[u8], want: &[u8]) {
    let mut buf = frag.to_vec();
    let r = k.open(seq, TYPE, VERSION, &mut buf).unwrap();
    assert_eq!(&buf[r], want);
}

fn open_err(k: &RecordKey<RcAesCbc>, seq: u64, frag: &[u8]) {
    let mut buf = frag.to_vec();
    assert_eq!(
        k.open(seq, TYPE, VERSION, &mut buf),
        Err(Error::DecryptFailed)
    );
    assert!(buf.iter().all(|&b| b == 0), "buffer wiped on failure");
}

#[test]
fn seal_matches_reference_and_round_trips() {
    let mut lens: Vec<usize> = (0..=300).collect();
    lens.extend([
        1000,
        4095,
        4096,
        4097,
        MAX_PLAINTEXT_LEN - 1,
        MAX_PLAINTEXT_LEN,
    ]);
    for alg in ALGS {
        for order in ORDERS {
            let k = key(alg, order);
            assert_eq!(k.mac_len(), alg.mac_len());
            assert_eq!(k.mac_algorithm(), alg);
            assert_eq!(k.mac_order(), order);
            let cipher = cipher_for(alg);
            let mk = mac_key(alg);
            for &len in &lens {
                let seq = len as u64 * 7 + 1;
                let pt = data(len);
                let total = k.sealed_len(len);
                let mut buf = vec![0xeeu8; total + 3];
                buf[IV_LEN..IV_LEN + len].copy_from_slice(&pt);
                let n = k.seal(seq, TYPE, VERSION, &iv(seq), &mut buf, len).unwrap();
                assert_eq!(n, total);
                assert_eq!(buf[total..], [0xee; 3], "no write past the fragment");
                let pad = match order {
                    MacOrder::MacThenEncrypt => min_pad(len + alg.mac_len()),
                    MacOrder::EncryptThenMac => min_pad(len),
                };
                let p = Params {
                    alg,
                    order,
                    mac_key: &mk,
                    cipher: &cipher,
                    seq,
                    iv: iv(seq),
                };
                let want = ref_record(&p, &pt, pad, |_| pad as u8);
                assert_eq!(buf[..total], want[..], "{alg:?} {order:?} len {len}");
                open_ok(&k, seq, &buf[..total], &pt);
            }
        }
    }
}

#[test]
fn every_padding_length_is_accepted() {
    for alg in ALGS {
        for order in ORDERS {
            let k = key(alg, order);
            let cipher = cipher_for(alg);
            let mk = mac_key(alg);
            for pad_len in 0..=255usize {
                for base in [0usize, 7, 40] {
                    // Smallest plaintext length >= base that aligns.
                    let fixed = pad_len
                        + 1
                        + if order == MacOrder::MacThenEncrypt {
                            alg.mac_len()
                        } else {
                            0
                        };
                    let len = base + (16 - (base + fixed) % 16) % 16;
                    let seq = (pad_len * 3 + base) as u64;
                    let pt = data(len);
                    let p = Params {
                        alg,
                        order,
                        mac_key: &mk,
                        cipher: &cipher,
                        seq,
                        iv: iv(seq),
                    };
                    let frag = ref_record(&p, &pt, pad_len, |_| pad_len as u8);
                    open_ok(&k, seq, &frag, &pt);
                }
            }
        }
    }
}

#[test]
fn invalid_padding_is_rejected() {
    for alg in ALGS {
        for order in ORDERS {
            let k = key(alg, order);
            let cipher = cipher_for(alg);
            let mk = mac_key(alg);
            for pad_len in (1..=255usize).step_by(3).chain([255]) {
                let fixed = pad_len
                    + 1
                    + if order == MacOrder::MacThenEncrypt {
                        alg.mac_len()
                    } else {
                        0
                    };
                let len = 5 + (16 - (5 + fixed) % 16) % 16;
                let pt = data(len);
                let p = Params {
                    alg,
                    order,
                    mac_key: &mk,
                    cipher: &cipher,
                    seq: 9,
                    iv: iv(pad_len as u64),
                };
                // One wrong padding byte at a time (the MAC, where it covers
                // the padding, is computed over the wrong bytes so only the
                // padding check can reject the record).
                for bad in [0, pad_len / 2, pad_len - 1] {
                    let frag = ref_record(&p, &pt, pad_len, |i| {
                        if i == bad {
                            pad_len as u8 ^ 0x01
                        } else {
                            pad_len as u8
                        }
                    });
                    open_err(&k, 9, &frag);
                }
            }
        }
    }
}

#[test]
fn padding_length_beyond_record_is_rejected() {
    // A padding length byte that claims more bytes than the record holds
    // (all candidate padding bytes equal to it, so only the length bound
    // can reject). The MAC-then-encrypt record is built by hand: the
    // reference construction would not fit.
    for alg in ALGS {
        let h = alg.mac_len();
        let cipher = cipher_for(alg);
        let mk = mac_key(alg);
        for order in ORDERS {
            let k = key(alg, order);
            for blocks in [4usize, 5, 8] {
                let n = 16 * blocks;
                for claimed in [n as u8 - 1, n as u8, 200, 255] {
                    let mut body = vec![claimed; n];
                    let iv = iv(claimed.into());
                    cipher.cbc_encrypt(&iv, &mut body);
                    let mut frag = iv.to_vec();
                    frag.extend(body);
                    if order == MacOrder::EncryptThenMac {
                        let tag = ref_hmac(alg, &mk, &[&header(3, frag.len()), &frag]);
                        frag.extend(tag);
                    }
                    if order == MacOrder::MacThenEncrypt && usize::from(claimed) + 1 + h <= n {
                        continue;
                    }
                    if order == MacOrder::EncryptThenMac && usize::from(claimed) < n {
                        continue;
                    }
                    open_err(&k, 3, &frag);
                }
            }
        }
    }
}

#[test]
fn tampering_is_rejected() {
    for alg in ALGS {
        for order in ORDERS {
            let k = key(alg, order);
            for len in [0usize, 1, 15, 16, 33, 100] {
                let pt = data(len);
                let total = k.sealed_len(len);
                let mut frag = vec![0u8; total];
                frag[IV_LEN..IV_LEN + len].copy_from_slice(&pt);
                k.seal(5, TYPE, VERSION, &iv(5), &mut frag, len).unwrap();
                open_ok(&k, 5, &frag, &pt);
                // Every byte (IV, ciphertext, MAC, padding and its length).
                for i in 0..total {
                    for bit in [0x01u8, 0x80] {
                        let mut t = frag.clone();
                        t[i] ^= bit;
                        open_err(&k, 5, &t);
                    }
                }
                // Truncation and extension.
                for cut in [1, 15, 16, 32] {
                    if cut <= total {
                        open_err(&k, 5, &frag[..total - cut]);
                    }
                }
                open_err(&k, 5, &frag[16..]);
                let mut longer = frag.clone();
                longer.extend([0u8; 16]);
                open_err(&k, 5, &longer);
                // Wrong sequence number, type and version.
                open_err(&k, 6, &frag);
                let mut buf = frag.clone();
                assert!(k.open(5, TYPE + 1, VERSION, &mut buf).is_err());
                let mut buf = frag.clone();
                assert!(k.open(5, TYPE, [3, 2], &mut buf).is_err());
                // Wrong key.
                let other = RecordKey::new(cipher_for(alg), alg, &vec![0x42; alg.mac_len()], order)
                    .unwrap();
                open_err(&other, 5, &frag);
            }
        }
    }
}

#[test]
fn public_length_checks() {
    for alg in ALGS {
        for order in ORDERS {
            let k = key(alg, order);
            for len in [
                0usize, 1, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 79, 80,
            ] {
                // Junk of every short length is rejected (only block-aligned
                // lengths could reach the MAC check, and they fail there).
                open_err(&k, 0, &vec![0x5a; len]);
            }
            open_err(&k, 0, &vec![0x5a; MAX_FRAGMENT_LEN + 16]);
            open_err(&k, 0, &vec![0x5a; MAX_FRAGMENT_LEN + 1]);
        }
    }
}

#[test]
fn oversized_plaintext_is_rejected() {
    // Validly protected records with 2^14 + 1 plaintext bytes.
    for alg in ALGS {
        let cipher = cipher_for(alg);
        let mk = mac_key(alg);
        for order in ORDERS {
            let k = key(alg, order);
            let len = MAX_PLAINTEXT_LEN + 1;
            let fixed = 1 + if order == MacOrder::MacThenEncrypt {
                alg.mac_len()
            } else {
                0
            };
            let pad = (16 - (len + fixed) % 16) % 16;
            let p = Params {
                alg,
                order,
                mac_key: &mk,
                cipher: &cipher,
                seq: 1,
                iv: iv(1),
            };
            let frag = ref_record(&p, &data(len), pad, |_| pad as u8);
            open_err(&k, 1, &frag);
        }
    }
}

#[test]
fn seal_and_key_errors() {
    for alg in ALGS {
        for order in ORDERS {
            assert_eq!(
                RecordKey::new(cipher_for(alg), alg, &[0; 19], order).err(),
                Some(Error::InvalidKey)
            );
            let k = key(alg, order);
            let mut buf = vec![0u8; k.sealed_len(MAX_PLAINTEXT_LEN + 1)];
            assert_eq!(
                k.seal(0, TYPE, VERSION, &iv(0), &mut buf, MAX_PLAINTEXT_LEN + 1),
                Err(Error::InvalidLength)
            );
            let mut short = vec![0u8; k.sealed_len(10) - 1];
            assert_eq!(
                k.seal(0, TYPE, VERSION, &iv(0), &mut short, 10),
                Err(Error::InvalidLength)
            );
        }
    }
}

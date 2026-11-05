//! AES-CBC: NIST SP 800-38A and FIPS 197 known answers, Wycheproof
//! (PKCS#5 padding handled here, since the mode itself does not pad), every
//! available AES backend against the portable one, and a differential test
//! against RustCrypto's `cbc` + `aes`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::aes::Backend;
use browntls_crypto::cbc::AesCbcKey;
use serde::Deserialize;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn backends() -> Vec<Backend> {
    let v: Vec<Backend> = Backend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect();
    assert!(v.contains(&Backend::Soft));
    v
}

/// Small deterministic PRNG (xorshift64*) so failures are reproducible.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        self.fill(&mut v);
        v
    }

    fn block(&mut self) -> [u8; 16] {
        let mut b = [0u8; 16];
        self.fill(&mut b);
        b
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

// ------------------------------------------------------------ known answers

const SP800_38A_IV: &str = "000102030405060708090a0b0c0d0e0f";
const SP800_38A_PT: &str = "6bc1bee22e409f96e93d7e117393172a\
                            ae2d8a571e03ac9c9eb76fac45af8e51\
                            30c81c46a35ce411e5fbc1191a0a52ef\
                            f69f2445df4f9b17ad2b417be66c3710";

/// NIST SP 800-38A Appendix F.2.1-F.2.2 (CBC-AES128) and F.2.5-F.2.6
/// (CBC-AES256), each encrypted and decrypted whole and block by block.
#[test]
fn sp800_38a_f2() {
    let cases = [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "7649abac8119b246cee98e9b12e9197d\
             5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e22229516\
             3ff1caa1681fac09120eca307586e1a7",
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
             9cfc4e967edb808d679f777bc6702c7d\
             39f23369a9d9bacfa530e26304231461\
             b2eb05e2c39be9fcda6c19078c6a9d1b",
        ),
    ];
    let iv: [u8; 16] = h(SP800_38A_IV).try_into().unwrap();
    let pt = h(SP800_38A_PT);
    for (key, ct) in cases {
        let (key, ct) = (h(key), h(ct));
        for backend in backends() {
            let what = format!("{backend:?} AES-{}", key.len() * 8);
            let cbc = AesCbcKey::with_backend(&key, backend).unwrap();
            assert_eq!(cbc.backend(), backend);

            let mut buf = pt.clone();
            cbc.encrypt(&iv, &mut buf).unwrap();
            assert_eq!(buf, ct, "{what} encrypt");
            cbc.decrypt(&iv, &mut buf).unwrap();
            assert_eq!(buf, pt, "{what} decrypt");

            // One block per call, chaining through the previous ciphertext
            // block as the next IV.
            let mut chained = pt.clone();
            let mut prev = iv;
            for block in chained.chunks_mut(16) {
                cbc.encrypt(&prev, block).unwrap();
                prev = block.try_into().unwrap();
            }
            assert_eq!(chained, ct, "{what} chained encrypt");
            let mut prev = iv;
            for block in chained.chunks_mut(16) {
                let next: [u8; 16] = (&*block).try_into().unwrap();
                cbc.decrypt(&prev, block).unwrap();
                prev = next;
            }
            assert_eq!(chained, pt, "{what} chained decrypt");
        }
    }
}

/// FIPS 197 Appendix C.1 and C.3: the inverse cipher on one block (CBC
/// with a zero IV is the bare block cipher).
#[test]
fn fips197_appendix_c_decrypt() {
    let pt = h("00112233445566778899aabbccddeeff");
    for (key, ct) in [
        (
            "000102030405060708090a0b0c0d0e0f",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ] {
        for backend in backends() {
            let cbc = AesCbcKey::with_backend(&h(key), backend).unwrap();
            let mut buf = h(ct);
            cbc.decrypt(&[0; 16], &mut buf).unwrap();
            assert_eq!(buf, pt, "{backend:?} {key}");
        }
    }
}

#[test]
fn invalid_inputs() {
    for len in [0usize, 8, 15, 17, 24, 31, 33, 48, 64] {
        let r = AesCbcKey::new(&vec![0u8; len]);
        if len == 16 || len == 32 {
            assert!(r.is_ok(), "{len}");
        } else {
            assert_eq!(r.err(), Some(Error::InvalidKey), "{len}");
        }
    }
    for backend in Backend::ALL.into_iter().filter(|b| !b.is_available()) {
        assert_eq!(
            AesCbcKey::with_backend(&[0; 16], backend).err(),
            Some(Error::Unsupported)
        );
    }
    let cbc = AesCbcKey::new(&[1; 32]).unwrap();
    for len in [1usize, 15, 17, 100, 4095] {
        let mut buf = vec![0x5a; len];
        assert_eq!(cbc.encrypt(&[2; 16], &mut buf), Err(Error::InvalidLength));
        assert_eq!(cbc.decrypt(&[2; 16], &mut buf), Err(Error::InvalidLength));
        assert!(buf.iter().all(|&b| b == 0x5a), "{len} untouched");
    }
}

// --------------------------------------------------------------- backends

/// Every block count from 0 to 80 (all register-group tails of every
/// backend), larger buffers with odd block counts, unaligned buffers, both
/// key sizes; each accelerated backend must match the portable one in both
/// directions.
#[test]
fn backends_match_portable() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let mut counts: Vec<usize> = (0..=80).collect();
    counts.extend([127, 128, 129, 255, 256, 257, 1023, 1025, 4097]);
    for &blocks in &counts {
        for key_len in [16usize, 32] {
            let key = rng.bytes(key_len);
            let iv = rng.block();
            let soft = AesCbcKey::with_backend(&key, Backend::Soft).unwrap();
            let pt = rng.bytes(16 * blocks);
            let mut expected = pt.clone();
            soft.encrypt(&iv, &mut expected).unwrap();
            let mut back = expected.clone();
            soft.decrypt(&iv, &mut back).unwrap();
            assert_eq!(back, pt, "soft round trip, {blocks} blocks");

            for backend in backends() {
                let what = format!("{backend:?} AES-{} {blocks} blocks", key_len * 8);
                let cbc = AesCbcKey::with_backend(&key, backend).unwrap();
                // Misalign the buffer by a random offset.
                let off = rng.below(16);
                let mut storage = vec![0u8; off + pt.len()];
                let buf = &mut storage[off..];
                buf.copy_from_slice(&pt);
                cbc.encrypt(&iv, buf).unwrap();
                assert_eq!(buf, &expected[..], "{what} encrypt");
                cbc.decrypt(&iv, buf).unwrap();
                assert_eq!(buf, &pt[..], "{what} decrypt");

                // Decrypting arbitrary data (not produced by encryption).
                let junk = rng.bytes(16 * blocks);
                let mut a = junk.clone();
                let mut b = junk;
                soft.decrypt(&iv, &mut a).unwrap();
                cbc.decrypt(&iv, &mut b).unwrap();
                assert_eq!(a, b, "{what} decrypt random");
            }
        }
    }
}

/// A buffer decrypted in pieces of random block counts, each chained to the
/// last ciphertext block of the previous piece, equals one-shot decryption.
#[test]
fn split_calls_match_one_shot() {
    let mut rng = Rng(0xfeed_beef_dead_cafe);
    for backend in backends() {
        for _ in 0..20 {
            let key_len = if rng.below(2) == 0 { 16 } else { 32 };
            let key = rng.bytes(key_len);
            let cbc = AesCbcKey::with_backend(&key, backend).unwrap();
            let iv = rng.block();
            let ct_len = 16 * (1 + rng.below(100));
            let ct = rng.bytes(ct_len);
            let mut whole = ct.clone();
            cbc.decrypt(&iv, &mut whole).unwrap();
            let mut pieces = ct.clone();
            let mut prev = iv;
            let mut pos = 0;
            while pos < pieces.len() {
                let n = 16 * (1 + rng.below(20)).min((pieces.len() - pos) / 16);
                let next: [u8; 16] = ct[pos + n - 16..pos + n].try_into().unwrap();
                cbc.decrypt(&prev, &mut pieces[pos..pos + n]).unwrap();
                prev = next;
                pos += n;
            }
            assert_eq!(pieces, whole, "{backend:?}");
        }
    }
}

// ------------------------------------------------------------ differential

fn rustcrypto(key: &[u8], iv: &[u8; 16], buf: &mut [u8], encrypt: bool) {
    use cbc::cipher::block_padding::NoPadding;
    use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
    let len = buf.len();
    match (key.len(), encrypt) {
        (16, true) => {
            cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
                .unwrap()
                .encrypt_padded::<NoPadding>(buf, len)
                .unwrap();
        }
        (16, false) => {
            cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                .unwrap()
                .decrypt_padded::<NoPadding>(buf)
                .unwrap();
        }
        (32, true) => {
            cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                .unwrap()
                .encrypt_padded::<NoPadding>(buf, len)
                .unwrap();
        }
        (32, false) => {
            cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                .unwrap()
                .decrypt_padded::<NoPadding>(buf)
                .unwrap();
        }
        _ => unreachable!(),
    }
}

#[test]
fn differential_rustcrypto() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for i in 0..300 {
        let key = rng.bytes(if i % 2 == 0 { 16 } else { 32 });
        let iv = rng.block();
        let data_len = 16 * rng.below(70);
        let data = rng.bytes(data_len);
        let mut ours_ct = data.clone();
        let mut theirs_ct = data.clone();
        rustcrypto(&key, &iv, &mut theirs_ct, true);
        let mut theirs_pt = data.clone();
        rustcrypto(&key, &iv, &mut theirs_pt, false);
        for backend in backends() {
            let cbc = AesCbcKey::with_backend(&key, backend).unwrap();
            ours_ct.copy_from_slice(&data);
            cbc.encrypt(&iv, &mut ours_ct).unwrap();
            assert_eq!(ours_ct, theirs_ct, "{backend:?} encrypt #{i}");
            let mut ours_pt = data.clone();
            cbc.decrypt(&iv, &mut ours_pt).unwrap();
            assert_eq!(ours_pt, theirs_pt, "{backend:?} decrypt #{i}");
        }
    }
}

// --------------------------------------------------------------- wycheproof

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WycheproofFile {
    number_of_tests: usize,
    test_groups: Vec<Group>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    key_size: usize,
    tests: Vec<Test>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Test {
    tc_id: usize,
    key: String,
    iv: String,
    msg: String,
    ct: String,
    result: String,
    flags: Vec<String>,
}

/// Removes PKCS#5 padding (test-side only; variable time is fine here).
fn pkcs5_unpad(buf: &[u8]) -> Option<&[u8]> {
    let &n = buf.last()?;
    let n = usize::from(n);
    if n == 0 || n > 16 || n > buf.len() {
        return None;
    }
    let (msg, pad) = buf.split_at(buf.len() - n);
    pad.iter().all(|&b| usize::from(b) == n).then_some(msg)
}

fn pkcs5_pad(msg: &[u8]) -> Vec<u8> {
    let n = 16 - msg.len() % 16;
    let mut v = msg.to_vec();
    v.resize(msg.len() + n, n as u8);
    v
}

#[test]
fn wycheproof_aes_cbc_pkcs5() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/wycheproof/aes_cbc_pkcs5_test.json"
    ))
    .expect("test vector file present");
    let file: WycheproofFile = serde_json::from_slice(&data).expect("valid JSON");
    let backends = backends();
    let (mut total, mut valid, mut invalid, mut skipped) = (0, 0, 0, 0);
    for group in &file.test_groups {
        total += group.tests.len();
        // AES-192 is not implemented by `browntls-crypto`.
        if group.key_size == 192 {
            assert_eq!(
                AesCbcKey::new(&[0; 24]).err(),
                Some(Error::InvalidKey),
                "AES-192 refused"
            );
            skipped += group.tests.len();
            continue;
        }
        for t in &group.tests {
            let (key, ct, msg) = (h(&t.key), h(&t.ct), h(&t.msg));
            let iv: [u8; 16] = h(&t.iv).try_into().unwrap();
            assert_eq!(key.len() * 8, group.key_size);
            for &backend in &backends {
                let what = format!("tcId {} {backend:?}", t.tc_id);
                let cbc = AesCbcKey::with_backend(&key, backend).unwrap();
                let mut buf = ct.clone();
                let decrypted = cbc.decrypt(&iv, &mut buf);
                match t.result.as_str() {
                    "valid" => {
                        decrypted.unwrap();
                        assert_eq!(pkcs5_unpad(&buf), Some(&msg[..]), "{what} decrypt");
                        let mut enc = pkcs5_pad(&msg);
                        cbc.encrypt(&iv, &mut enc).unwrap();
                        assert_eq!(enc, ct, "{what} encrypt");
                    }
                    "invalid" => {
                        assert!(
                            t.flags
                                .iter()
                                .any(|f| f == "BadPadding" || f == "NoPadding"),
                            "{what} unexpected flags {:?}",
                            t.flags
                        );
                        // Either not whole blocks or the padding is wrong.
                        let rejected = match decrypted {
                            Err(Error::InvalidLength) => true,
                            Ok(()) => pkcs5_unpad(&buf).is_none(),
                            Err(e) => panic!("{what}: {e:?}"),
                        };
                        assert!(rejected, "{what} must be rejected");
                    }
                    other => panic!("{what}: unexpected result {other}"),
                }
            }
            if t.result == "valid" {
                valid += 1;
            } else {
                invalid += 1;
            }
        }
    }
    assert_eq!(total, file.number_of_tests);
    println!(
        "wycheproof: {total} vectors; {valid} valid + {invalid} invalid run on {} backends, \
         {skipped} skipped (AES-192)",
        backends.len()
    );
    assert_eq!((valid, invalid, skipped), (48, 96, 72));
}

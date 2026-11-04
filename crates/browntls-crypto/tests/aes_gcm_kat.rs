//! Known-answer tests for AES and AES-GCM on every backend available at run
//! time: FIPS 197 block vectors, the McGrew–Viega / SP 800-38D GCM test
//! cases and the Wycheproof `aes_gcm_test.json` suite.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_arguments
)]

use browntls_crypto::Error;
use browntls_crypto::aead::Aead;
use browntls_crypto::aes::{self, Aes128, Aes256};
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm, GhashBackend};
use serde::Deserialize;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn aes_backends() -> Vec<aes::Backend> {
    aes::Backend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect()
}

fn ghash_backends() -> Vec<GhashBackend> {
    GhashBackend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect()
}

/// Runs `f` for every available (AES, GHASH) backend pair.
fn for_each_pair(mut f: impl FnMut(aes::Backend, GhashBackend)) {
    for ab in aes_backends() {
        for gb in ghash_backends() {
            f(ab, gb);
        }
    }
}

#[test]
fn report_available_backends() {
    println!("AES backends: {:?}", aes_backends());
    println!("GHASH backends: {:?}", ghash_backends());
    println!(
        "selected: {:?} / {:?}",
        aes::Backend::select(),
        GhashBackend::select()
    );
    assert!(aes::Backend::select().is_available());
    assert!(GhashBackend::select().is_available());
}

#[test]
fn fips197_appendix_c_block_vectors() {
    let pt = h("00112233445566778899aabbccddeeff");
    let key128: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let key256: [u8; 32] = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .try_into()
        .unwrap();
    for backend in aes_backends() {
        let mut block: [u8; 16] = pt.clone().try_into().unwrap();
        Aes128::with_backend(&key128, backend)
            .unwrap()
            .encrypt_block(&mut block);
        assert_eq!(
            hex::encode(block),
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            "{backend:?}"
        );
        let mut block: [u8; 16] = pt.clone().try_into().unwrap();
        Aes256::with_backend(&key256, backend)
            .unwrap()
            .encrypt_block(&mut block);
        assert_eq!(
            hex::encode(block),
            "8ea2b7ca516745bfeafc49904b496089",
            "{backend:?}"
        );
    }
}

#[test]
fn fips197_appendix_b_example() {
    let key: [u8; 16] = h("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
    for backend in aes_backends() {
        let mut block: [u8; 16] = h("3243f6a8885a308d313198a2e0370734").try_into().unwrap();
        Aes128::with_backend(&key, backend)
            .unwrap()
            .encrypt_block(&mut block);
        assert_eq!(
            hex::encode(block),
            "3925841d02dc09fbdc118597196a0b32",
            "{backend:?}"
        );
    }
}

#[test]
fn encrypt_blocks_matches_single_blocks_for_every_length() {
    let key: [u8; 32] = core::array::from_fn(|i| (i * 17 + 3) as u8);
    let soft = Aes256::with_backend(&key, aes::Backend::Soft).unwrap();
    for backend in aes_backends() {
        let aes = Aes256::with_backend(&key, backend).unwrap();
        for n in 0..=40usize {
            let mut blocks: Vec<[u8; 16]> = (0..n)
                .map(|i| core::array::from_fn(|j| (i * 31 + j * 7) as u8))
                .collect();
            let mut expected = blocks.clone();
            for b in &mut expected {
                soft.encrypt_block(b);
            }
            aes.encrypt_blocks(&mut blocks);
            assert_eq!(blocks, expected, "{backend:?} n={n}");
        }
    }
}

struct GcmCase {
    key: &'static str,
    iv: &'static str,
    pt: &'static str,
    aad: &'static str,
    ct: &'static str,
    tag: &'static str,
}

/// McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", test cases
/// 1–4 (AES-128) and 13–16 (AES-256); also in NIST SP 800-38D validation.
const GCM_CASES: &[GcmCase] = &[
    GcmCase {
        key: "00000000000000000000000000000000",
        iv: "000000000000000000000000",
        pt: "",
        aad: "",
        ct: "",
        tag: "58e2fccefa7e3061367f1d57a4e7455a",
    },
    GcmCase {
        key: "00000000000000000000000000000000",
        iv: "000000000000000000000000",
        pt: "00000000000000000000000000000000",
        aad: "",
        ct: "0388dace60b6a392f328c2b971b2fe78",
        tag: "ab6e47d42cec13bdf53a67b21257bddf",
    },
    GcmCase {
        key: "feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        aad: "",
        ct: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        tag: "4d5c2af327cd64a62cf35abd2ba6fab4",
    },
    GcmCase {
        key: "feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        ct: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        tag: "5bc94fbc3221a5db94fae95ae7121a47",
    },
    GcmCase {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        pt: "",
        aad: "",
        ct: "",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
    },
    GcmCase {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        pt: "00000000000000000000000000000000",
        aad: "",
        ct: "cea7403d4d606b6e074ec5d3baf39d18",
        tag: "d0d1c8a799996bf0265b98b5d48ab919",
    },
    GcmCase {
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        aad: "",
        ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        tag: "b094dac5d93471bdec1a502270e3cc6c",
    },
    GcmCase {
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        tag: "76fc6ece0f4e1768cddf8853bb2d551b",
    },
];

/// Seals and opens with the backend pair, checking against expected values.
fn check_gcm(
    ab: aes::Backend,
    gb: GhashBackend,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
    valid: bool,
) {
    let seal_open = |buf: &mut Vec<u8>,
                     open_tag: &[u8; 16],
                     open_ct: &[u8]|
     -> ([u8; 16], Result<(), Error>, Vec<u8>) {
        if key.len() == 16 {
            let k: [u8; 16] = key.try_into().unwrap();
            let gcm = Aes128Gcm::with_backends(&k, ab, gb).unwrap();
            let t = gcm.seal_in_place(nonce, aad, buf).unwrap();
            let mut o = open_ct.to_vec();
            let r = gcm.open_in_place(nonce, aad, &mut o, open_tag);
            (t, r, o)
        } else {
            let k: [u8; 32] = key.try_into().unwrap();
            let gcm = Aes256Gcm::with_backends(&k, ab, gb).unwrap();
            let t = gcm.seal_in_place(nonce, aad, buf).unwrap();
            let mut o = open_ct.to_vec();
            let r = gcm.open_in_place(nonce, aad, &mut o, open_tag);
            (t, r, o)
        }
    };
    let mut buf = pt.to_vec();
    let (t, r, opened) = seal_open(&mut buf, tag, ct);
    if valid {
        assert_eq!(
            hex::encode(&buf),
            hex::encode(ct),
            "{ab:?}/{gb:?} ciphertext"
        );
        assert_eq!(hex::encode(t), hex::encode(tag), "{ab:?}/{gb:?} tag");
        assert_eq!(r, Ok(()), "{ab:?}/{gb:?} open");
        assert_eq!(opened, pt, "{ab:?}/{gb:?} plaintext");
    } else {
        assert_eq!(r, Err(Error::DecryptFailed), "{ab:?}/{gb:?} must reject");
        assert!(
            opened.iter().all(|&b| b == 0),
            "{ab:?}/{gb:?} buffer zeroed"
        );
    }
}

#[test]
fn gcm_spec_test_cases_on_all_backends() {
    for_each_pair(|ab, gb| {
        for case in GCM_CASES {
            let nonce: [u8; 12] = h(case.iv).try_into().unwrap();
            let tag: [u8; 16] = h(case.tag).try_into().unwrap();
            check_gcm(
                ab,
                gb,
                &h(case.key),
                &nonce,
                &h(case.aad),
                &h(case.pt),
                &h(case.ct),
                &tag,
                true,
            );
        }
    });
}

#[derive(Deserialize)]
struct WycheproofFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofGroup>,
}

#[derive(Deserialize)]
struct WycheproofGroup {
    #[serde(rename = "ivSize")]
    iv_size: usize,
    #[serde(rename = "keySize")]
    key_size: usize,
    #[serde(rename = "tagSize")]
    tag_size: usize,
    tests: Vec<WycheproofTest>,
}

#[derive(Deserialize)]
struct WycheproofTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

#[test]
fn wycheproof_aes_gcm() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/wycheproof/aes_gcm_test.json"
    ))
    .expect("test vector file present");
    let file: WycheproofFile = serde_json::from_slice(&data).expect("valid JSON");
    let mut total = 0;
    let mut skipped_iv = 0;
    let mut skipped_key = 0;
    let mut valid = 0;
    let mut invalid = 0;
    let pairs: Vec<(aes::Backend, GhashBackend)> = {
        let mut v = Vec::new();
        for_each_pair(|a, g| v.push((a, g)));
        v
    };
    for group in &file.test_groups {
        total += group.tests.len();
        // Only 128-bit tags and 96-bit nonces are supported; the AEAD API
        // cannot even express other sizes, so such groups are skipped
        // explicitly (never silently accepted).
        assert_eq!(group.tag_size, 128, "file only contains 128-bit tags");
        if group.key_size == 192 {
            skipped_key += group.tests.len();
            continue;
        }
        if group.iv_size != 96 {
            skipped_iv += group.tests.len();
            continue;
        }
        for t in &group.tests {
            let nonce: [u8; 12] = h(&t.iv).try_into().unwrap();
            let tag_bytes = h(&t.tag);
            let tag: [u8; 16] = tag_bytes.try_into().unwrap();
            let is_valid = match t.result.as_str() {
                "valid" => true,
                "invalid" => false,
                other => panic!("tcId {} unexpected result {other}", t.tc_id),
            };
            if is_valid {
                valid += 1;
            } else {
                invalid += 1;
            }
            for &(ab, gb) in &pairs {
                check_gcm(
                    ab,
                    gb,
                    &h(&t.key),
                    &nonce,
                    &h(&t.aad),
                    &h(&t.msg),
                    &h(&t.ct),
                    &tag,
                    is_valid,
                );
            }
            let _ = &t.flags;
        }
    }
    assert_eq!(total, file.number_of_tests);
    println!(
        "wycheproof: {total} vectors, {valid} valid + {invalid} invalid run on {} backend pairs, \
         {skipped_iv} skipped (non-96-bit IV), {skipped_key} skipped (AES-192)",
        pairs.len()
    );
    // The file holds 79 valid and 54 invalid AES-128/256 vectors with 96-bit IVs.
    assert!(
        valid >= 79 && invalid >= 54,
        "unexpectedly few vectors exercised"
    );
}

#[test]
fn key_length_is_validated() {
    assert_eq!(Aes128Gcm::new(&[0; 15]).err(), Some(Error::InvalidKey));
    assert_eq!(Aes128Gcm::new(&[0; 32]).err(), Some(Error::InvalidKey));
    assert_eq!(Aes256Gcm::new(&[0; 16]).err(), Some(Error::InvalidKey));
    assert!(Aes128Gcm::new(&[0; 16]).is_ok());
    assert!(Aes256Gcm::new(&[0; 32]).is_ok());
}

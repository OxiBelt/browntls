//! Known-answer, differential and negative tests for AES-CCM on every AES
//! backend available at run time: the NIST SP 800-38C Appendix C examples,
//! the RFC 3610 packet vectors, the Wycheproof `aes_ccm_test.json` suite,
//! every backend against the portable one and against the independent
//! RustCrypto `ccm` crate, and tampering / zeroisation checks.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_arguments
)]

use aes_gcm::aes::{Aes128, Aes256};
use browntls_crypto::Error;
use browntls_crypto::aead::Aead;
use browntls_crypto::aes;
use browntls_crypto::ccm::{Aes128Ccm, Aes128Ccm8, AesCcm};
use ccm::aead::consts::{U4, U6, U7, U8, U9, U10, U11, U12, U13, U14, U16};
use ccm::{AeadInOut, KeyInit};
use serde::Deserialize;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn backends() -> Vec<aes::Backend> {
    aes::Backend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect()
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

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// Seals with the generic API on `backend` and checks the result, then
/// opens it again.
fn check_generic(
    backend: aes::Backend,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &[u8],
    tag: &[u8],
    what: &str,
) {
    let ccm = AesCcm::with_backend(key, backend).unwrap();
    let mut buf = pt.to_vec();
    let mut t = vec![0u8; tag.len()];
    ccm.seal_in_place(nonce, aad, &mut buf, &mut t).unwrap();
    assert_eq!(
        hex::encode(&buf),
        hex::encode(ct),
        "{what} {backend:?} ciphertext"
    );
    assert_eq!(hex::encode(&t), hex::encode(tag), "{what} {backend:?} tag");
    ccm.open_in_place(nonce, aad, &mut buf, tag)
        .unwrap_or_else(|e| panic!("{what} {backend:?} open: {e}"));
    assert_eq!(buf, pt, "{what} {backend:?} plaintext");
}

#[test]
fn report_available_backends() {
    println!("AES backends: {:?}", backends());
    println!("selected: {:?}", aes::Backend::select());
    assert_eq!(
        Aes128Ccm::new(&[0; 16]).unwrap().backend(),
        aes::Backend::select()
    );
    assert_eq!(
        Aes128Ccm8::new(&[0; 16]).unwrap().backend(),
        aes::Backend::select()
    );
}

// ------------------------------------------------------- SP 800-38C

/// NIST SP 800-38C Appendix C, Examples 1-4: K = 40..4f, N, A and P are
/// prefixes of 10 11 12 ..., 00 01 02 ... and 20 21 22 ...; Example 4 uses
/// 2^16 bytes of additional data (00 .. ff repeated 256 times), exercising the
/// `0xff 0xfe` length encoding.
#[test]
fn sp800_38c_appendix_c_examples() {
    let key = h("404142434445464748494a4b4c4d4e4f");
    let nonce: Vec<u8> = (0x10..0x1d).collect();
    let pt: Vec<u8> = (0x20..0x40).collect();
    let short_aad: Vec<u8> = (0..20).collect();
    let long_aad: Vec<u8> = (0..65536u32).map(|i| i as u8).collect();
    // (Tlen, Nlen, Alen, Plen in bytes, C as printed: ciphertext || tag)
    let examples: [(usize, usize, &[u8], usize, &str); 4] = [
        (4, 7, &short_aad[..8], 4, "7162015b4dac255d"),
        (
            6,
            8,
            &short_aad[..16],
            16,
            "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd",
        ),
        (
            8,
            12,
            &short_aad[..20],
            24,
            "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951",
        ),
        (
            14,
            13,
            &long_aad,
            32,
            "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72\
             b4ac6bec93e8598e7f0dadbcea5b",
        ),
    ];
    for backend in backends() {
        for (i, (t, n, aad, p, c)) in examples.iter().enumerate() {
            let c = h(c);
            let (ct, tag) = c.split_at(*p);
            assert_eq!(tag.len(), *t);
            check_generic(
                backend,
                &key,
                &nonce[..*n],
                aad,
                &pt[..*p],
                ct,
                tag,
                &format!("example {}", i + 1),
            );
        }
    }
}

// ------------------------------------------------------- RFC 3610

const KEY_1: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
const KEY_2: &str = "d7828d13b2b0bdc325a76236df93cc6b";

/// An RFC 3610 §8 packet vector: the input packet's first `header_len`
/// bytes are the additional data and the rest the plaintext; the output is
/// the header, the ciphertext and the `tag_len`-byte tag.
struct Packet {
    number: u32,
    key: &'static str,
    nonce: &'static str,
    header_len: usize,
    tag_len: usize,
    input: &'static str,
    output: &'static str,
}

/// RFC 3610 §8, Packet Vectors #1-#24 (13-byte nonces, so L = 2; 8- and
/// 10-byte tags), copied from the RFC text.
const RFC3610_PACKETS: &[Packet] = &[
    Packet {
        number: 1,
        key: KEY_1,
        nonce: "00000003020100a0a1a2a3a4a5",
        header_len: 8,
        tag_len: 8,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
        output: "0001020304050607588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0",
    },
    Packet {
        number: 2,
        key: KEY_1,
        nonce: "00000004030201a0a1a2a3a4a5",
        header_len: 8,
        tag_len: 8,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        output: "000102030405060772c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916",
    },
    Packet {
        number: 3,
        key: KEY_1,
        nonce: "00000005040302a0a1a2a3a4a5",
        header_len: 8,
        tag_len: 8,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        output: "000102030405060751b1e5f44a197d1da46b0f8e2d282ae871e838bb64da8596574adaa76fbd9fb0c5",
    },
    Packet {
        number: 4,
        key: KEY_1,
        nonce: "00000006050403a0a1a2a3a4a5",
        header_len: 12,
        tag_len: 8,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
        output: "000102030405060708090a0ba28c6865939a9a79faaa5c4c2a9d4a91cdac8c96c861b9c9e61ef1",
    },
    Packet {
        number: 5,
        key: KEY_1,
        nonce: "00000007060504a0a1a2a3a4a5",
        header_len: 12,
        tag_len: 8,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        output: "000102030405060708090a0bdcf1fb7b5d9e23fb9d4e131253658ad86ebdca3e51e83f077d9c2d93",
    },
    Packet {
        number: 6,
        key: KEY_1,
        nonce: "00000008070605a0a1a2a3a4a5",
        header_len: 12,
        tag_len: 8,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        output: "000102030405060708090a0b6fc1b011f006568b5171a42d953d469b2570a4bd87405a0443ac91cb94",
    },
    Packet {
        number: 7,
        key: KEY_1,
        nonce: "00000009080706a0a1a2a3a4a5",
        header_len: 8,
        tag_len: 10,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
        output: "00010203040506070135d1b2c95f41d5d1d4fec185d166b8094e999dfed96c048c56602c97acbb7490",
    },
    Packet {
        number: 8,
        key: KEY_1,
        nonce: "0000000a090807a0a1a2a3a4a5",
        header_len: 8,
        tag_len: 10,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        output: "00010203040506077b75399ac0831dd2f0bbd75879a2fd8f6cae6b6cd9b7db24c17b4433f434963f34b4",
    },
    Packet {
        number: 9,
        key: KEY_1,
        nonce: "0000000b0a0908a0a1a2a3a4a5",
        header_len: 8,
        tag_len: 10,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        output: "000102030405060782531a60cc24945a4b8279181ab5c84df21ce7f9b73f42e197ea9c07e56b5eb17e5f4e",
    },
    Packet {
        number: 10,
        key: KEY_1,
        nonce: "0000000c0b0a09a0a1a2a3a4a5",
        header_len: 12,
        tag_len: 10,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
        output: "000102030405060708090a0b07342594157785152b074098330abb141b947b566aa9406b4d999988dd",
    },
    Packet {
        number: 11,
        key: KEY_1,
        nonce: "0000000d0c0b0aa0a1a2a3a4a5",
        header_len: 12,
        tag_len: 10,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        output: "000102030405060708090a0b676bb20380b0e301e8ab79590a396da78b834934f53aa2e9107a8b6c022c",
    },
    Packet {
        number: 12,
        key: KEY_1,
        nonce: "0000000e0d0c0ba0a1a2a3a4a5",
        header_len: 12,
        tag_len: 10,
        input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        output: "000102030405060708090a0bc0ffa0d6f05bdb67f24d43a4338d2aa4bed7b20e43cd1aa31662e7ad65d6db",
    },
    Packet {
        number: 13,
        key: KEY_2,
        nonce: "00412b4ea9cdbe3c9696766cfa",
        header_len: 8,
        tag_len: 8,
        input: "0be1a88bace018b108e8cf97d820ea258460e96ad9cf5289054d895ceac47c",
        output: "0be1a88bace018b14cb97f86a2a4689a877947ab8091ef5386a6ffbdd080f8e78cf7cb0cddd7b3",
    },
    Packet {
        number: 14,
        key: KEY_2,
        nonce: "0033568ef7b2633c9696766cfa",
        header_len: 8,
        tag_len: 8,
        input: "63018f76dc8a1bcb9020ea6f91bdd85afa0039ba4baff9bfb79c7028949cd0ec",
        output: "63018f76dc8a1bcb4ccb1e7ca981befaa0726c55d378061298c85c92814abc33c52ee81d7d77c08a",
    },
    Packet {
        number: 15,
        key: KEY_2,
        nonce: "00103fe41336713c9696766cfa",
        header_len: 8,
        tag_len: 8,
        input: "aa6cfa36cae86b40b916e0eacc1c00d7dcec68ec0b3bbb1a02de8a2d1aa346132e",
        output: "aa6cfa36cae86b40b1d23a2220ddc0ac900d9aa03c61fcf4a559a4417767089708a776796edb723506",
    },
    Packet {
        number: 16,
        key: KEY_2,
        nonce: "00764c63b8058e3c9696766cfa",
        header_len: 12,
        tag_len: 8,
        input: "d0d0735c531e1becf049c24412daac5630efa5396f770ce1a66b21f7b2101c",
        output: "d0d0735c531e1becf049c24414d253c3967b70609b7cbb7c499160283245269a6f49975bcadeaf",
    },
    Packet {
        number: 17,
        key: KEY_2,
        nonce: "00f8b678094e3b3c9696766cfa",
        header_len: 12,
        tag_len: 8,
        input: "77b60f011c03e1525899bcaee88b6a46c78d63e52eb8c546efb5de6f75e9cc0d",
        output: "77b60f011c03e1525899bcae5545ff1a085ee2efbf52b2e04bee1e2336c73e3f762c0c7744fe7e3c",
    },
    Packet {
        number: 18,
        key: KEY_2,
        nonce: "00d560912d3f703c9696766cfa",
        header_len: 12,
        tag_len: 8,
        input: "cd9044d2b71fdb8120ea60c06435acbafb11a82e2f071d7ca4a5ebd93a803ba87f",
        output: "cd9044d2b71fdb8120ea60c0009769ecabdf48625594c59251e6035722675e04c847099e5ae0704551",
    },
    Packet {
        number: 19,
        key: KEY_2,
        nonce: "0042fff8f1951c3c9696766cfa",
        header_len: 8,
        tag_len: 10,
        input: "d85bc7e69f944fb88a19b950bcf71a018e5e6701c91787659809d67dbedd18",
        output: "d85bc7e69f944fb8bc218daa947427b6db386a99ac1aef23ade0b52939cb6a637cf9bec2408897c6ba",
    },
    Packet {
        number: 20,
        key: KEY_2,
        nonce: "00920f40e56cdc3c9696766cfa",
        header_len: 8,
        tag_len: 10,
        input: "74a0ebc9069f5b371761433c37c5a35fc1f39f406302eb907c6163be38c98437",
        output: "74a0ebc9069f5b375810e6fd25874022e80361a478e3e9cf484ab04f447efff6f0a477cc2fc9bf548944",
    },
    Packet {
        number: 21,
        key: KEY_2,
        nonce: "0027ca0c7120bc3c9696766cfa",
        header_len: 8,
        tag_len: 10,
        input: "44a3aa3aae6475caa434a8e58500c6e41530538862d686ea9e81301b5ae4226bfa",
        output: "44a3aa3aae6475caf2beed7bc5098e83feb5b31608f8e29c38819a89c8e776f1544d4151a4ed3a8b87b9ce",
    },
    Packet {
        number: 22,
        key: KEY_2,
        nonce: "005b8ccbcd9af83c9696766cfa",
        header_len: 12,
        tag_len: 10,
        input: "ec46bb63b02520c33c49fd70b96b49e21d621741632875db7f6c9243d2d7c2",
        output: "ec46bb63b02520c33c49fd7031d750a09da3ed7fddd49a2032aabf17ec8ebf7d22c8088c666be5c197",
    },
    Packet {
        number: 23,
        key: KEY_2,
        nonce: "003ebe94044b9a3c9696766cfa",
        header_len: 12,
        tag_len: 10,
        input: "47a65ac78b3d594227e85e71e2fcfbb880442c731bf95167c8ffd7895e337076",
        output: "47a65ac78b3d594227e85e71e882f1dbd38ce3eda7c23f04dd65071eb41342acdf7e00dccec7ae52987d",
    },
    Packet {
        number: 24,
        key: KEY_2,
        nonce: "008d493b30ae8b3c9696766cfa",
        header_len: 12,
        tag_len: 10,
        input: "6e37a6ef546d955d34ab6059abf21c0b02feb88f856df4a37381bce3cc128517d4",
        output: "6e37a6ef546d955d34ab6059f32905b88a641b04b9c9ffb58cc390900f3da12ab16dce9e82efa16da62059",
    },
];

#[test]
fn rfc3610_packet_vectors() {
    assert_eq!(RFC3610_PACKETS.len(), 24);
    for backend in backends() {
        for p in RFC3610_PACKETS {
            let input = h(p.input);
            let output = h(p.output);
            assert_eq!(output.len(), input.len() + p.tag_len, "#{}", p.number);
            assert_eq!(
                output[..p.header_len],
                input[..p.header_len],
                "#{}",
                p.number
            );
            let (aad, pt) = input.split_at(p.header_len);
            let (ct, tag) = output[p.header_len..].split_at(pt.len());
            check_generic(
                backend,
                &h(p.key),
                &h(p.nonce),
                aad,
                pt,
                ct,
                tag,
                &format!("packet #{}", p.number),
            );
        }
    }
}

// ------------------------------------------------------- Wycheproof

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

/// Checks a vector through the TLS-facing [`Aes128Ccm`] (16-byte tag) or
/// [`Aes128Ccm8`] (8-byte tag).
fn check_typed(
    backend: aes::Backend,
    key: &[u8; 16],
    nonce: &[u8; 12],
    t: &WycheproofTest,
    valid: bool,
) {
    let (aad, pt, ct, tag) = (h(&t.aad), h(&t.msg), h(&t.ct), h(&t.tag));
    let what = format!("tcId {} {backend:?}", t.tc_id);
    let mut sealed = pt.clone();
    let mut opened = ct.clone();
    let (sealed_tag, opened_result) = match tag.len() {
        16 => {
            let c = Aes128Ccm::with_backend(key, backend).unwrap();
            let sealed_tag = c.seal_in_place(nonce, &aad, &mut sealed).unwrap().to_vec();
            let tag: [u8; 16] = tag.as_slice().try_into().unwrap();
            (sealed_tag, c.open_in_place(nonce, &aad, &mut opened, &tag))
        }
        8 => {
            let c = Aes128Ccm8::with_backend(key, backend).unwrap();
            let sealed_tag = c.seal_in_place(nonce, &aad, &mut sealed).unwrap().to_vec();
            let tag: [u8; 8] = tag.as_slice().try_into().unwrap();
            (sealed_tag, c.open_in_place(nonce, &aad, &mut opened, &tag))
        }
        n => panic!("{what}: unexpected tag length {n}"),
    };
    if valid {
        assert_eq!(hex::encode(&sealed), t.ct, "{what} ciphertext");
        assert_eq!(hex::encode(&sealed_tag), t.tag, "{what} tag");
        assert_eq!(opened_result, Ok(()), "{what} open");
        assert_eq!(opened, pt, "{what} plaintext");
    } else {
        assert_eq!(
            opened_result,
            Err(Error::DecryptFailed),
            "{what} must reject"
        );
        assert!(opened.iter().all(|&b| b == 0), "{what} buffer zeroed");
    }
}

#[test]
fn wycheproof_aes_ccm() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/wycheproof/aes_ccm_test.json"
    ))
    .expect("test vector file present");
    let file: WycheproofFile = serde_json::from_slice(&data).expect("valid JSON");
    let backends = backends();
    let (mut total, mut valid, mut invalid, mut skipped_key) = (0, 0, 0, 0);
    let (mut size_rejected, mut typed_ccm, mut typed_ccm8) = (0, 0, 0);
    for group in &file.test_groups {
        total += group.tests.len();
        // AES-192 is not implemented by `browntls-crypto`.
        if group.key_size == 192 {
            skipped_key += group.tests.len();
            continue;
        }
        let typed = group.key_size == 128 && group.iv_size == 96;
        for t in &group.tests {
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
            let bad_size = t.flags.iter().any(|f| {
                matches!(
                    f.as_str(),
                    "InvalidNonceSize" | "InvalidTagSize" | "InsecureTagSize"
                )
            });
            if bad_size {
                assert!(!is_valid, "tcId {}", t.tc_id);
                size_rejected += 1;
            }
            let (key, nonce, aad) = (h(&t.key), h(&t.iv), h(&t.aad));
            let (pt, ct, tag) = (h(&t.msg), h(&t.ct), h(&t.tag));
            assert_eq!(key.len() * 8, group.key_size);
            assert_eq!(nonce.len() * 8, group.iv_size);
            assert_eq!(tag.len() * 8, group.tag_size);
            for &backend in &backends {
                let what = format!("tcId {} {backend:?}", t.tc_id);
                if is_valid {
                    check_generic(backend, &key, &nonce, &aad, &pt, &ct, &tag, &what);
                    continue;
                }
                let ccm = AesCcm::with_backend(&key, backend).unwrap();
                let mut buf = ct.clone();
                let r = ccm.open_in_place(&nonce, &aad, &mut buf, &tag);
                if bad_size {
                    // Parameters outside SP 800-38C §A.1 are refused outright,
                    // in both directions.
                    assert_eq!(r, Err(Error::InvalidLength), "{what}");
                    let mut out_tag = vec![0u8; tag.len()];
                    let mut msg = pt.clone();
                    assert_eq!(
                        ccm.seal_in_place(&nonce, &aad, &mut msg, &mut out_tag),
                        Err(Error::InvalidLength),
                        "{what}"
                    );
                } else {
                    assert_eq!(r, Err(Error::DecryptFailed), "{what}");
                    assert!(buf.iter().all(|&b| b == 0), "{what} buffer zeroed");
                }
            }
            // The TLS 1.3 parameter sets: 96-bit nonces with 128-bit
            // (AEAD_AES_128_CCM) and 64-bit (AEAD_AES_128_CCM_8) tags.
            if typed && matches!(group.tag_size, 64 | 128) {
                let key: [u8; 16] = key.as_slice().try_into().unwrap();
                let nonce: [u8; 12] = nonce.as_slice().try_into().unwrap();
                for &backend in &backends {
                    check_typed(backend, &key, &nonce, t, is_valid);
                }
                if group.tag_size == 128 {
                    typed_ccm += 1;
                } else {
                    typed_ccm8 += 1;
                }
            }
        }
    }
    assert_eq!(total, file.number_of_tests);
    println!(
        "wycheproof: {total} vectors; {valid} valid + {invalid} invalid run on {} backends \
         ({size_rejected} with unsupported sizes), {skipped_key} skipped (AES-192); \
         {typed_ccm} through Aes128Ccm, {typed_ccm8} through Aes128Ccm8",
        backends.len()
    );
    // AES-128 and AES-256 hold 270 valid and 98 invalid vectors (44 of them
    // with unsupported sizes); 78 AES-128 vectors have a 96-bit nonce and a
    // 128-bit tag and 8 a 64-bit tag.
    assert_eq!((valid, invalid, size_rejected), (270, 98, 44));
    assert_eq!((typed_ccm, typed_ccm8), (78, 8));
}

// ------------------------------------------------------- differential

/// Seals with the RustCrypto `ccm` crate for any SP 800-38C parameter set.
fn reference_seal(key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8], tag_len: usize) -> Vec<u8> {
    macro_rules! go {
        ($c:ty, $m:ty, $n:ty) => {{
            let c = ccm::Ccm::<$c, $m, $n>::new_from_slice(key).unwrap();
            let nonce = ccm::Nonce::<$n>::try_from(nonce).unwrap();
            c.encrypt_inout_detached(&nonce, aad, buf.into())
                .unwrap()
                .to_vec()
        }};
    }
    macro_rules! by_nonce {
        ($c:ty, $m:ty) => {
            match nonce.len() {
                7 => go!($c, $m, U7),
                8 => go!($c, $m, U8),
                9 => go!($c, $m, U9),
                10 => go!($c, $m, U10),
                11 => go!($c, $m, U11),
                12 => go!($c, $m, U12),
                13 => go!($c, $m, U13),
                n => panic!("nonce length {n}"),
            }
        };
    }
    macro_rules! by_tag {
        ($c:ty) => {
            match tag_len {
                4 => by_nonce!($c, U4),
                6 => by_nonce!($c, U6),
                8 => by_nonce!($c, U8),
                10 => by_nonce!($c, U10),
                12 => by_nonce!($c, U12),
                14 => by_nonce!($c, U14),
                16 => by_nonce!($c, U16),
                t => panic!("tag length {t}"),
            }
        };
    }
    match key.len() {
        16 => by_tag!(Aes128),
        32 => by_tag!(Aes256),
        n => panic!("key length {n}"),
    }
}

/// Opens with the RustCrypto `ccm` crate (12-byte nonces).
fn reference_open(key: &[u8], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8]) -> bool {
    macro_rules! go {
        ($m:ty) => {{
            let c = ccm::Ccm::<Aes128, $m, U12>::new_from_slice(key).unwrap();
            let tag = ccm::Tag::<$m>::try_from(tag).unwrap();
            c.decrypt_inout_detached(&(*nonce).into(), aad, buf.into(), &tag)
                .is_ok()
        }};
    }
    match tag.len() {
        8 => go!(U8),
        16 => go!(U16),
        t => panic!("tag length {t}"),
    }
}

/// Every parameter set of SP 800-38C, random inputs: every available backend
/// matches the portable one and the RustCrypto `ccm` crate, and opens.
#[test]
fn every_parameter_set_matches_portable_and_rustcrypto() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let backends = backends();
    let aad_lens = [0usize, 1, 2, 13, 14, 15, 16, 17, 31, 32, 33, 100];
    for key_len in [16, 32] {
        for nonce_len in 7..=13 {
            for tag_len in (4..=16).step_by(2) {
                for _ in 0..3 {
                    let key = rng.bytes(key_len);
                    let nonce = rng.bytes(nonce_len);
                    let aad_len = aad_lens[rng.below(aad_lens.len())];
                    let aad = rng.bytes(aad_len);
                    let pt_len = rng.below(600);
                    let pt = rng.bytes(pt_len);
                    let what = format!(
                        "k={key_len} n={nonce_len} t={tag_len} a={} p={}",
                        aad.len(),
                        pt.len()
                    );
                    let mut expected = pt.clone();
                    let expected_tag = reference_seal(&key, &nonce, &aad, &mut expected, tag_len);
                    for &backend in &backends {
                        let ccm = AesCcm::with_backend(&key, backend).unwrap();
                        let mut buf = pt.clone();
                        let mut tag = vec![0u8; tag_len];
                        ccm.seal_in_place(&nonce, &aad, &mut buf, &mut tag).unwrap();
                        assert_eq!(buf, expected, "{what} {backend:?}");
                        assert_eq!(tag, expected_tag, "{what} {backend:?}");
                        ccm.open_in_place(&nonce, &aad, &mut buf, &tag).unwrap();
                        assert_eq!(buf, pt, "{what} {backend:?}");
                    }
                }
            }
        }
    }
}

/// The TLS parameter sets at the lengths that matter for records and for
/// the implementation's block, chunk and length-encoding boundaries: the
/// typed APIs, the generic one, the portable backend and RustCrypto agree.
#[test]
fn tls_parameter_sets_at_boundary_lengths() {
    let mut rng = Rng(0x5eed_cc3a_0000_0001);
    let backends = backends();
    let mut msg_lens: Vec<usize> = (0..=70).collect();
    msg_lens.extend([
        127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 4096, 16383, 16384, 16385,
        16401,
    ]);
    let aad_lens = [0usize, 5, 13, 65279, 65280, 65281];
    let key: [u8; 16] = rng.bytes(16).try_into().unwrap();
    let ccm_soft = Aes128Ccm::with_backend(&key, aes::Backend::Soft).unwrap();
    for (i, &len) in msg_lens.iter().enumerate() {
        let aad = rng.bytes(aad_lens[i % aad_lens.len()]);
        let nonce: [u8; 12] = rng.bytes(12).try_into().unwrap();
        let pt = rng.bytes(len);
        for tag_len in [16usize, 8] {
            let what = format!("t={tag_len} a={} p={len}", aad.len());
            let mut expected = pt.clone();
            let expected_tag = reference_seal(&key, &nonce, &aad, &mut expected, tag_len);
            // RustCrypto opens what the portable backend seals.
            let mut buf = pt.clone();
            let mut tag = vec![0u8; tag_len];
            AesCcm::with_backend(&key, aes::Backend::Soft)
                .unwrap()
                .seal_in_place(&nonce, &aad, &mut buf, &mut tag)
                .unwrap();
            assert!(reference_open(&key, &nonce, &aad, &mut buf, &tag), "{what}");
            assert_eq!(buf, pt, "{what}");
            for &backend in &backends {
                let mut buf = pt.clone();
                let tag = if tag_len == 16 {
                    let c = Aes128Ccm::with_backend(&key, backend).unwrap();
                    let tag = c.seal_in_place(&nonce, &aad, &mut buf).unwrap();
                    assert_eq!(buf, expected, "{what} {backend:?}");
                    c.open_in_place(&nonce, &aad, &mut buf, &tag).unwrap();
                    tag.to_vec()
                } else {
                    let c = Aes128Ccm8::with_backend(&key, backend).unwrap();
                    let tag = c.seal_in_place(&nonce, &aad, &mut buf).unwrap();
                    assert_eq!(buf, expected, "{what} {backend:?}");
                    c.open_in_place(&nonce, &aad, &mut buf, &tag).unwrap();
                    tag.to_vec()
                };
                assert_eq!(tag, expected_tag, "{what} {backend:?}");
                assert_eq!(buf, pt, "{what} {backend:?}");
            }
        }
        // The portable typed instance is the same mode as the generic one.
        let mut a = pt.clone();
        let tag = ccm_soft.seal_in_place(&nonce, &aad, &mut a).unwrap();
        let mut b = pt.clone();
        let mut generic_tag = [0u8; 16];
        AesCcm::with_backend(&key, aes::Backend::Soft)
            .unwrap()
            .seal_in_place(&nonce, &aad, &mut b, &mut generic_tag)
            .unwrap();
        assert_eq!((a, tag), (b, generic_tag));
    }
}

// ------------------------------------------------------- negative cases

/// Any change to the ciphertext, tag, additional data, nonce or length is
/// rejected, and the buffer is zeroed rather than released.
#[test]
fn tampering_is_rejected_and_buffer_zeroed() {
    let mut rng = Rng(0xbad_c0de);
    let key: [u8; 16] = rng.bytes(16).try_into().unwrap();
    let nonce: [u8; 12] = rng.bytes(12).try_into().unwrap();
    let aad = rng.bytes(13);
    let pt = rng.bytes(100);
    for backend in backends() {
        let ccm = Aes128Ccm::with_backend(&key, backend).unwrap();
        let ccm8 = Aes128Ccm8::with_backend(&key, backend).unwrap();
        let mut ct = pt.clone();
        let tag = ccm.seal_in_place(&nonce, &aad, &mut ct).unwrap();
        let mut ct8 = pt.clone();
        let tag8 = ccm8.seal_in_place(&nonce, &aad, &mut ct8).unwrap();
        assert_eq!(ct, ct8, "same keystream for both tag lengths");
        assert_ne!(tag[..8], tag8, "the tag length is bound into B_0");

        let open = |nonce: &[u8; 12], aad: &[u8], ct: &[u8], tag: &[u8; 16]| {
            let mut buf = ct.to_vec();
            let r = ccm.open_in_place(nonce, aad, &mut buf, tag);
            (r, buf)
        };
        let open8 = |nonce: &[u8; 12], aad: &[u8], ct: &[u8], tag: &[u8; 8]| {
            let mut buf = ct.to_vec();
            let r = ccm8.open_in_place(nonce, aad, &mut buf, tag);
            (r, buf)
        };
        let rejected = |(r, buf): (Result<(), Error>, Vec<u8>), what: &str| {
            assert_eq!(r, Err(Error::DecryptFailed), "{backend:?} {what}");
            assert!(buf.iter().all(|&b| b == 0), "{backend:?} {what}: zeroed");
        };

        assert_eq!(open(&nonce, &aad, &ct, &tag), (Ok(()), pt.clone()));
        assert_eq!(open8(&nonce, &aad, &ct8, &tag8), (Ok(()), pt.clone()));
        for bit in 0..ct.len() * 8 {
            let mut t = ct.clone();
            t[bit / 8] ^= 1 << (bit % 8);
            rejected(
                open(&nonce, &aad, &t, &tag),
                &format!("ciphertext bit {bit}"),
            );
            rejected(
                open8(&nonce, &aad, &t, &tag8),
                &format!("ciphertext bit {bit}"),
            );
        }
        for i in 0..16 {
            let mut t = tag;
            t[i] ^= 0x80;
            rejected(open(&nonce, &aad, &ct, &t), &format!("tag byte {i}"));
        }
        for i in 0..8 {
            let mut t = tag8;
            t[i] ^= 0x01;
            rejected(
                open8(&nonce, &aad, &ct8, &t),
                &format!("CCM_8 tag byte {i}"),
            );
        }
        for i in 0..aad.len() {
            let mut a = aad.clone();
            a[i] ^= 0x10;
            rejected(open(&nonce, &a, &ct, &tag), &format!("aad byte {i}"));
            rejected(open8(&nonce, &a, &ct8, &tag8), &format!("aad byte {i}"));
        }
        rejected(open(&nonce, &aad[..12], &ct, &tag), "truncated aad");
        rejected(open(&nonce, &[], &ct, &tag), "missing aad");
        for i in 0..12 {
            let mut n = nonce;
            n[i] ^= 0x04;
            rejected(open(&n, &aad, &ct, &tag), &format!("nonce byte {i}"));
            rejected(open8(&n, &aad, &ct8, &tag8), &format!("nonce byte {i}"));
        }
        rejected(open(&nonce, &aad, &ct[..99], &tag), "truncated ciphertext");
        rejected(
            open8(&nonce, &aad, &ct8[..99], &tag8),
            "truncated ciphertext",
        );
        let mut longer = ct.clone();
        longer.push(0);
        rejected(open(&nonce, &aad, &longer, &tag), "extended ciphertext");
        // A CCM_8 tag is not a prefix of the CCM tag, and the generic API
        // binds the tag length: opening with a truncated tag fails.
        let generic = AesCcm::with_backend(&key, backend).unwrap();
        for t in (4..16).step_by(2) {
            let mut buf = ct.clone();
            assert_eq!(
                generic.open_in_place(&nonce, &aad, &mut buf, &tag[..t]),
                Err(Error::DecryptFailed),
                "{backend:?} tag truncated to {t}"
            );
            assert!(buf.iter().all(|&b| b == 0));
        }
    }
}

#[test]
fn lengths_and_keys_are_validated() {
    // q = 2 (13-byte nonce): at most 2^16 - 1 bytes (SP 800-38C §A.1).
    let generic = AesCcm::new(&[7; 16]).unwrap();
    let mut buf = vec![0x55u8; 0xffff];
    let mut tag = [0u8; 16];
    generic
        .seal_in_place(&[1; 13], &[], &mut buf, &mut tag)
        .unwrap();
    generic
        .open_in_place(&[1; 13], &[], &mut buf, &tag)
        .unwrap();
    assert!(buf.iter().all(|&b| b == 0x55));
    let mut buf = vec![0u8; 0x1_0000];
    assert_eq!(
        generic.seal_in_place(&[1; 13], &[], &mut buf, &mut tag),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        generic.open_in_place(&[1; 13], &[], &mut buf, &tag),
        Err(Error::InvalidLength)
    );
    // Nonce and tag lengths outside SP 800-38C §A.1.
    let mut buf = [0u8; 4];
    for n in [0usize, 6, 14, 16] {
        assert_eq!(
            generic.seal_in_place(&vec![0; n], &[], &mut buf, &mut tag),
            Err(Error::InvalidLength),
            "nonce {n}"
        );
    }
    for t in [0usize, 2, 3, 5, 15, 17] {
        let mut tag = vec![0u8; t];
        assert_eq!(
            generic.seal_in_place(&[0; 12], &[], &mut buf, &mut tag),
            Err(Error::InvalidLength),
            "tag {t}"
        );
        assert_eq!(
            generic.open_in_place(&[0; 12], &[], &mut buf, &tag),
            Err(Error::InvalidLength),
            "tag {t}"
        );
    }

    // q = 3 (12-byte nonce): P_MAX = 2^24 - 1 (RFC 5116 §5.3, RFC 6655 §6.1).
    let mut big = vec![0u8; 1 << 24];
    let ccm = Aes128Ccm::new(&[1; 16]).unwrap();
    let ccm8 = Aes128Ccm8::new(&[1; 16]).unwrap();
    assert_eq!(
        ccm.seal_in_place(&[0; 12], &[], &mut big),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        ccm.open_in_place(&[0; 12], &[], &mut big, &[0; 16]),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        ccm8.seal_in_place(&[0; 12], &[], &mut big),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        ccm8.open_in_place(&[0; 12], &[], &mut big, &[0; 8]),
        Err(Error::InvalidLength)
    );

    // Keys: AES-128 for the typed APIs; AES-128 or AES-256 for the generic
    // one (AES-192 is not implemented).
    assert_eq!(Aes128Ccm::KEY_LEN, 16);
    assert_eq!((Aes128Ccm8::KEY_LEN, Aes128Ccm8::TAG_LEN), (16, 8));
    for len in [0usize, 15, 17, 24, 32] {
        assert_eq!(Aes128Ccm::new(&vec![0; len]).err(), Some(Error::InvalidKey));
        assert_eq!(
            Aes128Ccm8::new(&vec![0; len]).err(),
            Some(Error::InvalidKey)
        );
    }
    assert_eq!(AesCcm::new(&[0; 24]).err(), Some(Error::InvalidKey));
    assert!(AesCcm::new(&[0; 32]).is_ok());
    for backend in aes::Backend::ALL {
        if !backend.is_available() {
            assert_eq!(
                Aes128Ccm::with_backend(&[0; 16], backend).err(),
                Some(Error::Unsupported)
            );
            assert_eq!(
                AesCcm::with_backend(&[0; 32], backend).err(),
                Some(Error::Unsupported)
            );
        }
    }
}

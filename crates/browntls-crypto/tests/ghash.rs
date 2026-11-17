//! Standalone GHASH ([`Ghash`]) on every backend available at run time: the
//! RFC 8452 Appendix A vector and the GHASH(H, A, C) values of all eighteen
//! McGrew–Viega GCM test cases, a bit-serial reference (SP 800-38D,
//! Algorithms 1 and 2), the AES-GCM tag relation against this crate's
//! AES-GCM and the RustCrypto `aes` and `aes-gcm` crates, every way of
//! splitting the input, and the documented rules for mixing the update
//! forms.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aes::cipher::{BlockCipherEncrypt as _, KeyInit as _};
use aes_gcm::AeadInOut as _;
use browntls_crypto::accel::{self, Algorithm, Policy};
use browntls_crypto::aead::Aead;
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm, GHASH_BLOCK_LEN, Ghash, GhashBackend};

type Block = [u8; GHASH_BLOCK_LEN];

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn block(s: &str) -> Block {
    h(s).try_into().expect("one block")
}

/// The backends this CPU can run.
fn backends() -> Vec<GhashBackend> {
    GhashBackend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect()
}

/// Deterministic test bytes (xorshift64).
fn bytes(seed: u64, len: usize) -> Vec<u8> {
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

// ------------------------------------------------------------ reference

/// Multiplication in GF(2^128), bit by bit (SP 800-38D, Algorithm 1).
fn gf_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe1 << 120;
    let mut z = 0;
    let mut v = y;
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
    }
    z
}

/// `GHASH_H` of `data` zero-padded to whole blocks (SP 800-38D,
/// Algorithm 2).
fn reference(key: &Block, data: &[u8]) -> Block {
    let hk = u128::from_be_bytes(*key);
    let mut y = 0u128;
    for chunk in data.chunks(GHASH_BLOCK_LEN) {
        let mut b = [0u8; GHASH_BLOCK_LEN];
        b[..chunk.len()].copy_from_slice(chunk);
        y = gf_mul(y ^ u128::from_be_bytes(b), hk);
    }
    y.to_be_bytes()
}

/// GCM's length block: the bit lengths of `a` and `c`, big-endian.
fn lengths(a: &[u8], c: &[u8]) -> Block {
    let mut l = [0u8; GHASH_BLOCK_LEN];
    l[..8].copy_from_slice(&(8 * a.len() as u64).to_be_bytes());
    l[8..].copy_from_slice(&(8 * c.len() as u64).to_be_bytes());
    l
}

/// GCM's GHASH input `A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64`.
fn gcm_input(a: &[u8], c: &[u8]) -> Vec<u8> {
    let pad = |x: &[u8]| {
        let mut v = x.to_vec();
        v.resize(x.len().next_multiple_of(GHASH_BLOCK_LEN), 0);
        v
    };
    let mut x = pad(a);
    x.extend(pad(c));
    x.extend(lengths(a, c));
    x
}

/// `GHASH_H(A, C)` as GCM computes it, with `ghash`.
fn ghash_gcm(mut ghash: Ghash, a: &[u8], c: &[u8]) -> Block {
    ghash.update_padded(a);
    ghash.update_padded(c);
    ghash.update_blocks(&[lengths(a, c)]);
    ghash.finalize()
}

/// `GHASH_H(X)`, with `X` passed to `update` in one piece.
fn ghash(key: &Block, backend: GhashBackend, data: &[u8]) -> Block {
    let mut g = Ghash::with_backend(key, backend);
    g.update(data);
    g.finalize()
}

// -------------------------------------------------------- known answers

#[test]
fn report_available_backends() {
    println!("GHASH backends: {:?}", backends());
    println!("selected: {:?}", GhashBackend::select());
    assert!(backends().contains(&GhashBackend::Soft));
    assert!(GhashBackend::select().is_available());
}

/// RFC 8452, Appendix A: GHASH(H, X_1, X_2).
#[test]
fn rfc8452_appendix_a() {
    let key = block("25629347589242761d31f826ba4b757b");
    let x = [
        block("4f4f95668c83dfb6401762bb2d01a262"),
        block("d1a24ddd2721d006bbe45f20d3c9f362"),
    ];
    let want = block("bd9b3997046731fb96251b91f9c99d7a");
    assert_eq!(reference(&key, x.as_flattened()), want);
    for b in backends() {
        let mut g = Ghash::with_backend(&key, b);
        g.update_blocks(&x);
        assert_eq!(g.finalize(), want, "{b:?}: update_blocks");
        assert_eq!(ghash(&key, b, x.as_flattened()), want, "{b:?}: update");
        let mut g = Ghash::with_backend(&key, b);
        g.update_padded(x.as_flattened());
        assert_eq!(g.finalize(), want, "{b:?}: update_padded");
    }
}

/// One McGrew–Viega test case: the key, `H = E_K(0^128)`, `A`, `C` and
/// GHASH(H, A, C) as the specification lists them.
struct Spec {
    case: u32,
    key: &'static str,
    h: &'static str,
    a: &'static str,
    c: &'static str,
    ghash: &'static str,
}

/// Test cases 1 to 18 of "The Galois/Counter Mode of Operation (GCM)"
/// (McGrew and Viega, Appendix B; AES-128, AES-192 and AES-256 keys).
const SPEC: &[Spec] = &[
    Spec {
        case: 1,
        key: "00000000000000000000000000000000",
        h: "66e94bd4ef8a2c3b884cfa59ca342b2e",
        a: "",
        c: "",
        ghash: "00000000000000000000000000000000",
    },
    Spec {
        case: 2,
        key: "00000000000000000000000000000000",
        h: "66e94bd4ef8a2c3b884cfa59ca342b2e",
        a: "",
        c: "0388dace60b6a392f328c2b971b2fe78",
        ghash: "f38cbb1ad69223dcc3457ae5b6b0f885",
    },
    Spec {
        case: 3,
        key: "feffe9928665731c6d6a8f9467308308",
        h: "b83b533708bf535d0aa6e52980d53b78",
        a: "",
        c: concat!(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        ),
        ghash: "7f1b32b81b820d02614f8895ac1d4eac",
    },
    Spec {
        case: 4,
        key: "feffe9928665731c6d6a8f9467308308",
        h: "b83b533708bf535d0aa6e52980d53b78",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        c: concat!(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        ),
        ghash: "698e57f70e6ecc7fd9463b7260a9ae5f",
    },
    Spec {
        case: 5,
        key: "feffe9928665731c6d6a8f9467308308",
        h: "b83b533708bf535d0aa6e52980d53b78",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        c: concat!(
            "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423",
            "73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        ),
        ghash: "df586bb4c249b92cb6922877e444d37b",
    },
    Spec {
        case: 6,
        key: "feffe9928665731c6d6a8f9467308308",
        h: "b83b533708bf535d0aa6e52980d53b78",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        c: concat!(
            "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7",
            "01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
        ),
        ghash: "1c5afe9760d3932f3c9a878aac3dc3de",
    },
    Spec {
        case: 7,
        key: "000000000000000000000000000000000000000000000000",
        h: "aae06992acbf52a3e8f4a96ec9300bd7",
        a: "",
        c: "",
        ghash: "00000000000000000000000000000000",
    },
    Spec {
        case: 8,
        key: "000000000000000000000000000000000000000000000000",
        h: "aae06992acbf52a3e8f4a96ec9300bd7",
        a: "",
        c: "98e7247c07f0fe411c267e4384b0f600",
        ghash: "e2c63f0ac44ad0e02efa05ab6743d4ce",
    },
    Spec {
        case: 9,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        h: "466923ec9ae682214f2c082badb39249",
        a: "",
        c: concat!(
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c",
            "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
        ),
        ghash: "51110d40f6c8fff0eb1ae33445a889f0",
    },
    Spec {
        case: 10,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        h: "466923ec9ae682214f2c082badb39249",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        c: concat!(
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c",
            "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
        ),
        ghash: "ed2ce3062e4a8ec06db8b4c490e8a268",
    },
    Spec {
        case: 11,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        h: "466923ec9ae682214f2c082badb39249",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        c: concat!(
            "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057",
            "fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
        ),
        ghash: "1e6a133806607858ee80eaf237064089",
    },
    Spec {
        case: 12,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        h: "466923ec9ae682214f2c082badb39249",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        c: concat!(
            "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e45",
            "81e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
        ),
        ghash: "82567fb0b4cc371801eadec005968e94",
    },
    Spec {
        case: 13,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        h: "dc95c078a2408989ad48a21492842087",
        a: "",
        c: "",
        ghash: "00000000000000000000000000000000",
    },
    Spec {
        case: 14,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        h: "dc95c078a2408989ad48a21492842087",
        a: "",
        c: "cea7403d4d606b6e074ec5d3baf39d18",
        ghash: "83de425c5edc5d498f382c441041ca92",
    },
    Spec {
        case: 15,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        h: "acbef20579b4b8ebce889bac8732dad7",
        a: "",
        c: concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        ),
        ghash: "4db870d37cb75fcb46097c36230d1612",
    },
    Spec {
        case: 16,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        h: "acbef20579b4b8ebce889bac8732dad7",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        c: concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        ),
        ghash: "8bd0c4d8aacd391e67cca447e8c38f65",
    },
    Spec {
        case: 17,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        h: "acbef20579b4b8ebce889bac8732dad7",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        c: concat!(
            "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0",
            "feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        ),
        ghash: "75a34288b8c68f811c52b2e9a2f97f63",
    },
    Spec {
        case: 18,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        h: "acbef20579b4b8ebce889bac8732dad7",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        c: concat!(
            "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4",
            "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
        ),
        ghash: "d5ffcf6fc5ac4d69722187421a7f170b",
    },
];

/// GHASH(H, A, C) of every McGrew–Viega test case on every backend, with
/// `H` checked against the RustCrypto `aes` crate (which also covers the
/// AES-192 keys this crate does not implement).
#[test]
fn gcm_spec_ghash_values() {
    assert_eq!(SPEC.len(), 18);
    for (i, t) in SPEC.iter().enumerate() {
        assert_eq!(t.case as usize, i + 1);
        let key = h(t.key);
        let mut hk = [0u8; GHASH_BLOCK_LEN];
        match key.len() {
            16 => aes::Aes128::new_from_slice(&key)
                .unwrap()
                .encrypt_block((&mut hk).into()),
            24 => aes::Aes192::new_from_slice(&key)
                .unwrap()
                .encrypt_block((&mut hk).into()),
            _ => aes::Aes256::new_from_slice(&key)
                .unwrap()
                .encrypt_block((&mut hk).into()),
        }
        assert_eq!(hk, block(t.h), "case {}: H", t.case);
        let (a, c, want) = (h(t.a), h(t.c), block(t.ghash));
        assert_eq!(reference(&hk, &gcm_input(&a, &c)), want, "case {}", t.case);
        for b in backends() {
            let got = ghash_gcm(Ghash::with_backend(&hk, b), &a, &c);
            assert_eq!(got, want, "case {} on {b:?}", t.case);
        }
        assert_eq!(ghash_gcm(Ghash::new(&hk), &a, &c), want, "case {}", t.case);
    }
}

// ------------------------------------------------- reference, any input

/// Keys that exercise the edges of the field: zero, one (the element `1`
/// is the block 0x80 00 .. 00), `x^127` (0x00 .. 01), all ones, and
/// arbitrary ones.
fn keys() -> Vec<Block> {
    let mut keys = vec![
        [0; GHASH_BLOCK_LEN],
        block("80000000000000000000000000000000"),
        block("00000000000000000000000000000001"),
        [0xff; GHASH_BLOCK_LEN],
    ];
    for seed in 1..=4 {
        keys.push(bytes(seed * 0x9e37_79b9, 16).try_into().unwrap());
    }
    keys
}

/// Every backend equals the bit-serial reference for keys at the edges of
/// the field and lengths across every block-grouping boundary of the
/// backends (8, 32 blocks and their multiples).
#[test]
fn backends_match_reference() {
    let lens: Vec<usize> = (0..=272).chain([511, 512, 513, 1023, 1024, 1040]).collect();
    let data = bytes(7, 1040);
    for key in keys() {
        for &len in &lens {
            let want = reference(&key, &data[..len]);
            for b in backends() {
                assert_eq!(ghash(&key, b, &data[..len]), want, "{b:?} len={len}");
            }
        }
    }
    // The zero key maps everything to zero, and the key `1` sums blocks.
    assert_eq!(ghash(&[0; 16], GhashBackend::Soft, &data), [0; 16]);
    let one = block("80000000000000000000000000000000");
    let sum = data[..64]
        .chunks(16)
        .fold([0u8; 16], |acc, c| core::array::from_fn(|i| acc[i] ^ c[i]));
    for b in backends() {
        assert_eq!(ghash(&one, b, &data[..64]), sum, "{b:?}");
    }
}

/// A long input (4097 blocks and a partial one) agrees across backends and
/// with the reference.
#[test]
fn long_input() {
    let key: Block = bytes(99, 16).try_into().unwrap();
    let data = bytes(100, 65_536 + 13);
    let want = reference(&key, &data);
    for b in backends() {
        assert_eq!(ghash(&key, b, &data), want, "{b:?}");
    }
}

// ------------------------------------------------------- AES-GCM relation

/// `tag = GHASH_H(A, C) xor E_K(J0)` with `H = E_K(0^128)` and `J0 = IV ||
/// 0^31 || 1`, for this crate's AES-GCM and the RustCrypto `aes-gcm` crate,
/// with `H` and `E_K(J0)` from the RustCrypto `aes` crate.
#[test]
fn aes_gcm_tag_relation() {
    for wide in [false, true] {
        for seed in 0..12u64 {
            let key = bytes(seed + 1000, if wide { 32 } else { 16 });
            let nonce: [u8; 12] = bytes(seed + 2000, 12).try_into().unwrap();
            let aad = bytes(seed + 3000, (seed as usize * 7) % 41);
            let pt = bytes(
                seed + 4000,
                [0, 1, 15, 16, 17, 100, 255, 256, 513, 1100][seed as usize % 10],
            );

            let mut ct = pt.clone();
            let tag = if wide {
                Aes256Gcm::new(&key)
                    .unwrap()
                    .seal_in_place(&nonce, &aad, &mut ct)
            } else {
                Aes128Gcm::new(&key)
                    .unwrap()
                    .seal_in_place(&nonce, &aad, &mut ct)
            }
            .unwrap();
            let mut rc_ct = pt.clone();
            let rc_tag = if wide {
                aes_gcm::Aes256Gcm::new_from_slice(&key)
                    .unwrap()
                    .encrypt_inout_detached(&nonce.into(), &aad, (&mut rc_ct[..]).into())
            } else {
                aes_gcm::Aes128Gcm::new_from_slice(&key)
                    .unwrap()
                    .encrypt_inout_detached(&nonce.into(), &aad, (&mut rc_ct[..]).into())
            }
            .unwrap();
            assert_eq!((&ct, tag.as_slice()), (&rc_ct, rc_tag.as_slice()));

            let mut hk = [0u8; GHASH_BLOCK_LEN];
            let mut mask = [0u8; GHASH_BLOCK_LEN];
            mask[..12].copy_from_slice(&nonce);
            mask[15] = 1;
            if wide {
                let aes = aes::Aes256::new_from_slice(&key).unwrap();
                aes.encrypt_block((&mut hk).into());
                aes.encrypt_block((&mut mask).into());
            } else {
                let aes = aes::Aes128::new_from_slice(&key).unwrap();
                aes.encrypt_block((&mut hk).into());
                aes.encrypt_block((&mut mask).into());
            }
            let masked = |s: Block| -> Block { core::array::from_fn(|i| s[i] ^ mask[i]) };
            for b in backends() {
                let s = ghash_gcm(Ghash::with_backend(&hk, b), &aad, &ct);
                assert_eq!(masked(s), tag, "{b:?} wide={wide} seed={seed}");
                // The same with A and C streamed in pieces, each ended by
                // an empty `update_padded`.
                let mut g = Ghash::with_backend(&hk, b);
                for part in aad.chunks(5) {
                    g.update(part);
                }
                g.update_padded(&[]);
                for part in ct.chunks(37) {
                    g.update(part);
                }
                g.update_padded(&[]);
                g.update_blocks(&[lengths(&aad, &ct)]);
                assert_eq!(masked(g.finalize()), tag, "{b:?} streamed seed={seed}");
            }
        }
    }
}

// ------------------------------------------------ splitting and mixing

/// The value does not depend on how `update` input is split: at every
/// split point, in one-byte pieces and in irregular pieces.
#[test]
fn split_points_do_not_matter() {
    let key: Block = bytes(5, 16).try_into().unwrap();
    for len in [0usize, 1, 15, 16, 17, 100, 200, 600] {
        let data = bytes(len as u64 + 6, len);
        let want = reference(&key, &data);
        for b in backends() {
            for at in 0..=len {
                let mut g = Ghash::with_backend(&key, b);
                let (x, y) = data.split_at(at);
                g.update(x);
                g.update(y);
                assert_eq!(g.finalize(), want, "{b:?} len={len} at={at}");
            }
            let mut g = Ghash::with_backend(&key, b);
            for byte in &data {
                g.update(core::slice::from_ref(byte));
            }
            assert_eq!(g.finalize(), want, "{b:?} len={len} bytewise");
            let mut g = Ghash::with_backend(&key, b);
            let mut rest = &data[..];
            for step in [3usize, 16, 0, 29, 1, 64, 7].iter().cycle() {
                if rest.is_empty() {
                    break;
                }
                let (x, y) = rest.split_at((*step).min(rest.len()));
                g.update(x);
                rest = y;
            }
            assert_eq!(g.finalize(), want, "{b:?} len={len} irregular");
        }
    }
}

/// The documented mixing rules: padding happens only in `update_padded`
/// and `finalize`, at the next block boundary of the whole input, and
/// `update_blocks` is `update` of the same bytes.
#[test]
fn mixing_update_forms() {
    let key: Block = bytes(8, 16).try_into().unwrap();
    let data = bytes(9, 90);
    let blocks: Vec<Block> = bytes(10, 48)
        .chunks(16)
        .map(|c| c.try_into().unwrap())
        .collect();
    let padded = |x: &[u8]| {
        let mut v = x.to_vec();
        v.resize(x.len().next_multiple_of(16), 0);
        v
    };
    for b in backends() {
        // Nothing absorbed: the value is zero, and padding adds nothing.
        assert_eq!(Ghash::with_backend(&key, b).finalize(), [0; 16]);
        let mut g = Ghash::with_backend(&key, b);
        g.update_padded(&[]);
        g.update_blocks(&[]);
        g.update(&[]);
        assert_eq!(g.finalize(), [0; 16], "{b:?}");
        for at in [0usize, 1, 15, 16, 17, 40, 90] {
            let (x, y) = data.split_at(at);
            // `update(x)` then `update_padded(y)` pads `x || y` once.
            let mut g = Ghash::with_backend(&key, b);
            g.update(x);
            g.update_padded(y);
            assert_eq!(g.finalize(), reference(&key, &data), "{b:?} at={at}");
            // `update_padded(x)` then `update(y)` pads `x` first.
            let mut g = Ghash::with_backend(&key, b);
            g.update_padded(x);
            g.update(y);
            let mut want = padded(x);
            want.extend_from_slice(y);
            assert_eq!(g.finalize(), reference(&key, &want), "{b:?} at={at}");
            // Blocks after a partial block continue it.
            let mut g = Ghash::with_backend(&key, b);
            g.update(x);
            g.update_blocks(&blocks);
            g.update(y);
            let mut want = x.to_vec();
            want.extend_from_slice(blocks.as_flattened());
            want.extend_from_slice(y);
            assert_eq!(g.finalize(), reference(&key, &want), "{b:?} at={at}");
            // Padding on a block boundary adds nothing; padding twice
            // pads once.
            let mut g = Ghash::with_backend(&key, b);
            g.update_padded(x);
            g.update_padded(&[]);
            g.update_blocks(&blocks);
            g.update_padded(&[]);
            let mut want = padded(x);
            want.extend_from_slice(blocks.as_flattened());
            assert_eq!(g.finalize(), reference(&key, &want), "{b:?} at={at}");
        }
    }
}

// ------------------------------------------------------------- backends

/// Every backend can be named: an available one is used, any other falls
/// back to the portable code; all give the same value. `new` takes the
/// selected backend, which follows the GHASH policy.
#[test]
fn backend_selection() {
    let key: Block = bytes(11, 16).try_into().unwrap();
    let data = bytes(12, 333);
    let want = reference(&key, &data);
    for b in GhashBackend::ALL {
        let g = Ghash::with_backend(&key, b);
        let used = if b.is_available() {
            b
        } else {
            GhashBackend::Soft
        };
        assert_eq!(g.backend(), used, "{b:?}");
        assert_eq!(ghash(&key, b, &data), want, "{b:?}");
    }
    let g = Ghash::new(&key);
    assert_eq!(g.backend(), GhashBackend::select());
    // Portable code only (the only test of this binary that changes the
    // policy; the others do not depend on it).
    accel::set_policy(Algorithm::Ghash, Policy::NONE).unwrap();
    let mut g = Ghash::new(&key);
    let backend = g.backend();
    g.update(&data);
    let got = g.finalize();
    accel::set_policy(Algorithm::Ghash, Policy::PREFERRED).unwrap();
    assert_eq!(backend, GhashBackend::Soft);
    assert_eq!(got, want);
}

/// `Debug` shows the backend and nothing of the key or the state.
#[test]
fn debug_shows_backend_only() {
    let key = [0xab; GHASH_BLOCK_LEN];
    for b in backends() {
        let mut g = Ghash::with_backend(&key, b);
        g.update(&[0xcd; 21]);
        assert_eq!(format!("{g:?}"), format!("Ghash {{ backend: {b:?}, .. }}"));
    }
}

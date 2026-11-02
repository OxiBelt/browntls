//! ChaCha20, Poly1305 and ChaCha20-Poly1305: RFC 8439 vectors, Wycheproof
//! vectors and differential tests against the RustCrypto implementation, run
//! on every backend available on the executing CPU.
#![allow(clippy::unwrap_used)]

use browntls_crypto::Error;
use browntls_crypto::aead::Aead;
use browntls_crypto::chacha::{
    Backend, ChaCha20Poly1305, Poly1305, PolyBackend, chacha20_xor, chacha20_xor_with,
};

fn h(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(s).unwrap()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    h(s).try_into().unwrap()
}

fn backends() -> Vec<Backend> {
    let b: Vec<_> = Backend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect();
    b
}

fn poly_backends() -> Vec<PolyBackend> {
    PolyBackend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect()
}

fn aeads(key: &[u8]) -> Vec<ChaCha20Poly1305> {
    let mut v = Vec::new();
    for b in backends() {
        for p in poly_backends() {
            v.push(ChaCha20Poly1305::with_backends(key, b, p).unwrap());
        }
    }
    v
}

/// Deterministic test RNG (SplitMix64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.next() as u8;
        }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0; n];
        self.fill(&mut v);
        v
    }
}

const IETF_TEXT: &[u8] = b"Any submission to the IETF intended by the Contributor for \
publication as all or part of an IETF Internet-Draft or RFC and any statement made within \
the context of an IETF activity is considered an \"IETF Contribution\". Such statements \
include oral statements in IETF sessions, as well as written and electronic communications \
made at any time or place, which are addressed to";

const JABBERWOCKY: &[u8] = b"'Twas brillig, and the slithy toves\nDid gyre and gimble in the \
wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";

const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";

/// (key, nonce, counter, plaintext, ciphertext): RFC 8439 2.4.2 and A.1/A.2.
/// (key, nonce, initial counter, plaintext, ciphertext).
type ChaChaVector = ([u8; 32], [u8; 12], u32, Vec<u8>, Vec<u8>);

fn chacha_vectors() -> Vec<ChaChaVector> {
    let zero_key = [0u8; 32];
    let mut key_one = [0u8; 32];
    key_one[31] = 1;
    let mut key_ff = [0u8; 32];
    key_ff[1] = 0xff;
    let mut nonce2 = [0u8; 12];
    nonce2[11] = 2;
    let seq_key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let jab_key = arr("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
    vec![
        // 2.4.2
        (
            seq_key,
            arr("000000000000004a00000000"),
            1,
            SUNSCREEN.to_vec(),
            h(
                "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b
               f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8
               07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736
               5af90bbf74a35be6b40b8eedf2785e42874d",
            ),
        ),
        // A.1 #1 (also A.2 #1)
        (
            zero_key,
            [0; 12],
            0,
            vec![0; 64],
            h(
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7
               da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            ),
        ),
        // A.1 #2
        (
            zero_key,
            [0; 12],
            1,
            vec![0; 64],
            h(
                "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed
               29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
            ),
        ),
        // A.1 #3
        (
            key_one,
            [0; 12],
            1,
            vec![0; 64],
            h(
                "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a
               8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
            ),
        ),
        // A.1 #4
        (
            key_ff,
            [0; 12],
            2,
            vec![0; 64],
            h(
                "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca
               13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
            ),
        ),
        // A.1 #5
        (
            zero_key,
            nonce2,
            0,
            vec![0; 64],
            h(
                "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7
               8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
            ),
        ),
        // A.2 #2
        (
            key_one,
            nonce2,
            1,
            IETF_TEXT.to_vec(),
            h(
                "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec
               2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d
               4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950
               42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a
               d00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d
               c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b
               0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c
               cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b
               c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f
               5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6
               98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab
               7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
            ),
        ),
        // A.2 #3
        (
            jab_key,
            nonce2,
            42,
            JABBERWOCKY.to_vec(),
            h(
                "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf
               166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb
               f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77
               04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
            ),
        ),
        // A.4 #1-#3: the Poly1305 key is the first 32 bytes of block 0.
        (
            zero_key,
            [0; 12],
            0,
            vec![0; 32],
            h("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"),
        ),
        (
            key_one,
            nonce2,
            0,
            vec![0; 32],
            h("ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739"),
        ),
        (
            jab_key,
            nonce2,
            0,
            vec![0; 32],
            h("965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae"),
        ),
    ]
}

#[test]
fn rfc8439_chacha20() {
    for (key, nonce, ctr, pt, ct) in chacha_vectors() {
        let mut buf = pt.clone();
        chacha20_xor(&key, ctr, &nonce, &mut buf);
        assert_eq!(hex::encode(&buf), hex::encode(&ct));
        for b in backends() {
            let mut buf = pt.clone();
            chacha20_xor_with(b, &key, ctr, &nonce, &mut buf).unwrap();
            assert_eq!(buf, ct, "{b:?}");
            chacha20_xor_with(b, &key, ctr, &nonce, &mut buf).unwrap();
            assert_eq!(buf, pt, "{b:?}");
        }
    }
}

/// QUIC header protection (RFC 9001, A.5): counter from the sample's first
/// four bytes, nonce from the rest, 5-byte mask.
#[test]
fn quic_header_protection_mask() {
    let hp = arr("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    let sample = h("5e5cd55c41f69080575d7999c25a5bfb");
    let ctr = u32::from_le_bytes(sample[..4].try_into().unwrap());
    let nonce: [u8; 12] = sample[4..].try_into().unwrap();
    for b in backends() {
        let mut mask = [0u8; 5];
        chacha20_xor_with(b, &hp, ctr, &nonce, &mut mask).unwrap();
        assert_eq!(hex::encode(mask), "aefefe7d03", "{b:?}");
    }
}

/// (key, message, tag): RFC 8439 2.5.2 and A.3.
fn poly_vectors() -> Vec<([u8; 32], Vec<u8>, [u8; 16])> {
    let rs = |r: &str, s: &str| -> [u8; 32] { arr(&format!("{r}{s}")) };
    let z16 = "00000000000000000000000000000000";
    let ones = "ffffffffffffffffffffffffffffffff";
    vec![
        (
            arr("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
            b"Cryptographic Forum Research Group".to_vec(),
            arr("a8061dc1305136c6c22b8baf0c0127a9"),
        ),
        ([0; 32], vec![0; 64], [0; 16]),
        (
            rs(z16, "36e5f6b5c5e06070f0efca96227a863e"),
            IETF_TEXT.to_vec(),
            arr("36e5f6b5c5e06070f0efca96227a863e"),
        ),
        (
            rs("36e5f6b5c5e06070f0efca96227a863e", z16),
            IETF_TEXT.to_vec(),
            arr("f3477e7cd95417af89a6b8794c310cf0"),
        ),
        (
            arr("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
            JABBERWOCKY.to_vec(),
            arr("4541669a7eaaee61e708dc7cbcc5eb62"),
        ),
        // #5: partially reduced result not fully reduced.
        (
            rs("02000000000000000000000000000000", z16),
            h(ones),
            arr("03000000000000000000000000000000"),
        ),
        // #6: s addition overflows 2^128.
        (
            rs("02000000000000000000000000000000", ones),
            h("02000000000000000000000000000000"),
            arr("03000000000000000000000000000000"),
        ),
        // #7: carry from lower limb with all-ones limb.
        (
            rs("01000000000000000000000000000000", z16),
            h(
                "ffffffffffffffffffffffffffffffff f0ffffffffffffffffffffffffffffff
               11000000000000000000000000000000",
            ),
            arr("05000000000000000000000000000000"),
        ),
        // #8: result exactly 2^130 - 5.
        (
            rs("01000000000000000000000000000000", z16),
            h(
                "ffffffffffffffffffffffffffffffff fbfefefefefefefefefefefefefefefe
               01010101010101010101010101010101",
            ),
            [0; 16],
        ),
        // #9: result exactly 2^130 - 6.
        (
            rs("02000000000000000000000000000000", z16),
            h("fdffffffffffffffffffffffffffffff"),
            arr("faffffffffffffffffffffffffffffff"),
        ),
        // #10: 131-bit intermediate result.
        (
            rs("01000000000000000400000000000000", z16),
            h(
                "e33594d7505e43b90000000000000000 3394d7505e4379cd0100000000000000
               00000000000000000000000000000000 01000000000000000000000000000000",
            ),
            arr("14000000000000005500000000000000"),
        ),
        // #11: 131-bit final result.
        (
            rs("01000000000000000400000000000000", z16),
            h(
                "e33594d7505e43b90000000000000000 3394d7505e4379cd0100000000000000
               00000000000000000000000000000000",
            ),
            arr("13000000000000000000000000000000"),
        ),
    ]
}

#[test]
fn rfc8439_poly1305() {
    for (key, msg, tag) in poly_vectors() {
        assert_eq!(Poly1305::new(&key).finalize(), {
            let mut p = Poly1305::new(&key);
            p.update(&[]);
            p.finalize()
        });
        for b in poly_backends() {
            let mut p = Poly1305::with_backend(&key, b);
            p.update(&msg);
            assert_eq!(hex::encode(p.finalize()), hex::encode(tag), "{b:?}");
            // Incremental updates across every split point.
            for split in 0..=msg.len() {
                let mut p = Poly1305::with_backend(&key, b);
                p.update(&msg[..split]);
                p.update(&msg[split..]);
                assert_eq!(p.finalize(), tag, "{b:?} split {split}");
            }
            let mut p = Poly1305::with_backend(&key, b);
            p.update(&msg);
            assert!(p.verify(&tag).is_ok());
            let mut bad = tag;
            bad[15] ^= 0x80;
            let mut p = Poly1305::with_backend(&key, b);
            p.update(&msg);
            assert_eq!(p.verify(&bad), Err(Error::InvalidSignature));
        }
    }
}

/// Byte-at-a-time and random chunking agree with one-shot on long inputs.
#[test]
fn poly1305_chunking() {
    let mut rng = Rng(7);
    let key: [u8; 32] = rng.bytes(32).try_into().unwrap();
    let msg = rng.bytes(3000);
    for b in poly_backends() {
        let mut one = Poly1305::with_backend(&key, b);
        one.update(&msg);
        let want = one.finalize();
        let mut p = Poly1305::with_backend(&key, b);
        let mut rest = &msg[..];
        while !rest.is_empty() {
            let n = rng.below(80).min(rest.len());
            p.update(&rest[..n]);
            rest = &rest[n..];
        }
        assert_eq!(p.finalize(), want, "{b:?}");
        let mut s = Poly1305::with_backend(&key, PolyBackend::Soft);
        s.update(&msg);
        assert_eq!(s.finalize(), want, "{b:?} vs soft");
    }
}

/// RFC 8439 2.8.2 and A.5.
#[test]
fn rfc8439_aead() {
    struct V {
        key: [u8; 32],
        nonce: [u8; 12],
        aad: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
        tag: [u8; 16],
    }
    let vectors = [
        V {
            key: arr("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            nonce: arr("070000004041424344454647"),
            aad: h("50515253c0c1c2c3c4c5c6c7"),
            pt: SUNSCREEN.to_vec(),
            ct: h(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
                   3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
                   92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
                   3ff4def08e4b7a9de576d26586cec64b6116",
            ),
            tag: arr("1ae10b594f09e26a7e902ecbd0600691"),
        },
        V {
            key: arr("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
            nonce: arr("000000000102030405060708"),
            aad: h("f33388860000000000004e91"),
            pt: "Internet-Drafts are draft documents valid for a maximum of six months \
                 and may be updated, replaced, or obsoleted by other documents at any time. \
                 It is inappropriate to use Internet-Drafts as reference material or to cite \
                 them other than as /\u{201c}work in progress./\u{201d}"
                .as_bytes()
                .to_vec(),
            ct: h(
                "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2
                   4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf
                   332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855
                   9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4
                   b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e
                   af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a
                   0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10
                   49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29
                   a6ad5cb4022b02709b",
            ),
            tag: arr("eead9d67890cbb22392336fea1851f38"),
        },
    ];
    for v in &vectors {
        for a in aeads(&v.key) {
            let mut buf = v.pt.clone();
            let tag = a.seal_in_place(&v.nonce, &v.aad, &mut buf).unwrap();
            assert_eq!(hex::encode(&buf), hex::encode(&v.ct), "{a:?}");
            assert_eq!(tag, v.tag, "{a:?}");
            a.open_in_place(&v.nonce, &v.aad, &mut buf, &v.tag).unwrap();
            assert_eq!(buf, v.pt, "{a:?}");
        }
    }
}

#[derive(serde::Deserialize)]
struct WycheFile {
    #[serde(rename = "testGroups")]
    groups: Vec<WycheGroup>,
}

#[derive(serde::Deserialize)]
struct WycheGroup {
    #[serde(rename = "ivSize")]
    iv_size: usize,
    tests: Vec<WycheTest>,
}

#[derive(serde::Deserialize)]
struct WycheTest {
    #[serde(rename = "tcId")]
    id: u32,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
}

#[test]
fn wycheproof() {
    let file: WycheFile =
        serde_json::from_str(include_str!("data/wycheproof/chacha20_poly1305_test.json")).unwrap();
    let (mut run, mut skipped) = (0, 0);
    for g in &file.groups {
        for t in &g.tests {
            if g.iv_size != 96 {
                // Only 96-bit nonces are representable in this API.
                assert_eq!(t.result, "invalid", "tc {}", t.id);
                skipped += 1;
                continue;
            }
            let (key, aad, msg, ct) = (h(&t.key), h(&t.aad), h(&t.msg), h(&t.ct));
            let nonce: [u8; 12] = h(&t.iv).try_into().unwrap();
            let tag: [u8; 16] = h(&t.tag).try_into().unwrap();
            let valid = match t.result.as_str() {
                "valid" | "acceptable" => true,
                "invalid" => false,
                r => panic!("unknown result {r}"),
            };
            for a in aeads(&key) {
                let mut buf = ct.clone();
                let res = a.open_in_place(&nonce, &aad, &mut buf, &tag);
                if valid {
                    res.unwrap_or_else(|e| panic!("tc {} {a:?}: {e}", t.id));
                    assert_eq!(buf, msg, "tc {} {a:?}", t.id);
                    let mut buf = msg.clone();
                    let got = a.seal_in_place(&nonce, &aad, &mut buf).unwrap();
                    assert_eq!(buf, ct, "tc {} {a:?}", t.id);
                    assert_eq!(got, tag, "tc {} {a:?}", t.id);
                } else {
                    assert_eq!(res, Err(Error::DecryptFailed), "tc {} {a:?}", t.id);
                    assert!(buf.iter().all(|&b| b == 0), "tc {} {a:?}", t.id);
                }
            }
            run += 1;
        }
    }
    eprintln!("wycheproof: {run} run, {skipped} skipped (non-96-bit nonce)");
    assert!(run > 250);
}

fn reference_seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    use chacha20poly1305::{AeadInOut, KeyInit};
    let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).unwrap();
    let tag = c
        .encrypt_inout_detached(&(*nonce).into(), aad, buf.into())
        .unwrap();
    tag.into()
}

fn differential_lengths() -> Vec<usize> {
    let mut lens: Vec<usize> = (0..=1100).collect();
    // Block-count boundaries for 1/4/8/16/32-block steps and TLS records.
    for blocks in [31usize, 32, 33, 63, 64, 65, 255, 256, 257] {
        for d in [-1isize, 0, 1] {
            lens.push((blocks * 64).wrapping_add_signed(d));
        }
    }
    lens.extend([16384, 16384 + 1, 16384 + 15, 16384 + 16, 16384 + 255, 16383]);
    lens
}

#[test]
fn differential_vs_rustcrypto() {
    let mut rng = Rng(0x5eed);
    for (i, len) in differential_lengths().into_iter().enumerate() {
        let key = rng.bytes(32);
        let nonce: [u8; 12] = rng.bytes(12).try_into().unwrap();
        let aad_len = if i % 3 == 0 { 13 } else { rng.below(70) };
        let aad = rng.bytes(aad_len);
        let pt = rng.bytes(len);
        let mut want = pt.clone();
        let want_tag = reference_seal(&key, &nonce, &aad, &mut want);
        for a in aeads(&key) {
            let mut buf = pt.clone();
            let tag = a.seal_in_place(&nonce, &aad, &mut buf).unwrap();
            assert!(buf == want && tag == want_tag, "len {len} {a:?}");
            a.open_in_place(&nonce, &aad, &mut buf, &tag).unwrap();
            assert!(buf == pt, "len {len} {a:?}");
        }
    }
}

/// Every backend against the portable one for the raw cipher, including
/// counters that wrap mid-message and unaligned buffers.
#[test]
fn chacha20_backends_match_soft() {
    let mut rng = Rng(42);
    let mut lens = differential_lengths();
    lens.extend([2048 + 64 * 7, 4096, 65536 + 5]);
    for len in lens {
        let key: [u8; 32] = rng.bytes(32).try_into().unwrap();
        let nonce: [u8; 12] = rng.bytes(12).try_into().unwrap();
        let ctr = match rng.below(4) {
            0 => 0,
            1 => u32::MAX - rng.below(40) as u32,
            _ => rng.next() as u32,
        };
        let offset = rng.below(16);
        let mut base = rng.bytes(len + offset);
        let mut want = base.clone();
        chacha20_xor_with(Backend::Soft, &key, ctr, &nonce, &mut want[offset..]).unwrap();
        for b in backends() {
            let mut got = base.clone();
            chacha20_xor_with(b, &key, ctr, &nonce, &mut got[offset..]).unwrap();
            assert!(got == want, "{b:?} len {len} ctr {ctr} offset {offset}");
        }
        base.clear();
    }
}

#[test]
fn unavailable_backends_are_rejected() {
    for b in Backend::ALL {
        let mut d = [0u8; 3];
        let r = chacha20_xor_with(b, &[0; 32], 0, &[0; 12], &mut d);
        assert_eq!(r.is_ok(), b.is_available(), "{b:?}");
        let a = ChaCha20Poly1305::with_backends(&[0; 32], b, PolyBackend::Soft);
        assert_eq!(a.is_ok(), b.is_available(), "{b:?}");
    }
    assert_eq!(
        ChaCha20Poly1305::new(&[0; 31]).err(),
        Some(Error::InvalidKey)
    );
    assert_eq!(
        ChaCha20Poly1305::new(&[0; 33]).err(),
        Some(Error::InvalidKey)
    );
    let a = ChaCha20Poly1305::new(&[0; 32]).unwrap();
    eprintln!("available: {:?}; default: {:?}", backends(), a.backends());
    assert_eq!(a.backends(), (Backend::best(), PolyBackend::best()));
}

#[test]
fn tampering_is_detected_and_output_zeroed() {
    let mut rng = Rng(99);
    for len in [0usize, 1, 16, 17, 64, 300, 1024] {
        let key = rng.bytes(32);
        let nonce: [u8; 12] = rng.bytes(12).try_into().unwrap();
        let aad = rng.bytes(21);
        let pt = rng.bytes(len);
        for a in aeads(&key) {
            let mut ct = pt.clone();
            let tag = a.seal_in_place(&nonce, &aad, &mut ct).unwrap();
            let check = |nonce: &[u8; 12], aad: &[u8], ct: &[u8], tag: &[u8; 16], what: &str| {
                let mut buf = ct.to_vec();
                assert_eq!(
                    a.open_in_place(nonce, aad, &mut buf, tag),
                    Err(Error::DecryptFailed),
                    "{what} len {len} {a:?}"
                );
                assert!(buf.iter().all(|&b| b == 0), "{what} not zeroed");
            };
            for bit in 0..128 {
                let mut t = tag;
                t[bit / 8] ^= 1 << (bit % 8);
                check(&nonce, &aad, &ct, &t, "tag bit");
            }
            for i in 0..ct.len().min(70) {
                let mut c = ct.clone();
                c[i] ^= 0x01;
                check(&nonce, &aad, &c, &tag, "ciphertext byte");
            }
            for i in 0..aad.len() {
                let mut d = aad.clone();
                d[i] ^= 0x80;
                check(&nonce, &d, &ct, &tag, "aad byte");
            }
            check(&nonce, &aad[..20], &ct, &tag, "truncated aad");
            if !ct.is_empty() {
                check(&nonce, &aad, &ct[..ct.len() - 1], &tag, "truncated ct");
            }
            let mut n = nonce;
            n[11] ^= 1;
            check(&n, &aad, &ct, &tag, "nonce");
            // AAD moved into the ciphertext must not verify either.
            check(&nonce, &[], &ct, &tag, "empty aad");
            let mut ok = ct.clone();
            a.open_in_place(&nonce, &aad, &mut ok, &tag).unwrap();
            assert_eq!(ok, pt);
        }
    }
}

/// Run with `cargo test --release -p browntls-crypto --test chacha_poly1305
/// -- --ignored --nocapture throughput`.
#[test]
#[ignore = "benchmark"]
fn throughput() {
    use std::time::Instant;
    let key = [7u8; 32];
    let nonce = [1u8; 12];
    for size in [64usize, 1350, 16384] {
        let mut buf = vec![0u8; size];
        let iters = (64 << 20) / size;
        for b in backends() {
            let start = Instant::now();
            for _ in 0..iters {
                chacha20_xor_with(b, &key, 1, &nonce, &mut buf).unwrap();
            }
            let mbs = (iters * size) as f64 / start.elapsed().as_secs_f64() / 1e6;
            eprintln!("chacha20 {b:?} {size:>5} B: {mbs:8.0} MB/s");
        }
        for p in poly_backends() {
            let start = Instant::now();
            for _ in 0..iters {
                let mut m = Poly1305::with_backend(&key, p);
                m.update(&buf);
                std::hint::black_box(m.finalize());
            }
            let mbs = (iters * size) as f64 / start.elapsed().as_secs_f64() / 1e6;
            eprintln!("poly1305 {p:?} {size:>5} B: {mbs:8.0} MB/s");
        }
        for a in aeads(&key) {
            let start = Instant::now();
            for _ in 0..iters {
                std::hint::black_box(a.seal_in_place(&nonce, &[0; 13], &mut buf).unwrap());
            }
            let mbs = (iters * size) as f64 / start.elapsed().as_secs_f64() / 1e6;
            eprintln!("aead {:?} {size:>5} B: {mbs:8.0} MB/s", a.backends());
        }
        {
            use chacha20poly1305::{AeadInOut, KeyInit};
            let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).unwrap();
            let start = Instant::now();
            for _ in 0..iters {
                std::hint::black_box(
                    c.encrypt_inout_detached(&nonce.into(), &[0; 13], buf.as_mut_slice().into())
                        .unwrap(),
                );
            }
            let mbs = (iters * size) as f64 / start.elapsed().as_secs_f64() / 1e6;
            eprintln!("aead rustcrypto {size:>5} B: {mbs:8.0} MB/s");
        }
    }
}

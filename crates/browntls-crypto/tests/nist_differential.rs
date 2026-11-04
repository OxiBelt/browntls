#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_lossless
)]
//! NIST curves: RFC 6979 known answers, differential tests against the
//! RustCrypto `p256` / `p384` / `p521` crates, encoding round trips, API edge
//! cases and an ignored throughput measurement.

use browntls_crypto::hash::HashAlgorithm;
use browntls_crypto::nist::{p256, p384, p521};
use browntls_crypto::rand::{FixedRng, OsRng, SecureRandom};

/// RFC 6979 A.2.5, A.2.6 and A.2.7: `(hash, message, r, s)` per curve.
struct Rfc6979 {
    hash: HashAlgorithm,
    msg: &'static [u8],
    r: &'static str,
    s: &'static str,
}

const P256_KEY: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
const P256_PUB: &str = "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6\
    7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
const P256_VECTORS: &[Rfc6979] = &[
    Rfc6979 {
        hash: HashAlgorithm::Sha256,
        msg: b"sample",
        r: "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        s: "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha384,
        msg: b"sample",
        r: "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719",
        s: "4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha512,
        msg: b"sample",
        r: "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
        s: "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha256,
        msg: b"test",
        r: "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        s: "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha384,
        msg: b"test",
        r: "83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6",
        s: "8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha512,
        msg: b"test",
        r: "461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04",
        s: "39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55",
    },
];

const P384_KEY: &str = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8\
    96D5724E4C70A825F872C9EA60D2EDF5";
const P384_VECTORS: &[Rfc6979] = &[
    Rfc6979 {
        hash: HashAlgorithm::Sha256,
        msg: b"sample",
        r: "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
        s: "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha384,
        msg: b"sample",
        r: "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46",
        s: "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha512,
        msg: b"sample",
        r: "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709",
        s: "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha256,
        msg: b"test",
        r: "6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B",
        s: "2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha384,
        msg: b"test",
        r: "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB",
        s: "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha512,
        msg: b"test",
        r: "A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D06FB6495CD21B4B6E340FC236584FB277",
        s: "976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B224634A2092CD3792E0159AD9CEE37659C736",
    },
];

const P521_KEY: &str = "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C\
    AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538";
const P521_VECTORS: &[Rfc6979] = &[
    Rfc6979 {
        hash: HashAlgorithm::Sha256,
        msg: b"sample",
        r: "1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
        s: "04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha384,
        msg: b"sample",
        r: "1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67451",
        s: "1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65D61",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha512,
        msg: b"sample",
        r: "0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA",
        s: "0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha256,
        msg: b"test",
        r: "00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8",
        s: "0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha384,
        msg: b"test",
        r: "14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF6075578C",
        s: "133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0ED94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B979",
    },
    Rfc6979 {
        hash: HashAlgorithm::Sha512,
        msg: b"test",
        r: "13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D",
        s: "1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3",
    },
];

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// Left-pads a hex integer (possibly with an odd digit count, as RFC 6979
/// prints P-521 values) to `len` bytes.
fn unhex_fixed(s: &str, len: usize) -> Vec<u8> {
    let padded = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_owned()
    };
    let v = unhex(&padded);
    let mut out = vec![0u8; len - v.len()];
    out.extend_from_slice(&v);
    out
}

/// A small deterministic byte source for reproducible "random" scalars.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

struct XorShiftRng(std::cell::RefCell<XorShift>);

impl XorShiftRng {
    fn new(seed: u64) -> Self {
        Self(std::cell::RefCell::new(XorShift(seed)))
    }
}

impl SecureRandom for XorShiftRng {
    fn fill(&self, dest: &mut [u8]) -> Result<(), browntls_crypto::Error> {
        let mut s = self.0.borrow_mut();
        for b in dest {
            *b = s.next() as u8;
        }
        Ok(())
    }
}

macro_rules! curve_tests {
    (
        $curve:ident, $rc:ident, $fl:literal, $hash:ident, $key:ident, $vectors:ident,
        order = $order:literal,
        rfc6979 = $rfc_test:ident, differential = $diff_test:ident, encodings = $enc_test:ident,
        edge = $edge_test:ident
    ) => {
        #[test]
        fn $rfc_test() {
            let sk = $curve::SecretKey::from_bytes(&unhex_fixed($key, $fl)).unwrap();
            let signer = $curve::SigningKey::new(sk);
            let pk = signer.verifying_key();
            for v in $vectors {
                let sig = signer.sign_deterministic(v.hash, v.msg).unwrap();
                let mut expected = unhex_fixed(v.r, $fl);
                expected.extend_from_slice(&unhex_fixed(v.s, $fl));
                assert_eq!(
                    hex::encode(sig.fixed()),
                    hex::encode(&expected),
                    "{:?} {:?}",
                    v.hash,
                    std::str::from_utf8(v.msg).unwrap()
                );
                $curve::verify(&pk, v.hash, v.msg, sig.as_der()).unwrap();
                // Hedging with randomness must change the signature but keep it valid.
                let rng = XorShiftRng::new(0x9e37_79b9_7f4a_7c15);
                let hedged = signer.sign(v.hash, v.msg, &rng).unwrap();
                assert_ne!(hedged, sig);
                $curve::verify(&pk, v.hash, v.msg, hedged.as_der()).unwrap();
                // A tampered message or signature fails.
                let mut bad_msg = v.msg.to_vec();
                bad_msg.push(0);
                assert!($curve::verify(&pk, v.hash, &bad_msg, sig.as_der()).is_err());
                let mut bad_sig = sig.as_der().to_vec();
                let last = bad_sig.len() - 1;
                bad_sig[last] ^= 1;
                assert!($curve::verify(&pk, v.hash, v.msg, &bad_sig).is_err());
            }
        }

        #[test]
        fn $diff_test() {
            use ::$rc::ecdsa::signature::hazmat::PrehashVerifier;
            use ::$rc::ecdsa::signature::{Signer, Verifier};
            let mut rng = XorShift(0x0123_4567_89ab_cdef);
            let mut scalars: Vec<Vec<u8>> = Vec::new();
            // Sparse scalars m * 2^(16 j); every entry of the width-6 P-256
            // comb is covered by `p256_comb_entries_match_rustcrypto`.
            for j in 0..($fl * 8 / 16 + 1) {
                for m in [1u8, 2, 7, 8] {
                    let mut d = vec![0u8; $fl];
                    let bit = 16 * j;
                    if bit + 4 <= 8 * $fl {
                        let byte = $fl - 1 - bit / 8;
                        d[byte] = m << (bit % 8);
                        scalars.push(d);
                    }
                }
            }
            scalars.push(vec![0; $fl - 1].into_iter().chain([1u8]).collect());
            for _ in 0..12 {
                let mut d = vec![0u8; $fl];
                for b in &mut d {
                    *b = rng.next() as u8;
                }
                d[0] &= if $fl == 66 { 0x01 } else { 0xff };
                scalars.push(d);
            }
            let msgs: [&[u8]; 3] = [b"", b"browntls", &[0xabu8; 1000]];
            for d in &scalars {
                let Ok(theirs) = ::$rc::SecretKey::from_slice(d) else {
                    continue;
                };
                let ours = $curve::SecretKey::from_bytes(d).unwrap();
                assert_eq!(ours.to_bytes().as_slice(), d.as_slice());
                // Public keys agree.
                let their_pk = theirs.public_key();
                let their_pk_bytes = their_pk.to_sec1_bytes();
                assert_eq!(
                    ours.public_key().to_uncompressed().as_slice(),
                    &their_pk_bytes[..]
                );
                // ECDH agrees in both directions.
                let other = $curve::SecretKey::generate(&OsRng).unwrap();
                let other_theirs = ::$rc::SecretKey::from_slice(&other.to_bytes()[..]).unwrap();
                let shared_ours = ours.diffie_hellman(&other.public_key()).unwrap();
                let shared_theirs = ::$rc::ecdh::diffie_hellman(
                    theirs.to_nonzero_scalar(),
                    other_theirs.public_key().as_affine(),
                );
                assert_eq!(
                    &shared_ours[..],
                    shared_theirs.raw_secret_bytes().as_slice()
                );
                let shared_back = other.diffie_hellman(&ours.public_key()).unwrap();
                assert_eq!(shared_ours, shared_back);
                // Deterministic signatures are bit-identical (RFC 6979 with the curve's hash).
                let their_signer = ::$rc::ecdsa::SigningKey::from(&theirs);
                let their_vk = ::$rc::ecdsa::VerifyingKey::from(&their_signer);
                let our_signer = $curve::SigningKey::new(ours.clone());
                for msg in msgs {
                    let theirs_sig: ::$rc::ecdsa::Signature = their_signer.sign(msg);
                    let ours_sig = our_signer
                        .sign_deterministic(HashAlgorithm::$hash, msg)
                        .unwrap();
                    assert_eq!(
                        ours_sig.fixed().as_slice(),
                        theirs_sig.to_bytes().as_slice()
                    );
                    assert_eq!(ours_sig.as_der(), theirs_sig.to_der().as_bytes());
                    // Our hedged signature verifies with theirs.
                    let hedged = our_signer.sign(HashAlgorithm::$hash, msg, &OsRng).unwrap();
                    let parsed = ::$rc::ecdsa::Signature::from_slice(hedged.fixed()).unwrap();
                    their_vk.verify(msg, &parsed).unwrap();
                    // Their signature verifies with ours (DER and fixed).
                    $curve::verify(
                        &ours.public_key(),
                        HashAlgorithm::$hash,
                        msg,
                        theirs_sig.to_der().as_bytes(),
                    )
                    .unwrap();
                    $curve::verify_fixed(
                        &ours.public_key(),
                        HashAlgorithm::$hash,
                        msg,
                        &theirs_sig.to_bytes(),
                    )
                    .unwrap();
                    // Cross-hash: SHA-512 and SHA-224 over this curve, checked via prehash.
                    for alg in [
                        HashAlgorithm::Sha512,
                        HashAlgorithm::Sha224,
                        HashAlgorithm::Sha3_256,
                    ] {
                        let sig = our_signer.sign(alg, msg, &OsRng).unwrap();
                        let digest = browntls_crypto::hash::DynHash::digest(alg, msg);
                        let parsed = ::$rc::ecdsa::Signature::from_slice(sig.fixed()).unwrap();
                        their_vk.verify_prehash(digest.as_ref(), &parsed).unwrap();
                        $curve::verify(&ours.public_key(), alg, msg, sig.as_der()).unwrap();
                    }
                }
            }
        }

        #[test]
        fn $enc_test() {
            use ::$rc::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
            let ours = $curve::SecretKey::generate(&OsRng).unwrap();
            let theirs = ::$rc::SecretKey::from_slice(&ours.to_bytes()[..]).unwrap();
            // Their encodings load into ours.
            let sec1 = theirs.to_sec1_der().unwrap();
            let loaded = $curve::SecretKey::from_sec1_der(&sec1).unwrap();
            assert_eq!(&loaded.to_bytes()[..], &ours.to_bytes()[..]);
            let pkcs8 = theirs.to_pkcs8_der().unwrap();
            let loaded = $curve::SecretKey::from_pkcs8_der(pkcs8.as_bytes()).unwrap();
            assert_eq!(&loaded.to_bytes()[..], &ours.to_bytes()[..]);
            let spki = theirs.public_key().to_public_key_der().unwrap();
            let pk = $curve::PublicKey::from_spki_der(spki.as_bytes()).unwrap();
            assert_eq!(pk, ours.public_key());
            // Ours load into theirs.
            let mut buf = [0u8; $curve::SEC1_PRIVATE_MAX_LEN];
            let n = ours.to_sec1_der(&mut buf).unwrap();
            let back = ::$rc::SecretKey::from_sec1_der(&buf[..n]).unwrap();
            assert_eq!(back.to_bytes().as_slice(), ours.to_bytes().as_slice());
            assert_eq!(
                &buf[..n],
                sec1.as_slice(),
                "SEC 1 encodings should be identical"
            );
            let mut buf = [0u8; $curve::SPKI_MAX_LEN];
            let n = ours.public_key().to_spki_der(&mut buf).unwrap();
            assert_eq!(&buf[..n], spki.as_bytes());
            assert_eq!(
                ::$rc::PublicKey::from_public_key_der(&buf[..n]).unwrap(),
                theirs.public_key()
            );
            // Tampering with the embedded public key is detected.
            let mut bad = sec1.to_vec();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert!($curve::SecretKey::from_sec1_der(&bad).is_err());
            // Signatures: DER <-> fixed round trip.
            let sig = $curve::SigningKey::new(ours.clone())
                .sign(HashAlgorithm::$hash, b"x", &OsRng)
                .unwrap();
            let from_fixed = $curve::Signature::from_fixed(sig.fixed()).unwrap();
            assert_eq!(from_fixed.as_der(), sig.as_der());
            assert_eq!($curve::Signature::from_der(sig.as_der()).unwrap(), sig);
            assert!(sig.as_der().len() <= $curve::SIGNATURE_DER_MAX_LEN);
        }

        #[test]
        fn $edge_test() {
            // Zero and n are not valid scalars; n - 1 is.
            assert!($curve::SecretKey::from_bytes(&[0u8; $fl]).is_err());
            assert!($curve::SecretKey::from_bytes(&[0u8; $fl - 1]).is_err());
            let n = unhex_fixed($order, $fl);
            let n: &[u8] = &n;
            assert!($curve::SecretKey::from_bytes(n).is_err());
            let mut n_minus_1 = n.to_vec();
            let last = n_minus_1.len() - 1;
            n_minus_1[last] -= 1;
            let sk = $curve::SecretKey::from_bytes(&n_minus_1).unwrap();
            // (n - 1) G = -G: same x as G, y negated.
            let g = ::$rc::SecretKey::from_slice(&unhex_fixed("01", $fl))
                .unwrap()
                .public_key()
                .to_sec1_bytes();
            let pk = sk.public_key().to_uncompressed();
            assert_eq!(&pk[1..1 + $fl], &g[1..1 + $fl]);
            assert_ne!(&pk[1 + $fl..], &g[1 + $fl..]);
            // Public key validation: identity, off-curve, coordinate >= p, hybrid, truncated.
            assert!($curve::PublicKey::from_sec1_bytes(&[0]).is_err());
            assert!($curve::PublicKey::from_sec1_bytes(&[]).is_err());
            let mut off = pk;
            off[$fl] ^= 1;
            assert!($curve::PublicKey::from_sec1_bytes(&off).is_err());
            let mut big = pk;
            for b in &mut big[1..1 + $fl] {
                *b = 0xff;
            }
            assert!($curve::PublicKey::from_sec1_bytes(&big).is_err());
            let mut hybrid = pk;
            hybrid[0] = 0x06 | (pk[pk.len() - 1] & 1);
            assert!($curve::PublicKey::from_sec1_bytes(&hybrid).is_err());
            assert!($curve::PublicKey::from_sec1_bytes(&pk[..pk.len() - 1]).is_err());
            // A failing RNG surfaces as RandomFailure for generation and hedged signing.
            assert_eq!(
                $curve::SecretKey::generate(&FixedRng::new(&[])).unwrap_err(),
                browntls_crypto::Error::RandomFailure
            );
            let signer = $curve::SigningKey::new(sk.clone());
            assert_eq!(
                signer
                    .sign(HashAlgorithm::$hash, b"m", &FixedRng::new(&[1; 8]))
                    .unwrap_err(),
                browntls_crypto::Error::RandomFailure
            );
            // Deterministic signing is reproducible; prehash length is checked.
            let a = signer
                .sign_deterministic(HashAlgorithm::$hash, b"m")
                .unwrap();
            let b = signer
                .sign_deterministic(HashAlgorithm::$hash, b"m")
                .unwrap();
            assert_eq!(a, b);
            assert_eq!(
                signer
                    .sign_prehashed(HashAlgorithm::$hash, &[0; 7], None)
                    .unwrap_err(),
                browntls_crypto::Error::InvalidLength
            );
            // Signature parsing: r = 0, s = n, trailing byte, wrong length fixed form.
            let der = a.as_der();
            assert!($curve::Signature::from_der(&[der, &[0]].concat()).is_err());
            let mut zero_r = a.fixed().to_vec();
            zero_r[..$fl].fill(0);
            assert!($curve::Signature::from_fixed(&zero_r).is_err());
            let mut s_is_n = a.fixed().to_vec();
            s_is_n[$fl..].copy_from_slice(n);
            assert!($curve::Signature::from_fixed(&s_is_n).is_err());
            assert!($curve::Signature::from_fixed(&a.fixed()[1..]).is_err());
            assert!($curve::verify(&sk.public_key(), HashAlgorithm::$hash, b"m", &[]).is_err());
            // A key generated from a fixed RNG is deterministic.
            let seed = vec![0x42u8; $fl];
            let k1 = $curve::SecretKey::generate(&FixedRng::new(&seed)).unwrap();
            let k2 = $curve::SecretKey::generate(&FixedRng::new(&seed)).unwrap();
            assert_eq!(&k1.to_bytes()[..], &k2.to_bytes()[..]);
            assert_eq!(k1.to_bytes()[1..], seed[1..]);
        }
    };
}

curve_tests!(
    p256,
    p256,
    32,
    Sha256,
    P256_KEY,
    P256_VECTORS,
    order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    rfc6979 = p256_rfc6979_vectors,
    differential = p256_matches_rustcrypto,
    encodings = p256_encodings_interoperate,
    edge = p256_edge_cases
);
curve_tests!(
    p384,
    p384,
    48,
    Sha384,
    P384_KEY,
    P384_VECTORS,
    order = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    rfc6979 = p384_rfc6979_vectors,
    differential = p384_matches_rustcrypto,
    encodings = p384_encodings_interoperate,
    edge = p384_edge_cases
);
curve_tests!(
    p521,
    p521,
    66,
    Sha512,
    P521_KEY,
    P521_VECTORS,
    order = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    rfc6979 = p521_rfc6979_vectors,
    differential = p521_matches_rustcrypto,
    encodings = p521_encodings_interoperate,
    edge = p521_edge_cases
);

#[test]
fn p256_rfc6979_public_key() {
    let sk = p256::SecretKey::from_bytes(&unhex_fixed(P256_KEY, 32)).unwrap();
    assert_eq!(
        hex::encode(sk.public_key().to_uncompressed()),
        P256_PUB.to_lowercase()
    );
}

/// Keys from one curve must not load on another.
#[test]
fn curve_mismatch_is_rejected() {
    use ::p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    let k = p384::SecretKey::generate(&OsRng).unwrap();
    let theirs = ::p384::SecretKey::from_slice(&k.to_bytes()[..]).unwrap();
    let pkcs8 = theirs.to_pkcs8_der().unwrap();
    assert!(p256::SecretKey::from_pkcs8_der(pkcs8.as_bytes()).is_err());
    assert!(p521::SecretKey::from_pkcs8_der(pkcs8.as_bytes()).is_err());
    let sec1 = theirs.to_sec1_der().unwrap();
    assert!(p256::SecretKey::from_sec1_der(&sec1).is_err());
    let spki = theirs.public_key().to_public_key_der().unwrap();
    assert!(p256::PublicKey::from_spki_der(spki.as_bytes()).is_err());
    assert!(p521::PublicKey::from_spki_der(spki.as_bytes()).is_err());
    assert!(p256::PublicKey::from_sec1_bytes(&k.public_key().to_uncompressed()).is_err());
}

/// Rough operation rates on the host (release build recommended):
/// `cargo test --release -p browntls-crypto --test nist_differential -- --ignored --nocapture throughput`
#[test]
#[ignore = "throughput measurement"]
fn throughput() {
    macro_rules! bench {
        ($curve:ident, $hash:ident, $iters:literal) => {{
            let a = $curve::SecretKey::generate(&OsRng).unwrap();
            let b = $curve::SecretKey::generate(&OsRng).unwrap();
            let pk_b = b.public_key();
            let signer = $curve::SigningKey::new(a.clone());
            let msg = [0x5au8; 64];
            let sig = signer.sign(HashAlgorithm::$hash, &msg, &OsRng).unwrap();
            let t = std::time::Instant::now();
            for _ in 0..$iters {
                std::hint::black_box(a.diffie_hellman(&pk_b).unwrap());
            }
            let ecdh = f64::from($iters) / t.elapsed().as_secs_f64();
            let t = std::time::Instant::now();
            for _ in 0..$iters {
                std::hint::black_box($curve::SecretKey::generate(&OsRng).unwrap());
            }
            let keygen = f64::from($iters) / t.elapsed().as_secs_f64();
            let t = std::time::Instant::now();
            for _ in 0..$iters {
                std::hint::black_box(signer.sign(HashAlgorithm::$hash, &msg, &OsRng).unwrap());
            }
            let sign = f64::from($iters) / t.elapsed().as_secs_f64();
            let t = std::time::Instant::now();
            for _ in 0..$iters {
                std::hint::black_box(
                    $curve::verify(&a.public_key(), HashAlgorithm::$hash, &msg, sig.as_der()).unwrap(),
                );
            }
            let verify = f64::from($iters) / t.elapsed().as_secs_f64();
            println!(
                "{:>5}: ecdh {ecdh:8.0}/s  keygen {keygen:8.0}/s  sign {sign:8.0}/s  verify {verify:8.0}/s",
                stringify!($curve)
            );
        }};
    }
    println!("features: {:?}", browntls_crypto::cpu::features());
    bench!(p256, Sha256, 2000);
    bench!(p384, Sha384, 500);
    bench!(p521, Sha512, 200);
}

/// Big-endian `a - b` (no underflow expected).
fn be_sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; a.len()];
    let mut borrow = 0i16;
    for i in (0..a.len()).rev() {
        let mut d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[i] = u8::try_from(d).unwrap();
    }
    assert_eq!(borrow, 0);
    out
}

/// Every entry of a P-256 comb table with Booth width up to 6, positive and
/// negative: public keys for `m * 2^(6 j)` and `n - m * 2^(6 j)`
/// (`m <= 32`) agree with RustCrypto.
#[test]
fn p256_comb_entries_match_rustcrypto() {
    let n = unhex_fixed(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        32,
    );
    for j in 0..43usize {
        for m in 1u64..=32 {
            // k = m << (6 j) as 32 big-endian bytes, if it fits.
            let bit = 6 * j;
            if bit + 64 - m.leading_zeros() as usize > 256 {
                continue;
            }
            let mut k = vec![0u8; 32];
            let wide = u128::from(m) << (bit % 8);
            for (o, b) in wide.to_le_bytes().iter().enumerate() {
                let byte = bit / 8 + o;
                if byte < 32 {
                    k[31 - byte] |= b;
                }
            }
            for d in [k.clone(), be_sub(&n, &k)] {
                let theirs = ::p256::SecretKey::from_slice(&d).unwrap();
                let ours = p256::SecretKey::from_bytes(&d).unwrap();
                assert_eq!(
                    ours.public_key().to_uncompressed().as_slice(),
                    &theirs.public_key().to_sec1_bytes()[..],
                    "j = {j}, m = {m}"
                );
            }
        }
    }
}

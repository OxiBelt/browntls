//! X448 tests: RFC 7748 §5.2 and §6.2 vectors, Wycheproof `x448_test.json`,
//! and differential tests against RustCrypto's `x448`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::curve448::x448::{BASEPOINT, PrivateKey, is_all_zero, x448, x448_base};
use browntls_crypto::rand::{OsRng, SecureRandom};

fn h56(s: &str) -> [u8; 56] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn rfc7748_section_5_2() {
    let cases = [
        (
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
             700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
             814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
             e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
        ),
        (
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5\
             38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b\
             165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7\
             ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
        ),
    ];
    for (k, u, out) in cases {
        assert_eq!(hex::encode(x448(&h56(k), &h56(u))), out);
    }
}

fn iterate(n: u32) -> [u8; 56] {
    let mut k = BASEPOINT;
    let mut u = BASEPOINT;
    for _ in 0..n {
        let r = x448(&k, &u);
        u = k;
        k = r;
    }
    k
}

#[test]
fn rfc7748_iterations_1_and_1000() {
    assert_eq!(
        hex::encode(iterate(1)),
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a\
         4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"
    );
    assert_eq!(
        hex::encode(iterate(1000)),
        "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4\
         af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"
    );
}

#[test]
#[ignore = "slow: 1,000,000 ladder iterations"]
fn rfc7748_iterations_1000000() {
    assert_eq!(
        hex::encode(iterate(1_000_000)),
        "077f453681caca3693198420bbe515cae0002472519b3e67661a7e89\
         cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37"
    );
}

#[test]
fn rfc7748_section_6_2() {
    let a = PrivateKey::from_bytes(&h56(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
         d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
    ));
    let b = PrivateKey::from_bytes(&h56(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
         6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
    ));
    let pa = a.public_key();
    let pb = b.public_key();
    assert_eq!(
        hex::encode(pa),
        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
         22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
    );
    assert_eq!(
        hex::encode(pb),
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
         27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
    );
    assert_eq!(x448_base(a.as_bytes()), pa);
    let k = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
             b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";
    assert_eq!(hex::encode(a.diffie_hellman(&pb).unwrap()), k);
    assert_eq!(hex::encode(b.diffie_hellman(&pa).unwrap()), k);
    assert!(!is_all_zero(&a.diffie_hellman(&pb).unwrap()));
}

#[derive(serde::Deserialize)]
struct XdhFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    groups: Vec<XdhGroup>,
}

#[derive(serde::Deserialize)]
struct XdhGroup {
    curve: String,
    tests: Vec<XdhTest>,
}

#[derive(serde::Deserialize)]
struct XdhTest {
    #[serde(rename = "tcId")]
    id: u32,
    public: String,
    private: String,
    shared: String,
    result: String,
    flags: Vec<String>,
}

#[test]
fn wycheproof_x448() {
    let file: XdhFile = serde_json::from_str(include_str!("data/wycheproof/x448_test.json"))
        .expect("parse x448_test.json");
    let (mut valid, mut acceptable, mut invalid, mut zero) = (0, 0, 0, 0);
    for g in &file.groups {
        assert_eq!(g.curve, "curve448");
        for t in &g.tests {
            let public = hex::decode(&t.public).unwrap();
            let private: [u8; 56] = hex::decode(&t.private).unwrap().try_into().unwrap();
            let shared = hex::decode(&t.shared).unwrap();
            match t.result.as_str() {
                // "invalid" vectors have a 57-byte public key: the fixed-size
                // API cannot take it, and the TLS layer rejects the length.
                "invalid" => {
                    assert!(t.flags.iter().any(|f| f == "PublicKeyTooLong"));
                    assert_ne!(public.len(), 56, "tc {}", t.id);
                    assert!(<[u8; 56]>::try_from(public.as_slice()).is_err());
                    invalid += 1;
                    continue;
                }
                "valid" => valid += 1,
                // Twist points, non-canonical u and low-order u still define
                // the output exactly per RFC 7748.
                "acceptable" => acceptable += 1,
                r => panic!("unknown result {r}"),
            }
            let pk: [u8; 56] = public.as_slice().try_into().unwrap();
            let got = x448(&private, &pk);
            assert_eq!(got.as_slice(), shared.as_slice(), "tc {}", t.id);
            let dh = PrivateKey::from_bytes(&private).diffie_hellman(&pk);
            if shared.iter().all(|&b| b == 0) {
                assert!(is_all_zero(&got));
                assert!(
                    t.flags.iter().any(|f| f == "ZeroSharedSecret"),
                    "tc {}",
                    t.id
                );
                assert_eq!(dh, Err(Error::KeyAgreementFailed), "tc {}", t.id);
                zero += 1;
            } else {
                assert!(!is_all_zero(&got));
                assert_eq!(dh.unwrap().as_slice(), shared.as_slice(), "tc {}", t.id);
            }
        }
    }
    eprintln!(
        "wycheproof x448: {valid} valid, {acceptable} acceptable ({zero} all-zero rejected by DH), {invalid} invalid"
    );
    assert_eq!(valid + acceptable + invalid, file.number_of_tests);
    assert_eq!(file.number_of_tests, 510);
}

/// u-coordinates around the field boundaries and the small-order points.
fn edge_u_values() -> Vec<[u8; 56]> {
    // p = 2^448 - 2^224 - 1.
    let mut p = [0xffu8; 56];
    p[28] = 0xfe;
    let mut v = vec![[0u8; 56], BASEPOINT, p, [0xff; 56]];
    let mut one = [0u8; 56];
    one[0] = 1;
    v.push(one);
    for delta in [1u8, 2, 3, 5] {
        let mut x = p;
        x[0] = x[0].wrapping_add(delta); // p + delta (low byte wraps)
        v.push(x);
        let mut y = p;
        y[0] = y[0].wrapping_sub(delta); // p - delta
        v.push(y);
    }
    // p - 1 = -1 (order 2 on the twist side of the ladder's view).
    let mut m1 = p;
    m1[0] = 0xfe;
    v.push(m1);
    let mut top = [0u8; 56];
    top[55] = 0x80;
    v.push(top);
    v
}

#[test]
fn small_order_inputs_give_all_zero() {
    // u = 0, 1 and -1 (and the non-canonical forms p and p + 1 of 0 and 1)
    // have order dividing 4 on the curve or its twist, so a clamped scalar
    // (a multiple of 4) maps them to zero.
    let mut p = [0xffu8; 56];
    p[28] = 0xfe;
    let mut p_minus_1 = p;
    p_minus_1[0] = 0xfe;
    let mut p_plus_1 = [0u8; 56];
    p_plus_1[28..].fill(0xff);
    let mut one = [0u8; 56];
    one[0] = 1;
    let rng = OsRng;
    for _ in 0..8 {
        let mut k = [0u8; 56];
        rng.fill(&mut k).unwrap();
        let key = PrivateKey::from_bytes(&k);
        for u in [[0u8; 56], one, p_minus_1, p, p_plus_1] {
            assert!(is_all_zero(&x448(&k, &u)));
            assert_eq!(key.diffie_hellman(&u), Err(Error::KeyAgreementFailed));
        }
    }
}

#[test]
fn differential_vs_rustcrypto() {
    let rng = OsRng;
    let mut inputs = edge_u_values();
    for _ in 0..24 {
        let mut u = [0u8; 56];
        rng.fill(&mut u).unwrap();
        inputs.push(u);
        let mut k = [0u8; 56];
        rng.fill(&mut k).unwrap();
        inputs.push(x448_base(&k));
    }
    for (i, u) in inputs.iter().enumerate() {
        let mut k = [0u8; 56];
        rng.fill(&mut k).unwrap();
        if i == 0 {
            k = [0xff; 56];
        } else if i == 1 {
            k = [0; 56];
        }
        let ours = x448(&k, u);
        let theirs = ::x448::x448_unchecked(k, *u);
        assert_eq!(
            ours,
            theirs,
            "k = {}, u = {}",
            hex::encode(k),
            hex::encode(u)
        );
    }
    // Public keys and shared secrets through the oracle's key types.
    for _ in 0..16 {
        let mut a = [0u8; 56];
        let mut b = [0u8; 56];
        rng.fill(&mut a).unwrap();
        rng.fill(&mut b).unwrap();
        let ours_a = PrivateKey::from_bytes(&a);
        let ours_b = PrivateKey::from_bytes(&b);
        let theirs_a = ::x448::StaticSecret::from(a);
        let theirs_pa = ::x448::PublicKey::from(&theirs_a);
        assert_eq!(&ours_a.public_key(), theirs_pa.as_bytes());
        let pb = ours_b.public_key();
        let theirs_pb = ::x448::PublicKey::from_bytes(&pb).unwrap();
        assert_eq!(
            &ours_a.diffie_hellman(&pb).unwrap(),
            theirs_a.diffie_hellman(&theirs_pb).as_bytes()
        );
    }
}

#[test]
fn generate_and_agree() {
    let a = PrivateKey::generate(&OsRng).unwrap();
    let b = PrivateKey::generate(&OsRng).unwrap();
    let s1 = a.diffie_hellman(&b.public_key()).unwrap();
    let s2 = b.diffie_hellman(&a.public_key()).unwrap();
    assert_eq!(s1, s2);
    assert!(PrivateKey::from_slice(&[0u8; 55]).is_err());
    assert!(PrivateKey::from_slice(&[0u8; 57]).is_err());
    assert_eq!(
        PrivateKey::from_slice(a.as_bytes()).unwrap().public_key(),
        a.public_key()
    );
    assert_eq!(format!("{a:?}"), "x448::PrivateKey { .. }");
}

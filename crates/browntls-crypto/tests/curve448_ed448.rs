//! Ed448 tests: every RFC 8032 §7.4 vector, Wycheproof `ed448_test.json`,
//! RFC 8410 PKCS#8 handling, and differential tests against RustCrypto's
//! `ed448-goldilocks`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::curve448::ed448::{
    MAX_CONTEXT_LEN, OID_ED448, PKCS8_V1_LEN, SigningKey, VerifyingKey,
};
use browntls_crypto::rand::{OsRng, SecureRandom};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn h57(s: &str) -> [u8; 57] {
    h(s).try_into().unwrap()
}

fn h114(s: &str) -> [u8; 114] {
    h(s).try_into().unwrap()
}

/// An RFC 8032 §7.4 test vector: name, secret key, public key, message,
/// context, signature (hex, as printed in the RFC with whitespace removed).
struct Vector {
    name: &'static str,
    secret: &'static str,
    public: &'static str,
    message: &'static str,
    context: &'static str,
    signature: &'static str,
}

const MSG_1023: &str = "\
6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412\
a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd\
86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc\
3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e9\
72660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9\
b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd32321\
9b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab79717\
2b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813\
a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0\
596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f520\
96cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1\
526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998\
d0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee\
85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6\
155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4\
c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db9\
77025e7f5924388c7e340a732e554440e76570f8dd71b7d640b3450d1fd5f041\
0a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456\
f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab\
0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3\
120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535\
aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf969614\
9e4ac824ad3460538fdc25421beec2cc6818162d06bbed0c40a387192349db67\
a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a605\
9d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263\
be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d\
02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c\
392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e\
79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd33034efc6245eddd\
7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4\
b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695\
568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87";

const RFC8032_7_4: [Vector; 9] = [
    Vector {
        name: "Blank",
        secret: "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3\
                 528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
        public: "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778\
                 edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        message: "",
        context: "",
        signature: "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f\
                    2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a\
                    9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db\
                    b61149f05a7363268c71d95808ff2e652600",
    },
    Vector {
        name: "1 octet",
        secret: "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a\
                 fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
        public: "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086\
                 6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        message: "03",
        context: "",
        signature: "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435\
                    2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb\
                    cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f\
                    f3348ab21aa4adafd1d234441cf807c03a00",
    },
    Vector {
        name: "1 octet (with context)",
        secret: "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a\
                 fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
        public: "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086\
                 6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        message: "03",
        context: "666f6f",
        signature: "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2\
                    151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da\
                    1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d\
                    5428407e85dcbc98a49155c13764e66c3c00",
    },
    Vector {
        name: "11 octets",
        secret: "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffd\
                 f60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
        public: "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e3\
                 65fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
        message: "0c3e544074ec63b0265e0c",
        context: "",
        signature: "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d3\
                    89dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b05\
                    1068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5\
                    028961c9bf8ffd973fe5d5c206492b140e00",
    },
    Vector {
        name: "12 octets",
        secret: "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d93\
                 9f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
        public: "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc\
                 24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
        message: "64a65f3cdedcdd66811e2915",
        context: "",
        signature: "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4a\
                    e90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457e\
                    b1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861\
                    e72003cbae6d6b8b827e4e6c143064ff3c00",
    },
    Vector {
        name: "13 octets",
        secret: "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b29\
                 49c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
        public: "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb381\
                 5c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
        message: "64a65f3cdedcdd66811e2915e7",
        context: "",
        signature: "6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb\
                    4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca\
                    1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf5\
                    6b4e7e0ba5519234d047155ac727a1053100",
    },
    Vector {
        name: "64 octets",
        secret: "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bf\
                 f21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
        public: "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a\
                 39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
        message: "bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5\
                  512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944",
        context: "",
        signature: "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b1\
                    8dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722e\
                    f552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba\
                    5f30e88e36ec2703b349ca229c2670833900",
    },
    Vector {
        name: "256 octets",
        secret: "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d3756\
                 9b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
        public: "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9b\
                 fe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
        message: "15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567c\
                  fa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89\
                  e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072f\
                  c1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a60\
                  39c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b5\
                  90316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce0\
                  12d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409\
                  a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11",
        context: "",
        signature: "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f\
                    00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a\
                    61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc6\
                    0987fd08527c1a8e80d5823e65cafe2a3d00",
    },
    Vector {
        name: "1023 octets",
        secret: "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec\
                 44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8",
        public: "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799d\
                 a08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
        message: MSG_1023,
        context: "",
        signature: "e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bd\
                    df7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d\
                    76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed57\
                    3603ce30d8bb761785dc30dbc320869e1a00",
    },
];

#[test]
fn rfc8032_section_7_4() {
    for v in &RFC8032_7_4 {
        let key = SigningKey::from_seed(&h57(v.secret));
        let public = h57(v.public);
        let msg = h(v.message);
        let ctx = h(v.context);
        let expected = h114(v.signature);
        assert_eq!(key.verifying_key().as_bytes(), &public, "{}", v.name);
        let sig = key.sign_with_context(&ctx, &msg).unwrap();
        assert_eq!(sig, expected, "{}", v.name);
        if ctx.is_empty() {
            assert_eq!(key.sign(&msg), expected, "{}", v.name);
        }
        let vk = VerifyingKey::from_bytes(&public).unwrap();
        assert_eq!(
            vk.verify_with_context(&ctx, &msg, &expected),
            Ok(()),
            "{}",
            v.name
        );
        // The context is bound: the vector fails with a different context.
        let other_ctx: &[u8] = if ctx.is_empty() { b"foo" } else { b"" };
        assert!(vk.verify_with_context(other_ctx, &msg, &expected).is_err());
        // Any single-bit change of the signature or message is rejected.
        for bit in [0, 7, 8 * 56 + 7, 8 * 57, 8 * 113 - 1] {
            let mut bad = expected;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(
                vk.verify_with_context(&ctx, &msg, &bad).is_err(),
                "{} bit {bit}",
                v.name
            );
        }
        let mut bad_msg = msg.clone();
        bad_msg.push(0);
        assert!(vk.verify_with_context(&ctx, &bad_msg, &expected).is_err());
    }
    assert_eq!(h(MSG_1023).len(), 1023);
}

#[derive(serde::Deserialize)]
struct EddsaFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    groups: Vec<EddsaGroup>,
}

#[derive(serde::Deserialize)]
struct EddsaGroup {
    #[serde(rename = "publicKey")]
    public_key: EddsaKey,
    tests: Vec<EddsaTest>,
}

#[derive(serde::Deserialize)]
struct EddsaKey {
    curve: String,
    pk: String,
}

#[derive(serde::Deserialize)]
struct EddsaTest {
    #[serde(rename = "tcId")]
    id: u32,
    comment: String,
    msg: String,
    sig: String,
    result: String,
    flags: Vec<String>,
}

fn wycheproof() -> EddsaFile {
    serde_json::from_str(include_str!("data/wycheproof/ed448_test.json"))
        .expect("parse ed448_test.json")
}

#[test]
fn wycheproof_ed448() {
    let file = wycheproof();
    let (mut valid, mut invalid) = (0, 0);
    for g in &file.groups {
        assert_eq!(g.public_key.curve, "edwards448");
        let vk = VerifyingKey::from_slice(&h(&g.public_key.pk)).unwrap();
        for t in &g.tests {
            let msg = h(&t.msg);
            let sig = h(&t.sig);
            let accepted = match <[u8; 114]>::try_from(sig.as_slice()) {
                Ok(sig) => vk.verify(&msg, &sig).is_ok(),
                Err(_) => false,
            };
            match t.result.as_str() {
                "valid" => {
                    assert!(accepted, "valid tc {} rejected ({:?})", t.id, t.flags);
                    valid += 1;
                }
                "invalid" => {
                    assert!(!accepted, "invalid tc {} accepted ({:?})", t.id, t.flags);
                    invalid += 1;
                }
                r => panic!("unexpected result {r} in tc {}", t.id),
            }
        }
    }
    eprintln!("wycheproof ed448: {valid} valid, {invalid} invalid");
    assert_eq!(valid + invalid, file.number_of_tests);
    assert_eq!(file.number_of_tests, 87);
}

/// The RFC 8032 known-answer tests also appear in Wycheproof (tcId 78-86);
/// comparing the two catches transcription errors in either copy.
#[test]
fn rfc_vectors_agree_with_wycheproof_copies() {
    let file = wycheproof();
    let mut matched = 0;
    for g in &file.groups {
        for t in g.tests.iter().filter(|t| t.comment.starts_with("RFC 8032")) {
            let v = RFC8032_7_4
                .iter()
                .find(|v| v.public == g.public_key.pk && v.message == t.msg && v.context.is_empty())
                .or_else(|| {
                    RFC8032_7_4
                        .iter()
                        .find(|v| h(v.public) == h(&g.public_key.pk) && h(v.message) == h(&t.msg))
                })
                .unwrap_or_else(|| panic!("tc {} ({}) has no RFC copy", t.id, t.comment));
            if t.result == "valid" {
                assert!(v.context.is_empty());
                assert_eq!(h(v.signature), h(&t.sig), "tc {}", t.id);
            } else {
                // tc 80: the with-context signature presented without context.
                assert_eq!(t.comment, "RFC 8032: 1 octet with context");
                let with_ctx = RFC8032_7_4.iter().find(|v| !v.context.is_empty()).unwrap();
                assert_eq!(h(with_ctx.signature), h(&t.sig));
            }
            matched += 1;
        }
    }
    assert_eq!(matched, 9);
}

#[test]
fn verifying_key_validation() {
    // Wrong lengths.
    assert!(VerifyingKey::from_slice(&[0u8; 56]).is_err());
    assert!(VerifyingKey::from_slice(&[0u8; 58]).is_err());
    let good = h57(RFC8032_7_4[0].public);
    VerifyingKey::from_bytes(&good).unwrap();
    // Unused bits 448..454 set: y >= 2^448 > p.
    for bit in 0..7 {
        let mut pk = good;
        pk[56] |= 1 << bit;
        assert_eq!(VerifyingKey::from_bytes(&pk), Err(Error::InvalidKey));
    }
    // y = p (non-canonical zero) and y = p + 1 (non-canonical one).
    let mut p = [0xffu8; 57];
    p[28] = 0xfe;
    p[56] = 0;
    assert_eq!(VerifyingKey::from_bytes(&p), Err(Error::InvalidKey));
    let mut p_plus_1 = [0u8; 57];
    p_plus_1[28..56].fill(0xff);
    assert_eq!(VerifyingKey::from_bytes(&p_plus_1), Err(Error::InvalidKey));
    // The identity and the other small-order points.
    let mut identity = [0u8; 57];
    identity[0] = 1;
    assert_eq!(VerifyingKey::from_bytes(&identity), Err(Error::InvalidKey));
    assert_eq!(VerifyingKey::from_bytes(&[0u8; 57]), Err(Error::InvalidKey));
    // y = 2 is not on the curve.
    let mut two = [0u8; 57];
    two[0] = 2;
    assert_eq!(VerifyingKey::from_bytes(&two), Err(Error::InvalidKey));
}

#[test]
fn signature_scalar_must_be_canonical() {
    let key = SigningKey::from_seed(&[3; 57]);
    let vk = key.verifying_key();
    let sig = key.sign(b"msg");
    // S + L (Wycheproof covers this too) and a non-zero top byte.
    let l = h57(
        "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
    );
    let mut s = [0u8; 57];
    s.copy_from_slice(&sig[57..]);
    let mut carry = 0u16;
    for i in 0..57 {
        let v = u16::from(s[i]) + u16::from(l[i]) + carry;
        s[i] = v as u8;
        carry = v >> 8;
    }
    let mut bad = sig;
    bad[57..].copy_from_slice(&s);
    assert_eq!(vk.verify(b"msg", &bad), Err(Error::InvalidSignature));
    let mut bad = sig;
    bad[113] = 1;
    assert_eq!(vk.verify(b"msg", &bad), Err(Error::InvalidSignature));
    vk.verify(b"msg", &sig).unwrap();
}

const RFC8410_LIKE_HEADER: &str = "3047020100300506032b6571043b0439";

#[test]
fn pkcs8_rfc8410() {
    let seed = h57(RFC8032_7_4[1].secret);
    let key = SigningKey::from_seed(&seed);
    let der = key.to_pkcs8_der();
    assert_eq!(der.len(), PKCS8_V1_LEN);
    assert_eq!(hex::encode(&der[..16]), RFC8410_LIKE_HEADER);
    assert_eq!(&der[9..12], &OID_ED448);
    let back = SigningKey::from_pkcs8_der(&der[..]).unwrap();
    assert_eq!(back.seed(), &seed);
    assert_eq!(back.verifying_key(), key.verifying_key());

    // v2 with the matching public key.
    let public = *key.verifying_key().as_bytes();
    let v2 = pkcs8_v2(&seed, &public);
    assert_eq!(SigningKey::from_pkcs8_der(&v2).unwrap().seed(), &seed);
    // v2 with a different public key.
    let mut wrong = public;
    wrong[0] ^= 1;
    assert_eq!(
        SigningKey::from_pkcs8_der(&pkcs8_v2(&seed, &wrong)).unwrap_err(),
        Error::InvalidKey
    );
    // v1 must not carry a public key.
    let mut v1_with_public = v2.clone();
    assert_eq!(v1_with_public[3..6], [0x02, 0x01, 0x01]);
    v1_with_public[5] = 0;
    assert!(SigningKey::from_pkcs8_der(&v1_with_public).is_err());
    // An Ed25519 key, a short seed, parameters on the algorithm, trailing data.
    let ed25519 = h(
        "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842",
    );
    assert_eq!(
        SigningKey::from_pkcs8_der(&ed25519).unwrap_err(),
        Error::InvalidKey
    );
    let mut short = h("3046020100300506032b6571043a0438");
    short.extend_from_slice(&seed[..56]);
    assert_eq!(
        SigningKey::from_pkcs8_der(&short).unwrap_err(),
        Error::InvalidKey
    );
    let mut params = h("3049020100300706032b65710500043b0439");
    params.extend_from_slice(&seed);
    assert_eq!(
        SigningKey::from_pkcs8_der(&params).unwrap_err(),
        Error::InvalidKey
    );
    let mut trailing = der.to_vec();
    trailing.push(0);
    assert!(SigningKey::from_pkcs8_der(&trailing).is_err());
    assert!(SigningKey::from_pkcs8_der(&der[..PKCS8_V1_LEN - 1]).is_err());
}

/// Builds a v2 OneAsymmetricKey with the given public key (no attributes).
fn pkcs8_v2(seed: &[u8; 57], public: &[u8; 57]) -> Vec<u8> {
    let mut v = h("308183020101300506032b6571043b0439");
    v.extend_from_slice(seed);
    v.extend_from_slice(&[0x81, 0x3a, 0x00]);
    v.extend_from_slice(public);
    assert_eq!(v.len(), 3 + 0x83);
    v
}

#[test]
fn differential_vs_rustcrypto() {
    use ed448_goldilocks::signature::{Signer, Verifier};
    let rng = OsRng;
    for i in 0..24 {
        let mut seed = [0u8; 57];
        rng.fill(&mut seed).unwrap();
        let mut msg = vec![0u8; i * 37];
        rng.fill(&mut msg).unwrap();
        let ours = SigningKey::from_seed(&seed);
        let theirs = ed448_goldilocks::SigningKey::try_from(&seed[..]).unwrap();
        let their_vk = theirs.verifying_key();
        assert_eq!(
            ours.verifying_key().as_bytes(),
            their_vk.as_bytes().as_slice()
        );

        // Deterministic signatures agree, with and without a context.
        let sig = ours.sign(&msg);
        let their_sig = theirs.sign(&msg);
        assert_eq!(sig.as_slice(), their_sig.to_bytes().as_slice());
        let mut ctx_buf = [0u8; MAX_CONTEXT_LEN];
        rng.fill(&mut ctx_buf).unwrap();
        let ctx = &ctx_buf[..(i * 11) % (MAX_CONTEXT_LEN + 1)];
        let sig_ctx = ours.sign_with_context(ctx, &msg).unwrap();
        let their_sig_ctx = theirs.sign_ctx(ctx, &msg).unwrap();
        assert_eq!(sig_ctx.as_slice(), their_sig_ctx.to_bytes().as_slice());

        // Each side verifies the other's signatures and rejects tampering.
        let vk = VerifyingKey::from_bytes(their_vk.as_bytes()).unwrap();
        vk.verify(&msg, &their_sig.to_bytes()).unwrap();
        their_vk
            .verify(
                &msg,
                &ed448_goldilocks::Signature::from_slice(&sig).unwrap(),
            )
            .unwrap();
        their_vk.verify(&msg, &their_sig).unwrap();
        let mut bad = sig;
        bad[(i * 7) % 114] ^= 0x10;
        let ours_ok = vk.verify(&msg, &bad).is_ok();
        let theirs_ok = ed448_goldilocks::Signature::from_slice(&bad)
            .map(|s| their_vk.verify(&msg, &s).is_ok())
            .unwrap_or(false);
        assert!(!ours_ok && !theirs_ok);

        // PKCS#8 v1 encodings agree.
        use ed448_goldilocks::pkcs8::EncodePrivateKey;
        let their_der = theirs.to_pkcs8_der().unwrap();
        let our_der = ours.to_pkcs8_der();
        if their_der.as_bytes() != &our_der[..] {
            // The oracle may emit a v2 encoding with the public key; ours
            // must still parse it to the same key.
            let parsed = SigningKey::from_pkcs8_der(their_der.as_bytes()).unwrap();
            assert_eq!(parsed.seed(), &seed);
        }
        assert_eq!(
            SigningKey::from_pkcs8_der(&our_der[..]).unwrap().seed(),
            &seed
        );
    }
}

#[test]
fn generate_sign_verify() {
    let key = SigningKey::generate(&OsRng).unwrap();
    let vk = key.verifying_key();
    let sig = key.sign(b"hello");
    vk.verify(b"hello", &sig).unwrap();
    assert!(vk.verify(b"hellp", &sig).is_err());
    let vk2 = VerifyingKey::from_slice(vk.as_bytes()).unwrap();
    assert_eq!(vk, vk2);
    assert!(format!("{key:?}").starts_with("SigningKey { public: VerifyingKey("));
}

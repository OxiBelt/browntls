//! Known-answer tests: NIST ACVP and Wycheproof vectors for all three
//! parameter sets.
//!
//! They live in the crate (not under `tests/`) because the ACVP "internal"
//! groups sign and verify a raw formatted message `M'`
//! (ML-DSA.Sign_internal, ML-DSA.Verify_internal) and the "externalMu"
//! groups and Wycheproof's `Internal` cases sign a given `mu`; those entry
//! points are deliberately not public.
//!
//! * `tests/data/acvp/`: a trimmed copy of the ACVP-Server ML-DSA
//!   `internalProjection.json` files; see the README there for provenance
//!   and the trimming rule. The `preHash` groups (HashML-DSA) are dropped,
//!   since HashML-DSA is not implemented; every other group is run, the
//!   `externalMu` ones included.
//! * `tests/data/wycheproof/mldsa_{44,65,87}_{verify,sign_seed,
//!   sign_noseed}_test.json` (Apache-2.0, from the C2SP/wycheproof
//!   `testvectors_v1` set), unmodified and run completely.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::format;
use std::fs;
use std::string::String;
use std::vec::Vec;

use serde_json::Value;

use super::{
    MlDsa44, MlDsa65, MlDsa87, ParameterSet, SigningKey, VerifyingKey, compute_mu, external_mu,
};
use crate::Error;
use crate::rand::FixedRng;

fn load(dir: &str, name: &str) -> Value {
    let path = format!("{}/tests/data/{dir}/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

fn hex_of(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or("")).unwrap()
}

fn opt_hex(v: &Value, k: &str) -> Option<Vec<u8>> {
    v[k].as_str().map(|s| hex::decode(s).unwrap())
}

fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap()
}

/// Runs `f::<P>` for the parameter set named `name`.
macro_rules! dispatch {
    ($name:expr, $f:ident ( $($arg:expr),* )) => {
        match $name {
            "ML-DSA-44" => $f::<MlDsa44>($($arg),*),
            "ML-DSA-65" => $f::<MlDsa65>($($arg),*),
            "ML-DSA-87" => $f::<MlDsa87>($($arg),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

// ---------------------------------------------------------------------------
// ACVP.
// ---------------------------------------------------------------------------

fn acvp_keygen_case<P: ParameterSet>(t: &Value) {
    let id = &t["tcId"];
    let sk = SigningKey::<P>::from_seed(&arr(&hex_of(t, "seed")));
    assert_eq!(sk.verifying_key().as_bytes(), hex_of(t, "pk"), "tcId {id}");
    assert_eq!(
        sk.to_expanded_bytes().as_ref(),
        hex_of(t, "sk"),
        "tcId {id}"
    );
    let loaded = SigningKey::<P>::from_expanded_bytes(&hex_of(t, "sk")).unwrap();
    assert_eq!(loaded.verifying_key(), sk.verifying_key(), "tcId {id}");
}

#[test]
fn acvp_keygen() {
    let v = load("acvp", "ML-DSA-keyGen-FIPS204.json");
    let mut count = 0;
    for g in v["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            dispatch!(g["parameterSet"].as_str().unwrap(), acvp_keygen_case(t));
            count += 1;
        }
    }
    assert_eq!(count, 75);
}

/// The interface of an ACVP group: external (pure, with context), internal
/// on `M'`, or internal on `mu`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Interface {
    External,
    Internal,
    ExternalMu,
}

fn interface(g: &Value) -> Interface {
    match (
        g["signatureInterface"].as_str().unwrap(),
        g["externalMu"].as_bool().unwrap(),
    ) {
        ("external", false) => {
            assert_eq!(g["preHash"], "pure");
            Interface::External
        }
        ("internal", false) => Interface::Internal,
        ("internal", true) => Interface::ExternalMu,
        other => panic!("unexpected group {other:?}"),
    }
}

fn verify_as<P: ParameterSet>(
    vk: &VerifyingKey<P>,
    iface: Interface,
    t: &Value,
    sig: &[u8],
) -> Result<(), Error> {
    match iface {
        Interface::External => {
            vk.verify_with_context(&hex_of(t, "message"), &hex_of(t, "context"), sig)
        }
        Interface::Internal => vk.verify_internal(&hex_of(t, "message"), sig),
        Interface::ExternalMu => vk.verify_mu(&arr(&hex_of(t, "mu")), sig),
    }
}

fn acvp_siggen_case<P: ParameterSet>(g: &Value, t: &Value) {
    let id = &t["tcId"];
    let iface = interface(g);
    let deterministic = g["deterministic"].as_bool().unwrap();
    let sk = SigningKey::<P>::from_expanded_bytes(&hex_of(t, "sk")).unwrap();
    let rnd: [u8; 32] = if deterministic {
        assert!(t.get("rnd").is_none());
        [0; 32]
    } else {
        arr(&hex_of(t, "rnd"))
    };
    let sig = match iface {
        Interface::External => {
            let (msg, ctx) = (hex_of(t, "message"), hex_of(t, "context"));
            if deterministic {
                sk.sign_deterministic(&msg, &ctx)
            } else {
                // The hedged API with a source that yields exactly `rnd`.
                sk.sign(&msg, &ctx, &FixedRng::new(&rnd))
            }
        }
        Interface::Internal => sk.sign_internal(&hex_of(t, "message"), &rnd),
        Interface::ExternalMu => sk.sign_mu(&arr(&hex_of(t, "mu")), &rnd),
    }
    .unwrap();
    assert_eq!(sig.as_ref(), hex_of(t, "signature"), "tcId {id}");
    verify_as(sk.verifying_key(), iface, t, sig.as_ref()).unwrap();
}

#[test]
fn acvp_siggen() {
    let v = load("acvp", "ML-DSA-sigGen-FIPS204.json");
    let mut seen = std::collections::BTreeSet::new();
    let (mut groups, mut cases) = (0, 0);
    for g in v["testGroups"].as_array().unwrap() {
        groups += 1;
        let name = g["parameterSet"].as_str().unwrap();
        seen.insert(format!(
            "{name} {:?} {}",
            interface(g),
            g["deterministic"].as_bool().unwrap()
        ));
        for t in g["tests"].as_array().unwrap() {
            cases += 1;
            dispatch!(name, acvp_siggen_case(g, t));
        }
    }
    // Three sets, three interfaces, deterministic and hedged; two cases
    // each after trimming.
    assert_eq!(seen.len(), 18);
    assert_eq!((groups, cases), (18, 36));
}

fn acvp_sigver_case<P: ParameterSet>(g: &Value, t: &Value) -> bool {
    let vk = VerifyingKey::<P>::from_bytes(&hex_of(t, "pk")).unwrap();
    let ok = verify_as(&vk, interface(g), t, &hex_of(t, "signature"));
    if let Err(e) = ok {
        assert_eq!(e, Error::InvalidSignature);
    }
    assert_eq!(
        ok.is_ok(),
        t["testPassed"].as_bool().unwrap(),
        "tcId {} ({})",
        t["tcId"],
        t["reason"]
    );
    ok.is_ok()
}

#[test]
fn acvp_sigver() {
    let v = load("acvp", "ML-DSA-sigVer-FIPS204.json");
    let (mut valid, mut invalid) = (0, 0);
    for g in v["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            if dispatch!(g["parameterSet"].as_str().unwrap(), acvp_sigver_case(g, t)) {
                valid += 1;
            } else {
                invalid += 1;
            }
        }
    }
    assert_eq!((valid, invalid), (9, 36));
}

// ---------------------------------------------------------------------------
// Wycheproof.
// ---------------------------------------------------------------------------

fn tests_of(v: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    v["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
}

/// Whether the result must be accepted (`Some(true)`), rejected
/// (`Some(false)`) or may go either way (`None`, "acceptable").
fn expected(t: &Value) -> Option<bool> {
    match t["result"].as_str().unwrap() {
        "valid" => Some(true),
        "invalid" => Some(false),
        "acceptable" => None,
        other => panic!("unexpected result {other}"),
    }
}

fn check(t: &Value, accepted: bool) {
    if let Some(e) = expected(t) {
        assert_eq!(accepted, e, "tcId {} ({})", t["tcId"], t["comment"]);
    }
}

fn wycheproof_verify<P: ParameterSet>(file: &str) -> usize {
    let v = load("wycheproof", file);
    assert_eq!(v["algorithm"], P::NAME);
    let mut count = 0;
    for (g, t) in tests_of(&v) {
        count += 1;
        let Ok(vk) = VerifyingKey::<P>::from_bytes(&hex_of(g, "publicKey")) else {
            check(t, false);
            continue;
        };
        let r = vk.verify_with_context(&hex_of(t, "msg"), &hex_of(t, "ctx"), &hex_of(t, "sig"));
        check(t, r.is_ok());
    }
    count
}

/// Signs test `t` with `sk` as the vector asks: from `mu` (`Internal`
/// cases), hedged with the given `rnd`, or deterministically. Returns the
/// signature and the `mu` it covers.
fn wycheproof_sign<P: ParameterSet>(
    sk: &SigningKey<P>,
    t: &Value,
) -> Result<(P::Signature, [u8; 64]), Error> {
    let rnd: [u8; 32] = opt_hex(t, "rnd").map_or([0; 32], |r| arr(&r));
    let Some(msg) = opt_hex(t, "msg") else {
        let mu = arr(&hex_of(t, "mu"));
        return Ok((sk.sign_mu(&mu, &rnd)?, mu));
    };
    let ctx = hex_of(t, "ctx");
    let mu = external_mu(&sk.verifying_key().tr, &msg, &ctx)?;
    if let Some(m) = opt_hex(t, "mu") {
        assert_eq!(mu.as_slice(), m, "tcId {} mu", t["tcId"]);
    }
    let sig = if t.get("rnd").is_some() {
        sk.sign(&msg, &ctx, &FixedRng::new(&rnd))?
    } else {
        sk.sign_deterministic(&msg, &ctx)?
    };
    Ok((sig, mu))
}

fn wycheproof_sign_tests<P: ParameterSet>(file: &str, seeded: bool) -> usize {
    let v = load("wycheproof", file);
    assert_eq!(v["algorithm"], P::NAME);
    let mut count = 0;
    for (g, t) in tests_of(&v) {
        count += 1;
        let key = if seeded {
            let seed = hex_of(g, "privateSeed");
            <[u8; 32]>::try_from(seed.as_slice())
                .map(|s| SigningKey::<P>::from_seed(&s))
                .map_err(|_| Error::InvalidLength)
        } else {
            SigningKey::<P>::from_expanded_bytes(&hex_of(g, "privateKey"))
        };
        let Ok(sk) = key else {
            check(t, false);
            continue;
        };
        if let Some(pk) = opt_hex(g, "publicKey") {
            assert_eq!(sk.verifying_key().as_bytes(), pk, "tcId {}", t["tcId"]);
        }
        match wycheproof_sign(&sk, t) {
            Ok((sig, mu)) => {
                check(t, true);
                assert_eq!(sig.as_ref(), hex_of(t, "sig"), "tcId {}", t["tcId"]);
                sk.verifying_key().verify_mu(&mu, sig.as_ref()).unwrap();
            }
            Err(e) => {
                assert_eq!(e, Error::InvalidLength);
                check(t, false);
            }
        }
    }
    count
}

fn wycheproof_all<P: ParameterSet>(n: u32) -> usize {
    let mut count = wycheproof_verify::<P>(&format!("mldsa_{n}_verify_test.json"));
    count += wycheproof_sign_tests::<P>(&format!("mldsa_{n}_sign_seed_test.json"), true);
    count += wycheproof_sign_tests::<P>(&format!("mldsa_{n}_sign_noseed_test.json"), false);
    count
}

#[test]
fn wycheproof_mldsa44() {
    assert_eq!(wycheproof_all::<MlDsa44>(44), 180 + 86 + 73);
}

#[test]
fn wycheproof_mldsa65() {
    assert_eq!(wycheproof_all::<MlDsa65>(65), 210 + 105 + 78);
}

#[test]
fn wycheproof_mldsa87() {
    assert_eq!(wycheproof_all::<MlDsa87>(87), 241 + 96 + 69);
}

/// `compute_mu` with the external prefix matches `external_mu`.
#[test]
fn mu_formatting() {
    let tr = [7u8; 64];
    let ctx: String = "ctx".into();
    let mu = external_mu(&tr, b"msg", ctx.as_bytes()).unwrap();
    assert_eq!(mu, compute_mu(&tr, &[], b"\x00\x03ctxmsg"));
    assert_eq!(
        external_mu(&tr, b"", &[0; 256]).unwrap_err(),
        Error::InvalidLength
    );
}

//! Differential tests of the native provider's signing keys and signature
//! verification algorithms against the RustCrypto provider, `ring` (through
//! `rcgen`) and the `rsa` crate, including certificate path validation and
//! handshake signature verification with run-time generated certificates.
//!
//! Every key is generated at run time; nothing secret is committed.

#![cfg(all(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use browntls::crypto::{WebPkiSupportedAlgorithms, native, rustcrypto};
use browntls::internal::msgs::codec::{Codec, Reader};
use browntls::sign::{CertifiedKey, Signer, SigningKey};
use browntls::{DigitallySignedStruct, Error, SignatureAlgorithm, SignatureScheme};
use browntls_pki::{
    CertificateDer, EndEntityCert, KeyUsage, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
    PrivateSec1KeyDer, RawPublicKeyEntity, SubjectPublicKeyInfoDer, UnixTime,
};

use SignatureScheme as S;

fn random_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    native::SECURE_RANDOM.fill(&mut out).unwrap();
    out
}

// ---------------------------------------------------------------------------
// Key generation (run time only)

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    P256,
    P384,
    P521,
    Ed25519,
    Rsa,
}

struct TestKey {
    name: &'static str,
    kind: Kind,
    der: PrivateKeyDer<'static>,
}

impl TestKey {
    fn pkcs8(name: &'static str, kind: Kind, der: Vec<u8>) -> Self {
        Self {
            name,
            kind,
            der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
        }
    }

    fn schemes(&self) -> &'static [SignatureScheme] {
        match self.kind {
            Kind::P256 => &[S::ECDSA_NISTP256_SHA256],
            Kind::P384 => &[S::ECDSA_NISTP384_SHA384],
            Kind::P521 => &[S::ECDSA_NISTP521_SHA512],
            Kind::Ed25519 => &[S::ED25519],
            Kind::Rsa => &[
                S::RSA_PSS_SHA256,
                S::RSA_PSS_SHA384,
                S::RSA_PSS_SHA512,
                S::RSA_PKCS1_SHA256,
                S::RSA_PKCS1_SHA384,
                S::RSA_PKCS1_SHA512,
            ],
        }
    }

    fn rcgen_alg(&self) -> Option<&'static rcgen::SignatureAlgorithm> {
        match self.kind {
            Kind::P256 => Some(&rcgen::PKCS_ECDSA_P256_SHA256),
            Kind::P384 => Some(&rcgen::PKCS_ECDSA_P384_SHA384),
            Kind::Ed25519 => Some(&rcgen::PKCS_ED25519),
            Kind::Rsa => Some(&rcgen::PKCS_RSA_SHA256),
            Kind::P521 => None,
        }
    }

    fn native(&self) -> Arc<dyn SigningKey> {
        native::KEY_PROVIDER
            .load_private_key(self.der.clone_key())
            .unwrap_or_else(|e| panic!("native failed to load {}: {e}", self.name))
    }
}

fn rcgen_pkcs8(alg: &'static rcgen::SignatureAlgorithm) -> Vec<u8> {
    rcgen::KeyPair::generate_for(alg).unwrap().serialize_der()
}

fn rsa_pkcs8(bits: usize) -> Vec<u8> {
    let key =
        browntls_crypto::rsa::RsaPrivateKey::generate(bits, &browntls_crypto::rand::OsRng).unwrap();
    let mut der = vec![0u8; browntls_crypto::rsa::MAX_PKCS8_PRIVATE_KEY_DER_LEN];
    let len = key.to_pkcs8_der(&mut der).unwrap();
    der.truncate(len);
    der
}

/// An RSA key generated and encoded by the `rsa` crate.
fn rsa_crate_key(bits: usize) -> (Vec<u8>, Vec<u8>) {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
    (
        key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        key.to_pkcs1_der().unwrap().as_bytes().to_vec(),
    )
}

fn p521_crate_pkcs8() -> Vec<u8> {
    use p521::pkcs8::EncodePrivateKey;
    loop {
        let mut bytes = random_vec(66);
        bytes[0] &= 0x01;
        if let Ok(secret) = p521::SecretKey::from_slice(&bytes) {
            return secret.to_pkcs8_der().unwrap().as_bytes().to_vec();
        }
    }
}

/// The keys every test uses, generated once per test binary run.
fn test_keys() -> &'static [TestKey] {
    static KEYS: std::sync::OnceLock<Vec<TestKey>> = std::sync::OnceLock::new();
    KEYS.get_or_init(generate_keys)
}

fn generate_keys() -> Vec<TestKey> {
    use browntls_crypto::nist::{p256, p521};
    use browntls_crypto::rand::OsRng;

    let p256_sec1 = {
        let k = p256::SecretKey::generate(&OsRng).unwrap();
        let mut der = [0u8; p256::SEC1_PRIVATE_MAX_LEN];
        let len = k.to_sec1_der(&mut der).unwrap();
        der[..len].to_vec()
    };
    let p521_sec1 = {
        let k = p521::SecretKey::generate(&OsRng).unwrap();
        let mut der = [0u8; p521::SEC1_PRIVATE_MAX_LEN];
        let len = k.to_sec1_der(&mut der).unwrap();
        der[..len].to_vec()
    };
    let ed25519_v1 = browntls_crypto::curve25519::ed25519::SigningKey::generate(&OsRng)
        .unwrap()
        .to_pkcs8_der()
        .to_vec();
    let rsa3072_pkcs1 = {
        let key = browntls_crypto::rsa::RsaPrivateKey::generate(3072, &OsRng).unwrap();
        let mut der = vec![0u8; browntls_crypto::rsa::MAX_PKCS1_PRIVATE_KEY_DER_LEN];
        let len = key.to_pkcs1_der(&mut der).unwrap();
        der.truncate(len);
        der
    };
    let (rsa_crate_pkcs8, rsa_crate_pkcs1) = rsa_crate_key(2048);

    vec![
        TestKey::pkcs8(
            "P-256 PKCS#8 (ring)",
            Kind::P256,
            rcgen_pkcs8(&rcgen::PKCS_ECDSA_P256_SHA256),
        ),
        TestKey {
            name: "P-256 SEC 1 (browntls-crypto)",
            kind: Kind::P256,
            der: PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(p256_sec1)),
        },
        TestKey::pkcs8(
            "P-384 PKCS#8 (ring)",
            Kind::P384,
            rcgen_pkcs8(&rcgen::PKCS_ECDSA_P384_SHA384),
        ),
        TestKey::pkcs8("P-521 PKCS#8 (p521)", Kind::P521, p521_crate_pkcs8()),
        TestKey {
            name: "P-521 SEC 1 (browntls-crypto)",
            kind: Kind::P521,
            der: PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(p521_sec1)),
        },
        TestKey::pkcs8(
            "Ed25519 PKCS#8 v2 (ring)",
            Kind::Ed25519,
            rcgen_pkcs8(&rcgen::PKCS_ED25519),
        ),
        TestKey::pkcs8(
            "Ed25519 PKCS#8 v1 (browntls-crypto)",
            Kind::Ed25519,
            ed25519_v1,
        ),
        TestKey::pkcs8(
            "RSA-2048 PKCS#8 (browntls-crypto)",
            Kind::Rsa,
            rsa_pkcs8(2048),
        ),
        TestKey {
            name: "RSA-3072 PKCS#1 (browntls-crypto)",
            kind: Kind::Rsa,
            der: PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(rsa3072_pkcs1)),
        },
        TestKey::pkcs8("RSA-2048 PKCS#8 (rsa crate)", Kind::Rsa, rsa_crate_pkcs8),
        TestKey {
            name: "RSA-2048 PKCS#1 (rsa crate)",
            kind: Kind::Rsa,
            der: PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(rsa_crate_pkcs1)),
        },
    ]
}

// ---------------------------------------------------------------------------
// Verification helpers

/// Verifies as TLS does: every algorithm the provider maps `scheme` to is
/// tried against the raw `SubjectPublicKeyInfo`.
fn verify(
    algs: &WebPkiSupportedAlgorithms,
    scheme: SignatureScheme,
    spki: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> bool {
    let Some((_, candidates)) = algs.mapping.iter().find(|(s, _)| *s == scheme) else {
        return false;
    };
    let spki = SubjectPublicKeyInfoDer::from_slice(spki);
    let entity = RawPublicKeyEntity::try_from(&spki).unwrap();
    candidates
        .iter()
        .any(|alg| entity.verify_signature(*alg, msg, sig).is_ok())
}

const PROVIDERS: [(&str, &WebPkiSupportedAlgorithms); 2] = [
    ("native", &native::SUPPORTED_SIG_ALGS),
    ("rustcrypto", &rustcrypto::SUPPORTED_SIG_ALGS),
];

/// Signs with `signer` and checks both providers verify, and reject a
/// changed message, a flipped signature bit and a truncated signature.
fn check_signature(
    who: &str,
    spki: &[u8],
    scheme: SignatureScheme,
    sign: impl Fn(&[u8]) -> Vec<u8>,
) {
    for len in [0, 1, 32, 1000] {
        let msg = random_vec(len);
        let sig = sign(&msg);
        for (provider, algs) in PROVIDERS {
            assert!(
                verify(algs, scheme, spki, &msg, &sig),
                "{provider} rejected a {scheme:?} signature from {who}"
            );
            let mut other = msg.clone();
            other.push(1);
            assert!(!verify(algs, scheme, spki, &other, &sig));
            for i in [0, sig.len() / 2, sig.len() - 1] {
                let mut bad = sig.clone();
                bad[i] ^= 0x01;
                assert!(
                    !verify(algs, scheme, spki, &msg, &bad),
                    "{provider} accepted a tampered {scheme:?} signature from {who}"
                );
            }
            assert!(!verify(algs, scheme, spki, &msg, &sig[..sig.len() - 1]));
            assert!(!verify(algs, scheme, spki, &msg, &[]));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests

#[test]
fn native_signatures_verify_with_both_providers() {
    for key in test_keys() {
        let signing_key = key.native();
        let spki = signing_key.public_key().unwrap().as_ref().to_vec();
        for scheme in key.schemes() {
            let signer = signing_key
                .choose_scheme(&[*scheme])
                .unwrap_or_else(|| panic!("{} cannot sign {scheme:?}", key.name));
            assert_eq!(signer.scheme(), *scheme);
            check_signature(key.name, &spki, *scheme, |m| signer.sign(m).unwrap());
        }
    }
}

#[test]
fn rustcrypto_signatures_verify_with_native() {
    for key in test_keys() {
        if key.kind == Kind::Rsa {
            // The RustCrypto provider cannot sign with RSA; see the `rsa`
            // crate test below.
            assert!(rustcrypto::sign::any_supported_type(&key.der).is_err());
            continue;
        }
        let oracle = rustcrypto::sign::any_supported_type(&key.der)
            .unwrap_or_else(|e| panic!("rustcrypto failed to load {}: {e}", key.name));
        let native_key = key.native();
        // Both providers derive the same SubjectPublicKeyInfo.
        assert_eq!(
            oracle.public_key().unwrap().as_ref(),
            native_key.public_key().unwrap().as_ref(),
            "{}",
            key.name
        );
        assert_eq!(oracle.algorithm(), native_key.algorithm());
        let spki = oracle.public_key().unwrap().as_ref().to_vec();
        for scheme in key.schemes() {
            let signer = oracle.choose_scheme(&[*scheme]).unwrap();
            check_signature(key.name, &spki, *scheme, |m| signer.sign(m).unwrap());
        }
    }
}

#[test]
fn ring_signatures_verify_with_native() {
    use rcgen::{PublicKeyData, SigningKey as _};
    for key in test_keys() {
        let Some(base_alg) = key.rcgen_alg() else {
            continue;
        };
        let PrivateKeyDer::Pkcs8(pkcs8) = &key.der else {
            continue;
        };
        let pkcs8 = rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.secret_der().to_vec());
        let algs: &[(&'static rcgen::SignatureAlgorithm, SignatureScheme)] = match key.kind {
            Kind::Rsa => &[
                (&rcgen::PKCS_RSA_SHA256, S::RSA_PKCS1_SHA256),
                (&rcgen::PKCS_RSA_SHA384, S::RSA_PKCS1_SHA384),
                (&rcgen::PKCS_RSA_SHA512, S::RSA_PKCS1_SHA512),
            ],
            _ => &[(base_alg, key.schemes()[0])],
        };
        for (alg, scheme) in algs {
            // ring rejects some encodings (e.g. PKCS#8 v1 Ed25519 is fine,
            // RSA keys must be at least 2048 bits); every key here is valid.
            let ring_key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, alg)
                .unwrap_or_else(|e| panic!("ring failed to load {}: {e}", key.name));
            let spki = ring_key.subject_public_key_info();
            assert_eq!(
                spki,
                key.native().public_key().unwrap().as_ref(),
                "SPKI mismatch for {}",
                key.name
            );
            check_signature(key.name, &spki, *scheme, |m| ring_key.sign(m).unwrap());
        }
    }
}

#[test]
fn rsa_crate_signatures_verify_with_native() {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::sha2::{Sha256, Sha384, Sha512};
    use rsa::signature::{SignatureEncoding, Signer as _};

    for key in test_keys().iter().filter(|k| k.kind == Kind::Rsa) {
        let private = match &key.der {
            PrivateKeyDer::Pkcs8(der) => {
                rsa::RsaPrivateKey::from_pkcs8_der(der.secret_der()).unwrap()
            }
            PrivateKeyDer::Pkcs1(der) => {
                use rsa::pkcs1::DecodeRsaPrivateKey;
                rsa::RsaPrivateKey::from_pkcs1_der(der.secret_der()).unwrap()
            }
            _ => unreachable!(),
        };
        let spki = key.native().public_key().unwrap().as_ref().to_vec();
        let k = || private.clone();
        #[allow(clippy::type_complexity)]
        let signers: Vec<(SignatureScheme, Box<dyn Fn(&[u8]) -> Vec<u8> + '_>)> = vec![
            (
                S::RSA_PKCS1_SHA256,
                Box::new(move |m| {
                    rsa::pkcs1v15::SigningKey::<Sha256>::new(k())
                        .sign(m)
                        .to_vec()
                }),
            ),
            (
                S::RSA_PKCS1_SHA384,
                Box::new(move |m| {
                    rsa::pkcs1v15::SigningKey::<Sha384>::new(k())
                        .sign(m)
                        .to_vec()
                }),
            ),
            (
                S::RSA_PKCS1_SHA512,
                Box::new(move |m| {
                    rsa::pkcs1v15::SigningKey::<Sha512>::new(k())
                        .sign(m)
                        .to_vec()
                }),
            ),
            (
                S::RSA_PSS_SHA256,
                Box::new(move |m| rsa::pss::SigningKey::<Sha256>::new(k()).sign(m).to_vec()),
            ),
            (
                S::RSA_PSS_SHA384,
                Box::new(move |m| rsa::pss::SigningKey::<Sha384>::new(k()).sign(m).to_vec()),
            ),
            (
                S::RSA_PSS_SHA512,
                Box::new(move |m| rsa::pss::SigningKey::<Sha512>::new(k()).sign(m).to_vec()),
            ),
        ];
        for (scheme, sign) in signers {
            check_signature(key.name, &spki, scheme, sign);
        }
    }
}

#[test]
fn rsa_scheme_choice_and_cross_scheme_rejection() {
    let key = TestKey::pkcs8("RSA-2048", Kind::Rsa, rsa_pkcs8(2048));
    let signing_key = key.native();
    assert_eq!(signing_key.algorithm(), SignatureAlgorithm::RSA);
    // PSS is preferred over PKCS#1 v1.5 and larger hashes over smaller ones.
    for (offered, chosen) in [
        (
            &[S::RSA_PKCS1_SHA256, S::RSA_PSS_SHA256][..],
            S::RSA_PSS_SHA256,
        ),
        (&[S::RSA_PSS_SHA256, S::RSA_PSS_SHA512], S::RSA_PSS_SHA512),
        (
            &[S::RSA_PKCS1_SHA384, S::RSA_PKCS1_SHA256],
            S::RSA_PKCS1_SHA384,
        ),
    ] {
        assert_eq!(signing_key.choose_scheme(offered).unwrap().scheme(), chosen);
    }
    assert!(
        signing_key
            .choose_scheme(&[S::ED25519, S::ECDSA_NISTP256_SHA256, S::RSA_PKCS1_SHA1])
            .is_none()
    );

    // A signature made under one scheme does not verify under another.
    let spki = signing_key.public_key().unwrap().as_ref().to_vec();
    let sig = signing_key
        .choose_scheme(&[S::RSA_PSS_SHA256])
        .unwrap()
        .sign(b"msg")
        .unwrap();
    for (_, algs) in PROVIDERS {
        assert!(verify(algs, S::RSA_PSS_SHA256, &spki, b"msg", &sig));
        for other in [
            S::RSA_PSS_SHA384,
            S::RSA_PKCS1_SHA256,
            S::ECDSA_NISTP256_SHA256,
            S::ED25519,
        ] {
            assert!(!verify(algs, other, &spki, b"msg", &sig), "{other:?}");
        }
    }
}

#[test]
fn signatures_do_not_verify_under_other_keys_or_schemes() {
    let keys = test_keys();
    for (i, a) in keys.iter().enumerate() {
        let ka = a.native();
        let scheme = a.schemes()[0];
        let sig = ka.choose_scheme(&[scheme]).unwrap().sign(b"msg").unwrap();
        let spki_a = ka.public_key().unwrap().as_ref().to_vec();
        for b in keys.iter().skip(i + 1) {
            let spki_b = b.native().public_key().unwrap().as_ref().to_vec();
            if spki_a == spki_b {
                // The same key in two encodings (rsa crate PKCS#8 / PKCS#1).
                continue;
            }
            for (provider, algs) in PROVIDERS {
                for s in b.schemes() {
                    assert!(
                        !verify(algs, *s, &spki_b, b"msg", &sig),
                        "{provider}: {} signature verified with {}",
                        a.name,
                        b.name
                    );
                }
            }
        }
    }
    // ECDSA signatures are DER; the fixed-size form is rejected.
    let key = TestKey::pkcs8(
        "P-256",
        Kind::P256,
        rcgen_pkcs8(&rcgen::PKCS_ECDSA_P256_SHA256),
    );
    let signing_key = key.native();
    let spki = signing_key.public_key().unwrap().as_ref().to_vec();
    let sig = signing_key
        .choose_scheme(&[S::ECDSA_NISTP256_SHA256])
        .unwrap()
        .sign(b"msg")
        .unwrap();
    assert_eq!(sig[0], 0x30);
    let mut fixed = vec![0u8; 64];
    let r_len = sig[3] as usize;
    let r = &sig[4..4 + r_len];
    let s = &sig[6 + r_len..];
    fixed[32 - r.len().min(32)..32].copy_from_slice(&r[r.len().saturating_sub(32)..]);
    fixed[64 - s.len().min(32)..].copy_from_slice(&s[s.len().saturating_sub(32)..]);
    for (_, algs) in PROVIDERS {
        assert!(verify(algs, S::ECDSA_NISTP256_SHA256, &spki, b"msg", &sig));
        assert!(!verify(
            algs,
            S::ECDSA_NISTP256_SHA256,
            &spki,
            b"msg",
            &fixed
        ));
    }
}

#[test]
fn ecdsa_schemes_accept_any_curve_like_rustls() {
    // In TLS 1.2 an ECDSA scheme names only the hash; the mapping therefore
    // lists every curve. A P-384 key signing with SHA-256 verifies under
    // ECDSA_NISTP256_SHA256.
    use browntls_crypto::hash::HashAlgorithm;
    use browntls_crypto::nist::p384;
    let key = p384::SigningKey::generate(&browntls_crypto::rand::OsRng).unwrap();
    let sig = key
        .sign(HashAlgorithm::Sha256, b"msg", &browntls_crypto::rand::OsRng)
        .unwrap();
    let mut spki = [0u8; p384::SPKI_MAX_LEN];
    let len = key.verifying_key().to_spki_der(&mut spki).unwrap();
    for (_, algs) in PROVIDERS {
        assert!(verify(
            algs,
            S::ECDSA_NISTP256_SHA256,
            &spki[..len],
            b"msg",
            sig.as_der()
        ));
        assert!(!verify(
            algs,
            S::ECDSA_NISTP384_SHA384,
            &spki[..len],
            b"msg",
            sig.as_der()
        ));
    }
}

#[test]
fn malformed_keys_are_rejected() {
    let garbage: Vec<PrivateKeyDer<'static>> = vec![
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![])),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00])),
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(vec![0x30, 0x00])),
        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(random_vec(121))),
    ];
    for der in garbage {
        assert!(native::KEY_PROVIDER.load_private_key(der).is_err());
    }
    // Truncations of a valid key never load (and never panic).
    for key in test_keys() {
        let bytes = key.der.secret_der().to_vec();
        for cut in [1, 2, bytes.len() / 2, bytes.len() - 1] {
            let der = match &key.der {
                PrivateKeyDer::Pkcs8(_) => {
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes[..cut].to_vec()))
                }
                PrivateKeyDer::Pkcs1(_) => {
                    PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(bytes[..cut].to_vec()))
                }
                PrivateKeyDer::Sec1(_) => {
                    PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(bytes[..cut].to_vec()))
                }
                _ => unreachable!(),
            };
            assert!(
                native::KEY_PROVIDER.load_private_key(der).is_err(),
                "{} truncated to {cut}",
                key.name
            );
        }
    }
    // An RSA key below 2048 bits is refused.
    let (small, _) = rsa_crate_key(1024);
    assert!(
        native::KEY_PROVIDER
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(small)))
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Certificates

/// A native signing key presented to `rcgen` so it can sign certificates.
struct NativeCertSigner {
    signer: Box<dyn Signer>,
    public_key: Vec<u8>,
    alg: &'static rcgen::SignatureAlgorithm,
}

impl NativeCertSigner {
    fn new(key: &TestKey) -> Self {
        let signing_key = key.native();
        let scheme = match key.kind {
            Kind::Rsa => S::RSA_PKCS1_SHA256,
            _ => key.schemes()[0],
        };
        let spki = signing_key.public_key().unwrap().as_ref().to_vec();
        Self {
            signer: signing_key.choose_scheme(&[scheme]).unwrap(),
            public_key: subject_public_key(&spki),
            alg: key.rcgen_alg().unwrap(),
        }
    }
}

impl rcgen::PublicKeyData for NativeCertSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.alg
    }
}

impl rcgen::SigningKey for NativeCertSigner {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.signer
            .sign(msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

/// The contents of the `subjectPublicKey` BIT STRING of an SPKI.
fn subject_public_key(spki: &[u8]) -> Vec<u8> {
    fn read(input: &[u8]) -> (u8, &[u8], &[u8]) {
        let tag = input[0];
        let (len, header) = match input[1] {
            n if n < 0x80 => (n as usize, 2),
            0x81 => (input[2] as usize, 3),
            0x82 => (u16::from_be_bytes([input[2], input[3]]) as usize, 4),
            _ => panic!("unsupported length"),
        };
        (tag, &input[header..header + len], &input[header + len..])
    }
    let (_, body, _) = read(spki);
    let (_, _alg, rest) = read(body);
    let (tag, bits, _) = read(rest);
    assert_eq!(tag, 0x03);
    assert_eq!(bits[0], 0);
    bits[1..].to_vec()
}

fn cert_params(ca: bool) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(vec!["native.example".to_string()]).unwrap();
    if ca {
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    }
    params
}

fn dss(scheme: SignatureScheme, sig: &[u8]) -> DigitallySignedStruct {
    let mut bytes = u16::from(scheme).to_be_bytes().to_vec();
    bytes.extend_from_slice(&u16::try_from(sig.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(sig);
    DigitallySignedStruct::read(&mut Reader::init(&bytes)).unwrap()
}

fn verify_path(
    ee: &CertificateDer<'_>,
    ca: &CertificateDer<'_>,
    algs: &[&dyn browntls_pki::SignatureVerificationAlgorithm],
) -> Result<(), browntls_pki::Error> {
    let anchor = browntls_pki::anchor_from_trusted_cert(ca)?;
    let ee = EndEntityCert::try_from(ee)?;
    ee.verify_for_usage(
        algs,
        &[anchor],
        &[],
        UnixTime::now(),
        KeyUsage::server_auth(),
        None,
        None,
    )
    .map(|_| ())
}

#[test]
fn certificate_chains_verify_with_both_providers() {
    let keys: Vec<&TestKey> = test_keys()
        .iter()
        .filter(|k| k.rcgen_alg().is_some())
        .collect();
    for ca_key in &keys {
        // CA certificates signed by native keys, end-entity certificates
        // signed by the CA (native) for an end-entity key of every type.
        let ca_signer = NativeCertSigner::new(ca_key);
        let ca_params = cert_params(true);
        let ca_cert = ca_params.self_signed(&ca_signer).unwrap();
        let ca_der = CertificateDer::from(ca_cert.der().to_vec());
        let issuer = rcgen::Issuer::new(ca_params, ca_signer);

        for ee_key in &keys {
            let ee_signer = NativeCertSigner::new(ee_key);
            let ee_cert = cert_params(false).signed_by(&ee_signer, &issuer).unwrap();
            let ee_der = CertificateDer::from(ee_cert.der().to_vec());

            for (provider, algs) in [
                ("native", native::ALL_VERIFICATION_ALGS),
                ("rustcrypto", rustcrypto::SUPPORTED_SIG_ALGS.all),
            ] {
                verify_path(&ee_der, &ca_der, algs).unwrap_or_else(|e| {
                    panic!(
                        "{provider} rejected {} -> {}: {e:?}",
                        ca_key.name, ee_key.name
                    )
                });
            }

            // The certificate matches its key (`keys_match` compares SPKIs).
            let certified = CertifiedKey::from_der(
                vec![ee_der.clone()],
                ee_key.der.clone_key(),
                &native::default_provider(),
            )
            .unwrap();
            certified.keys_match().unwrap();

            // Handshake signatures verify against the certificate.
            let msg = random_vec(100);
            for scheme in ee_key.schemes() {
                let sig = certified
                    .key
                    .choose_scheme(&[*scheme])
                    .unwrap()
                    .sign(&msg)
                    .unwrap();
                for (_, algs) in PROVIDERS {
                    #[cfg(feature = "tls12")]
                    browntls::crypto::verify_tls12_signature(
                        &msg,
                        &ee_der,
                        &dss(*scheme, &sig),
                        algs,
                    )
                    .unwrap();
                    let tls13 = browntls::crypto::verify_tls13_signature(
                        &msg,
                        &ee_der,
                        &dss(*scheme, &sig),
                        algs,
                    );
                    if scheme.as_str().is_some_and(|s| s.starts_with("RSA_PKCS1")) {
                        assert!(tls13.is_err(), "TLS 1.3 accepted {scheme:?}");
                    } else {
                        tls13.unwrap();
                    }
                    let mut bad = sig.clone();
                    *bad.last_mut().unwrap() ^= 1;
                    assert!(
                        browntls::crypto::verify_tls13_signature(
                            &msg,
                            &ee_der,
                            &dss(*scheme, &bad),
                            algs
                        )
                        .is_err()
                    );
                }
            }
        }

        // A certificate signed by a different CA key does not chain.
        let other = NativeCertSigner::new(&TestKey::pkcs8(
            "other P-256",
            Kind::P256,
            rcgen_pkcs8(&rcgen::PKCS_ECDSA_P256_SHA256),
        ));
        let other_issuer = rcgen::Issuer::new(cert_params(true), other);
        let ee_signer = NativeCertSigner::new(keys[0]);
        let ee_cert = cert_params(false)
            .signed_by(&ee_signer, &other_issuer)
            .unwrap();
        let ee_der = CertificateDer::from(ee_cert.der().to_vec());
        assert!(verify_path(&ee_der, &ca_der, native::ALL_VERIFICATION_ALGS).is_err());
    }
}

#[test]
fn ring_signed_certificates_verify_with_native() {
    // Certificates signed by ring (through rcgen) for each key type it
    // supports, verified by the native algorithms.
    for alg in [
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ED25519,
    ] {
        let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let ca_params = cert_params(true);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let ee_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let ee_cert = cert_params(false).signed_by(&ee_key, &issuer).unwrap();
        let ca_der = CertificateDer::from(ca_cert.der().to_vec());
        let ee_der = CertificateDer::from(ee_cert.der().to_vec());
        verify_path(&ee_der, &ca_der, native::ALL_VERIFICATION_ALGS).unwrap();

        // Tampering with the end-entity signature breaks the chain.
        let mut tampered = ee_der.as_ref().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered = CertificateDer::from(tampered);
        assert!(verify_path(&tampered, &ca_der, native::ALL_VERIFICATION_ALGS).is_err());

        // The certificate's key loads into a native signing key that matches.
        let certified = CertifiedKey::from_der(
            vec![ee_der],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ee_key.serialize_der())),
            &native::default_provider(),
        )
        .unwrap();
        certified.keys_match().unwrap();
    }
}

#[test]
fn mismatched_certificate_and_key_are_detected() {
    let cert_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = cert_params(false).self_signed(&cert_key).unwrap();
    let other = rcgen_pkcs8(&rcgen::PKCS_ECDSA_P256_SHA256);
    let err = CertifiedKey::from_der(
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(other)),
        &native::default_provider(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        Error::InconsistentKeys(browntls::InconsistentKeys::KeyMismatch)
    );
}

#[test]
fn verification_algorithm_lists() {
    // 16, plus Ed448 and RSASSA-PSS keys (without parameters and
    // restricted) for each of the three `rsa_pss_pss_*` schemes.
    assert_eq!(native::ALL_VERIFICATION_ALGS.len(), 16 + 1 + 6);
    // The RustCrypto provider's schemes, in the same order, then the
    // optional RFC 9846 schemes in a non-preferred tier.
    let native_schemes = native::SUPPORTED_SIG_ALGS.supported_schemes();
    let common = rustcrypto::SUPPORTED_SIG_ALGS.supported_schemes();
    assert_eq!(native_schemes[..common.len()], common[..]);
    assert_eq!(
        native_schemes[common.len()..],
        [
            S::ED448,
            S::RSA_PSS_PSS_SHA512,
            S::RSA_PSS_PSS_SHA384,
            S::RSA_PSS_PSS_SHA256
        ]
    );
    assert!(!native::SUPPORTED_SIG_ALGS.fips());
}

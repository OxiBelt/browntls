//! Shared test support: `SignatureVerificationAlgorithm` implementations
//! built on RustCrypto, and `rcgen` helpers that generate certificate chains
//! at run time (no private keys are stored in the repository).

#![allow(dead_code)]

use std::sync::OnceLock;

use browntls_pki::alg_id;
use browntls_pki::{
    AlgorithmIdentifier, CertificateDer, EndEntityCert, Error, InvalidSignature, KeyUsage,
    PathVerifier, RevocationOptions, SignatureVerificationAlgorithm, TrustAnchor, UnixTime,
    anchor_from_trusted_cert,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SigningKey,
};
use rsa::pkcs1::DecodeRsaPublicKey as _;
use rsa::pkcs8::EncodePrivateKey as _;
use rsa::signature::{RandomizedSigner as _, Verifier as _};
use sha2::Digest as _;

// ---------------------------------------------------------------------------
// Signature verification algorithms
// ---------------------------------------------------------------------------

type VerifyFn = fn(&[u8], &[u8], &[u8]) -> bool;

/// A test-only verification algorithm.
#[derive(Debug)]
pub struct TestAlg {
    name: &'static str,
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
    verify: VerifyFn,
}

impl SignatureVerificationAlgorithm for TestAlg {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        if (self.verify)(public_key, message, signature) {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

fn p256_sha256(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    let (Ok(vk), Ok(sig)) = (
        p256::ecdsa::VerifyingKey::from_sec1_bytes(key),
        p256::ecdsa::Signature::from_der(sig),
    ) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

fn p256_sha384(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    let (Ok(vk), Ok(sig)) = (
        p256::ecdsa::VerifyingKey::from_sec1_bytes(key),
        p256::ecdsa::Signature::from_der(sig),
    ) else {
        return false;
    };
    let digest = <sha2v11::Sha384 as sha2v11::Digest>::digest(msg);
    vk.verify_prehash(&digest, &sig).is_ok()
}

fn p384_sha384(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use p384::ecdsa::signature::Verifier as _;
    let (Ok(vk), Ok(sig)) = (
        p384::ecdsa::VerifyingKey::from_sec1_bytes(key),
        p384::ecdsa::Signature::from_der(sig),
    ) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

fn p384_sha256(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
    let (Ok(vk), Ok(sig)) = (
        p384::ecdsa::VerifyingKey::from_sec1_bytes(key),
        p384::ecdsa::Signature::from_der(sig),
    ) else {
        return false;
    };
    let digest = <sha2v11::Sha256 as sha2v11::Digest>::digest(msg);
    vk.verify_prehash(&digest, &sig).is_ok()
}

fn ed25519(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(key) else {
        return false;
    };
    let (Ok(vk), Ok(sig)) = (
        ed25519_dalek::VerifyingKey::from_bytes(&key),
        ed25519_dalek::Signature::from_slice(sig),
    ) else {
        return false;
    };
    vk.verify_strict(msg, &sig).is_ok()
}

fn rsa_pkcs1<D>(key: &[u8], msg: &[u8], sig: &[u8]) -> bool
where
    D: sha2::Digest + rsa::pkcs1::AssociatedOid,
{
    let (Ok(pk), Ok(sig)) = (
        rsa::RsaPublicKey::from_pkcs1_der(key),
        rsa::pkcs1v15::Signature::try_from(sig),
    ) else {
        return false;
    };
    rsa::pkcs1v15::VerifyingKey::<D>::new(pk)
        .verify(msg, &sig)
        .is_ok()
}

fn rsa_pss_sha256(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        rsa::RsaPublicKey::from_pkcs1_der(key),
        rsa::pss::Signature::try_from(sig),
    ) else {
        return false;
    };
    rsa::pss::VerifyingKey::<sha2::Sha256>::new_with_salt_len(pk, 32)
        .verify(msg, &sig)
        .is_ok()
}

macro_rules! alg {
    ($name:ident, $pk:expr, $sig:expr, $f:expr) => {
        pub static $name: TestAlg = TestAlg {
            name: stringify!($name),
            public_key: $pk,
            signature: $sig,
            verify: $f,
        };
    };
}

alg!(
    ECDSA_P256_SHA256,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA256,
    p256_sha256
);
alg!(
    ECDSA_P256_SHA384,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA384,
    p256_sha384
);
alg!(
    ECDSA_P384_SHA384,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA384,
    p384_sha384
);
alg!(
    ECDSA_P384_SHA256,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA256,
    p384_sha256
);
alg!(ED25519, alg_id::ED25519, alg_id::ED25519, ed25519);
alg!(
    RSA_PKCS1_SHA256,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA256,
    rsa_pkcs1::<sha2::Sha256>
);
alg!(
    RSA_PKCS1_SHA384,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA384,
    rsa_pkcs1::<sha2::Sha384>
);
alg!(
    RSA_PKCS1_SHA512,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA512,
    rsa_pkcs1::<sha2::Sha512>
);
alg!(
    RSA_PSS_SHA256,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA256,
    rsa_pss_sha256
);

/// `sha256WithRSAEncryption` with the parameters field absent instead of
/// `NULL`, which some older certificates use.
pub const RSA_PKCS1_SHA256_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);
alg!(
    RSA_PKCS1_SHA256_NO_PARAMS,
    alg_id::RSA_ENCRYPTION,
    RSA_PKCS1_SHA256_ABSENT_PARAMS,
    rsa_pkcs1::<sha2::Sha256>
);

/// Every test algorithm.
pub static ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    &ECDSA_P256_SHA256,
    &ECDSA_P256_SHA384,
    &ECDSA_P384_SHA384,
    &ECDSA_P384_SHA256,
    &ED25519,
    &RSA_PKCS1_SHA256,
    &RSA_PKCS1_SHA384,
    &RSA_PKCS1_SHA512,
    &RSA_PSS_SHA256,
    &RSA_PKCS1_SHA256_NO_PARAMS,
];

/// Only the ECDSA P-256/SHA-256 algorithm.
pub static P256_ONLY: &[&dyn SignatureVerificationAlgorithm] = &[&ECDSA_P256_SHA256];

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

pub const fn secs(s: u64) -> UnixTime {
    UnixTime::since_unix_epoch(core::time::Duration::from_secs(s))
}

/// 2024-06-01T00:00:00Z, inside rcgen's default validity period.
pub const NOW: UnixTime = secs(1_717_200_000);

/// rcgen's `OffsetDateTime` for a Unix timestamp.
pub fn at(secs: u64) -> time::OffsetDateTime {
    rcgen::date_time_ymd(1970, 1, 1) + core::time::Duration::from_secs(secs)
}

// ---------------------------------------------------------------------------
// Keys and parameters
// ---------------------------------------------------------------------------

fn rsa_private_key() -> &'static rsa::RsaPrivateKey {
    static KEY: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap())
}

/// A fresh key pair for `alg`. RSA keys are generated with the `rsa` crate
/// (ring cannot generate them) and shared between tests.
pub fn key_for(alg: &'static rcgen::SignatureAlgorithm) -> KeyPair {
    if *alg == rcgen::PKCS_RSA_SHA256
        || *alg == rcgen::PKCS_RSA_SHA384
        || *alg == rcgen::PKCS_RSA_SHA512
    {
        let pkcs8 = rsa_private_key().to_pkcs8_der().unwrap();
        let der = rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
        KeyPair::from_pkcs8_der_and_sign_algo(&der, alg).unwrap()
    } else {
        KeyPair::generate_for(alg).unwrap()
    }
}

/// Signs `msg` with the shared RSA key using RSASSA-PSS/SHA-256.
pub fn rsa_pss_sign(msg: &[u8]) -> Vec<u8> {
    let signing = rsa::pss::SigningKey::<sha2::Sha256>::new(rsa_private_key().clone());
    let sig: rsa::pss::Signature = signing.sign_with_rng(&mut rand::thread_rng(), msg);
    rsa::signature::SignatureEncoding::to_vec(&sig)
}

/// SHA-256 of `data`, for building key identifiers in hand-made certificates.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(data).to_vec()
}

/// CA parameters: `cA` TRUE without path length, `keyCertSign` and
/// `cRLSign`, subject `O=<name>, CN=<name>`.
pub fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::OrganizationName, name);
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// End-entity parameters: explicit non-CA, `serverAuth` EKU, the given SANs.
pub fn ee_params(sans: &[&str]) -> CertificateParams {
    let mut params =
        CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "end entity");
    params.is_ca = IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
}

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

/// A generated chain: root, zero or more intermediates (nearest the root
/// first), and an end entity.
pub struct Chain {
    pub root: CertifiedIssuer<'static, KeyPair>,
    pub intermediates: Vec<CertifiedIssuer<'static, KeyPair>>,
    pub ee: Certificate,
    pub ee_key: KeyPair,
}

impl Chain {
    /// Builds `root -> intermediates... -> ee` from the given parameters.
    pub fn build(
        alg: &'static rcgen::SignatureAlgorithm,
        root: CertificateParams,
        intermediates: Vec<CertificateParams>,
        ee: &CertificateParams,
    ) -> Self {
        let root = CertifiedIssuer::self_signed(root, key_for(alg)).unwrap();
        let mut built: Vec<CertifiedIssuer<'static, KeyPair>> = Vec::new();
        for params in intermediates {
            let issuer: &Issuer<'_, KeyPair> = match built.last() {
                Some(last) => last,
                None => &root,
            };
            built.push(CertifiedIssuer::signed_by(params, key_for(alg), issuer).unwrap());
        }
        let ee_key = key_for(alg);
        let issuer: &Issuer<'_, KeyPair> = match built.last() {
            Some(last) => last,
            None => &root,
        };
        let ee = ee.signed_by(&ee_key, issuer).unwrap();
        Self {
            root,
            intermediates: built,
            ee,
            ee_key,
        }
    }

    /// A chain with `depth` intermediates and default parameters.
    pub fn simple(alg: &'static rcgen::SignatureAlgorithm, depth: usize) -> Self {
        let intermediates = (0..depth)
            .map(|i| ca_params(&format!("intermediate {i}")))
            .collect();
        Self::build(
            alg,
            ca_params("root"),
            intermediates,
            &ee_params(&["example.com"]),
        )
    }

    pub fn ee_der(&self) -> CertificateDer<'static> {
        self.ee.der().to_vec().into()
    }

    /// Intermediates as DER, nearest the end entity first.
    pub fn intermediate_ders(&self) -> Vec<CertificateDer<'static>> {
        self.intermediates
            .iter()
            .rev()
            .map(|c| c.der().to_vec().into())
            .collect()
    }

    pub fn root_der(&self) -> CertificateDer<'static> {
        self.root.der().to_vec().into()
    }

    /// Verifies the chain for server authentication at `time`.
    pub fn verify_at(&self, time: UnixTime) -> Result<(), Error> {
        self.verify_with(ALGS, time, KeyUsage::server_auth(), None)
    }

    pub fn verify_with(
        &self,
        algs: &[&dyn SignatureVerificationAlgorithm],
        time: UnixTime,
        usage: KeyUsage,
        revocation: Option<RevocationOptions<'_>>,
    ) -> Result<(), Error> {
        let root = self.root_der();
        let anchors = [anchor_from_trusted_cert(&root).unwrap()];
        verify(
            &self.ee_der(),
            &self.intermediate_ders(),
            &anchors,
            algs,
            time,
            usage,
            revocation,
            None,
        )
    }
}

/// Parses `ee` and builds a path, discarding the verified path.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    ee: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &[TrustAnchor<'_>],
    algs: &[&dyn SignatureVerificationAlgorithm],
    time: UnixTime,
    usage: KeyUsage,
    revocation: Option<RevocationOptions<'_>>,
    verify_path: Option<PathVerifier<'_>>,
) -> Result<(), Error> {
    let ee = EndEntityCert::try_from(ee)?;
    ee.verify_for_usage(
        algs,
        anchors,
        intermediates,
        time,
        usage,
        revocation,
        verify_path,
    )
    .map(|_| ())
}

/// Trust anchors for the given root certificates.
pub fn anchors<'a>(roots: &'a [CertificateDer<'a>]) -> Vec<TrustAnchor<'a>> {
    roots
        .iter()
        .map(|r| anchor_from_trusted_cert(r).unwrap())
        .collect()
}

/// Signs `msg` with an rcgen key pair.
pub fn sign(key: &KeyPair, msg: &[u8]) -> Vec<u8> {
    key.sign(msg).unwrap()
}

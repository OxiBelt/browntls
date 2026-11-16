//! Keys and certificates generated once per process for `tls_config` and
//! `pki_api`.
//!
//! The ECDSA P-256/P-384 and Ed25519 keys come from `rcgen` (random); the
//! RSA, RSA-PSS, P-521 and Ed448 keys are derived from fixed seeds with
//! `browntls-crypto`, so that they are the same in every process. Every key
//! with a certificate chains to [`Fixtures::ca`]; the P-384 one through an
//! intermediate.

use std::sync::OnceLock;

use browntls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use browntls_crypto::rsa::{MAX_PKCS8_PRIVATE_KEY_DER_LEN, RsaKeyAlgorithm, RsaPrivateKey};

/// The DelegationUsage extension (RFC 9345 §4.2): OID 1.3.6.1.4.1.44363.44,
/// value NULL.
const DELEGATION_USAGE: &[u64] = &[1, 3, 6, 1, 4, 1, 44363, 44];

/// The serial number of the P-256 end entity, revoked by
/// [`Fixtures::crl_revoking`].
pub(crate) const P256_SERIAL: &[u8] = &[0x11, 0x22, 0x33, 0x44];

/// A private key, optionally with a certificate chain for it.
pub(crate) struct Key {
    pub(crate) name: &'static str,
    der: PrivateKeyDer<'static>,
    /// End entity first; empty for keys without a certificate.
    pub(crate) chain: Vec<CertificateDer<'static>>,
    /// Whether the rustcrypto provider can load it (no RSA, no Ed448).
    pub(crate) rustcrypto: bool,
}

impl Key {
    pub(crate) fn der(&self) -> PrivateKeyDer<'static> {
        self.der.clone_key()
    }
}

/// Everything generated at start-up.
pub(crate) struct Fixtures {
    /// The root.
    pub(crate) ca: CertificateDer<'static>,
    /// An unrelated root that issued nothing here.
    pub(crate) other_ca: CertificateDer<'static>,
    /// The intermediate between [`Self::ca`] and the P-384 end entity.
    pub(crate) intermediate: CertificateDer<'static>,
    /// A CRL from the root revoking an unrelated serial number.
    pub(crate) crl_clean: Vec<u8>,
    /// A CRL from the root revoking the P-256 end entity.
    pub(crate) crl_revoking: Vec<u8>,
    /// [`KEY_NAMES`] order.
    pub(crate) keys: Vec<Key>,
}

/// Indices into [`Fixtures::keys`].
pub(crate) const P256: usize = 0;
pub(crate) const P384: usize = 1;
pub(crate) const ED25519: usize = 2;
pub(crate) const RSA: usize = 3;
pub(crate) const RSA_PKCS1: usize = 4;
pub(crate) const RSA_PSS: usize = 5;
pub(crate) const P521: usize = 6;
pub(crate) const P256_SEC1: usize = 7;
pub(crate) const ED448: usize = 8;
/// A key whose chain is the P-256 chain: the key does not match the
/// certificate.
pub(crate) const MISMATCHED: usize = 9;
pub(crate) const KEY_COUNT: usize = 10;

/// xorshift64*: a deterministic source for the RSA key generation.
struct SeededRng(std::cell::Cell<u64>);

impl browntls_crypto::rand::SecureRandom for SeededRng {
    fn fill(&self, dest: &mut [u8]) -> Result<(), browntls_crypto::Error> {
        for b in dest {
            let mut x = self.0.get();
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0.set(x);
            *b = (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8;
        }
        Ok(())
    }
}

fn ca_params(name: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params
}

fn end_entity_params(serial: Option<&[u8]>, delegation: bool) -> rcgen::CertificateParams {
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "*.wild.example".to_string()])
            .expect("end-entity params");
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::from([
            127, 0, 0, 1,
        ])));
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    if let Some(serial) = serial {
        params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
    }
    if delegation {
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                DELEGATION_USAGE,
                vec![0x05, 0x00],
            ));
    }
    params
}

fn crl(issuer: &rcgen::Issuer<'_, rcgen::KeyPair>, serial: &[u8]) -> Vec<u8> {
    rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2026, 11, 1),
        next_update: rcgen::date_time_ymd(2027, 11, 1),
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from_slice(serial),
            revocation_time: rcgen::date_time_ymd(2026, 11, 1),
            reason_code: Some(rcgen::RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .expect("CRL")
    .der()
    .to_vec()
}

fn der(cert: &rcgen::Certificate) -> CertificateDer<'static> {
    CertificateDer::from(cert.der().to_vec())
}

fn generate() -> Fixtures {
    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let ca_cert = ca_params("browntls fuzz root")
        .self_signed(&ca_key)
        .expect("CA");
    let issuer = rcgen::Issuer::new(ca_params("browntls fuzz root"), ca_key);

    let other_key = rcgen::KeyPair::generate().expect("other CA key");
    let other_ca = ca_params("browntls unrelated root")
        .self_signed(&other_key)
        .expect("other CA");

    let int_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("int key");
    let int_cert = ca_params("browntls fuzz intermediate")
        .signed_by(&int_key, &issuer)
        .expect("intermediate");
    let int_issuer = rcgen::Issuer::new(ca_params("browntls fuzz intermediate"), int_key);

    let pkcs8 =
        |kp: &rcgen::KeyPair| PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der()));

    // P-256: delegation usage, known serial number.
    let p256 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("p256");
    let p256_cert = end_entity_params(Some(P256_SERIAL), true)
        .signed_by(&p256, &issuer)
        .expect("p256 cert");
    // P-384 under the intermediate.
    let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("p384");
    let p384_cert = end_entity_params(None, false)
        .signed_by(&p384, &int_issuer)
        .expect("p384 cert");
    // Ed25519.
    let ed25519 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
    let ed25519_cert = end_entity_params(None, true)
        .signed_by(&ed25519, &issuer)
        .expect("ed25519 cert");

    // RSA-2048 from a fixed seed, in PKCS #8 and PKCS #1, and as an
    // id-RSASSA-PSS key restricted to SHA-256.
    let rsa = RsaPrivateKey::generate(2048, &SeededRng(std::cell::Cell::new(0x5eed_1234_abcd)))
        .expect("RSA key");
    let mut buf = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
    let len = rsa.to_pkcs8_der(&mut buf).expect("RSA PKCS#8");
    let rsa_pkcs8 = buf[..len].to_vec();
    let len = rsa.to_pkcs1_der(&mut buf).expect("RSA PKCS#1");
    let rsa_pkcs1 = buf[..len].to_vec();
    let len = rsa
        .to_pkcs8_der_with_algorithm(
            RsaKeyAlgorithm::RsassaPss(Some(browntls_crypto::hash::HashAlgorithm::Sha256)),
            &mut buf,
        )
        .expect("RSA-PSS PKCS#8");
    let rsa_pss = buf[..len].to_vec();
    let rsa_kp = rcgen::KeyPair::try_from(rsa_pkcs8.as_slice()).expect("rcgen RSA");
    let rsa_cert = end_entity_params(None, false)
        .signed_by(&rsa_kp, &issuer)
        .expect("RSA cert");

    // P-521 (SEC 1) and P-256 (SEC 1) from fixed scalars; Ed448 from a seed.
    let mut sec1 = [0u8; 256];
    let mut scalar = [0x42u8; 66];
    scalar[0] = 0; // below the group order
    let p521 = browntls_crypto::nist::p521::SecretKey::from_bytes(&scalar).expect("p521 scalar");
    let len = p521.to_sec1_der(&mut sec1).expect("p521 SEC 1");
    let p521_sec1 = sec1[..len].to_vec();
    let p256_secret = browntls_crypto::nist::p256::SecretKey::from_pkcs8_der(&p256.serialize_der())
        .expect("p256 from PKCS#8");
    let len = p256_secret.to_sec1_der(&mut sec1).expect("p256 SEC 1");
    let p256_sec1 = sec1[..len].to_vec();
    let ed448 = browntls_crypto::curve448::ed448::SigningKey::from_seed(&[0x17; 57]);
    let ed448_pkcs8 = ed448.to_pkcs8_der().to_vec();

    let other = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("other");

    let p256_chain = vec![der(&p256_cert)];
    let rsa_chain = vec![der(&rsa_cert)];
    let keys = vec![
        Key {
            name: "p256",
            der: pkcs8(&p256),
            chain: p256_chain.clone(),
            rustcrypto: true,
        },
        Key {
            name: "p384",
            der: pkcs8(&p384),
            chain: vec![der(&p384_cert), der(&int_cert)],
            rustcrypto: true,
        },
        Key {
            name: "ed25519",
            der: pkcs8(&ed25519),
            chain: vec![der(&ed25519_cert)],
            rustcrypto: true,
        },
        Key {
            name: "rsa",
            der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(rsa_pkcs8)),
            chain: rsa_chain.clone(),
            rustcrypto: false,
        },
        Key {
            name: "rsa-pkcs1",
            der: PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(rsa_pkcs1)),
            chain: rsa_chain,
            rustcrypto: false,
        },
        Key {
            name: "rsa-pss",
            der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(rsa_pss)),
            chain: Vec::new(),
            rustcrypto: false,
        },
        Key {
            name: "p521",
            der: PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(p521_sec1)),
            chain: Vec::new(),
            rustcrypto: true,
        },
        Key {
            name: "p256-sec1",
            der: PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(p256_sec1)),
            chain: p256_chain.clone(),
            rustcrypto: true,
        },
        Key {
            name: "ed448",
            der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ed448_pkcs8)),
            chain: Vec::new(),
            rustcrypto: false,
        },
        Key {
            name: "mismatched",
            der: pkcs8(&other),
            chain: p256_chain,
            rustcrypto: true,
        },
    ];
    assert_eq!(keys.len(), KEY_COUNT);

    Fixtures {
        ca: der(&ca_cert),
        other_ca: der(&other_ca),
        intermediate: der(&int_cert),
        crl_clean: crl(&issuer, &[0x7b, 4, 5, 6]),
        crl_revoking: crl(&issuer, P256_SERIAL),
        keys,
    }
}

/// The process's fixtures, generated on first use.
pub(crate) fn get() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(generate)
}

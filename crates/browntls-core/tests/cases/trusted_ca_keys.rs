// Shared cases, included by `tests/trusted_ca_keys.rs` (RustCrypto
// provider) and `tests/trusted_ca_keys_native.rs` (native provider): the
// `trusted_ca_keys` extension (RFC 6066 §6), its identifiers, and the
// resolver that follows it. Provider items are reached through the
// including target's `prov` module.

use std::sync::Arc;

use browntls_core::client::UnbufferedClientConnection;
use browntls_core::pki_types::{CertificateDer, SubjectPublicKeyInfoDer};
use browntls_core::{
    CertificateError, ClientConfig, ClientConnection, DistinguishedName, Error, RootCertStore,
    TrustedAuthority, version,
};
use common::hello_wire::*;
use common::*;

include!("trusted_ca_keys/vectors.rs");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn sha1_of(s: &str) -> [u8; 20] {
    hex(s).try_into().unwrap()
}

fn sha1(data: &[u8]) -> [u8; 20] {
    prov::sha1(data)
}

/// Each vector certificate with its identifiers.
fn vectors() -> [(
    CertificateDer<'static>,
    &'static str,
    &'static str,
    &'static str,
); 3] {
    [
        (
            CertificateDer::from(hex(RSA_CA)),
            RSA_CERT_SHA1,
            RSA_KEY_SHA1,
            RSA_SUBJECT,
        ),
        (
            CertificateDer::from(hex(P256_CA)),
            P256_CERT_SHA1,
            P256_KEY_SHA1,
            P256_SUBJECT,
        ),
        (
            CertificateDer::from(hex(ED25519_CA)),
            ED25519_CERT_SHA1,
            ED25519_KEY_SHA1,
            ED25519_SUBJECT,
        ),
    ]
}

#[test]
fn identifiers_from_certificates_match_independent_vectors() {
    for (cert, cert_sha1, key_sha1, subject) in vectors() {
        assert_eq!(
            TrustedAuthority::cert_sha1_hash(&cert, sha1),
            TrustedAuthority::CertSha1Hash(sha1_of(cert_sha1))
        );
        assert_eq!(
            TrustedAuthority::key_sha1_hash(&cert, sha1).unwrap(),
            TrustedAuthority::KeySha1Hash(sha1_of(key_sha1)),
            "{subject}"
        );
        assert_eq!(
            TrustedAuthority::x509_name(&cert).unwrap(),
            TrustedAuthority::X509Name(DistinguishedName::new(hex(subject)))
        );
    }
    // RFC 6066 §6: the RSA modulus is hashed without its leading zero.
    assert_ne!(
        TrustedAuthority::key_sha1_hash(&CertificateDer::from(hex(RSA_CA)), sha1).unwrap(),
        TrustedAuthority::KeySha1Hash(sha1_of(RSA_KEY_SHA1_WITH_ZERO))
    );
}

#[test]
fn identifiers_from_trust_anchors_and_spki_agree() {
    for (cert, _, key_sha1, subject) in vectors() {
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let anchor = &roots.roots[0];
        assert_eq!(
            TrustedAuthority::key_sha1_hash_of_anchor(anchor, sha1).unwrap(),
            TrustedAuthority::KeySha1Hash(sha1_of(key_sha1))
        );
        assert_eq!(
            TrustedAuthority::x509_name_of_anchor(anchor),
            TrustedAuthority::X509Name(DistinguishedName::new(hex(subject)))
        );
        let spki = browntls_core::pki_types::Cert::try_from(&cert)
            .unwrap()
            .subject_public_key_info();
        assert_eq!(
            TrustedAuthority::key_sha1_hash_of_spki(&spki, sha1).unwrap(),
            TrustedAuthority::KeySha1Hash(sha1_of(key_sha1))
        );
    }
}

#[test]
fn malformed_input_is_an_error() {
    let bad = Error::InvalidCertificate(CertificateError::BadEncoding);
    let mut cut = hex(P256_CA);
    cut.truncate(100);
    let cut = CertificateDer::from(cut);
    assert_eq!(
        TrustedAuthority::key_sha1_hash(&cut, sha1),
        Err(bad.clone())
    );
    assert_eq!(TrustedAuthority::x509_name(&cut), Err(bad.clone()));
    // A certificate is not parsed for its hash.
    assert!(matches!(
        TrustedAuthority::cert_sha1_hash(&cut, sha1),
        TrustedAuthority::CertSha1Hash(_)
    ));
    // An rsaEncryption key whose RSAPublicKey is not a SEQUENCE of two
    // INTEGERs, and an SPKI cut short.
    let rsa_alg = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut spki = vec![0x30, 21];
    spki.extend(rsa_alg);
    spki.extend([0x03, 0x04, 0x00, 0x02, 0x01, 0x05]);
    for spki in [spki.clone(), spki[..spki.len() - 1].to_vec()] {
        assert_eq!(
            TrustedAuthority::key_sha1_hash_of_spki(&SubjectPublicKeyInfoDer::from(spki), sha1),
            Err(bad.clone())
        );
    }
}

#[test]
fn matches_certificate_by_each_identifier() {
    let [(rsa, ..), (p256, ..), _] = vectors();
    for id in [
        TrustedAuthority::cert_sha1_hash(&rsa, sha1),
        TrustedAuthority::key_sha1_hash(&rsa, sha1).unwrap(),
        TrustedAuthority::x509_name(&rsa).unwrap(),
    ] {
        assert!(id.matches_certificate(&rsa, sha1), "{id:?}");
        assert!(!id.matches_certificate(&p256, sha1), "{id:?}");
    }
    assert!(!TrustedAuthority::PreAgreed.matches_certificate(&rsa, sha1));
    let cut = CertificateDer::from(hex(RSA_CA)[..50].to_vec());
    let name = TrustedAuthority::x509_name(&rsa).unwrap();
    assert!(!name.matches_certificate(&cut, sha1));
}

/// Identifiers that name `chain`'s CA, the key derived as a client does
/// from the roots it trusts. Not the name: the generated CAs of one key
/// type share their subject name, as two CAs may (RFC 6066 §6).
fn ids_for(chain: &Chain) -> Vec<TrustedAuthority> {
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    vec![
        TrustedAuthority::key_sha1_hash_of_anchor(&roots.roots[0], sha1).unwrap(),
        TrustedAuthority::cert_sha1_hash(&chain.ca, sha1),
    ]
}

/// A client that verifies with WebPKI against the CAs of `chains`.
fn client_trusting(
    chains: &[&Chain],
    versions: &[&'static browntls_core::SupportedProtocolVersion],
    list: Option<Vec<TrustedAuthority>>,
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    for chain in chains {
        roots.add(chain.ca.clone()).unwrap();
    }
    let verifier = browntls_core::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider(),
    )
    .build()
    .unwrap();
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.trusted_ca_keys = list;
    config
}

/// The `trusted_ca_keys` body of the hello at the start of `buf`.
fn trusted_ca_keys_ext(buf: &[u8], client: bool) -> Option<Vec<u8>> {
    hello_extensions(buf, client)
        .into_iter()
        .find(|(typ, _)| *typ == EXT_TRUSTED_CA_KEYS)
        .map(|(_, body)| body)
}

/// A TLS 1.3-only client sends no `trusted_ca_keys`: the extension does
/// not exist in TLS 1.3.
#[test]
fn a_tls13_only_client_does_not_send_the_list() {
    let chain = server_chain(KeyType::EcdsaP256);
    let config = client_trusting(&[&chain], &[&version::TLS13], Some(ids_for(&chain)));
    let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    assert_eq!(trusted_ca_keys_ext(&take_flight(&mut client), true), None);
}

/// A list that a server would refuse, or that cannot be encoded, fails
/// connection creation, on the buffered and the unbuffered API.
#[test]
fn an_unsendable_list_fails_connection_creation() {
    let chain = server_chain(KeyType::EcdsaP256);
    let name = |len: usize| TrustedAuthority::X509Name(DistinguishedName::new(vec![0x30; len]));
    let lists = [
        // RFC 6066 §6: DistinguishedName<1..2^16-1>.
        vec![name(0)],
        vec![name(0x1_0000)],
        // More entries than a server reads.
        vec![TrustedAuthority::PreAgreed; 1025],
        // 1000 entries of 3 + 100 bytes: longer than the extension can be.
        vec![name(100); 1000],
    ];
    for list in lists {
        for versions in [&[&version::TLS13][..], &versions_all()[..]] {
            let config = Arc::new(client_trusting(&[&chain], versions, Some(list.clone())));
            assert!(matches!(
                ClientConnection::new(config.clone(), server_name()),
                Err(Error::General(_))
            ));
            assert!(matches!(
                UnbufferedClientConnection::new(config, server_name()),
                Err(Error::General(_))
            ));
        }
    }
    // The limit itself is fine.
    let config = client_trusting(
        &[&chain],
        &[&version::TLS13],
        Some(vec![TrustedAuthority::PreAgreed; 1024]),
    );
    ClientConnection::new(Arc::new(config), server_name()).unwrap();
}

fn versions_all() -> Vec<&'static browntls_core::SupportedProtocolVersion> {
    vec![
        &version::TLS13,
        #[cfg(feature = "tls12")]
        &version::TLS12,
    ]
}

#[cfg(feature = "tls12")]
include!("trusted_ca_keys/tls12.rs");

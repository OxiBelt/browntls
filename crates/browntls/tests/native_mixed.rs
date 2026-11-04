//! Building a mixed provider: per-component fallback between the native
//! (`browntls-crypto`) provider and the RustCrypto provider.
//!
//! A [`CryptoProvider`] is plain data: every field is a list of static trait
//! objects, so an application can take the native provider and replace any
//! component with another implementation, or assemble a cipher suite from
//! parts of both. The examples here are the documented pattern:
//!
//! 1. [`mixed_provider`]: native cipher suites and key exchange with
//!    RustCrypto signature verification and private key loading.
//! 2. [`mixed_suite`]: a TLS 1.3 suite with the native AES-GCM record
//!    protection but RustCrypto's SHA-256 and HKDF.

#![cfg(all(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, OutboundChunks, OutboundPlainMessage,
};
use browntls::crypto::{CipherSuiteCommon, CryptoProvider, native, rustcrypto};
use browntls::{ContentType, NamedGroup, ProtocolVersion, SupportedCipherSuite, Tls13CipherSuite};
use browntls_pki::{PrivateKeyDer, PrivatePkcs8KeyDer, RawPublicKeyEntity};

/// Native record protection, hashing, key derivation, key exchange and
/// randomness; RustCrypto certificate / handshake signature verification and
/// private key loading.
fn mixed_provider() -> CryptoProvider {
    CryptoProvider {
        signature_verification_algorithms: rustcrypto::SUPPORTED_SIG_ALGS,
        key_provider: &rustcrypto::RustCrypto,
        // Key exchange groups can be mixed too: the native hybrid first, then
        // RustCrypto's X25519.
        kx_groups: vec![
            native::kx_group::X25519MLKEM768,
            rustcrypto::kx_group::X25519,
        ],
        ..native::default_provider()
    }
}

/// `TLS13_AES_128_GCM_SHA256` with native AES-GCM and RustCrypto SHA-256 /
/// HKDF. Suites are referenced as `&'static`, so a suite built at run time is
/// leaked once (or declared as a `static` from `native::{aead, hash, hkdf}`).
fn mixed_suite() -> SupportedCipherSuite {
    let rc = rustcrypto::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let suite: &'static Tls13CipherSuite = Box::leak(Box::new(Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: rc.common.suite,
            hash_provider: rc.common.hash_provider,
            confidentiality_limit: rc.common.confidentiality_limit,
        },
        hkdf_provider: rc.hkdf_provider,
        aead_alg: native::aead::TLS13_AES_128_GCM,
    }));
    SupportedCipherSuite::Tls13(suite)
}

/// The same suite assembled entirely from the native building blocks, as a
/// `static`.
static NATIVE_PARTS_SUITE: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: browntls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: native::hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: native::hkdf::HKDF_SHA256,
    aead_alg: native::aead::TLS13_CHACHA20_POLY1305,
};

#[test]
fn mixed_provider_combines_components() {
    let provider = mixed_provider();
    assert_eq!(provider.cipher_suites, native::DEFAULT_CIPHER_SUITES);
    assert_eq!(
        provider
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect::<Vec<_>>(),
        [NamedGroup::X25519MLKEM768, NamedGroup::X25519]
    );
    assert!(!provider.fips());

    // A native client and a RustCrypto server for the classical fallback
    // group agree, so the mixed list is coherent.
    let client = provider.kx_groups[0].start().unwrap();
    let (_, classical) = client.hybrid_component().unwrap();
    let server = provider.kx_groups[1].start_and_complete(classical).unwrap();
    assert_eq!(
        client
            .complete_hybrid_component(&server.pub_key)
            .unwrap()
            .secret_bytes(),
        server.secret.secret_bytes()
    );

    // Keys are loaded by RustCrypto and their signatures verified by
    // RustCrypto; the native signing path is not involved.
    let pkcs8 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .serialize_der();
    let key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pkcs8.clone(),
        )))
        .unwrap();
    let signer = key
        .choose_scheme(&[browntls::SignatureScheme::ECDSA_NISTP256_SHA256])
        .unwrap();
    let sig = signer.sign(b"mixed").unwrap();
    let spki = key.public_key().unwrap();
    let entity = RawPublicKeyEntity::try_from(&spki).unwrap();
    let (_, algs) = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(s, _)| *s == browntls::SignatureScheme::ECDSA_NISTP256_SHA256)
        .unwrap();
    assert!(
        algs.iter()
            .any(|alg| entity.verify_signature(*alg, b"mixed", &sig).is_ok())
    );

    // RSA keys are refused by this provider's key loader (RustCrypto signs
    // nothing with RSA); swapping `key_provider` back to native restores RSA.
    let rsa = {
        let key =
            browntls_crypto::rsa::RsaPrivateKey::generate(2048, &browntls_crypto::rand::OsRng)
                .unwrap();
        let mut der = vec![0u8; browntls_crypto::rsa::MAX_PKCS8_PRIVATE_KEY_DER_LEN];
        let len = key.to_pkcs8_der(&mut der).unwrap();
        der.truncate(len);
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))
    };
    assert!(
        provider
            .key_provider
            .load_private_key(rsa.clone_key())
            .is_err()
    );
    let with_native_keys = CryptoProvider {
        key_provider: native::KEY_PROVIDER,
        ..mixed_provider()
    };
    assert!(with_native_keys.key_provider.load_private_key(rsa).is_ok());
}

fn roundtrip(enc_suite: SupportedCipherSuite, dec_suite: SupportedCipherSuite) {
    let (enc_suite, dec_suite) = (enc_suite.tls13().unwrap(), dec_suite.tls13().unwrap());
    // Derive the traffic key and IV with each suite's own HKDF from the same
    // secret, as the key schedule would.
    let secret = [0x5au8; 32];
    let derive = |s: &Tls13CipherSuite| {
        let expander = s.hkdf_provider.extract_from_secret(None, &secret);
        let mut key = vec![0u8; s.aead_alg.key_len()];
        let mut iv = [0u8; 12];
        expander.expand_slice(&[b"key"], &mut key).unwrap();
        expander.expand_slice(&[b"iv"], &mut iv).unwrap();
        (AeadKey::new(&key), Iv::new(iv))
    };
    let (key, iv) = derive(enc_suite);
    let mut enc = enc_suite.aead_alg.encrypter(key, iv);
    let (key, iv) = derive(dec_suite);
    let mut dec = dec_suite.aead_alg.decrypter(key, iv);

    let msg = OutboundPlainMessage {
        typ: ContentType::ApplicationData,
        version: ProtocolVersion::TLSv1_3,
        payload: OutboundChunks::Single(b"per-component fallback"),
    };
    let mut wire = enc.encrypt(msg, 0).unwrap().encode();
    let inbound = InboundOpaqueMessage::new(
        ContentType::ApplicationData,
        ProtocolVersion::TLSv1_2,
        &mut wire[5..],
    );
    assert_eq!(
        dec.decrypt(inbound, 0).unwrap().payload,
        b"per-component fallback"
    );
}

#[test]
fn mixed_suite_interoperates_with_both_providers() {
    let mixed = mixed_suite();
    roundtrip(mixed, rustcrypto::cipher_suite::TLS13_AES_128_GCM_SHA256);
    roundtrip(rustcrypto::cipher_suite::TLS13_AES_128_GCM_SHA256, mixed);
    roundtrip(mixed, native::cipher_suite::TLS13_AES_128_GCM_SHA256);
    roundtrip(native::cipher_suite::TLS13_AES_128_GCM_SHA256, mixed);

    // A provider can carry the mixed suite alongside the native ones.
    let provider = CryptoProvider {
        cipher_suites: vec![mixed, native::cipher_suite::TLS13_AES_256_GCM_SHA384],
        ..mixed_provider()
    };
    assert_eq!(provider.cipher_suites.len(), 2);
}

#[test]
fn static_suite_from_native_parts() {
    let suite = SupportedCipherSuite::Tls13(&NATIVE_PARTS_SUITE);
    roundtrip(
        suite,
        rustcrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    );
    roundtrip(native::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256, suite);
}

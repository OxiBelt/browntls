//! RFC 9963 §3 in the signature verification functions, with each
//! provider's opt-in table: only the client `CertificateVerify` functions
//! accept the legacy RSASSA-PKCS1-v1_5 schemes, and only the exact
//! encoding of RFC 8017 §8.2 verifies. The signatures are made with the
//! `rsa` crate, so the cases are the same for both providers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use alloc::vec::Vec;

use browntls_pki::{SubjectPublicKeyInfoDer, alg_id};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::sha2::{Digest, Sha256, Sha384, Sha512};
use rsa::signature::{SignatureEncoding, Signer as _};

use super::*;
use SignatureScheme as S;

const LEGACY: [S; 3] = [
    S::RSA_PKCS1_SHA256_LEGACY,
    S::RSA_PKCS1_SHA384_LEGACY,
    S::RSA_PKCS1_SHA512_LEGACY,
];

/// A fresh 2048-bit key and its `rsaEncryption` `SubjectPublicKeyInfo`
/// (test data).
fn generate() -> (rsa::PrivateKey, SubjectPublicKeyInfoDer<'static>) {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let key = rsa::PrivateKey::new(&mut rng, 2048).unwrap();
    let public = key.to_public_key().to_pkcs1_der().unwrap();
    let mut contents = crate::x509::wrap_in_sequence(alg_id::RSA_ENCRYPTION.as_ref());
    contents.extend_from_slice(&crate::x509::wrap_in_bit_string(public.as_bytes()));
    let spki = SubjectPublicKeyInfoDer::from(crate::x509::wrap_in_sequence(&contents));
    (key, spki)
}

/// RSASSA-PKCS1-v1_5 with the hash of the legacy scheme `scheme`.
fn sign(key: &rsa::PrivateKey, scheme: S, message: &[u8]) -> Vec<u8> {
    let key = key.clone();
    match scheme {
        S::RSA_PKCS1_SHA256_LEGACY => rsa::pkcs1v15::SigningKey::<Sha256>::new(key)
            .sign(message)
            .to_vec(),
        S::RSA_PKCS1_SHA384_LEGACY => rsa::pkcs1v15::SigningKey::<Sha384>::new(key)
            .sign(message)
            .to_vec(),
        _ => rsa::pkcs1v15::SigningKey::<Sha512>::new(key)
            .sign(message)
            .to_vec(),
    }
}

/// A signature whose encoded message is `00 01 FF.. 00 || t`:
/// RSASSA-PKCS1-v1_5 when `t` is the DER `DigestInfo`, and a malformed
/// variant otherwise.
fn sign_raw(key: &rsa::PrivateKey, t: &[u8]) -> Vec<u8> {
    key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), t).unwrap()
}

fn tlv(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let body = parts.concat();
    [&[tag, u8::try_from(body.len()).unwrap()][..], &body].concat()
}

fn check(table: &WebPkiSupportedAlgorithms, default: &WebPkiSupportedAlgorithms) {
    let (key, spki) = generate();
    let unadvertised =
        Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme);
    let message = b"TLS 1.3, client CertificateVerify";
    let client = |scheme, signature: &[u8], message: &[u8]| {
        let dss = DigitallySignedStruct::new(scheme, signature.to_vec());
        verify_tls13_client_signature_with_raw_key(message, &spki, &dss, table)
    };

    for scheme in LEGACY {
        let signature = sign(&key, scheme, message);
        client(scheme, &signature, message).unwrap();
        let dss = DigitallySignedStruct::new(scheme, signature.clone());

        // Not for a server's signature and not in TLS 1.2, whatever the
        // table maps; and not without the opt-in table.
        assert_eq!(
            verify_tls13_signature_with_raw_key(message, &spki, &dss, table).unwrap_err(),
            unadvertised
        );
        assert_eq!(
            verify_tls12_signature_with_raw_key(message, &spki, &dss, table).unwrap_err(),
            unadvertised
        );
        let no_cert = CertificateDer::from_slice(&[]);
        assert_eq!(
            verify_tls13_signature(message, &no_cert, &dss, table).unwrap_err(),
            unadvertised
        );
        assert_eq!(
            verify_tls12_signature(message, &no_cert, &dss, table).unwrap_err(),
            unadvertised
        );
        // The client function gets as far as the (here unusable)
        // certificate.
        assert_ne!(
            verify_tls13_client_signature(message, &no_cert, &dss, table).unwrap_err(),
            unadvertised
        );
        assert!(verify_tls13_client_signature_with_raw_key(message, &spki, &dss, default).is_err());
        assert!(verify_tls13_client_signature(message, &no_cert, &dss, default).is_err());

        // The wire value decodes to the named scheme, which the table
        // maps; a constructed `Unknown` of the same code point is under
        // the same restrictions but maps to nothing.
        assert_eq!(S::from(u16::from(scheme)), scheme);
        let unknown = S::Unknown(scheme.into());
        assert!(client(unknown, &signature, message).is_err());
        let dss = DigitallySignedStruct::new(unknown, signature.clone());
        assert_eq!(
            verify_tls13_signature_with_raw_key(message, &spki, &dss, table).unwrap_err(),
            unadvertised
        );

        // Another message, another legacy scheme (the wrong digest), or
        // the same bytes claimed as RSASSA-PSS or as the TLS 1.2 scheme
        // of the hash (which TLS 1.3 never accepts).
        assert!(client(scheme, &signature, b"other").is_err());
        for other in LEGACY.into_iter().filter(|other| *other != scheme) {
            assert!(
                client(other, &signature, message).is_err(),
                "{scheme:?} as {other:?}"
            );
        }
        let [hash, _] = scheme.to_array();
        let pss = S::from(u16::from_be_bytes([0x08, hash]));
        let tls12 = S::from(u16::from_be_bytes([hash, 0x01]));
        assert!(matches!(
            (pss, tls12),
            (
                S::RSA_PSS_SHA256 | S::RSA_PSS_SHA384 | S::RSA_PSS_SHA512,
                S::RSA_PKCS1_SHA256 | S::RSA_PKCS1_SHA384 | S::RSA_PKCS1_SHA512
            )
        ));
        assert!(client(pss, &signature, message).is_err());
        assert_eq!(
            client(tls12, &signature, message).unwrap_err(),
            unadvertised
        );
        // In TLS 1.2 the same bytes are a valid `rsa_pkcs1_*` signature.
        let dss = DigitallySignedStruct::new(tls12, signature.clone());
        verify_tls12_signature_with_raw_key(message, &spki, &dss, table).unwrap();
    }

    // An RSASSA-PSS signature under a legacy code point does not verify,
    // and the client functions still verify the TLS 1.3 schemes.
    let pss = rsa::pss::SigningKey::<Sha256>::new(key.clone())
        .sign(message)
        .to_vec();
    client(S::RSA_PSS_SHA256, &pss, message).unwrap();
    assert!(client(S::RSA_PKCS1_SHA256_LEGACY, &pss, message).is_err());

    // RFC 9963 §3: the DigestInfo must be the DER one, NULL parameters
    // included. `digest_info` is that encoding for SHA-256.
    let digest = Sha256::digest(message);
    let oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    let algorithm = tlv(0x30, &[&tlv(0x06, &[&oid]), &[0x05, 0x00]]);
    let digest_info = tlv(0x30, &[&algorithm, &tlv(0x04, &[&digest])]);
    let verify = |t: &[u8]| client(S::RSA_PKCS1_SHA256_LEGACY, &sign_raw(&key, t), message);
    verify(&digest_info).unwrap();

    let without_null = tlv(
        0x30,
        &[&tlv(0x30, &[&tlv(0x06, &[&oid])]), &tlv(0x04, &[&digest])],
    );
    // A long-form length where DER requires the short form.
    let mut ber_length = digest_info.clone();
    ber_length.splice(1..2, [0x81, digest_info[1]]);
    // A byte after the DigestInfo, and one more in the OCTET STRING.
    let trailing = [&digest_info[..], &[0]].concat();
    let long_digest = tlv(0x30, &[&algorithm, &tlv(0x04, &[&digest, &[0]])]);
    // SHA-384's identifier around a SHA-256 digest.
    let mut wrong_oid = digest_info.clone();
    assert_eq!(wrong_oid[14], 0x01);
    wrong_oid[14] = 0x02;
    // The digest of another message in a well-formed DigestInfo.
    let other_digest = tlv(
        0x30,
        &[&algorithm, &tlv(0x04, &[&Sha256::digest(b"other")])],
    );
    for (name, t) in [
        ("no NULL parameters", without_null),
        ("BER length", ber_length),
        ("bare digest", digest.to_vec()),
        ("trailing byte", trailing),
        ("long digest", long_digest),
        ("wrong hash identifier", wrong_oid),
        ("wrong digest", other_digest),
    ] {
        assert!(verify(&t).is_err(), "{name}");
    }

    // A changed signature, and one of another length.
    let signature = sign(&key, S::RSA_PKCS1_SHA256_LEGACY, message);
    for at in [0, 128, 255] {
        let mut changed = signature.clone();
        changed[at] ^= 1;
        assert!(client(S::RSA_PKCS1_SHA256_LEGACY, &changed, message).is_err());
    }
    for bad in [&signature[1..], &[&signature[..], &[0]].concat(), &[]] {
        assert!(client(S::RSA_PKCS1_SHA256_LEGACY, bad, message).is_err());
    }

    // An `id-RSASSA-PSS` key never verifies a legacy signature.
    let (_, key_bits) = crate::x509::split_spki(spki.as_ref()).unwrap();
    let mut contents = crate::x509::wrap_in_sequence(alg_id::RSASSA_PSS.as_ref());
    contents.extend_from_slice(&crate::x509::wrap_in_bit_string(key_bits));
    let pss_spki = SubjectPublicKeyInfoDer::from(crate::x509::wrap_in_sequence(&contents));
    let dss = DigitallySignedStruct::new(S::RSA_PKCS1_SHA256_LEGACY, signature);
    assert!(verify_tls13_client_signature_with_raw_key(message, &pss_spki, &dss, table).is_err());
}

#[cfg(feature = "native")]
#[test]
fn native() {
    use crate::crypto::native::{SUPPORTED_SIG_ALGS, SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY};
    check(
        &SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY,
        &SUPPORTED_SIG_ALGS,
    );
}

#[cfg(feature = "rustcrypto")]
#[test]
fn rustcrypto() {
    use crate::crypto::rustcrypto::{SUPPORTED_SIG_ALGS, SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY};
    check(
        &SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY,
        &SUPPORTED_SIG_ALGS,
    );
}

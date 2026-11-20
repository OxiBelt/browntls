//! Delegated-credential operations of the `tls_auth` target: decoding,
//! encoding, issuance, native key generation and validity.

use browntls_core::SignatureScheme;
use browntls_core::crypto::native::delegated_credential::generate;
use browntls_core::delegated_credential::{
    Credential, DelegatedCredential, DelegatedCredentialKey, valid_time_until,
};
use browntls_core::pki_types::{CertificateDer, SubjectPublicKeyInfoDer};

use super::{
    Cert, MAX_SPKI_LEN, credential_bytes, credential_scheme_ok, expected_signed_message, fixture,
    other_side, parse_dc, pick_cert, pick_cert_schemes, pick_scheme, pick_side, pick_valid_time,
    signature_verifies, unix,
};
use crate::input::{Input, put_field};

pub(super) fn decode(input: &mut Input) {
    let bytes = input.field();
    match (parse_dc(bytes), DelegatedCredential::from_bytes(bytes)) {
        (Some((valid_time, scheme, spki, algorithm, signature)), Ok(dc)) => {
            assert_eq!(dc.credential.valid_time, valid_time);
            assert_eq!(u16::from(dc.credential.dc_cert_verify_algorithm), scheme);
            assert_eq!(dc.credential.public_key.as_ref(), &spki[..]);
            assert_eq!(u16::from(dc.algorithm), algorithm);
            assert_eq!(dc.signature, signature);
            assert_eq!(dc.to_bytes(), bytes, "re-encoding differs");
        }
        (None, Err(_)) => {}
        (expected, got) => panic!("decoding {bytes:?}: {expected:?} vs {got:?}"),
    }
}

/// `n` bytes: the fuzzed `prefix` repeated.
fn stretch(prefix: &[u8], n: usize) -> Vec<u8> {
    if prefix.is_empty() {
        vec![0x30; n]
    } else {
        prefix.iter().copied().cycle().take(n).collect()
    }
}

pub(super) fn encode(input: &mut Input) {
    let valid_time = input.u32();
    let scheme = pick_scheme(input);
    let spki = if input.choose(4) == 0 {
        stretch(input.short_field(), MAX_SPKI_LEN - 1 + input.choose(3))
    } else {
        input.short_field().to_vec()
    };
    let algorithm = pick_scheme(input);
    let signature = input.field().to_vec();
    let dc = DelegatedCredential {
        credential: Credential {
            valid_time,
            dc_cert_verify_algorithm: scheme,
            public_key: SubjectPublicKeyInfoDer::from(spki.clone()),
        },
        algorithm,
        signature: signature.clone(),
    };
    let bytes = dc.to_bytes();
    let mut expected = credential_bytes(&dc.credential);
    expected.extend_from_slice(&u16::from(algorithm).to_be_bytes());
    put_field(&mut expected, &signature);
    assert_eq!(bytes, expected);
    let decodable = !spki.is_empty() && spki.len() <= MAX_SPKI_LEN && !signature.is_empty();
    match DelegatedCredential::from_bytes(&bytes) {
        Ok(again) => {
            assert!(decodable);
            assert_eq!(again, dc);
        }
        Err(_) => assert!(!decodable),
    }
}

pub(super) fn issue(input: &mut Input) {
    let fixture = fixture();
    let side = pick_side(input);
    let (cert, end_entity) = pick_cert(input);
    let cert_schemes = pick_cert_schemes(input);
    let valid_time = pick_valid_time(input);
    let dc_key = &fixture.dc_keys[input.choose(fixture.dc_keys.len())];
    let scheme = if input.choose(4) == 0 {
        pick_scheme(input)
    } else {
        dc_key.scheme
    };
    let spki = match input.choose(8) {
        0 => input.short_field().to_vec(),
        1 => stretch(b"\x30", MAX_SPKI_LEN + input.choose(2)),
        _ => dc_key.spki.as_ref().to_vec(),
    };
    let tamper = input.choose(5);
    let credential = Credential {
        valid_time,
        dc_cert_verify_algorithm: scheme,
        public_key: SubjectPublicKeyInfoDer::from(spki.clone()),
    };
    let cert_key = match cert {
        Cert::Plain => &fixture.plain_key,
        _ => &fixture.delegation_key,
    };
    let signer_ok = cert_schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256);
    let expected = cert == Cert::Delegation
        && credential_scheme_ok(scheme)
        && !spki.is_empty()
        && spki.len() <= MAX_SPKI_LEN
        && signer_ok;
    let result = DelegatedCredential::issue(
        side,
        &end_entity,
        &**cert_key,
        &cert_schemes,
        credential.clone(),
    );
    let mut dc = match result {
        Ok(dc) => {
            assert!(expected, "issued: {cert:?} {scheme:?} {cert_schemes:?}");
            dc
        }
        Err(e) => {
            assert!(!expected, "refused: {e:?}");
            return;
        }
    };
    assert_eq!(dc.credential, credential);
    assert_eq!(dc.algorithm, SignatureScheme::ECDSA_NISTP256_SHA256);
    assert_eq!(
        DelegatedCredential::signed_message(side, &end_entity, &dc.credential, dc.algorithm),
        expected_signed_message(side, end_entity.as_ref(), &dc.credential, dc.algorithm)
    );
    assert!(
        signature_verifies(side, &end_entity, &dc),
        "issued signature"
    );
    assert_eq!(
        DelegatedCredential::from_bytes(&dc.to_bytes()),
        Ok(dc.clone())
    );
    let expiry = dc.expiry(&end_entity).expect("expiry");
    assert_eq!(expiry.as_secs(), fixture.not_before + u64::from(valid_time));

    // A credential key matching the credential.
    let matching = scheme == dc_key.scheme && spki == dc_key.spki.as_ref();
    match DelegatedCredentialKey::new(&end_entity, dc.clone(), dc_key.key.clone()) {
        Ok(key) => {
            assert!(matching, "a mismatched credential key accepted");
            assert_eq!(key.credential(), &dc);
            assert_eq!(key.expiry(), expiry);
            assert_eq!(
                key.key().public_key().map(|k| k.as_ref().to_vec()),
                Some(dc_key.spki.as_ref().to_vec())
            );
            let _ = format!("{key:?}");
        }
        Err(_) => assert!(!matching, "a matching credential key refused"),
    }

    // Any change breaks the signature.
    let signer_side = match tamper {
        0 => {
            let at = usize::from(input.u16()) % dc.signature.len();
            dc.signature[at] ^= 1 << (input.byte() % 8);
            side
        }
        1 => {
            dc.credential.valid_time ^= 1 << (input.byte() % 32);
            side
        }
        2 => other_side(side),
        3 => {
            dc.credential.dc_cert_verify_algorithm = if scheme == SignatureScheme::ED25519 {
                SignatureScheme::ECDSA_NISTP256_SHA256
            } else {
                SignatureScheme::ED25519
            };
            side
        }
        _ => return,
    };
    assert!(
        !signature_verifies(signer_side, &end_entity, &dc),
        "a tampered credential verifies ({tamper})"
    );
}

pub(super) fn native_generate(input: &mut Input) {
    let fixture = fixture();
    let side = pick_side(input);
    let (cert, end_entity) = pick_cert(input);
    let cert_schemes = pick_cert_schemes(input);
    let scheme = pick_scheme(input);
    let valid_time = pick_valid_time(input);
    let cert_key = match cert {
        Cert::Plain => &fixture.plain_key,
        _ => &fixture.delegation_key,
    };
    let generatable = matches!(
        scheme,
        SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512
            | SignatureScheme::ED25519
            | SignatureScheme::ED448
    );
    let expected = cert == Cert::Delegation
        && generatable
        && cert_schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256);
    let issued = match generate(
        side,
        &end_entity,
        &**cert_key,
        &cert_schemes,
        scheme,
        valid_time,
    ) {
        Ok(issued) => {
            assert!(expected, "generated: {cert:?} {scheme:?} {cert_schemes:?}");
            issued
        }
        Err(e) => {
            assert!(!expected, "refused: {e:?}");
            return;
        }
    };
    let dc = &issued.credential;
    assert_eq!(dc.credential.valid_time, valid_time);
    assert_eq!(dc.credential.dc_cert_verify_algorithm, scheme);
    let spki = issued.signing_key.public_key().expect("public key");
    assert_eq!(dc.credential.public_key.as_ref(), spki.as_ref());
    // The private key as stored loads to the same key.
    let reloaded = fixture
        .provider
        .key_provider
        .load_private_key(issued.private_key.clone_key())
        .expect("the generated key loads");
    assert_eq!(
        reloaded.public_key().map(|k| k.as_ref().to_vec()),
        Some(spki.as_ref().to_vec())
    );
    assert!(reloaded.choose_scheme(&[scheme]).is_some());
    assert!(signature_verifies(side, &end_entity, dc));
    let key = DelegatedCredentialKey::new(&end_entity, dc.clone(), issued.signing_key.clone())
        .expect("a generated credential pairs with its key");
    assert_eq!(
        key.expiry().as_secs(),
        fixture.not_before + u64::from(valid_time)
    );
    let _ = format!("{issued:?}");
}

pub(super) fn validity(input: &mut Input) {
    let fixture = fixture();
    let (cert, end_entity) = pick_cert(input);
    let nb = fixture.not_before;
    let at = match input.choose(4) {
        0 => nb.wrapping_add(u64::from(input.byte())).wrapping_sub(128),
        1 => nb + u64::from(u32::MAX) + u64::from(input.byte()) - 128,
        _ => input.u64() >> 16,
    };
    let result = valid_time_until(&end_entity, unix(at));
    match cert {
        Cert::Garbage => assert!(result.is_err() || parses_as_certificate(&end_entity)),
        _ => {
            let expected = at
                .checked_sub(nb)
                .filter(|d| *d > 0)
                .and_then(|d| u32::try_from(d).ok());
            assert_eq!(result.ok(), expected, "valid_time_until({at})");
        }
    }
    let dc = DelegatedCredential {
        credential: Credential {
            valid_time: input.u32(),
            dc_cert_verify_algorithm: SignatureScheme::ED25519,
            public_key: SubjectPublicKeyInfoDer::from(vec![0x30]),
        },
        algorithm: SignatureScheme::ECDSA_NISTP256_SHA256,
        signature: vec![1],
    };
    match (cert, dc.expiry(&end_entity)) {
        (Cert::Garbage, result) => {
            assert!(result.is_err() || parses_as_certificate(&end_entity));
        }
        (_, result) => assert_eq!(
            result.map(|t| t.as_secs()).ok(),
            Some(nb + u64::from(dc.credential.valid_time))
        ),
    }
}

/// Whether fuzzed bytes happen to be a certificate.
fn parses_as_certificate(der: &CertificateDer<'_>) -> bool {
    browntls_core::pki_types::EndEntityCert::try_from(der).is_ok()
}

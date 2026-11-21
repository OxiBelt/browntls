use super::*;

#[test]
fn key_length_bounds() {
    assert!(ExternalPsk::new(b"id".to_vec(), alloc::vec![0; 15], HashAlgorithm::SHA256).is_err());
    assert!(ExternalPsk::new(b"id".to_vec(), alloc::vec![0; 16], HashAlgorithm::SHA256).is_ok());
    assert!(ExternalPsk::new(Vec::new(), alloc::vec![0; 16], HashAlgorithm::SHA256).is_err());
    assert!(ExternalPsk::new(b"id".to_vec(), alloc::vec![0; 16], HashAlgorithm::SHA1).is_err());
    assert!(ExternalPsk::new(b"id".to_vec(), alloc::vec![0; 1025], HashAlgorithm::SHA384).is_err());
}

#[test]
fn key_generation_bounds() {
    let psk =
        || ExternalPsk::new(b"id".to_vec(), alloc::vec![0x42; 32], HashAlgorithm::SHA256).unwrap();
    assert_eq!(psk().key_generation(), None);
    assert!(psk().with_key_generation(Vec::new()).is_err());
    assert!(
        psk()
            .with_key_generation(alloc::vec![0; ExternalPsk::MAX_KEY_GENERATION_LEN + 1])
            .is_err()
    );
    let generation = alloc::vec![0x5a; ExternalPsk::MAX_KEY_GENERATION_LEN];
    assert_eq!(
        psk()
            .with_key_generation(generation.clone())
            .unwrap()
            .key_generation(),
        Some(generation.as_slice())
    );
}

#[test]
fn ticket_binding_covers_key_generation_and_ticket_secret() {
    fn key(byte: u8, generation: Option<&[u8]>) -> ExternalPsk {
        let psk = ExternalPsk::new(
            b"identity".to_vec(),
            alloc::vec![byte; 32],
            HashAlgorithm::SHA256,
        )
        .unwrap();
        match generation {
            Some(generation) => psk.with_key_generation(generation.to_vec()).unwrap(),
            None => psk,
        }
    }

    #[cfg(feature = "native")]
    let suites = crate::crypto::native::default_provider().cipher_suites;
    #[cfg(all(not(feature = "native"), feature = "rustcrypto"))]
    let suites = crate::crypto::rustcrypto::default_provider().cipher_suites;

    let secret = [0x11; 32];
    let original = key(0x42, None);
    let binding = ExternalPskBinding::of(&original, &suites, &secret).unwrap();
    assert_eq!(binding.key_tag.len(), 32);
    assert!(binding.matches(&key(0x42, None), &suites, &secret));
    assert!(!binding.matches(&key(0x43, None), &suites, &secret));
    assert!(!binding.matches(&key(0x42, Some(b"one")), &suites, &secret));
    assert!(!binding.matches(&key(0x42, None), &suites, &[0x12; 32]));

    #[cfg(feature = "rustcrypto")]
    {
        use ::hmac::{Hmac, KeyInit, Mac};
        use sha2::Digest;

        let hmac = |key: &[u8], parts: &[&[u8]]| {
            let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).unwrap();
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().to_vec()
        };
        let context = sha2::Sha256::digest([&[0, 32][..], &secret, &[0], &[0, 0]].concat());
        let prk = hmac(&[0; 32], &[&[0x42; 32]]);
        let mut info = Vec::from(&[0, 32, 18][..]);
        info.extend_from_slice(b"tls13 ext psk bind");
        info.push(32);
        info.extend_from_slice(&context);
        assert_eq!(binding.key_tag, hmac(&prk, &[&info, &[1]]));
    }

    #[cfg(all(feature = "native", feature = "rustcrypto"))]
    {
        let rustcrypto = crate::crypto::rustcrypto::default_provider().cipher_suites;
        assert_eq!(
            binding.key_tag,
            ExternalPskBinding::of(&original, &rustcrypto, &secret)
                .unwrap()
                .key_tag
        );
    }

    let generated = key(0x42, Some(b"one"));
    let binding = ExternalPskBinding::of(&generated, &suites, &secret).unwrap();
    assert!(binding.matches(&key(0x42, Some(b"one")), &suites, &secret));
    assert!(!binding.matches(&key(0x42, Some(b"two")), &suites, &secret));
    assert!(!binding.matches(&key(0x43, Some(b"one")), &suites, &secret));

    let sha384 = ExternalPsk::new(
        b"identity-384".to_vec(),
        alloc::vec![0x42; 48],
        HashAlgorithm::SHA384,
    )
    .unwrap();
    assert_eq!(
        ExternalPskBinding::of(&sha384, &suites, &[0x22; 48])
            .unwrap()
            .key_tag
            .len(),
        48
    );
}

#[test]
fn imported_identity_round_trip() {
    let id = ImportedIdentity {
        external_identity: b"client-1".to_vec(),
        context: b"ctx".to_vec(),
        target_protocol: ProtocolVersion::TLSv1_3,
        target_kdf: ImportedIdentity::HKDF_SHA384,
    };
    let enc = id.encode();
    assert_eq!(
        enc,
        [
            &[0, 8][..],
            b"client-1",
            &[0, 3],
            b"ctx",
            &[0x03, 0x04, 0x00, 0x02]
        ]
        .concat()
    );
    assert_eq!(ImportedIdentity::decode(&enc), Some(id));
    // Trailing data, truncation and an empty external identity are refused.
    assert_eq!(
        ImportedIdentity::decode(&[enc.as_slice(), &[0]].concat()),
        None
    );
    assert_eq!(ImportedIdentity::decode(&enc[..enc.len() - 1]), None);
    assert_eq!(ImportedIdentity::decode(&[0, 0, 0, 0, 3, 4, 0, 1]), None);
}

#[test]
fn imported_identities_are_bound_to_tls_or_dtls_target_protocol() {
    #[cfg(feature = "native")]
    let suites = crate::crypto::native::default_provider().cipher_suites;
    #[cfg(all(not(feature = "native"), feature = "rustcrypto"))]
    let suites = crate::crypto::rustcrypto::default_provider().cipher_suites;

    let psk = Arc::new(
        ExternalPsk::new(
            b"external".to_vec(),
            alloc::vec![0x42; 32],
            HashAlgorithm::SHA256,
        )
        .unwrap()
        .imported(b"context".to_vec())
        .unwrap(),
    );
    let resolver = alloc::vec![psk];
    for (protocol, target) in [
        (Protocol::Tls13, ProtocolVersion::TLSv1_3),
        (Protocol::Dtls13, ProtocolVersion::DTLSv1_3),
    ] {
        let identity = ImportedIdentity {
            external_identity: b"external".to_vec(),
            context: b"context".to_vec(),
            target_protocol: target,
            target_kdf: ImportedIdentity::HKDF_SHA256,
        }
        .encode();
        let candidates = external_psk_candidates(
            &resolver,
            core::iter::once((identity.as_slice(), 32)),
            None,
            None,
            protocol,
        );
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].secret(&suites).is_some());

        let wrong_protocol = match protocol {
            Protocol::Tls13 => Protocol::Dtls13,
            Protocol::Dtls13 => Protocol::Tls13,
        };
        assert!(
            external_psk_candidates(
                &resolver,
                core::iter::once((identity.as_slice(), 32)),
                None,
                None,
                wrong_protocol,
            )
            .is_empty()
        );
    }
}

/// RFC 9258 `ipskx`, recomputed with the RustCrypto HMAC directly:
/// `epskx = HMAC(0^HashLen, epsk)`, then one HKDF-Expand block of
/// `HkdfLabel(L, "tls13 derived psk", Hash(ImportedIdentity))`. No
/// published test vectors exist for RFC 9258; this checks the
/// construction against an independent HMAC and both providers against
/// each other.
#[cfg(feature = "rustcrypto")]
#[test]
fn imported_psk_derivation() {
    use ::hmac::{Hmac, KeyInit, Mac};
    use sha2::Digest;

    fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).unwrap();
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }

    let epsk = [0x5au8; 32];
    for (target_kdf, target_len) in [
        (ImportedIdentity::HKDF_SHA256, 32usize),
        (ImportedIdentity::HKDF_SHA384, 48),
    ] {
        let identity = ImportedIdentity {
            external_identity: b"external".to_vec(),
            context: b"context".to_vec(),
            target_protocol: ProtocolVersion::TLSv1_3,
            target_kdf,
        }
        .encode();

        // The EPSK's hash is SHA-256 here, whatever the target.
        let epskx = hmac_sha256(&[0u8; 32], &[&epsk]);
        let identity_hash = sha2::Sha256::digest(&identity);
        let label = b"tls13 derived psk";
        let mut info = Vec::new();
        info.extend_from_slice(&(target_len as u16).to_be_bytes());
        info.push(label.len() as u8);
        info.extend_from_slice(label);
        info.push(identity_hash.len() as u8);
        info.extend_from_slice(&identity_hash);
        let mut expected = hmac_sha256(&epskx, &[&info, &[1]]);
        expected.extend(hmac_sha256(&epskx, &[&expected, &info, &[2]]));
        expected.truncate(target_len);

        let rustcrypto = crate::crypto::rustcrypto::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap();
        assert_eq!(
            derive_imported_psk(rustcrypto, &epsk, &identity, Protocol::Tls13, target_len,),
            expected
        );
        #[cfg(feature = "native")]
        {
            let native = crate::crypto::native::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
                .tls13()
                .unwrap();
            assert_eq!(
                derive_imported_psk(native, &epsk, &identity, Protocol::Tls13, target_len,),
                expected
            );
        }
    }
}

/// Checks the DTLS importer against an independent HMAC/HKDF expansion
/// for both supported hashes. RFC 9258 derives the identity hash and
/// HKDF-Extract with the external PSK's hash, and uses `dtls13` in the
/// HkdfLabel when the target protocol is DTLS 1.3.
#[cfg(feature = "rustcrypto")]
#[test]
fn dtls_imported_psk_sha256_and_sha384_expected_values() {
    use ::hmac::{Hmac, KeyInit, Mac};
    use sha2::Digest;

    fn expand_sha256(epsk: &[u8], identity: &[u8], target_len: usize) -> Vec<u8> {
        let mut extract = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&[0; 32]).unwrap();
        extract.update(epsk);
        let prk = extract.finalize().into_bytes();
        let identity_hash = sha2::Sha256::digest(identity);
        let label = b"dtls13derived psk";
        let mut info = Vec::new();
        info.extend_from_slice(&(target_len as u16).to_be_bytes());
        info.push(label.len() as u8);
        info.extend_from_slice(label);
        info.push(identity_hash.len() as u8);
        info.extend_from_slice(&identity_hash);
        let mut expand = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&prk).unwrap();
        expand.update(&info);
        expand.update(&[1]);
        expand.finalize().into_bytes()[..target_len].to_vec()
    }

    fn expand_sha384(epsk: &[u8], identity: &[u8], target_len: usize) -> Vec<u8> {
        let mut extract = <Hmac<sha2::Sha384> as KeyInit>::new_from_slice(&[0; 48]).unwrap();
        extract.update(epsk);
        let prk = extract.finalize().into_bytes();
        let identity_hash = sha2::Sha384::digest(identity);
        let label = b"dtls13derived psk";
        let mut info = Vec::new();
        info.extend_from_slice(&(target_len as u16).to_be_bytes());
        info.push(label.len() as u8);
        info.extend_from_slice(label);
        info.push(identity_hash.len() as u8);
        info.extend_from_slice(&identity_hash);
        let mut expand = <Hmac<sha2::Sha384> as KeyInit>::new_from_slice(&prk).unwrap();
        expand.update(&info);
        expand.update(&[1]);
        expand.finalize().into_bytes()[..target_len].to_vec()
    }

    let identity = ImportedIdentity {
        external_identity: b"external dtls".to_vec(),
        context: b"dtls importer context".to_vec(),
        target_protocol: ProtocolVersion::DTLSv1_3,
        target_kdf: ImportedIdentity::HKDF_SHA256,
    }
    .encode();
    let epsk256 = [0x37; 32];
    let suite256 = crate::crypto::rustcrypto::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let expected256 = expand_sha256(&epsk256, &identity, 32);
    assert_eq!(
        derive_imported_psk(suite256, &epsk256, &identity, Protocol::Dtls13, 32),
        expected256
    );

    let identity384 = ImportedIdentity {
        target_kdf: ImportedIdentity::HKDF_SHA384,
        ..ImportedIdentity::decode(&identity).unwrap()
    }
    .encode();
    let epsk384 = [0x93; 48];
    let suite384 = crate::crypto::rustcrypto::cipher_suite::TLS13_AES_256_GCM_SHA384
        .tls13()
        .unwrap();
    let expected384 = expand_sha384(&epsk384, &identity384, 48);
    assert_eq!(
        derive_imported_psk(suite384, &epsk384, &identity384, Protocol::Dtls13, 48),
        expected384
    );

    #[cfg(feature = "native")]
    {
        use crate::crypto::native::cipher_suite::{
            TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
        };

        assert_eq!(
            derive_imported_psk(
                TLS13_AES_128_GCM_SHA256.tls13().unwrap(),
                &epsk256,
                &identity,
                Protocol::Dtls13,
                32,
            ),
            expected256
        );
        assert_eq!(
            derive_imported_psk(
                TLS13_AES_256_GCM_SHA384.tls13().unwrap(),
                &epsk384,
                &identity384,
                Protocol::Dtls13,
                48,
            ),
            expected384
        );
    }
}

#[test]
fn imported_identity_length_bound() {
    let psk = ExternalPsk::new(
        alloc::vec![1; 60000],
        alloc::vec![0; 16],
        HashAlgorithm::SHA256,
    )
    .unwrap();
    assert!(psk.imported(alloc::vec![0; 5528]).is_err());
    let psk = ExternalPsk::new(
        alloc::vec![1; 60000],
        alloc::vec![0; 16],
        HashAlgorithm::SHA256,
    )
    .unwrap();
    assert!(psk.imported(alloc::vec![0; 5527]).is_ok());
}

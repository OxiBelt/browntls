use alloc::vec;
use alloc::vec::Vec;

use super::super::config::{
    EchConfigEntry, EchConfigExtension, encode_config_list, read_config_list,
};
use super::super::pem::{EchPem, EchPemError, NATIVE_PKCS8_CODEC};
use super::super::{EchConfig, EchServerConfig, EchServerKey};
use crate::crypto::hpke::{HpkeAead, HpkeKem};
use crate::crypto::native::hpke::ALL_SUPPORTED_SUITES;
use crate::msgs::base::PayloadU16;

fn key(id: u8) -> EchServerKey {
    EchServerKey::generate(id, "public.example", 32, ALL_SUPPORTED_SUITES).unwrap()
}

fn key_pem(key: &EchServerKey, list: &[u8]) -> EchPem {
    EchPem::from_server_key(key, list, &NATIVE_PKCS8_CODEC).unwrap()
}

#[test]
fn client_selection_and_decryption_use_supported_entry_order() {
    let key = key(1);
    let configured = encode_config_list([key.ech_config()].into_iter());
    let real = read_config_list(&configured).unwrap().remove(0);
    let mut first = real.contents.clone().unwrap();
    first.key_config.config_id = 2;
    first.key_config.cipher_suites.reverse();
    let preferred_suite = first.key_config.cipher_suites[0];

    let mut wrong_kem = first.clone();
    wrong_kem.key_config.kem_id = HpkeKem::DHKEM_P256_HKDF_SHA256;
    let mut wrong_public_key = first.clone();
    wrong_public_key.key_config.public_key.0[0] ^= 1;
    let mut invalid_name = first.clone();
    invalid_name.public_name = b"192.0.2.1".to_vec();
    let mut mandatory = first.clone();
    mandatory.extensions.push(EchConfigExtension {
        typ: 0x8000,
        data: PayloadU16::new(vec![3]),
    });
    let mut unsupported = first.clone();
    unsupported.key_config.cipher_suites.truncate(1);
    unsupported.key_config.cipher_suites[0].aead_id = HpkeAead::EXPORT_ONLY;

    let skipped = [
        wrong_kem,
        wrong_public_key,
        invalid_name,
        mandatory,
        unsupported,
    ]
    .map(EchConfigEntry::from_contents);
    let first = EchConfigEntry::from_contents(first);
    let opaque = [0xfe, 0x0c, 0, 0];
    let decrypt_list = encode_config_list(
        [opaque.as_slice()]
            .into_iter()
            .chain(skipped.iter().map(|entry| entry.encoded.as_slice()))
            .chain([first.encoded.as_slice(), &real.encoded]),
    );
    let public_list = encode_config_list(
        [opaque.as_slice()]
            .into_iter()
            .chain(skipped[2..].iter().map(|entry| entry.encoded.as_slice()))
            .chain([first.encoded.as_slice(), &real.encoded]),
    );
    let public = EchPem::from_config_list(&public_list).unwrap();
    let config = EchConfig::from_pem(&public, ALL_SUPPORTED_SUITES).unwrap();
    assert_eq!(config.config_id(), 2);
    assert_eq!(config.suite().sym, preferred_suite);
    assert!(matches!(
        EchConfig::from_pem(&public, &[]),
        Err(EchPemError::Tls(_))
    ));

    let config = EchServerConfig::from_pems(
        &[key_pem(&key, &decrypt_list)],
        &[public],
        ALL_SUPPORTED_SUITES,
    )
    .unwrap();
    assert_eq!(config.ech_config_list(), public_list);
    let installed: Vec<_> = config.keys.iter().map(EchServerKey::ech_config).collect();
    assert_eq!(installed, [first.encoded.as_slice(), &real.encoded]);
}

#[test]
fn every_decryption_bundle_requires_a_usable_private_key() {
    let key = key(1);
    let list = encode_config_list([key.ech_config()].into_iter());
    let retry = &[EchPem::from_config_list(&list).unwrap()];
    assert_eq!(
        EchServerConfig::from_pems(&[], retry, ALL_SUPPORTED_SUITES).unwrap_err(),
        EchPemError::NoUsableDecryptionKey,
    );
    assert_eq!(
        EchServerConfig::from_pems(retry, retry, ALL_SUPPORTED_SUITES).unwrap_err(),
        EchPemError::MissingPrivateKey,
    );
    assert_eq!(
        EchServerConfig::from_pems(&[key_pem(&key, &list)], &[], ALL_SUPPORTED_SUITES).unwrap_err(),
        EchPemError::InvalidRetryList,
    );
    assert_eq!(
        EchServerConfig::from_pems(&[key_pem(&key, &list)], retry, &[]).unwrap_err(),
        EchPemError::NoUsableDecryptionKey,
    );

    let mut invalid = read_config_list(&list).unwrap().remove(0).contents.unwrap();
    invalid.public_name = b"192.0.2.1".to_vec();
    let invalid = EchConfigEntry::from_contents(invalid);
    let invalid_list = encode_config_list([invalid.encoded.as_slice()].into_iter());
    assert_eq!(
        EchServerConfig::from_pems(
            &[key_pem(&key, &list), key_pem(&key, &invalid_list)],
            retry,
            ALL_SUPPORTED_SUITES,
        )
        .unwrap_err(),
        EchPemError::NoUsableDecryptionKey,
    );
}

#[test]
fn decryption_cap_counts_installed_entries_across_bundles() {
    let key = key(1);
    let opaque = [0xfe, 0x0c, 0, 0];
    let list = encode_config_list(
        core::iter::repeat_n(opaque.as_slice(), 65)
            .chain(core::iter::repeat_n(key.ech_config(), 63)),
    );
    let one = encode_config_list([key.ech_config()].into_iter());
    let two = encode_config_list(core::iter::repeat_n(key.ech_config(), 2));
    let retry = &[EchPem::from_config_list(&one).unwrap()];
    let keys = EchServerConfig::from_pems(
        &[key_pem(&key, &list), key_pem(&key, &one)],
        retry,
        ALL_SUPPORTED_SUITES,
    )
    .unwrap();
    assert_eq!(keys.keys.len(), 64);
    assert_eq!(
        EchServerConfig::from_pems(
            &[key_pem(&key, &list), key_pem(&key, &two)],
            retry,
            ALL_SUPPORTED_SUITES,
        )
        .unwrap_err(),
        EchPemError::TooManyDecryptionKeys,
    );
    assert_eq!(EchServerConfig::new(vec![key; 65]).unwrap().keys.len(), 65);
}

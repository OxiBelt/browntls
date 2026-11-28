//! The HPKE modes of RFC 9180 §5.1 through the facade: an application that
//! depends on `browntls` alone names the PSK, Auth and AuthPSK modes and
//! the exporter at `browntls::crypto::hpke`, and the native suites at
//! `browntls::crypto::native::hpke`.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls::Error;
use browntls::crypto::hpke::{
    HpkeAead, HpkeModes, HpkeOpenMode, HpkePsk, HpkeSealMode, HpkeSealer,
};
use browntls::crypto::native::hpke::{ALL_SUPPORTED_SUITES, ALL_SUPPORTED_SUITES_WITH_MODES};

#[test]
fn every_mode_round_trips_through_the_facade() {
    assert_eq!(
        ALL_SUPPORTED_SUITES_WITH_MODES.len(),
        ALL_SUPPORTED_SUITES.len() + 15
    );
    let suite: &dyn HpkeModes = ALL_SUPPORTED_SUITES_WITH_MODES[0];
    let (pk_r, sk_r) = suite.generate_key_pair().unwrap();
    let (pk_s, sk_s) = suite.generate_key_pair().unwrap();
    let psk = HpkePsk::new(vec![0x24; HpkePsk::MIN_KEY_LEN], b"facade".to_vec()).unwrap();
    let modes = [
        (HpkeSealMode::Base, HpkeOpenMode::Base),
        (HpkeSealMode::Psk(&psk), HpkeOpenMode::Psk(&psk)),
        (HpkeSealMode::Auth(&sk_s), HpkeOpenMode::Auth(&pk_s)),
        (
            HpkeSealMode::AuthPsk(&psk, &sk_s),
            HpkeOpenMode::AuthPsk(&psk, &pk_s),
        ),
    ];
    for (seal_mode, open_mode) in modes {
        let (enc, mut sealer) = suite
            .setup_sealer_with_mode(seal_mode, b"info", &pk_r)
            .unwrap();
        let mut opener = suite
            .setup_opener_with_mode(open_mode, &enc, b"info", &sk_r)
            .unwrap();
        let ciphertext = sealer.seal(b"aad", b"hello").unwrap();
        assert_eq!(opener.open(b"aad", &ciphertext).unwrap(), b"hello");
        let (mut ours, mut theirs) = ([0; 32], [0; 32]);
        sealer.export(b"exporter", &mut ours).unwrap();
        opener.export(b"exporter", &mut theirs).unwrap();
        assert_eq!(ours, theirs, "{seal_mode:?}");
        // The sender in this mode, the recipient in base mode: nothing
        // opens unless both are in base mode.
        if !matches!(seal_mode, HpkeSealMode::Base) {
            let mut base = suite
                .setup_opener_with_mode(HpkeOpenMode::Base, &enc, b"info", &sk_r)
                .unwrap();
            let ciphertext = sealer.seal(b"aad", b"again").unwrap();
            assert_eq!(base.open(b"aad", &ciphertext), Err(Error::DecryptError));
        }
    }
}

#[test]
fn export_only_suites_export_through_the_facade() {
    let suite = ALL_SUPPORTED_SUITES_WITH_MODES[ALL_SUPPORTED_SUITES.len()];
    assert_eq!(suite.suite().sym.aead_id, HpkeAead::EXPORT_ONLY);
    let (pk, sk) = suite.generate_key_pair().unwrap();
    let (enc, mut sealer) = suite
        .setup_sealer_with_mode(HpkeSealMode::Base, b"", &pk)
        .unwrap();
    let opener = suite
        .setup_opener_with_mode(HpkeOpenMode::Base, &enc, b"", &sk)
        .unwrap();
    assert!(sealer.seal(b"", b"no").is_err());
    let (mut ours, mut theirs) = ([0; 16], [0; 16]);
    HpkeSealer::export(&*sealer, b"", &mut ours).unwrap();
    opener.export(b"", &mut theirs).unwrap();
    assert_eq!(ours, theirs);
}

#[test]
fn psk_validation_through_the_facade() {
    assert!(HpkePsk::new(vec![1; 31], b"id".to_vec()).is_err());
    assert!(HpkePsk::new(vec![1; 32], Vec::new()).is_err());
    assert_eq!(
        HpkePsk::new(vec![1; 32], b"id".to_vec()).unwrap().id(),
        b"id"
    );
}

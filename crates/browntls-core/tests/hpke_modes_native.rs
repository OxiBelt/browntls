//! The HPKE modes of RFC 9180 §5.1 through the provider API
//! (`crypto::hpke::HpkeModes`), with the native provider's suites.
//!
//! Every mode round-trips for every suite of `ALL_SUPPORTED_SUITES_WITH_MODES`
//! and agrees with `browntls_crypto::hpke` in both directions; base mode is
//! the `Hpke` setup itself. A wrong pre-shared key, sender key, recipient key
//! or mode opens nothing and exports other bytes; keys of another KEM fail
//! the setup. Every key is generated for the test.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_core::Error;
use browntls_core::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeAead, HpkeModes, HpkeOpenMode, HpkeOpener, HpkePrivateKey,
    HpkePsk, HpkePublicKey, HpkeSealMode, HpkeSealer, HpkeSuite,
};
use browntls_core::crypto::native::hpke::{ALL_SUPPORTED_SUITES, ALL_SUPPORTED_SUITES_WITH_MODES};
use browntls_crypto::hpke as oracle;
use browntls_crypto::rand::{OsRng, SecureRandom};

const INFO: &[u8] = b"browntls HPKE modes test";
const AAD: &[u8] = b"associated data";
const PLAINTEXT: &[u8] = b"a message for the recipient";
const EXPORTER_CONTEXT: &[u8] = b"exporter context";

/// The four modes, as the tests name them.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Base,
    Psk,
    Auth,
    AuthPsk,
}

const MODES: [Mode; 4] = [Mode::Base, Mode::Psk, Mode::Auth, Mode::AuthPsk];

/// A recipient key pair, a sender key pair and a pre-shared key.
struct Keys {
    recipient: (HpkePublicKey, HpkePrivateKey),
    sender: (HpkePublicKey, HpkePrivateKey),
    psk: HpkePsk,
}

impl Keys {
    fn new(suite: &dyn HpkeModes) -> Self {
        Self {
            recipient: suite.generate_key_pair().unwrap(),
            sender: suite.generate_key_pair().unwrap(),
            psk: random_psk(b"psk identifier"),
        }
    }

    fn seal_mode(&self, mode: Mode) -> HpkeSealMode<'_> {
        match mode {
            Mode::Base => HpkeSealMode::Base,
            Mode::Psk => HpkeSealMode::Psk(&self.psk),
            Mode::Auth => HpkeSealMode::Auth(&self.sender.1),
            Mode::AuthPsk => HpkeSealMode::AuthPsk(&self.psk, &self.sender.1),
        }
    }

    fn open_mode(&self, mode: Mode) -> HpkeOpenMode<'_> {
        open_mode(mode, &self.psk, &self.sender.0)
    }

    fn seal(&self, suite: &dyn HpkeModes, mode: Mode) -> (EncapsulatedSecret, Box<dyn HpkeSealer>) {
        suite
            .setup_sealer_with_mode(self.seal_mode(mode), INFO, &self.recipient.0)
            .unwrap()
    }

    fn open(
        &self,
        suite: &dyn HpkeModes,
        mode: HpkeOpenMode<'_>,
        enc: &EncapsulatedSecret,
    ) -> Box<dyn HpkeOpener> {
        suite
            .setup_opener_with_mode(mode, enc, INFO, &self.recipient.1)
            .unwrap()
    }
}

fn open_mode<'a>(mode: Mode, psk: &'a HpkePsk, sender: &'a HpkePublicKey) -> HpkeOpenMode<'a> {
    match mode {
        Mode::Base => HpkeOpenMode::Base,
        Mode::Psk => HpkeOpenMode::Psk(psk),
        Mode::Auth => HpkeOpenMode::Auth(sender),
        Mode::AuthPsk => HpkeOpenMode::AuthPsk(psk, sender),
    }
}

fn random_psk(id: &[u8]) -> HpkePsk {
    let mut key = vec![0; HpkePsk::MIN_KEY_LEN];
    OsRng.fill(&mut key).unwrap();
    HpkePsk::new(key, id.to_vec()).unwrap()
}

fn can_seal(suite: HpkeSuite) -> bool {
    suite.sym.aead_id != HpkeAead::EXPORT_ONLY
}

fn export_sealer(sealer: &dyn HpkeSealer) -> [u8; 40] {
    let mut out = [0; 40];
    sealer.export(EXPORTER_CONTEXT, &mut out).unwrap();
    out
}

fn export_opener(opener: &dyn HpkeOpener) -> [u8; 40] {
    let mut out = [0; 40];
    opener.export(EXPORTER_CONTEXT, &mut out).unwrap();
    out
}

/// Asserts that `opener` cannot open what `sealer` seals and derives other
/// exported bytes.
fn assert_mismatch(sealer: &mut dyn HpkeSealer, opener: &mut dyn HpkeOpener, what: &str) {
    assert_ne!(export_sealer(sealer), export_opener(opener), "{what}");
    if let Ok(ciphertext) = sealer.seal(AAD, PLAINTEXT) {
        assert_eq!(
            opener.open(AAD, &ciphertext),
            Err(Error::DecryptError),
            "{what}"
        );
    }
}

fn oracle_suite(suite: HpkeSuite) -> oracle::Suite {
    oracle::Suite::from_ids(suite.kem.0, suite.sym.kdf_id.0, suite.sym.aead_id.0).unwrap()
}

/// One suite of each KEM, sealing, and one export-only suite.
fn sample_suites() -> Vec<&'static dyn HpkeModes> {
    let mut suites: Vec<&'static dyn HpkeModes> = ALL_SUPPORTED_SUITES_WITH_MODES[..45]
        .iter()
        .step_by(9)
        .copied()
        .collect();
    suites.push(ALL_SUPPORTED_SUITES_WITH_MODES[45]);
    suites
}

#[test]
fn table_lists_every_native_suite_after_the_ech_ones() {
    let ids = |suite: HpkeSuite| (suite.kem.0, suite.sym.kdf_id.0, suite.sym.aead_id.0);
    assert_eq!(ALL_SUPPORTED_SUITES.len(), 45);
    assert_eq!(ALL_SUPPORTED_SUITES_WITH_MODES.len(), 60);
    for (ech, modes) in ALL_SUPPORTED_SUITES
        .iter()
        .zip(ALL_SUPPORTED_SUITES_WITH_MODES)
    {
        assert_eq!(ech.suite(), modes.suite());
        assert!(can_seal(ech.suite()));
    }
    let export_only: Vec<_> = ALL_SUPPORTED_SUITES_WITH_MODES[45..]
        .iter()
        .map(|suite| ids(suite.suite()))
        .collect();
    let mut expected = Vec::new();
    for kem in [0x0020, 0x0010, 0x0011, 0x0012, 0x0021] {
        for kdf in [0x0001, 0x0002, 0x0003] {
            expected.push((kem, kdf, 0xffff));
        }
    }
    assert_eq!(export_only, expected);
    let mut all: Vec<_> = ALL_SUPPORTED_SUITES_WITH_MODES
        .iter()
        .map(|suite| ids(suite.suite()))
        .collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 5 * 3 * 4);
}

#[test]
fn every_mode_round_trips_for_every_suite() {
    for &suite in ALL_SUPPORTED_SUITES_WITH_MODES {
        let keys = Keys::new(suite);
        for mode in MODES {
            let what = format!("{:?} {mode:?}", suite.suite());
            let (enc, mut sealer) = keys.seal(suite, mode);
            let mut opener = keys.open(suite, keys.open_mode(mode), &enc);
            assert_eq!(export_sealer(&*sealer), export_opener(&*opener), "{what}");
            if can_seal(suite.suite()) {
                for i in 0..3u8 {
                    let ciphertext = sealer.seal(&[i], PLAINTEXT).unwrap();
                    assert_eq!(ciphertext.len(), PLAINTEXT.len() + 16, "{what}");
                    assert_eq!(opener.open(&[i], &ciphertext).unwrap(), PLAINTEXT);
                }
            } else {
                assert!(sealer.seal(AAD, PLAINTEXT).is_err(), "{what}");
                assert_eq!(
                    opener.open(AAD, &[0; 32]),
                    Err(Error::DecryptError),
                    "{what}"
                );
            }
        }
    }
}

#[test]
fn modes_agree_with_browntls_crypto_in_both_directions() {
    for &suite in ALL_SUPPORTED_SUITES_WITH_MODES {
        let theirs = oracle_suite(suite.suite());
        let keys = Keys::new(suite);
        let sk_r =
            oracle::PrivateKey::from_bytes(theirs.kem, keys.recipient.1.secret_bytes()).unwrap();
        let pk_r = sk_r.public_key();
        assert_eq!(pk_r.as_bytes(), keys.recipient.0.0);
        let sk_s =
            oracle::PrivateKey::from_bytes(theirs.kem, keys.sender.1.secret_bytes()).unwrap();
        let pk_s = sk_s.public_key();
        let psk = oracle::Psk::new(keys.psk.secret_bytes(), keys.psk.id()).unwrap();
        for mode in MODES {
            let what = format!("{:?} {mode:?}", suite.suite());

            // The provider seals; `browntls_crypto` opens and exports.
            let (enc, mut sealer) = keys.seal(suite, mode);
            let mut recipient = match mode {
                Mode::Base => theirs.setup_recipient(&enc.0, &sk_r, INFO),
                Mode::Psk => theirs.setup_recipient_psk(&enc.0, &sk_r, INFO, &psk),
                Mode::Auth => theirs.setup_recipient_auth(&enc.0, &sk_r, INFO, pk_s),
                Mode::AuthPsk => theirs.setup_recipient_auth_psk(&enc.0, &sk_r, INFO, &psk, pk_s),
            }
            .unwrap();
            assert_eq!(recipient.mode(), oracle_mode(mode), "{what}");
            let mut exported = [0; 40];
            recipient.export(EXPORTER_CONTEXT, &mut exported).unwrap();
            assert_eq!(export_sealer(&*sealer), exported, "{what}");
            if can_seal(suite.suite()) {
                let ciphertext = sealer.seal(AAD, PLAINTEXT).unwrap();
                assert_eq!(recipient.open(AAD, &ciphertext).unwrap(), PLAINTEXT);
            }

            // `browntls_crypto` seals; the provider opens and exports.
            let (enc, mut sender) = match mode {
                Mode::Base => theirs.setup_sender(pk_r, INFO, &OsRng),
                Mode::Psk => theirs.setup_sender_psk(pk_r, INFO, &psk, &OsRng),
                Mode::Auth => theirs.setup_sender_auth(pk_r, INFO, &sk_s, &OsRng),
                Mode::AuthPsk => theirs.setup_sender_auth_psk(pk_r, INFO, &psk, &sk_s, &OsRng),
            }
            .unwrap();
            let enc = EncapsulatedSecret(enc.as_bytes().to_vec());
            let mut opener = keys.open(suite, keys.open_mode(mode), &enc);
            sender.export(EXPORTER_CONTEXT, &mut exported).unwrap();
            assert_eq!(export_opener(&*opener), exported, "{what}");
            if can_seal(suite.suite()) {
                let ciphertext = sender.seal(AAD, PLAINTEXT).unwrap();
                assert_eq!(opener.open(AAD, &ciphertext).unwrap(), PLAINTEXT);
            }
        }
    }
}

fn oracle_mode(mode: Mode) -> oracle::Mode {
    match mode {
        Mode::Base => oracle::Mode::Base,
        Mode::Psk => oracle::Mode::Psk,
        Mode::Auth => oracle::Mode::Auth,
        Mode::AuthPsk => oracle::Mode::AuthPsk,
    }
}

#[test]
fn base_mode_is_the_hpke_setup_in_both_directions() {
    for (i, &suite) in ALL_SUPPORTED_SUITES_WITH_MODES.iter().enumerate() {
        // The same suite through the trait ECH uses.
        let ech: &dyn Hpke = ALL_SUPPORTED_SUITES.get(i).copied().unwrap_or(suite);
        assert_eq!(ech.suite(), suite.suite());
        let (pk, sk) = ech.generate_key_pair().unwrap();

        let (enc, mut sealer) = suite
            .setup_sealer_with_mode(HpkeSealMode::Base, INFO, &pk)
            .unwrap();
        let mut opener = ech.setup_opener(&enc, INFO, &sk).unwrap();
        assert_eq!(export_sealer(&*sealer), export_opener(&*opener));
        if can_seal(suite.suite()) {
            let ciphertext = sealer.seal(AAD, PLAINTEXT).unwrap();
            assert_eq!(opener.open(AAD, &ciphertext).unwrap(), PLAINTEXT);
        }

        let (enc, mut sealer) = ech.setup_sealer(INFO, &pk).unwrap();
        let mut opener = suite
            .setup_opener_with_mode(HpkeOpenMode::Base, &enc, INFO, &sk)
            .unwrap();
        assert_eq!(export_sealer(&*sealer), export_opener(&*opener));
        if can_seal(suite.suite()) {
            let ciphertext = sealer.seal(AAD, PLAINTEXT).unwrap();
            assert_eq!(opener.open(AAD, &ciphertext).unwrap(), PLAINTEXT);
        }
    }
}

#[test]
fn a_recipient_in_another_mode_opens_nothing() {
    for suite in sample_suites() {
        let keys = Keys::new(suite);
        for sealed in MODES {
            for opened in MODES.into_iter().filter(|&m| m != sealed) {
                let (enc, mut sealer) = keys.seal(suite, sealed);
                let mut opener = keys.open(suite, keys.open_mode(opened), &enc);
                let what = format!("{:?} sealed {sealed:?}, opened {opened:?}", suite.suite());
                assert_mismatch(&mut *sealer, &mut *opener, &what);
            }
        }
    }
}

#[test]
fn a_wrong_psk_sender_or_recipient_key_opens_nothing() {
    for suite in sample_suites() {
        let keys = Keys::new(suite);
        let other_key = random_psk(keys.psk.id());
        let other_id =
            HpkePsk::new(keys.psk.secret_bytes().to_vec(), b"other id".to_vec()).unwrap();
        let (other_sender, _) = suite.generate_key_pair().unwrap();
        let (_, other_recipient) = suite.generate_key_pair().unwrap();
        for mode in MODES {
            let what = |case: &str| format!("{:?} {mode:?}: {case}", suite.suite());
            if matches!(mode, Mode::Psk | Mode::AuthPsk) {
                for (case, psk) in [("PSK key", &other_key), ("PSK id", &other_id)] {
                    let (enc, mut sealer) = keys.seal(suite, mode);
                    let wrong = open_mode(mode, psk, &keys.sender.0);
                    let mut opener = keys.open(suite, wrong, &enc);
                    assert_mismatch(&mut *sealer, &mut *opener, &what(case));
                }
            }
            if matches!(mode, Mode::Auth | Mode::AuthPsk) {
                let (enc, mut sealer) = keys.seal(suite, mode);
                let wrong = open_mode(mode, &keys.psk, &other_sender);
                let mut opener = keys.open(suite, wrong, &enc);
                assert_mismatch(&mut *sealer, &mut *opener, &what("sender key"));
            }
            let (enc, mut sealer) = keys.seal(suite, mode);
            let mut opener = suite
                .setup_opener_with_mode(keys.open_mode(mode), &enc, INFO, &other_recipient)
                .unwrap();
            assert_mismatch(&mut *sealer, &mut *opener, &what("recipient key"));
            let (enc, mut sealer) = keys.seal(suite, mode);
            let mut opener = suite
                .setup_opener_with_mode(
                    keys.open_mode(mode),
                    &enc,
                    b"other info",
                    &keys.recipient.1,
                )
                .unwrap();
            assert_mismatch(&mut *sealer, &mut *opener, &what("info"));
        }
    }
}

#[test]
fn keys_of_another_kem_fail_the_setup() {
    // X25519 (32-byte keys) against P-256 (65-byte public keys) and X448
    // (56-byte keys): the lengths differ, so the setup sees the mismatch.
    let x25519 = ALL_SUPPORTED_SUITES_WITH_MODES[0];
    let p256 = ALL_SUPPORTED_SUITES_WITH_MODES[9];
    let x448 = ALL_SUPPORTED_SUITES_WITH_MODES[36];
    let keys = Keys::new(x25519);
    let (p256_pk, _) = p256.generate_key_pair().unwrap();
    let (x448_pk, x448_sk) = x448.generate_key_pair().unwrap();
    let general = |result: Result<(), Error>| matches!(result, Err(Error::General(_)));

    for mode in MODES {
        let sealed = x25519.setup_sealer_with_mode(keys.seal_mode(mode), INFO, &p256_pk);
        assert!(general(sealed.map(drop)), "{mode:?}: recipient key");
        let (enc, _) = keys.seal(x25519, mode);
        let opened = x25519.setup_opener_with_mode(keys.open_mode(mode), &enc, INFO, &x448_sk);
        assert!(general(opened.map(drop)), "{mode:?}: recipient private key");
        let short = EncapsulatedSecret(enc.0[..31].to_vec());
        let opened =
            x25519.setup_opener_with_mode(keys.open_mode(mode), &short, INFO, &keys.recipient.1);
        assert!(general(opened.map(drop)), "{mode:?}: enc");
    }
    for mode in [Mode::Auth, Mode::AuthPsk] {
        let sealed = match mode {
            Mode::Auth => HpkeSealMode::Auth(&x448_sk),
            _ => HpkeSealMode::AuthPsk(&keys.psk, &x448_sk),
        };
        let sealed = x25519.setup_sealer_with_mode(sealed, INFO, &keys.recipient.0);
        assert!(general(sealed.map(drop)), "{mode:?}: sender private key");
        let (enc, _) = keys.seal(x25519, mode);
        for sender in [&p256_pk, &x448_pk] {
            let wrong = open_mode(mode, &keys.psk, sender);
            let opened = x25519.setup_opener_with_mode(wrong, &enc, INFO, &keys.recipient.1);
            assert!(general(opened.map(drop)), "{mode:?}: sender public key");
        }
        // A low-order X25519 sender key: the Diffie-Hellman result is zero.
        let zero = HpkePublicKey(vec![0; 32]);
        let wrong = open_mode(mode, &keys.psk, &zero);
        let opened = x25519.setup_opener_with_mode(wrong, &enc, INFO, &keys.recipient.1);
        assert!(general(opened.map(drop)), "{mode:?}: low-order sender key");
    }
}

#[test]
fn exports_longer_than_255_hash_lengths_fail() {
    // HKDF-SHA256: `Nh` is 32.
    let suite = ALL_SUPPORTED_SUITES_WITH_MODES[45];
    let keys = Keys::new(suite);
    for mode in MODES {
        let (enc, sealer) = keys.seal(suite, mode);
        let opener = keys.open(suite, keys.open_mode(mode), &enc);
        let mut out = vec![0; 255 * 32];
        sealer.export(EXPORTER_CONTEXT, &mut out).unwrap();
        let mut theirs = vec![0; 255 * 32];
        opener.export(EXPORTER_CONTEXT, &mut theirs).unwrap();
        assert_eq!(out, theirs);
        out.push(0);
        assert!(matches!(
            sealer.export(EXPORTER_CONTEXT, &mut out),
            Err(Error::General(_))
        ));
        assert!(matches!(
            opener.export(EXPORTER_CONTEXT, &mut out),
            Err(Error::General(_))
        ));
    }
}

#[test]
fn psk_needs_32_bytes_and_an_identifier() {
    let rejected =
        |key: Vec<u8>, id: &[u8]| matches!(HpkePsk::new(key, id.to_vec()), Err(Error::General(_)));
    assert!(rejected(vec![7; 31], b"id"));
    assert!(rejected(Vec::new(), b"id"));
    assert!(rejected(vec![7; 32], b""));
    assert!(rejected(vec![7; 64], b""));

    let psk = HpkePsk::new(vec![7; 32], b"i".to_vec()).unwrap();
    assert_eq!(psk.id(), b"i");
    assert_eq!(psk.secret_bytes(), [7; 32]);
    assert_eq!(HpkePsk::MIN_KEY_LEN, 32);

    // Neither the key nor the identifier shows in a `Debug` form.
    let (_, sk) = ALL_SUPPORTED_SUITES_WITH_MODES[0]
        .generate_key_pair()
        .unwrap();
    let pk = HpkePublicKey(vec![9; 32]);
    assert_eq!(format!("{psk:?}"), "HpkePsk(..)");
    assert_eq!(
        format!("{:?}", HpkeSealMode::AuthPsk(&psk, &sk)),
        "AuthPsk(HpkePsk(..), HpkePrivateKey(..))"
    );
    assert_eq!(format!("{:?}", HpkeOpenMode::Psk(&psk)), "Psk(HpkePsk(..))");
    assert!(format!("{:?}", HpkeOpenMode::AuthPsk(&psk, &pk)).starts_with("AuthPsk(HpkePsk(..), "));
}

#[derive(Debug)]
struct NoExport;

impl HpkeSealer for NoExport {
    fn seal(&mut self, _: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(plaintext.to_vec())
    }
}

impl HpkeOpener for NoExport {
    fn open(&mut self, _: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(ciphertext.to_vec())
    }
}

#[test]
fn contexts_without_export_fail_it() {
    let unsupported = Err(Error::General("operation not supported".into()));
    let mut out = [0xaa; 16];
    assert_eq!(
        HpkeSealer::export(&NoExport, b"context", &mut out),
        unsupported
    );
    assert_eq!(
        HpkeOpener::export(&NoExport, b"context", &mut out),
        unsupported
    );
    assert_eq!(out, [0xaa; 16]);
}

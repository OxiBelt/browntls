//! The ECH records of a key log (RFC 9850 §2.3).
//!
//! `ECH_SECRET` is the KEM shared secret of the HPKE context that seals the
//! inner ClientHello, and `ECH_CONFIG` the `ECHConfig` that context was set
//! up with. Both are identified by the outer ClientHello's random.
//!
//! The secret leaves the HPKE implementation only when all of this holds:
//! the `key-log` feature is compiled in, the connection's [`KeyLog`] answers
//! [`KeyLog::will_log`] for `ECH_SECRET`, and the suite is the built-in
//! provider's (the only one with a
//! [`KemSecretCapture`](crate::crypto::hpke::KemSecretCapture)). In every
//! other case the ordinary setup runs, which has no way to return it. The
//! capturing setup cannot be called without the sink's answer: it takes a
//! [`KeyLogAuthorisation`], which only that answer makes.
use alloc::boxed::Box;

pub(crate) use crate::crypto::hpke::ECH_SECRET;
use crate::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, KemSecret,
    KemSecretCapture, KeyLogAuthorisation,
};
use crate::error::Error;
use crate::key_log::KeyLog;

/// The label of the `ECHConfig` in use.
pub(crate) const ECH_CONFIG: &str = "ECH_CONFIG";

/// [`Hpke::setup_sealer`] for a context whose KEM secret `key_log` may want.
///
/// `kem_secret` is empty afterwards unless `key_log` takes `ECH_SECRET` and
/// `hpke` can hand the secret out.
pub(crate) fn setup_sealer(
    hpke: &dyn Hpke,
    key_log: &dyn KeyLog,
    info: &[u8],
    pub_key: &HpkePublicKey,
    kem_secret: &mut KemSecret,
) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
    kem_secret.clear();
    match authorised_capture(hpke, key_log) {
        Some((capture, authorised)) => capture.setup_sealer(&authorised, info, pub_key, kem_secret),
        None => hpke.setup_sealer(info, pub_key),
    }
}

/// [`Hpke::setup_opener`] for a context whose KEM secret `key_log` may want.
///
/// `kem_secret` is empty afterwards unless `key_log` takes `ECH_SECRET` and
/// `hpke` can hand the secret out. The caller clears it again when the
/// context does not open the ciphertext it was set up for.
pub(crate) fn setup_opener(
    hpke: &dyn Hpke,
    key_log: &dyn KeyLog,
    enc: &EncapsulatedSecret,
    info: &[u8],
    secret_key: &HpkePrivateKey,
    kem_secret: &mut KemSecret,
) -> Result<Box<dyn HpkeOpener>, Error> {
    kem_secret.clear();
    match authorised_capture(hpke, key_log) {
        Some((capture, authorised)) => {
            capture.setup_opener(&authorised, enc, info, secret_key, kem_secret)
        }
        None => hpke.setup_opener(enc, info, secret_key),
    }
}

/// The capture of `hpke`, if it has one and `key_log` takes `ECH_SECRET`.
/// A suite without the capture does not have the sink asked at all.
fn authorised_capture<'a>(
    hpke: &'a dyn Hpke,
    key_log: &dyn KeyLog,
) -> Option<(&'a dyn KemSecretCapture, KeyLogAuthorisation)> {
    let capture = hpke.kem_secret_capture()?;
    Some((capture, KeyLogAuthorisation::ask(key_log)?))
}

/// Writes the records of one ECH offer: `ECH_SECRET` when `kem_secret` holds
/// the secret, then `ECH_CONFIG` with `config`, the serialized `ECHConfig`
/// (version and length included). `outer_random` is the outer ClientHello's
/// random, never the inner one's (RFC 9850 §2.3).
pub(crate) fn emit(
    key_log: &dyn KeyLog,
    outer_random: &[u8; 32],
    kem_secret: &KemSecret,
    config: &[u8],
) {
    if let Some(secret) = kem_secret.get() {
        crate::key_log::emit(key_log, ECH_SECRET, outer_random, secret);
    }
    crate::key_log::emit(key_log, ECH_CONFIG, outer_random, config);
}

#[cfg(all(test, feature = "native"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::type_complexity)]

    use alloc::format;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::crypto::hpke::HpkeSuite;
    use crate::crypto::native::hpke::ALL_SUPPORTED_SUITES;

    /// A sink that records what it is given and takes only `labels`.
    #[derive(Debug, Default)]
    struct Sink {
        labels: &'static [&'static str],
        asked: Mutex<Vec<String>>,
        lines: Mutex<Vec<(String, Vec<u8>, Vec<u8>)>>,
    }

    impl Sink {
        fn taking(labels: &'static [&'static str]) -> Self {
            Self {
                labels,
                ..Self::default()
            }
        }

        fn lines(&self) -> Vec<(String, Vec<u8>, Vec<u8>)> {
            self.lines.lock().unwrap().clone()
        }
    }

    impl KeyLog for Sink {
        fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
            self.lines.lock().unwrap().push((
                label.to_string(),
                client_random.to_vec(),
                secret.to_vec(),
            ));
        }

        fn will_log(&self, label: &str) -> bool {
            self.asked.lock().unwrap().push(label.to_string());
            self.labels.contains(&label)
        }
    }

    /// A suite that counts which of its entry points ran. With `sealed`
    /// false it stands for another library's suite, which has no capture.
    #[derive(Debug)]
    struct Counting {
        inner: &'static dyn Hpke,
        sealed: bool,
        plain: AtomicUsize,
        captured: AtomicUsize,
    }

    impl Counting {
        fn new(inner: &'static dyn Hpke, sealed: bool) -> Self {
            Self {
                inner,
                sealed,
                plain: AtomicUsize::new(0),
                captured: AtomicUsize::new(0),
            }
        }

        fn counts(&self) -> (usize, usize) {
            (
                self.plain.load(Ordering::Relaxed),
                self.captured.load(Ordering::Relaxed),
            )
        }
    }

    impl Hpke for Counting {
        fn suite(&self) -> HpkeSuite {
            self.inner.suite()
        }

        fn setup_sealer(
            &self,
            info: &[u8],
            pub_key: &HpkePublicKey,
        ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
            self.plain.fetch_add(1, Ordering::Relaxed);
            self.inner.setup_sealer(info, pub_key)
        }

        fn setup_opener(
            &self,
            enc: &EncapsulatedSecret,
            info: &[u8],
            secret_key: &HpkePrivateKey,
        ) -> Result<Box<dyn HpkeOpener>, Error> {
            self.plain.fetch_add(1, Ordering::Relaxed);
            self.inner.setup_opener(enc, info, secret_key)
        }

        fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
            self.inner.generate_key_pair()
        }

        fn kem_secret_capture(&self) -> Option<&dyn KemSecretCapture> {
            self.sealed.then_some(self)
        }
    }

    impl KemSecretCapture for Counting {
        fn setup_sealer(
            &self,
            authorised: &KeyLogAuthorisation,
            info: &[u8],
            pub_key: &HpkePublicKey,
            kem_secret: &mut KemSecret,
        ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
            self.captured.fetch_add(1, Ordering::Relaxed);
            self.inner
                .kem_secret_capture()
                .unwrap()
                .setup_sealer(authorised, info, pub_key, kem_secret)
        }

        fn setup_opener(
            &self,
            authorised: &KeyLogAuthorisation,
            enc: &EncapsulatedSecret,
            info: &[u8],
            secret_key: &HpkePrivateKey,
            kem_secret: &mut KemSecret,
        ) -> Result<Box<dyn HpkeOpener>, Error> {
            self.captured.fetch_add(1, Ordering::Relaxed);
            self.inner
                .kem_secret_capture()
                .unwrap()
                .setup_opener(authorised, enc, info, secret_key, kem_secret)
        }
    }

    /// `Nsecret` of a KEM (RFC 9180 §7.1).
    fn nsecret(kem: u16) -> usize {
        match kem {
            0x0010 | 0x0020 => 32,
            0x0011 => 48,
            0x0012 | 0x0021 => 64,
            _ => panic!("unknown KEM"),
        }
    }

    #[test]
    fn every_native_suite_hands_out_the_same_secret_on_both_sides() {
        let sink = Sink::taking(&[ECH_SECRET]);
        for hpke in ALL_SUPPORTED_SUITES {
            let (public, private) = hpke.generate_key_pair().unwrap();
            let mut sent = KemSecret::empty();
            let (enc, mut sealer) =
                setup_sealer(*hpke, &sink, b"info", &public, &mut sent).unwrap();
            let mut received = KemSecret::empty();
            let mut opener =
                setup_opener(*hpke, &sink, &enc, b"info", &private, &mut received).unwrap();
            let secret = sent.get().unwrap();
            assert_eq!(secret.len(), nsecret(hpke.suite().kem.0));
            assert_eq!(Some(secret), received.get());
            assert_ne!(secret, &[0u8; 64][..secret.len()]);
            assert_ne!(secret, &enc.0[..secret.len().min(enc.0.len())]);
            let sealed = sealer.seal(b"aad", b"inner").unwrap();
            assert_eq!(opener.open(b"aad", &sealed).unwrap(), b"inner");
        }
    }

    #[test]
    fn nothing_is_captured_unless_the_sink_takes_the_label() {
        let hpke = Counting::new(ALL_SUPPORTED_SUITES[0], true);
        let (public, private) = hpke.generate_key_pair().unwrap();
        for (sink, expect_capture) in [
            (Sink::taking(&[]), false),
            (Sink::taking(&[ECH_CONFIG, "CLIENT_RANDOM"]), false),
            (Sink::taking(&[ECH_SECRET]), true),
        ] {
            let before = hpke.counts();
            let mut sent = KemSecret::empty();
            let (enc, _) = setup_sealer(&hpke, &sink, b"info", &public, &mut sent).unwrap();
            let mut received = KemSecret::empty();
            setup_opener(&hpke, &sink, &enc, b"info", &private, &mut received).unwrap();
            let after = hpke.counts();
            if expect_capture {
                assert_eq!((after.0 - before.0, after.1 - before.1), (0, 2));
                assert!(sent.get().is_some() && received.get().is_some());
            } else {
                assert_eq!((after.0 - before.0, after.1 - before.1), (2, 0));
                assert!(sent.get().is_none() && received.get().is_none());
            }
            // The sink was asked about the secret's label only.
            assert_eq!(*sink.asked.lock().unwrap(), [ECH_SECRET, ECH_SECRET]);
        }
        // `NoKeyLog`, the default sink, takes nothing.
        let before = hpke.counts();
        let mut sent = KemSecret::empty();
        setup_sealer(&hpke, &crate::NoKeyLog, b"info", &public, &mut sent).unwrap();
        assert_eq!(hpke.counts(), (before.0 + 1, before.1));
        assert!(sent.get().is_none());
    }

    #[test]
    fn a_suite_without_the_capture_never_yields_a_secret() {
        let hpke = Counting::new(ALL_SUPPORTED_SUITES[0], false);
        let sink = Sink::taking(&[ECH_SECRET, ECH_CONFIG]);
        let (public, private) = hpke.generate_key_pair().unwrap();
        let mut sent = KemSecret::empty();
        let (enc, _) = setup_sealer(&hpke, &sink, b"info", &public, &mut sent).unwrap();
        let mut received = KemSecret::empty();
        setup_opener(&hpke, &sink, &enc, b"info", &private, &mut received).unwrap();
        assert_eq!(hpke.counts(), (2, 0));
        assert!(sent.get().is_none() && received.get().is_none());

        // Its records are the configuration alone.
        emit(&sink, &[7; 32], &sent, b"config");
        assert_eq!(
            sink.lines(),
            [(
                ECH_CONFIG.to_string(),
                [7u8; 32].to_vec(),
                b"config".to_vec()
            )]
        );
    }

    #[test]
    fn a_failed_setup_leaves_no_earlier_secret_in_the_buffer() {
        let hpke = ALL_SUPPORTED_SUITES[0];
        let sink = Sink::taking(&[ECH_SECRET]);
        let (public, private) = hpke.generate_key_pair().unwrap();
        let mut secret = KemSecret::empty();
        let (enc, _) = setup_sealer(hpke, &sink, b"info", &public, &mut secret).unwrap();
        assert!(secret.get().is_some());
        // A public key of the wrong length.
        let bad_key = HpkePublicKey(public.0[1..].to_vec());
        assert!(setup_sealer(hpke, &sink, b"info", &bad_key, &mut secret).is_err());
        assert!(secret.get().is_none());

        setup_opener(hpke, &sink, &enc, b"info", &private, &mut secret).unwrap();
        assert!(secret.get().is_some());
        let bad_enc = EncapsulatedSecret(enc.0[1..].to_vec());
        assert!(setup_opener(hpke, &sink, &bad_enc, b"info", &private, &mut secret).is_err());
        assert!(secret.get().is_none());

        // A sink that stops taking the label empties it too.
        setup_opener(hpke, &sink, &enc, b"info", &private, &mut secret).unwrap();
        assert!(secret.get().is_some());
        setup_opener(
            hpke,
            &Sink::taking(&[]),
            &enc,
            b"info",
            &private,
            &mut secret,
        )
        .unwrap();
        assert!(secret.get().is_none());
    }

    #[test]
    fn records_carry_the_given_random_and_respect_the_sink_per_label() {
        let mut secret = KemSecret::empty();
        secret.set(&[0xab; 32]);
        let random = [0x11; 32];

        let both = Sink::taking(&[ECH_SECRET, ECH_CONFIG]);
        emit(&both, &random, &secret, b"\xfe\x0d\x00\x00");
        assert_eq!(
            both.lines(),
            [
                (ECH_SECRET.to_string(), random.to_vec(), [0xab; 32].to_vec()),
                (
                    ECH_CONFIG.to_string(),
                    random.to_vec(),
                    b"\xfe\x0d\x00\x00".to_vec()
                ),
            ]
        );

        let config_only = Sink::taking(&[ECH_CONFIG]);
        emit(&config_only, &random, &secret, b"c");
        assert_eq!(config_only.lines().len(), 1);
        assert_eq!(config_only.lines()[0].0, ECH_CONFIG);

        let secret_only = Sink::taking(&[ECH_SECRET]);
        emit(&secret_only, &random, &secret, b"c");
        assert_eq!(secret_only.lines().len(), 1);
        assert_eq!(secret_only.lines()[0].0, ECH_SECRET);

        let neither = Sink::taking(&["CLIENT_RANDOM"]);
        emit(&neither, &random, &secret, b"c");
        assert!(neither.lines().is_empty());
    }

    #[test]
    fn the_buffer_hides_and_bounds_its_content() {
        let mut secret = KemSecret::empty();
        assert!(secret.get().is_none());
        secret.set(&[0x5a; 64]);
        assert_eq!(secret.get(), Some(&[0x5a; 64][..]));
        assert_eq!(format!("{secret:?}"), "KemSecret(..)");
        // No KEM has a longer secret: nothing is kept of one.
        secret.set(&[0x5a; 65]);
        assert!(secret.get().is_none());
        secret.set(&[1; 48]);
        secret.clear();
        assert!(secret.get().is_none());
        secret.set(&[]);
        assert!(secret.get().is_none());
    }
}

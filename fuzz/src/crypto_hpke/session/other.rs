//! The other-recipient step of a `crypto_hpke` session: recipients of the
//! genuine `enc` in another mode or with another PSK or sender key, and
//! sender keys of another KEM.

use browntls_crypto::Error;
use browntls_crypto::hpke::{Kem, PrivateKey, PublicKey};
use browntls_crypto::rand::FixedRng;

use super::{Pair, Session, checked_psk, setup_recipient, setup_sender};
use crate::crypto_hpke::{exact, mutate};
use crate::input::Input;

/// The session's key material that the step needs besides the contexts.
pub(super) struct Keys<'a> {
    pub(super) sk: &'a PrivateKey,
    pub(super) enc: &'a [u8],
    pub(super) info: &'a [u8],
    pub(super) ikm_e: &'a [u8],
}

impl Session {
    /// A recipient of the genuine `enc`, chosen by a byte:
    ///
    /// - 0: base mode;
    /// - 1, 2, 3: the session's PSK with a mutated key or identifier, or a
    ///   fuzzed PSK, and the session's sender key if it has one;
    /// - 4: the session's PSK if it has one and no sender key;
    /// - 5, 6: the session's PSK if it has one and the sender public key of
    ///   fuzzed `DeriveKeyPair` input, or fuzzed public key bytes;
    /// - 7: a sender key of another KEM ([`Session::foreign_sender`]).
    ///
    /// A wrong PSK or sender key is not detected at setup. The recipient
    /// must open the first message and export the sender's secret exactly
    /// when its mode, PSK and sender key are the session's; a setup may only
    /// fail on a sender public key that does not deserialize or gives a
    /// rejected Diffie-Hellman result (a low-order X25519 or X448 point).
    /// The oracle must agree on all of it.
    pub(super) fn other_recipient(&self, input: &mut Input<'_>, keys: &Keys<'_>) {
        let suite = self.suite;
        let kem = suite.kem;
        let has_psk = self.psk.is_some();
        let (mut key, mut id) = self.psk.clone().unwrap_or_default();
        let session_pk = self.pk_s().map(|pk| pk.as_bytes().to_vec());
        let (with_psk, pk_s) = match input.choose(8) {
            0 => (false, None),
            1 => {
                mutate(input, &mut key);
                (true, session_pk.clone())
            }
            2 => {
                mutate(input, &mut id);
                (true, session_pk.clone())
            }
            3 => {
                key = input.short_field().to_vec();
                id = input.short_field().to_vec();
                (true, session_pk.clone())
            }
            4 => (has_psk, None),
            5 => {
                let ikm = input.short_field();
                match kem.derive_key_pair(ikm) {
                    Ok(sk) => (has_psk, Some(sk.public_key().as_bytes().to_vec())),
                    Err(e) => {
                        assert_eq!(e, Error::InvalidLength);
                        assert!(ikm.len() < kem.private_key_len());
                        return;
                    }
                }
            }
            6 => {
                let mut bytes = exact(input, kem.public_key_len());
                mutate(input, &mut bytes);
                (has_psk, Some(bytes))
            }
            _ => return self.foreign_sender(input, keys),
        };
        let ctx = input.short_field();
        let psk = if with_psk {
            let Some(psk) = checked_psk(&key, &id) else {
                return;
            };
            Some(psk)
        } else {
            None
        };
        let psk_pair: Pair<'_> = with_psk.then_some((key.as_slice(), id.as_slice()));
        let same = psk_pair == self.psk_pair() && pk_s == session_pk;

        let ours = pk_s
            .as_deref()
            .map(|pk| PublicKey::from_bytes(kem, pk))
            .transpose()
            .and_then(|pk| {
                setup_recipient(
                    suite,
                    keys.enc,
                    keys.sk,
                    keys.info,
                    psk.as_ref(),
                    pk.as_ref(),
                )
            });
        let ours = match ours {
            Err(e) => {
                assert!(
                    e == Error::InvalidKey || e == Error::KeyAgreementFailed,
                    "{suite:?}: {e:?}"
                );
                assert!(pk_s.is_some() && !same, "{suite:?}: setup failed");
                None
            }
            Ok(mut r) => {
                let mut out = [0u8; 32];
                r.export(ctx, &mut out).expect("short export");
                let mut genuine = [0u8; 32];
                self.sender.export(ctx, &mut genuine).expect("short export");
                assert_eq!(
                    out == genuine,
                    same,
                    "{suite:?}: another mode, PSK or sender gave the same export"
                );
                let opened = self.first.as_ref().map(|m| r.open(&m.aad, &m.ct));
                match &opened {
                    Some(Ok(pt)) => {
                        assert!(same, "{suite:?}: opened in another mode or by another PSK");
                        assert_eq!(Some(pt), self.first.as_ref().map(|m| &m.pt));
                        assert_eq!(r.sequence_number(), 1);
                    }
                    Some(Err(e)) => {
                        assert_eq!(*e, Error::DecryptFailed);
                        assert!(!same, "{suite:?}: genuine first message rejected");
                        assert_eq!(r.sequence_number(), 0);
                    }
                    None => {}
                }
                Some((out.to_vec(), opened.and_then(Result::ok)))
            }
        };
        if let Some(oracle) = &self.oracle {
            let first = self.first.as_ref().map(|m| (&m.aad[..], &m.ct[..]));
            let theirs = oracle.recipient(keys.enc, psk_pair, pk_s.as_deref(), ctx, 32, first);
            assert_eq!(
                theirs, ours,
                "{suite:?}: another mode, PSK or sender differs from the oracle"
            );
        }
    }

    /// A sender key of another KEM, from fuzzed `DeriveKeyPair` input: the
    /// authenticated sender and recipient setups (with the session's PSK if
    /// it has one) refuse it with `InvalidKey`.
    fn foreign_sender(&self, input: &mut Input<'_>, keys: &Keys<'_>) {
        let suite = self.suite;
        let n = Kem::ALL.len();
        let index = Kem::ALL
            .iter()
            .position(|k| *k == suite.kem)
            .expect("listed");
        let other = Kem::ALL[(index + 1 + input.choose(n - 1)) % n];
        let ikm = input.short_field();
        let foreign = match other.derive_key_pair(ikm) {
            Ok(sk) => sk,
            Err(e) => {
                assert_eq!(e, Error::InvalidLength);
                assert!(ikm.len() < other.private_key_len());
                return;
            }
        };
        let psk = self.psk();
        let rng = FixedRng::new(keys.ikm_e);
        let pk_r = keys.sk.public_key();
        let sent = setup_sender(suite, pk_r, keys.info, psk.as_ref(), Some(&foreign), &rng);
        assert_eq!(sent.err(), Some(Error::InvalidKey), "{suite:?}: {other:?}");
        let pk = Some(foreign.public_key());
        let received = setup_recipient(suite, keys.enc, keys.sk, keys.info, psk.as_ref(), pk);
        assert_eq!(
            received.err(),
            Some(Error::InvalidKey),
            "{suite:?}: {other:?}"
        );
    }
}

//! The KEM shared secret that `browntls-crypto` hands to a key log
//! (`key-log` feature, RFC 9850 `ECH_SECRET`), against the `hpke` oracle's
//! `Decap`.

use browntls_crypto::Error;
use browntls_crypto::hpke::{Kem, KemSharedSecret, PrivateKey, Suite};
use browntls_crypto::rand::FixedRng;
use hpke::Deserializable as _;

fn oracle_secret<K: hpke::Kem>(ikm_r: &[u8], enc: &[u8]) -> Option<Vec<u8>> {
    let (sk, _) = K::derive_keypair(ikm_r);
    let enc = K::EncappedKey::from_bytes(enc).ok()?;
    K::decap(&sk, None, &enc)
        .ok()
        .map(|secret| secret.0.to_vec())
}

/// The oracle's `Decap(enc, skR)` for the key pair derived from `ikm_r`:
/// `None` without an oracle for `kem`, `Some(None)` when it rejects `enc`.
fn oracle(kem: Kem, ikm_r: &[u8], enc: &[u8]) -> Option<Option<Vec<u8>>> {
    Some(match kem {
        Kem::DhP256HkdfSha256 => oracle_secret::<hpke::kem::DhP256HkdfSha256>(ikm_r, enc),
        Kem::DhP384HkdfSha384 => oracle_secret::<hpke::kem::DhP384HkdfSha384>(ikm_r, enc),
        Kem::DhP521HkdfSha512 => oracle_secret::<hpke::kem::DhP521HkdfSha512>(ikm_r, enc),
        Kem::DhX25519HkdfSha256 => oracle_secret::<hpke::kem::X25519HkdfSha256>(ikm_r, enc),
        _ => return None,
    })
}

/// One session's key material, and the secret of its genuine `enc`.
pub(super) struct KemSecrets<'a> {
    suite: Suite,
    sk: &'a PrivateKey,
    ikm_r: &'a [u8],
    info: &'a [u8],
    enc: &'a [u8],
    genuine: Vec<u8>,
}

impl<'a> KemSecrets<'a> {
    /// Sets the session up again through the capturing entry points: the
    /// sender (same ephemeral key material, so the same `enc`) and the
    /// recipient hand out one secret of `Nsecret` bytes, which is the
    /// oracle's.
    pub(super) fn new(
        suite: Suite,
        sk: &'a PrivateKey,
        ikm_r: &'a [u8],
        ikm_e: &[u8],
        info: &'a [u8],
        enc: &'a [u8],
    ) -> Self {
        let mut sent = KemSharedSecret::new();
        assert!(sent.as_bytes().is_empty());
        let (again, _) = suite
            .setup_sender_with_kem_secret(sk.public_key(), info, &FixedRng::new(ikm_e), &mut sent)
            .expect("the plain setup succeeded");
        assert_eq!(again.as_bytes(), enc);
        let mut received = KemSharedSecret::new();
        suite
            .setup_recipient_with_kem_secret(enc, sk, info, &mut received)
            .expect("genuine enc");
        assert_eq!(sent.as_bytes(), received.as_bytes(), "{suite:?}");
        assert_eq!(sent.as_bytes().len(), suite.kem.shared_secret_len());
        if let Some(theirs) = oracle(suite.kem, ikm_r, enc) {
            assert_eq!(
                Some(sent.as_bytes()),
                theirs.as_deref(),
                "{suite:?}: KEM secret differs from the oracle"
            );
        }
        // A sender without randomness leaves nothing in the buffer.
        assert_eq!(
            suite
                .setup_sender_with_kem_secret(sk.public_key(), info, &FixedRng::new(&[]), &mut sent)
                .err(),
            Some(Error::RandomFailure)
        );
        assert!(sent.as_bytes().is_empty());
        Self {
            suite,
            sk,
            ikm_r,
            info,
            enc,
            genuine: received.as_bytes().to_vec(),
        }
    }

    /// A recipient for a fuzzed `enc`, which the plain setup accepted or not
    /// (`accepted`): the capturing setup agrees, an error empties the
    /// buffer, and a secret is the oracle's and differs from the genuine one
    /// exactly when `enc` does.
    pub(super) fn recipient(&self, fuzzed: &[u8], accepted: bool) {
        let suite = self.suite;
        let mut secret = KemSharedSecret::new();
        suite
            .setup_recipient_with_kem_secret(self.enc, self.sk, self.info, &mut secret)
            .expect("genuine enc");
        let ours = suite.setup_recipient_with_kem_secret(fuzzed, self.sk, self.info, &mut secret);
        assert_eq!(ours.is_ok(), accepted, "{suite:?}: setups disagree");
        if ours.is_err() {
            assert!(secret.as_bytes().is_empty(), "{suite:?}: stale secret");
        } else {
            assert_eq!(
                secret.as_bytes() == self.genuine,
                fuzzed == self.enc,
                "{suite:?}: a different enc gave the same KEM secret"
            );
        }
        if let Some(theirs) = oracle(suite.kem, self.ikm_r, fuzzed) {
            assert_eq!(
                ours.is_ok().then(|| secret.as_bytes()),
                theirs.as_deref(),
                "{suite:?}: KEM secret differs from the oracle"
            );
        }
    }
}

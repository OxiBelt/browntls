//! The session operation of the `crypto_hpke` target: a sender and a
//! recipient context driven by a sub-program of steps, byte for byte
//! against the `hpke` oracle.

use std::collections::VecDeque;
use std::convert::Infallible;

use browntls_crypto::Error;
use browntls_crypto::hpke::{Aead, Kdf, Kem, RecipientContext, SenderContext, Suite, TAG_LEN};
use browntls_crypto::rand::FixedRng;
use hpke::{Deserializable as _, Serializable as _};

use super::kem_secret::KemSecrets;
use super::{
    MAX_STEPS, STEP_EXPORT, STEP_OPEN, STEP_OPEN_FUZZED, STEP_OUT_OF_ORDER, STEP_SEAL,
    STEP_SEAL_IN_PLACE, STEPS, exact, mutate, suite,
};
use crate::input::Input;

/// A deterministic `rand_core` source for the oracle: replays bytes, then
/// zeros.
struct ReplayRng(Vec<u8>);

impl hpke::rand_core::TryRng for ReplayRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let n = dst.len().min(self.0.len());
        dst[..n].copy_from_slice(&self.0[..n]);
        dst[n..].fill(0);
        self.0.drain(..n);
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for ReplayRng {}

/// The `hpke` crate's sender and recipient for one session.
trait SessionOracle {
    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8>;
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>>;
    fn export(&self, ctx: &[u8], len: usize) -> Option<Vec<u8>>;
    /// Exports from a recipient set up with `enc`, or `None` if the setup
    /// fails.
    fn recipient_export(&self, enc: &[u8], ctx: &[u8], len: usize) -> Option<Vec<u8>>;
}

struct SessionO<A: hpke::aead::Aead, F: hpke::kdf::Kdf, K: hpke::Kem> {
    sender: hpke::aead::AeadCtxS<A, F, K>,
    recipient: hpke::aead::AeadCtxR<A, F, K>,
    sk: K::PrivateKey,
    info: Vec<u8>,
}

impl<A: hpke::aead::Aead, F: hpke::kdf::Kdf, K: hpke::Kem> SessionOracle for SessionO<A, F, K> {
    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        self.sender.seal(pt, aad).expect("oracle seal")
    }

    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        self.recipient.open(ct, aad).ok()
    }

    fn export(&self, ctx: &[u8], len: usize) -> Option<Vec<u8>> {
        let mut a = vec![0u8; len];
        let mut b = vec![0u8; len];
        let sa = self.sender.export(ctx, &mut a).ok().map(|()| a);
        let sb = self.recipient.export(ctx, &mut b).ok().map(|()| b);
        assert_eq!(sa, sb, "oracle contexts disagree");
        sa
    }

    fn recipient_export(&self, enc: &[u8], ctx: &[u8], len: usize) -> Option<Vec<u8>> {
        let enc = K::EncappedKey::from_bytes(enc).ok()?;
        let r = hpke::setup_receiver::<A, F, K>(&hpke::OpModeR::Base, &self.sk, &enc, &self.info)
            .ok()?;
        let mut out = vec![0u8; len];
        r.export(ctx, &mut out).ok()?;
        Some(out)
    }
}

fn session_oracle<A, F, K>(
    ikm_r: &[u8],
    ikm_e: &[u8],
    info: &[u8],
    enc: &[u8],
) -> Box<dyn SessionOracle>
where
    A: hpke::aead::Aead + 'static,
    F: hpke::kdf::Kdf + 'static,
    K: hpke::Kem + 'static,
{
    let (sk, pk) = K::derive_keypair(ikm_r);
    let (their_enc, sender) = hpke::setup_sender_with_rng::<A, F, K>(
        &hpke::OpModeS::Base,
        &pk,
        info,
        &mut ReplayRng(ikm_e.to_vec()),
    )
    .expect("oracle setup");
    assert_eq!(
        their_enc.to_bytes().as_slice(),
        enc,
        "enc differs from the oracle"
    );
    let recipient = hpke::setup_receiver::<A, F, K>(&hpke::OpModeR::Base, &sk, &their_enc, info)
        .expect("oracle setup");
    Box::new(SessionO {
        sender,
        recipient,
        sk,
        info: info.to_vec(),
    })
}

/// The oracle session for `suite`, if the oracle supports its KEM.
fn make_session_oracle(
    suite: Suite,
    ikm_r: &[u8],
    ikm_e: &[u8],
    info: &[u8],
    enc: &[u8],
) -> Option<Box<dyn SessionOracle>> {
    macro_rules! aeads {
        ($f:ty, $k:ty) => {
            match suite.aead {
                Aead::Aes128Gcm => Some(session_oracle::<hpke::aead::AesGcm128, $f, $k>(
                    ikm_r, ikm_e, info, enc,
                )),
                Aead::Aes256Gcm => Some(session_oracle::<hpke::aead::AesGcm256, $f, $k>(
                    ikm_r, ikm_e, info, enc,
                )),
                Aead::ChaCha20Poly1305 => {
                    Some(session_oracle::<hpke::aead::ChaCha20Poly1305, $f, $k>(
                        ikm_r, ikm_e, info, enc,
                    ))
                }
                Aead::ExportOnly => Some(session_oracle::<hpke::aead::ExportOnlyAead, $f, $k>(
                    ikm_r, ikm_e, info, enc,
                )),
                _ => None,
            }
        };
    }
    macro_rules! kdfs {
        ($k:ty) => {
            match suite.kdf {
                Kdf::HkdfSha256 => aeads!(hpke::kdf::HkdfSha256, $k),
                Kdf::HkdfSha384 => aeads!(hpke::kdf::HkdfSha384, $k),
                Kdf::HkdfSha512 => aeads!(hpke::kdf::HkdfSha512, $k),
                _ => None,
            }
        };
    }
    match suite.kem {
        Kem::DhP256HkdfSha256 => kdfs!(hpke::kem::DhP256HkdfSha256),
        Kem::DhP384HkdfSha384 => kdfs!(hpke::kem::DhP384HkdfSha384),
        Kem::DhP521HkdfSha512 => kdfs!(hpke::kem::DhP521HkdfSha512),
        Kem::DhX25519HkdfSha256 => kdfs!(hpke::kem::X25519HkdfSha256),
        _ => None,
    }
}

/// A sealed message not yet opened.
struct Sealed {
    aad: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
}

/// Both of our contexts and the oracle's, with the expected sequence
/// numbers.
struct Session {
    suite: Suite,
    sender: SenderContext,
    recipient: RecipientContext,
    oracle: Option<Box<dyn SessionOracle>>,
    sent: u64,
    received: u64,
    pending: VecDeque<Sealed>,
}

impl Session {
    fn check_state(&self) {
        assert_eq!(self.sender.suite(), self.suite);
        assert_eq!(self.recipient.suite(), self.suite);
        assert_eq!(self.sender.sequence_number(), self.sent);
        assert_eq!(self.recipient.sequence_number(), self.received);
    }

    fn seal(&mut self, aad: &[u8], pt: &[u8], in_place: bool) {
        let ct = if in_place {
            let mut buf = pt.to_vec();
            self.sender.seal_in_place(aad, &mut buf).map(|tag| {
                buf.extend_from_slice(&tag);
                buf
            })
        } else {
            self.sender.seal(aad, pt)
        };
        if self.suite.aead == Aead::ExportOnly {
            assert_eq!(ct, Err(Error::Unsupported));
            return;
        }
        let ct = ct.expect("seal");
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        if let Some(oracle) = &mut self.oracle {
            assert_eq!(
                ct,
                oracle.seal(aad, pt),
                "{:?}: ciphertext differs",
                self.suite
            );
        }
        self.sent += 1;
        self.pending.push_back(Sealed {
            aad: aad.to_vec(),
            pt: pt.to_vec(),
            ct,
        });
    }

    /// Opens with our recipient (in place or not) and the oracle; both must
    /// agree on success, and the result must be `expected`.
    fn open(&mut self, aad: &[u8], ct: &[u8], in_place: bool) -> Option<Vec<u8>> {
        let ours = if in_place && ct.len() >= TAG_LEN {
            let (body, tag) = ct.split_at(ct.len() - TAG_LEN);
            let tag: [u8; TAG_LEN] = tag.try_into().expect("TAG_LEN bytes");
            let mut buf = body.to_vec();
            let result = self.recipient.open_in_place(aad, &mut buf, &tag);
            match result {
                // An export-only suite refuses before decrypting anything,
                // so the buffer still holds the ciphertext.
                Err(Error::Unsupported) => assert_eq!(buf, body),
                Err(_) => assert!(buf.iter().all(|&b| b == 0), "plaintext released on failure"),
                Ok(()) => {}
            }
            result.map(|()| buf)
        } else {
            self.recipient.open(aad, ct)
        };
        if self.suite.aead == Aead::ExportOnly {
            // `open` rejects a ciphertext shorter than a tag before looking
            // at the AEAD.
            let expected = if ct.len() < TAG_LEN {
                Error::DecryptFailed
            } else {
                Error::Unsupported
            };
            assert_eq!(ours, Err(expected));
            return None;
        }
        let theirs = self.oracle.as_mut().map(|o| o.open(aad, ct));
        match ours {
            Ok(pt) => {
                self.received += 1;
                if let Some(theirs) = theirs {
                    assert_eq!(
                        theirs.as_ref(),
                        Some(&pt),
                        "{:?}: oracle disagrees",
                        self.suite
                    );
                }
                Some(pt)
            }
            Err(e) => {
                assert_eq!(e, Error::DecryptFailed);
                if let Some(theirs) = theirs {
                    assert_eq!(
                        theirs, None,
                        "{:?}: oracle opens what we reject",
                        self.suite
                    );
                }
                None
            }
        }
    }

    fn export(&self, ctx: &[u8], len: usize) {
        let mut a = vec![0u8; len];
        let mut b = vec![0xffu8; len];
        let ra = self.sender.export(ctx, &mut a);
        let rb = self.recipient.export(ctx, &mut b);
        assert_eq!(ra, rb);
        let limit = 255 * self.suite.kdf.output_len();
        if len > limit {
            assert_eq!(ra, Err(Error::InvalidLength));
        } else {
            assert_eq!(ra, Ok(()));
            assert_eq!(a, b, "{:?}: exports differ", self.suite);
        }
        if let Some(oracle) = &self.oracle {
            let theirs = oracle.export(ctx, len);
            assert_eq!(theirs.is_some(), ra.is_ok());
            if let Some(theirs) = theirs {
                assert_eq!(
                    theirs, a,
                    "{:?}: export differs from the oracle",
                    self.suite
                );
            }
        }
    }
}

/// A sender and a recipient on one suite, then a sub-program of steps.
pub(super) fn session(input: &mut Input<'_>) {
    let suite = suite(input);
    let kem = suite.kem;
    let nsk = kem.private_key_len();
    let ikm_r = input.short_field().to_vec();
    let short_rng = input.choose(8) == 0;
    let ikm_e_len = if short_rng { input.choose(nsk) } else { nsk };
    let ikm_e = exact(input, ikm_e_len);
    let info = input.short_field().to_vec();

    let sk = match kem.derive_key_pair(&ikm_r) {
        Ok(sk) => sk,
        Err(e) => {
            assert_eq!(e, Error::InvalidLength);
            assert!(ikm_r.len() < nsk);
            return;
        }
    };
    let (enc, sender) = match suite.setup_sender(sk.public_key(), &info, &FixedRng::new(&ikm_e)) {
        Ok(out) => out,
        Err(e) => {
            assert!(short_rng);
            assert_eq!(e, Error::RandomFailure);
            return;
        }
    };
    let ephemeral = kem.derive_key_pair(&ikm_e).expect("Nsk bytes");
    assert_eq!(enc.as_bytes(), ephemeral.public_key().as_bytes());
    assert_eq!(enc.as_ref(), enc.as_bytes());
    assert_eq!(enc.as_bytes().len(), kem.enc_len());
    let recipient = suite
        .setup_recipient(enc.as_bytes(), &sk, &info)
        .expect("genuine enc");
    let oracle = make_session_oracle(suite, &ikm_r, &ikm_e, &info, enc.as_bytes());
    let kem_secrets = KemSecrets::new(suite, &sk, &ikm_r, &ikm_e, &info, enc.as_bytes());
    let mut s = Session {
        suite,
        sender,
        recipient,
        oracle,
        sent: 0,
        received: 0,
        pending: VecDeque::new(),
    };
    s.check_state();

    for _ in 0..MAX_STEPS {
        if input.is_empty() {
            break;
        }
        match u8::try_from(input.choose(STEPS)).unwrap_or(0) {
            step @ (STEP_SEAL | STEP_SEAL_IN_PLACE) => {
                let aad = input.short_field();
                let pt = input.field();
                let pt = &pt[..pt.len().min(1024)];
                s.seal(aad, pt, step == STEP_SEAL_IN_PLACE);
            }
            STEP_OPEN => {
                let in_place = input.bool();
                let tamper = input.choose(4);
                let Some(msg) = s.pending.front() else {
                    continue;
                };
                let (mut aad, mut ct) = (msg.aad.clone(), msg.ct.clone());
                match tamper {
                    1 => {
                        let pos = usize::from(input.u16()) % ct.len();
                        ct[pos] ^= 1 << (input.byte() % 8);
                    }
                    2 => aad.push(input.byte()),
                    3 => {
                        ct.pop();
                    }
                    _ => {}
                }
                let opened = s.open(&aad, &ct, in_place);
                if tamper == 0 {
                    let msg = s.pending.pop_front().expect("front exists");
                    assert_eq!(opened, Some(msg.pt), "{suite:?}: genuine message rejected");
                } else {
                    assert_eq!(opened, None, "{suite:?}: tampered message accepted");
                }
            }
            STEP_OPEN_FUZZED => {
                let aad = input.short_field().to_vec();
                let ct = input.field().to_vec();
                let in_place = input.bool();
                let genuine = s
                    .pending
                    .front()
                    .is_some_and(|m| m.aad == aad && m.ct == ct);
                let opened = s.open(&aad, &ct, in_place);
                if suite.aead != Aead::ExportOnly {
                    assert_eq!(
                        opened.is_some(),
                        genuine,
                        "{suite:?}: forged message accepted"
                    );
                }
                if genuine && opened.is_some() {
                    s.pending.pop_front();
                }
            }
            STEP_EXPORT => {
                let ctx = input.short_field();
                let limit = 255 * suite.kdf.output_len();
                let len = match input.choose(3) {
                    0 => input.choose(256),
                    1 => limit - 4 + input.choose(9),
                    _ => usize::from(input.u16()) % (limit + 8),
                };
                s.export(ctx, len);
            }
            STEP_OUT_OF_ORDER => {
                // A later message under the current sequence number fails.
                let in_place = input.bool();
                if let Some(msg) = s.pending.get(1) {
                    let (aad, ct) = (msg.aad.clone(), msg.ct.clone());
                    assert_eq!(
                        s.open(&aad, &ct, in_place),
                        None,
                        "{suite:?}: replay accepted"
                    );
                }
            }
            _ => {
                // A recipient for a fuzzed or mutated enc.
                let mut fuzzed = if input.bool() {
                    enc.as_bytes().to_vec()
                } else {
                    exact(input, kem.enc_len())
                };
                mutate(input, &mut fuzzed);
                let ctx = input.short_field();
                let ours = suite.setup_recipient(&fuzzed, &sk, &info).map(|r| {
                    assert_eq!(r.sequence_number(), 0);
                    let mut out = [0u8; 48];
                    r.export(ctx, &mut out).expect("short export");
                    out
                });
                if let Err(e) = ours {
                    assert!(
                        e == Error::InvalidKey || e == Error::KeyAgreementFailed,
                        "{e:?}"
                    );
                }
                kem_secrets.recipient(&fuzzed, ours.is_ok());
                if let Some(oracle) = &s.oracle {
                    let theirs = oracle.recipient_export(&fuzzed, ctx, 48);
                    assert_eq!(
                        ours.ok().map(|o| o.to_vec()),
                        theirs,
                        "{suite:?}: recipient setup differs from the oracle"
                    );
                }
                if let Ok(out) = ours {
                    let mut genuine = [0u8; 48];
                    s.sender.export(ctx, &mut genuine).expect("short export");
                    assert_eq!(
                        out == genuine,
                        fuzzed == enc.as_bytes(),
                        "{suite:?}: a different enc gave the same secret"
                    );
                }
            }
        }
        s.check_state();
    }
}

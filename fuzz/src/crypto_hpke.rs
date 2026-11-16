//! `browntls-crypto` HPKE (RFC 9180, base mode) and the TLS-side HPKE
//! provider API (`browntls::crypto::hpke`, implemented by
//! `browntls::crypto::native::hpke`).
//!
//! The input is a program of up to [`MAX_OPS`] operations, each an op byte
//! followed by its arguments:
//!
//! - identifiers: fuzzed KEM, KDF and AEAD identifiers look up exactly the
//!   listed algorithms, `Suite::from_ids` agrees, every length accessor is
//!   consistent, and the TLS-side `HpkeAead::tag_len` agrees with the crate.
//! - keys: `DeriveKeyPair` on fuzzed key material, private and public key
//!   deserialization of fuzzed bytes, serialization, `GenerateKeyPair` from a
//!   fixed random source, and setups with a key of another KEM; checked
//!   against the RustCrypto `hpke` oracle (no oracle for X448).
//! - session: a suite, recipient key material, the sender's ephemeral key
//!   material (a fixed random source, so the encapsulation is deterministic)
//!   and `info`, then a sub-program of seals (in place or not) with fuzzed
//!   aad and plaintext, in-order and out-of-order opens, tampered and fuzzed
//!   ciphertexts, exports of fuzzed lengths and a recipient setup with a
//!   fuzzed `enc`. Sealed ciphertexts and exported secrets must equal the
//!   oracle's byte for byte, both contexts must agree, rejected ciphertexts
//!   must not advance the sequence number, and the oracle must accept and
//!   reject the same `enc` values.
//! - provider: one of the native provider's suites through the `Hpke`,
//!   `HpkeSealer` and `HpkeOpener` traits with fuzzed info, aad, plaintext,
//!   public keys, private keys and `enc`; results must agree with the crate
//!   API underneath.

use std::collections::VecDeque;
use std::convert::Infallible;

use browntls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeAead, HpkeKdf, HpkeKem, HpkePrivateKey, HpkePublicKey,
};
use browntls_crypto::Error;
use browntls_crypto::hpke::{
    Aead, Kdf, Kem, MAX_ENC_LEN, MAX_PRIVATE_KEY_LEN, MAX_PUBLIC_KEY_LEN, NONCE_LEN, PrivateKey,
    PublicKey, RecipientContext, SenderContext, Suite, TAG_LEN,
};
use browntls_crypto::rand::{FixedRng, OsRng};
use hpke::{Deserializable as _, Serializable as _};

use crate::input::{Input, put_field, put_short_field};

/// Operations per input.
const MAX_OPS: usize = 8;
/// Steps of one session's sub-program.
const MAX_STEPS: usize = 16;

const OP_IDS: u8 = 0;
const OP_KEYS: u8 = 1;
const OP_SESSION: u8 = 2;
const OP_PROVIDER: u8 = 3;
const OPS: usize = 4;

const STEP_SEAL: u8 = 0;
const STEP_SEAL_IN_PLACE: u8 = 1;
const STEP_OPEN: u8 = 2;
const STEP_OPEN_FUZZED: u8 = 3;
const STEP_EXPORT: u8 = 4;
const STEP_OUT_OF_ORDER: u8 = 5;
const STEP_RECIPIENT: u8 = 6;
const STEPS: usize = 7;

/// The `crypto_hpke` fuzz target.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match u8::try_from(input.choose(OPS)).unwrap_or(0) {
            OP_IDS => ids(&mut input),
            OP_KEYS => keys(&mut input),
            OP_SESSION => session(&mut input),
            _ => provider(&mut input),
        }
    }
}

/// `len` bytes from the input, zero-padded.
fn exact(input: &mut Input<'_>, len: usize) -> Vec<u8> {
    let mut out = input.bytes(len).to_vec();
    out.resize(len, 0);
    out
}

/// Fuzzed byte flips and a fuzzed length change.
fn mutate(input: &mut Input<'_>, bytes: &mut Vec<u8>) {
    for _ in 0..input.choose(3) {
        let pos = input.choose(256) % bytes.len().max(1);
        let flip = input.byte();
        if let Some(b) = bytes.get_mut(pos) {
            *b ^= flip;
        }
    }
    match input.choose(6) {
        1 => {
            bytes.pop();
        }
        2 => bytes.push(input.byte()),
        _ => {}
    }
}

/// A suite chosen by three bytes.
fn suite(input: &mut Input<'_>) -> Suite {
    Suite::new(
        *input.pick(&Kem::ALL),
        *input.pick(&Kdf::ALL),
        *input.pick(&Aead::ALL),
    )
}

/// A fuzzed identifier: mostly near the assigned ranges.
fn id(input: &mut Input<'_>) -> u16 {
    match input.choose(4) {
        0 => input.u16(),
        1 => 0xff00 | u16::from(input.byte()),
        _ => u16::from(input.byte() % 0x24),
    }
}

/// Identifier lookups and length accessors.
fn ids(input: &mut Input<'_>) {
    let (k, f, a) = (id(input), id(input), id(input));
    let kem = Kem::from_id(k);
    let kdf = Kdf::from_id(f);
    let aead = Aead::from_id(a);
    assert_eq!(kem, Kem::ALL.into_iter().find(|x| x.id() == k));
    assert_eq!(kdf, Kdf::ALL.into_iter().find(|x| x.id() == f));
    assert_eq!(aead, Aead::ALL.into_iter().find(|x| x.id() == a));
    let suite = Suite::from_ids(k, f, a);
    match (kem, kdf, aead) {
        (Some(kem), Some(kdf), Some(aead)) => {
            assert_eq!(suite, Some(Suite::new(kem, kdf, aead)));
        }
        _ => assert_eq!(suite, None),
    }
    // The TLS-side identifier types.
    let tag_len = HpkeAead(a).tag_len();
    assert_eq!(
        tag_len,
        aead.filter(|x| *x != Aead::ExportOnly).map(Aead::tag_len)
    );
    assert_eq!(
        tag_len.is_some(),
        HpkeAead(a) != HpkeAead::EXPORT_ONLY && aead.is_some()
    );

    for kem in Kem::ALL {
        assert_eq!(Kem::from_id(kem.id()), Some(kem));
        assert_eq!(kem.enc_len(), kem.public_key_len());
        assert!(kem.public_key_len() <= MAX_PUBLIC_KEY_LEN);
        assert!(kem.enc_len() <= MAX_ENC_LEN);
        assert!(kem.private_key_len() <= MAX_PRIVATE_KEY_LEN);
        assert_eq!(kem.shared_secret_len(), kem.kdf().output_len());
        assert_eq!(Kdf::from_id(kem.kdf().id()), Some(kem.kdf()));
    }
    for (kem, tls) in Kem::ALL.into_iter().zip([
        HpkeKem::DHKEM_P256_HKDF_SHA256,
        HpkeKem::DHKEM_P384_HKDF_SHA384,
        HpkeKem::DHKEM_P521_HKDF_SHA512,
        HpkeKem::DHKEM_X25519_HKDF_SHA256,
        HpkeKem::DHKEM_X448_HKDF_SHA512,
    ]) {
        assert_eq!(kem.id(), tls.0);
    }
    for (kdf, tls) in Kdf::ALL.into_iter().zip([
        HpkeKdf::HKDF_SHA256,
        HpkeKdf::HKDF_SHA384,
        HpkeKdf::HKDF_SHA512,
    ]) {
        assert_eq!(kdf.id(), tls.0);
        assert!(kdf.output_len() <= 64);
    }
    for (aead, tls) in Aead::ALL.into_iter().zip([
        HpkeAead::AES_128_GCM,
        HpkeAead::AES_256_GCM,
        HpkeAead::CHACHA20_POLY_1305,
        HpkeAead::EXPORT_ONLY,
    ]) {
        assert_eq!(aead.id(), tls.0);
        if aead == Aead::ExportOnly {
            assert_eq!(
                (aead.key_len(), aead.nonce_len(), aead.tag_len()),
                (0, 0, 0)
            );
            assert_eq!(tls.tag_len(), None);
        } else {
            assert_eq!((aead.nonce_len(), aead.tag_len()), (NONCE_LEN, TAG_LEN));
            assert!(aead.key_len() == 16 || aead.key_len() == 32);
            assert_eq!(tls.tag_len(), Some(TAG_LEN));
        }
    }
}

/// RFC 7748 clamping, as RFC 9180 §7.1.2 serializes X25519 keys.
fn clamp_x25519(k: &mut [u8]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// The `hpke` crate's view of one KEM.
trait KemOracle {
    /// `DeriveKeyPair(ikm)`: serialized private and public keys.
    fn derive(&self, ikm: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// The public key of a private key, if the private key is valid.
    fn private_key(&self, sk: &[u8]) -> Option<Vec<u8>>;
    /// Whether a public key is valid.
    fn public_key(&self, pk: &[u8]) -> bool;
}

struct KemO<K>(core::marker::PhantomData<K>);

impl<K: hpke::Kem> KemOracle for KemO<K> {
    fn derive(&self, ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = K::derive_keypair(ikm);
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
    }

    fn private_key(&self, sk: &[u8]) -> Option<Vec<u8>> {
        let sk = K::PrivateKey::from_bytes(sk).ok()?;
        Some(K::sk_to_pk(&sk).to_bytes().to_vec())
    }

    fn public_key(&self, pk: &[u8]) -> bool {
        K::PublicKey::from_bytes(pk).is_ok()
    }
}

fn kem_oracle(kem: Kem) -> Option<Box<dyn KemOracle>> {
    fn o<K: hpke::Kem + 'static>() -> Option<Box<dyn KemOracle>> {
        Some(Box::new(KemO::<K>(core::marker::PhantomData)))
    }
    match kem {
        Kem::DhP256HkdfSha256 => o::<hpke::kem::DhP256HkdfSha256>(),
        Kem::DhP384HkdfSha384 => o::<hpke::kem::DhP384HkdfSha384>(),
        Kem::DhP521HkdfSha512 => o::<hpke::kem::DhP521HkdfSha512>(),
        Kem::DhX25519HkdfSha256 => o::<hpke::kem::X25519HkdfSha256>(),
        // The oracle has no X448.
        _ => None,
    }
}

/// Our private key serialization, `Nsk` bytes.
fn private_bytes(sk: &PrivateKey) -> Vec<u8> {
    let mut out = vec![0u8; sk.kem().private_key_len()];
    let n = sk.write_bytes(&mut out).expect("Nsk bytes");
    assert_eq!(n, out.len());
    out
}

/// Key derivation, (de)serialization and generation.
fn keys(input: &mut Input<'_>) {
    let kem = *input.pick(&Kem::ALL);
    let nsk = kem.private_key_len();
    let oracle = kem_oracle(kem);
    match input.choose(5) {
        0 => {
            let ikm = input.short_field();
            let sk = match kem.derive_key_pair(ikm) {
                Ok(sk) => sk,
                Err(e) => {
                    assert_eq!(e, Error::InvalidLength);
                    assert!(ikm.len() < nsk);
                    return;
                }
            };
            assert!(ikm.len() >= nsk);
            assert_eq!(sk.kem(), kem);
            assert_eq!(sk.public_key().kem(), kem);
            assert_eq!(sk.public_key().as_bytes().len(), kem.public_key_len());
            let bytes = private_bytes(&sk);
            if let Some(oracle) = oracle {
                let (mut their_sk, their_pk) = oracle.derive(ikm);
                if kem == Kem::DhX25519HkdfSha256 {
                    clamp_x25519(&mut their_sk);
                }
                assert_eq!(sk.public_key().as_bytes(), their_pk, "{kem:?} pk");
                assert_eq!(bytes, their_sk, "{kem:?} sk");
            }
            // Serialization round trip, and short output buffers.
            let again = PrivateKey::from_bytes(kem, &bytes).expect("own encoding");
            assert_eq!(again.public_key(), sk.public_key());
            assert_eq!(private_bytes(&again), bytes);
            let mut short = vec![0u8; input.choose(nsk)];
            assert_eq!(sk.write_bytes(&mut short), Err(Error::InvalidLength));
            let mut long = vec![0xa5u8; nsk + 1 + input.choose(8)];
            assert_eq!(sk.write_bytes(&mut long), Ok(nsk));
            assert_eq!(&long[..nsk], bytes.as_slice());
            assert!(long[nsk..].iter().all(|&b| b == 0xa5));
        }
        1 => {
            let mut bytes = exact(input, nsk);
            mutate(input, &mut bytes);
            if input.bool() && bytes.len() == nsk {
                // All zeros or all ones: out of range for the NIST curves.
                let fill = if input.bool() { 0 } else { 0xff };
                bytes.fill(fill);
            }
            let result = PrivateKey::from_bytes(kem, &bytes);
            if bytes.len() != nsk {
                assert_eq!(result.err(), Some(Error::InvalidKey));
                return;
            }
            let their_pk = oracle.as_ref().map(|o| o.private_key(&bytes));
            let sk = match result {
                Ok(sk) => sk,
                Err(e) => {
                    assert_eq!(e, Error::InvalidKey);
                    if let Some(their) = their_pk {
                        assert_eq!(their, None, "{kem:?}: oracle accepts a rejected key");
                    }
                    return;
                }
            };
            assert_eq!(sk.kem(), kem);
            if let Some(their) = their_pk {
                assert_eq!(
                    their.as_deref(),
                    Some(sk.public_key().as_bytes()),
                    "{kem:?} pk"
                );
            }
            let mut expected = bytes.clone();
            if kem == Kem::DhX25519HkdfSha256 {
                clamp_x25519(&mut expected);
            } else if kem == Kem::DhX448HkdfSha512 {
                expected[0] &= 252;
                expected[55] |= 128;
            }
            assert_eq!(private_bytes(&sk), expected);
        }
        2 => {
            let mut bytes = if input.bool() {
                let ikm = exact(input, nsk);
                kem.derive_key_pair(&ikm)
                    .expect("Nsk bytes")
                    .public_key()
                    .as_bytes()
                    .to_vec()
            } else {
                exact(input, kem.public_key_len())
            };
            mutate(input, &mut bytes);
            let result = PublicKey::from_bytes(kem, &bytes);
            if bytes.len() != kem.public_key_len() {
                assert_eq!(result, Err(Error::InvalidKey));
                return;
            }
            if let Some(oracle) = &oracle {
                assert_eq!(
                    result.is_ok(),
                    oracle.public_key(&bytes),
                    "{kem:?}: public key validity differs from the oracle"
                );
            }
            match result {
                Ok(pk) => {
                    assert_eq!(pk.kem(), kem);
                    assert_eq!(pk.as_bytes(), bytes.as_slice());
                }
                Err(e) => assert_eq!(e, Error::InvalidKey),
            }
        }
        3 => {
            // GenerateKeyPair draws exactly Nsk bytes and derives from them.
            let rng_bytes = input.short_field();
            match kem.generate_key_pair(&FixedRng::new(rng_bytes)) {
                Ok(sk) => {
                    assert!(rng_bytes.len() >= nsk);
                    let derived = kem.derive_key_pair(&rng_bytes[..nsk]).expect("Nsk bytes");
                    assert_eq!(sk.public_key(), derived.public_key());
                    assert_eq!(private_bytes(&sk), private_bytes(&derived));
                }
                Err(e) => {
                    assert_eq!(e, Error::RandomFailure);
                    assert!(rng_bytes.len() < nsk);
                }
            }
            let sk = kem.generate_key_pair(&OsRng).expect("OS randomness");
            assert_eq!(sk.kem(), kem);
        }
        _ => {
            // Keys of another KEM are refused by both setups.
            let other = *input.pick(&Kem::ALL);
            let ikm = exact(input, MAX_PRIVATE_KEY_LEN);
            let sk = other.derive_key_pair(&ikm).expect("long enough");
            let suite = Suite::new(kem, *input.pick(&Kdf::ALL), *input.pick(&Aead::ALL));
            let sender = suite.setup_sender(sk.public_key(), b"", &OsRng);
            let enc = exact(input, kem.enc_len());
            let recipient = suite.setup_recipient(&enc, &sk, b"");
            if other != kem {
                assert_eq!(sender.err(), Some(Error::InvalidKey));
                assert_eq!(recipient.err(), Some(Error::InvalidKey));
            } else {
                let (enc, s) = sender.expect("valid key");
                let r = suite
                    .setup_recipient(enc.as_bytes(), &sk, b"")
                    .expect("genuine enc");
                let (mut a, mut b) = ([0u8; 32], [1u8; 32]);
                s.export(b"x", &mut a).expect("short export");
                r.export(b"x", &mut b).expect("short export");
                assert_eq!(a, b);
            }
        }
    }
}

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
fn session(input: &mut Input<'_>) {
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

/// The TLS-side provider API on one of the native suites.
fn provider(input: &mut Input<'_>) {
    let all = browntls::crypto::native::hpke::ALL_SUPPORTED_SUITES;
    let hpke: &dyn Hpke = *input.pick(all);
    let tls = hpke.suite();
    let suite = Suite::from_ids(tls.kem.0, tls.sym.kdf_id.0, tls.sym.aead_id.0)
        .expect("native suites are crate suites");
    assert_ne!(suite.aead, Aead::ExportOnly);
    assert!(!hpke.fips());
    let kem = suite.kem;
    let tag_len = tls.sym.aead_id.tag_len().expect("sealing AEAD");

    let (pk, sk) = if input.bool() {
        hpke.generate_key_pair().expect("OS randomness")
    } else {
        let ikm = exact(input, kem.private_key_len());
        let sk = kem.derive_key_pair(&ikm).expect("Nsk bytes");
        (
            HpkePublicKey(sk.public_key().as_bytes().to_vec()),
            HpkePrivateKey::from(private_bytes(&sk)),
        )
    };
    assert_eq!(sk.secret_bytes().len(), kem.private_key_len());
    let crate_sk = PrivateKey::from_bytes(kem, sk.secret_bytes()).expect("own key");
    assert_eq!(crate_sk.public_key().as_bytes(), pk.0.as_slice());
    assert!(format!("{sk:?}").contains(".."));
    let info = input.short_field().to_vec();

    // A fuzzed public key is usable exactly when the crate accepts it.
    if input.choose(4) == 0 {
        let mut bytes = pk.0.clone();
        mutate(input, &mut bytes);
        // Low-order X25519/X448 points parse but fail the agreement.
        let valid = PublicKey::from_bytes(kem, &bytes)
            .and_then(|pk| suite.setup_sender(&pk, &info, &OsRng))
            .is_ok();
        let result = hpke.setup_sealer(&info, &HpkePublicKey(bytes));
        assert_eq!(result.is_ok(), valid, "{tls:?}");
        return;
    }
    // Likewise a fuzzed private key.
    if input.choose(4) == 0 {
        let mut bytes = sk.secret_bytes().to_vec();
        mutate(input, &mut bytes);
        let fuzzed_sk = HpkePrivateKey::from(bytes.clone());
        let enc = exact(input, kem.enc_len());
        let expected = PrivateKey::from_bytes(kem, &bytes)
            .and_then(|k| suite.setup_recipient(&enc, &k, &info))
            .is_ok();
        let result = hpke.setup_opener(&EncapsulatedSecret(enc), &info, &fuzzed_sk);
        assert_eq!(result.is_ok(), expected, "{tls:?}");
        return;
    }

    let (enc, mut sealer) = hpke.setup_sealer(&info, &pk).expect("valid key");
    assert_eq!(enc.0.len(), kem.enc_len());
    let mut opener = hpke.setup_opener(&enc, &info, &sk).expect("genuine enc");
    let mut crate_opener = suite
        .setup_recipient(&enc.0, &crate_sk, &info)
        .expect("genuine enc");

    // A fuzzed enc: the opener exists exactly when the crate accepts it.
    if input.bool() {
        let mut bytes = enc.0.clone();
        mutate(input, &mut bytes);
        let expected = suite.setup_recipient(&bytes, &crate_sk, &info).is_ok();
        let result = hpke.setup_opener(&EncapsulatedSecret(bytes), &info, &sk);
        assert_eq!(result.is_ok(), expected, "{tls:?}");
    }

    for _ in 0..MAX_STEPS {
        if input.is_empty() {
            break;
        }
        let aad = input.short_field();
        let pt = input.field();
        let pt = &pt[..pt.len().min(1024)];
        let ct = sealer.seal(aad, pt).expect("seal");
        assert_eq!(ct.len(), pt.len() + tag_len);
        let tamper = input.choose(3);
        if tamper != 0 {
            let mut bad = ct.clone();
            if tamper == 1 {
                let pos = usize::from(input.u16()) % bad.len();
                bad[pos] ^= 1 << (input.byte() % 8);
            } else {
                bad.truncate(input.choose(bad.len()));
            }
            assert!(
                opener.open(aad, &bad).is_err(),
                "{tls:?}: tampered accepted"
            );
        }
        assert_eq!(opener.open(aad, &ct).expect("genuine"), pt, "{tls:?}");
        assert_eq!(crate_opener.open(aad, &ct).expect("genuine"), pt, "{tls:?}");
    }
}

/// The steps of a session seed that reach every step kind, for a KEM with
/// `enc_len`-byte encapsulated keys.
fn session_steps(enc_len: usize) -> Vec<u8> {
    let mut steps = Vec::new();
    for (aad, pt) in [(&b"aad"[..], &b"hello"[..]), (b"", b"")] {
        steps.push(STEP_SEAL);
        put_short_field(&mut steps, aad);
        put_field(&mut steps, pt);
    }
    steps.extend_from_slice(&[STEP_SEAL_IN_PLACE, 1, b'a', 0, 9]);
    steps.extend_from_slice(b"in place!");
    steps.extend_from_slice(&[STEP_OUT_OF_ORDER, 0]);
    // tampered: a flipped bit, extra aad, a short ciphertext
    steps.extend_from_slice(&[STEP_OPEN, 0, 1, 0, 3, 5]);
    steps.extend_from_slice(&[STEP_OPEN, 1, 2, 7]);
    steps.extend_from_slice(&[STEP_OPEN, 1, 3]);
    // genuine, then in place
    steps.extend_from_slice(&[STEP_OPEN, 0, 0]);
    steps.extend_from_slice(&[STEP_OPEN, 1, 0]);
    // forgeries: shorter than a tag, and tag-sized
    steps.extend_from_slice(&[STEP_OPEN_FUZZED, 0, 0, 3, 1, 2, 3, 1]);
    steps.extend_from_slice(&[STEP_OPEN_FUZZED, 0, 0, 20]);
    steps.extend_from_slice(&[0; 20]);
    steps.push(1);
    // exports: short, at the limit, past the limit, fuzzed
    steps.extend_from_slice(&[STEP_EXPORT, 3, b'c', b't', b'x', 0, 42]);
    steps.extend_from_slice(&[STEP_EXPORT, 0, 1, 4]);
    steps.extend_from_slice(&[STEP_EXPORT, 0, 1, 5]);
    steps.extend_from_slice(&[STEP_EXPORT, 1, b'e', 2, 0x12, 0x34]);
    // recipients: the genuine enc, a mutated one, a fuzzed one
    steps.extend_from_slice(&[STEP_RECIPIENT, 1, 0, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_RECIPIENT, 1, 1, 0, 9, 0, 1, b'x']);
    steps.extend_from_slice(&[STEP_RECIPIENT, 0]);
    steps.extend(core::iter::repeat_n(0x11, enc_len));
    steps.extend_from_slice(&[0, 0, 0]);
    // the last message
    steps.extend_from_slice(&[STEP_OPEN, 0, 0]);
    steps
}

/// Starting inputs for `crypto_hpke`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    // identifiers: valid, unknown, export-only, fully fuzzed
    for ids in [[2u8, 1, 1], [3, 33, 3], [0x23, 0x20, 0], [0x12, 2, 0x10]] {
        seeds.push(vec![OP_IDS, 2, ids[0], 2, ids[1], 2, ids[2]]);
    }
    seeds.push(vec![OP_IDS, 1, 0xff, 2, 1, 1, 0xff]);
    seeds.push(vec![OP_IDS, 0, 0x00, 0x20, 0, 0x00, 0x01, 1, 0xfe]);

    let ikm: Vec<u8> = (0..66u8).map(|i| i.wrapping_mul(47) ^ 0x2d).collect();
    for (k, kem) in (0u8..).zip(Kem::ALL) {
        let nsk = kem.private_key_len();
        let sk = private_bytes(&kem.derive_key_pair(&ikm).expect("long enough"));
        // DeriveKeyPair: long enough, too short
        let mut derive = vec![OP_KEYS, k, 0];
        put_short_field(&mut derive, &ikm);
        derive.extend_from_slice(&[5, 2]);
        seeds.push(derive);
        let mut short = vec![OP_KEYS, k, 0];
        put_short_field(&mut short, &ikm[..20]);
        seeds.push(short);
        // private keys: valid, fuzzed, zero, all ones, a length error
        seeds.push([&[OP_KEYS, k, 1][..], &sk, &[0, 0, 0]].concat());
        seeds.push([&[OP_KEYS, k, 1][..], &ikm[..nsk], &[0, 0, 0]].concat());
        seeds.push([&[OP_KEYS, k, 1][..], &ikm[..nsk], &[0, 0, 1, 1]].concat());
        seeds.push([&[OP_KEYS, k, 1][..], &ikm[..nsk], &[0, 0, 1, 0]].concat());
        seeds.push([&[OP_KEYS, k, 1][..], &sk, &[0, 1, 0]].concat());
        // public keys: genuine, mutated, fuzzed
        seeds.push([&[OP_KEYS, k, 2, 1][..], &ikm[..nsk], &[0, 0]].concat());
        seeds.push([&[OP_KEYS, k, 2, 1][..], &ikm[..nsk], &[1, 40, 1, 0]].concat());
        seeds.push([&[OP_KEYS, k, 2, 1][..], &ikm[..nsk], &[0, 2, 7]].concat());
        seeds.push([&[OP_KEYS, k, 2, 0][..], &ikm, &ikm, &ikm[..1], &[0, 0]].concat());
        // GenerateKeyPair: enough and too few random bytes
        let mut generate = vec![OP_KEYS, k, 3];
        put_short_field(&mut generate, &ikm);
        seeds.push(generate);
        seeds.push(vec![OP_KEYS, k, 3, 4, 1, 2, 3, 4]);
        // a key of another KEM, and of the same KEM
        seeds.push([&[OP_KEYS, k, 4, (k + 1) % 5][..], &ikm, &[0, 0]].concat());
        seeds.push([&[OP_KEYS, k, 4, k][..], &ikm, &[1, 2]].concat());
    }

    // Sessions with every step (the KDF rotates).
    for (k, kem) in (0u8..).zip(Kem::ALL) {
        let nsk = kem.private_key_len();
        let steps = session_steps(kem.enc_len());
        // X25519 with every AEAD; the other KEMs with one sealing AEAD and
        // P-256 also export-only (sessions on the larger curves are slow in
        // debug builds).
        let aeads: &[u8] = match kem {
            Kem::DhX25519HkdfSha256 => &[0, 1, 2, 3],
            Kem::DhP256HkdfSha256 => &[0, 3],
            _ => &[k % 3],
        };
        for &aead in aeads {
            let kdf = (k + aead) % 3;
            let mut seed = vec![OP_SESSION, k, kdf, aead];
            put_short_field(&mut seed, &ikm);
            seed.push(1); // a full random source
            seed.extend_from_slice(&ikm[..nsk]);
            put_short_field(&mut seed, b"info");
            seed.extend_from_slice(&steps);
            seeds.push(seed);
        }
        // short recipient key material, and a short random source
        let mut seed = vec![OP_SESSION, k, 0, 0];
        put_short_field(&mut seed, &ikm[..8]);
        seeds.push(seed);
        let mut seed = vec![OP_SESSION, k, 1, 2];
        put_short_field(&mut seed, &ikm);
        seed.extend_from_slice(&[0, 7]);
        seed.extend_from_slice(&ikm[..7]);
        seeds.push(seed);
    }

    // The provider: derived and generated keys, fuzzed public keys, private
    // keys and enc, seal/open rounds with tampering.
    let mut rounds = Vec::new();
    for tamper in [&[0u8][..], &[1, 0, 3, 5], &[2, 10]] {
        put_short_field(&mut rounds, b"aad");
        put_field(&mut rounds, b"client hello inner");
        rounds.extend_from_slice(tamper);
    }
    let all = browntls::crypto::native::hpke::ALL_SUPPORTED_SUITES;
    for index in [0u8, 9, 18, 27, 36, 2, 13, 44] {
        let tls = all[usize::from(index) % all.len()].suite();
        let kem = Kem::from_id(tls.kem.0).expect("crate KEM");
        let nsk = kem.private_key_len();
        let derived = [&[OP_PROVIDER, index, 0][..], &ikm[..nsk]].concat();
        let mut seed = derived.clone();
        put_short_field(&mut seed, b"info");
        seed.extend_from_slice(&[1, 1, 0]);
        seed.extend_from_slice(&rounds);
        seeds.push(seed);
        let mut seed = vec![OP_PROVIDER, index, 1];
        put_short_field(&mut seed, b"");
        seed.extend_from_slice(&[1, 1, 1, 1, 0, 0x80, 0]);
        seed.extend_from_slice(&rounds);
        seeds.push(seed);
        seeds.push([&derived[..], &[0, 0, 0, 0]].concat());
        seeds.push([&derived[..], &[0, 0, 1, 0, 0x80, 0]].concat());
        seeds.push([&derived[..], &[0, 1, 0, 0, 0]].concat());
        seeds.push([&derived[..], &[0, 1, 0, 0, 1]].concat());
    }
    seeds
}
